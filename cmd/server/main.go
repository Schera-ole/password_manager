package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Schera-ole/password_manager/internal/server/auth"
	"github.com/Schera-ole/password_manager/internal/server/config"
	grpcService "github.com/Schera-ole/password_manager/internal/server/grpc"
	"github.com/Schera-ole/password_manager/internal/server/migration"
	"github.com/Schera-ole/password_manager/internal/server/repository"
	"github.com/Schera-ole/password_manager/internal/server/service"
	"github.com/Schera-ole/password_manager/internal/server/tls"
	authpb "github.com/Schera-ole/password_manager/internal/shared/pb/auth"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	buildVersion string = "N/A"
	buildDate    string = "N/A"
	buildCommit  string = "N/A"
)

// main initializes and starts the password_manager server.
func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal("Failed to initialize zap logger: ", err)
	}
	defer logger.Sync()
	logSugar := logger.Sugar()

	// Print build information
	logSugar.Infof("Build version: %s", buildVersion)
	logSugar.Infof("Build date: %s", buildDate)
	logSugar.Infof("Build commit: %s", buildCommit)

	serverConfig, err := config.NewServerConfig()
	if err != nil {
		logSugar.Fatal("Failed to parse configuration: ", err)
	}

	var storage repository.Repository
	var commonService *service.CommonService

	// Create context for all lifecycle
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	// Create separate context for migrations
	migCtx, migCancel := context.WithTimeout(appCtx, 30*time.Second)
	defer migCancel()

	// Start migrations
	err = migration.RunMigrations(migCtx, serverConfig.DatabaseDSN, logSugar)
	if err != nil {
		logSugar.Errorf("%v", err)
	}

	// Crate data storage
	storage, err = repository.NewDBStorage(serverConfig.DatabaseDSN)
	if err != nil {
		logSugar.Fatalf("Error when open db connection: %v", err)
	}

	// Configura connection pool for database
	if dbStorage, ok := storage.(*repository.DBStorage); ok {
		dbStorage.SetDBConfig(
			serverConfig.MaxOpenConns,
			serverConfig.MaxIdleConns,
			serverConfig.ConnMaxLifetime,
		)
		logSugar.Infow("Database connection pool configured",
			"max_open_conns", serverConfig.MaxOpenConns,
			"max_idle_conns", serverConfig.MaxIdleConns,
			"conn_max_lifetime", serverConfig.ConnMaxLifetime,
		)
	}

	// Initialize JWT token manager with secrets from config
	tokenMgr, err := auth.NewJWTTokenManagerFromConfig(serverConfig.JWTAccessSecret)
	if err != nil {
		logSugar.Fatalf("Failed to create JWT token manager: %v", err)
	}
	logSugar.Info("JWT token manager initialized with config secrets")

	// Initialize TLS certificates
	var tlsCredentials credentials.TransportCredentials
	if serverConfig.TLSCertPath == "" || serverConfig.TLSKeyPath == "" {
		logSugar.Info("TLS certificate not provided, generating self-signed certificate...")
		certPath, keyPath, err := tls.GenerateSelfSignedCert()
		if err != nil {
			logSugar.Fatalf("Failed to generate TLS certificate: %v", err)
		}
		logSugar.Infof("Self-signed certificate generated at %s", certPath)
		serverConfig.TLSCertPath = certPath
		serverConfig.TLSKeyPath = keyPath
	}

	tlsCert, err := tls.LoadTLSCert(serverConfig.TLSCertPath, serverConfig.TLSKeyPath)
	if err != nil {
		logSugar.Fatalf("Failed to load TLS certificate: %v", err)
	}
	tlsCredentials = credentials.NewServerTLSFromCert(tlsCert)
	logSugar.Info("TLS credentials loaded successfully")

	// Initialize CommonService with the repository and token manager
	commonService = service.NewCommonService(storage, tokenMgr)

	// Check database connection health
	if err := commonService.Ping(appCtx); err != nil {
		logSugar.Fatalf("Database ping failed: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	var storageWg sync.WaitGroup
	storageWg.Add(1)

	go func() {
		defer storageWg.Done()
		<-appCtx.Done()
		if storage != nil {
			logSugar.Info("Closing database storage...")
			if err := storage.Close(); err != nil {
				logSugar.Errorf("Error closing storage: %v", err)
			} else {
				logSugar.Info("Database storage closed successfully")
			}
		}
	}()

	var grpcServer *grpc.Server
	pmGRPCservice := grpcService.NewPMGRPCService(commonService)
	listen, err := net.Listen("tcp", serverConfig.GRPCServerAddress)
	if err != nil {
		logSugar.Fatalf("Failed to listen on gRPC address %s: %v", serverConfig.GRPCServerAddress, err)
	}
	grpcServer = grpc.NewServer(
		grpc.Creds(tlsCredentials),
		grpc.UnaryInterceptor(grpcService.JWTInterceptor(tokenMgr, storage)),
	)
	authpb.RegisterAuthServiceServer(grpcServer, pmGRPCservice)
	pmpb.RegisterPasswordManagerServiceServer(grpcServer, pmGRPCservice)

	grpcErrChan := make(chan error, 1)

	go func() {
		logSugar.Infof("Starting gRPC server on %s", serverConfig.GRPCServerAddress)
		if err := grpcServer.Serve(listen); err != nil {
			logSugar.Errorf("gRPC server failed: %v", err)
			grpcErrChan <- err
		}
		close(grpcErrChan)
	}()

	logSugar.Info("Server started successfully")

	select {
	case err := <-grpcErrChan:
		logSugar.Errorf("gRPC server error: %v", err)
	case <-sigChan:
		logSugar.Info("Shutting down server...")
	}

	appCancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if grpcServer != nil {
			grpcServer.GracefulStop()
			logSugar.Info("gRPC server stopped gracefully")
		}
	}()

	select {
	case <-done:
		logSugar.Info("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		logSugar.Warn("Graceful shutdown timed out, forcing exit")
		grpcServer.Stop()
		logSugar.Info("gRPC server stopped forcefully")
	}

	logSugar.Info("Waiting for storage cleanup...")
	storageWg.Wait()
	logSugar.Info("All resources cleaned up, exiting")
}
