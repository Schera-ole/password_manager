/*
Copyright © 2026 Olga Leonteva
*/
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/Schera-ole/password_manager/internal/client/app"
	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/client/grpc"
	"github.com/spf13/cobra"

	"github.com/Schera-ole/password_manager/internal/client/input"
)

// appContextKey is a private type for context key
type appContextKey struct{}

// appContextKeyInstance is the key used to store App in context
var appContextKeyInstance = appContextKey{}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "Password Manager",
	Short: "Secure password manager CLI",
	Long: `Secure Password Manager CLI

A secure password manager with client-server architecture that allows you to store, retrieve, and manage your passwords safely.

The client connects to a remote server to synchronize your encrypted password entries across devices. All sensitive data is encrypted locally before being sent to the server.

Usage:
	 client [command]

Available Commands:
	 create      Create a new entry
	 delete      Delete specific entry
	 get         Get specific entry
	 list        List all entries
	 login       Login to password manager
	 logout      Logout from password manager
	 register    Register new user
	 sync        Synchronize entries with the server
	 update      Update existing entry
	 whoami      Show current authentication status

Flags:
	 -h, --help          help for Password Manager
	     --server string gRPC server address (host:port) (default "localhost:50051")
	     --db-path string path to local client bolt db

Use "client [command] --help" for more information about a command.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		serverAddr, _ := cmd.Flags().GetString("server")
		if envServer := os.Getenv("PM_SERVER"); envServer != "" {
			serverAddr = envServer
		}

		dbPath, _ := cmd.Flags().GetString("db-path")
		if envDBPath := os.Getenv("PM_DB_PATH"); envDBPath != "" {
			dbPath = envDBPath
		}

		// Create App instance
		appInstance, err := app.NewApp(serverAddr, dbPath)
		if err != nil {
			return fmt.Errorf("create app: %w", err)
		}

		// Check if there's leftover data from a previous user session
		isLoggedIn, err := appInstance.IsLoggedIn()
		if err != nil {
			return fmt.Errorf("check login status: %w", err)
		}
		if isLoggedIn {
			fmt.Fprintln(os.Stderr, "Warning: Previous session data detected. Running commands may use cached data.")
			fmt.Fprintln(os.Stderr, "Hint: Use 'client logout' to clear all local data before switching users.")
		}

		ctx := cmd.Context()
		ctx = context.WithValue(ctx, appContextKeyInstance, appInstance)

		cmd.SetContext(ctx)

		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().String("server", "localhost:50051", "gRPC server address (host:port)")
	rootCmd.PersistentFlags().String("db-path", "", "path to local client bolt db")

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// GetAppFromContext retrieves the App instance from command context
func GetAppFromContext(ctx context.Context) *app.App {
	if app, ok := ctx.Value(appContextKeyInstance).(*app.App); ok {
		return app
	}
	return nil
}

// promptPassword prompts the user for the master password and adds it to the context.
func promptPassword(cmd *cobra.Command) (context.Context, error) {
	pwd, err := input.ReadPassword("Enter master password: ")
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	defer crypto.ZeroMemory(pwd)

	ctx := grpc.WithPassword(cmd.Context(), string(pwd))

	// Add timeout from app config if available
	if appInstance := GetAppFromContext(ctx); appInstance != nil {
		ctx, cancel := appInstance.ContextWithTimeout()
		defer cancel()
		return ctx, nil
	}

	return ctx, nil
}
