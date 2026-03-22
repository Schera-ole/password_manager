package grpc

import (
	"context"
	"time"

	"github.com/Schera-ole/password_manager/internal/server/service"
	model "github.com/Schera-ole/password_manager/internal/shared/models"
	authpb "github.com/Schera-ole/password_manager/internal/shared/pb/auth"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PMGRPCService implements the gRPC Common service with user and password services.
type PMGRPCService struct {
	authpb.UnimplementedAuthServiceServer
	pmpb.UnimplementedPasswordManagerServiceServer
	commonService *service.CommonService
}

// NewPMGRPCService creates a new gRPC server instance with the given common service.
func NewPMGRPCService(commonService *service.CommonService) *PMGRPCService {
	return &PMGRPCService{
		commonService: commonService,
	}
}

// Register - registers a new user.
func (s *PMGRPCService) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.RegisterResponse, error) {
	return s.commonService.Register(ctx, req)
}

// Login - authenticates a user and returns tokens.
func (s *PMGRPCService) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	return s.commonService.Login(ctx, req)
}

// Logout - revokes access token for a device.
func (s *PMGRPCService) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.LogoutResponse, error) {
	return s.commonService.Logout(ctx, req)
}

// ListEntries - gets all user entries.
func (s *PMGRPCService) ListEntries(ctx context.Context, req *pmpb.ListEntriesRequest) (*pmpb.ListEntriesResponse, error) {
	// Extract user ID from context (from JWT token)
	userID := ctx.Value("user_id")
	if userID == nil {
		return nil, status.Error(codes.Unauthenticated, "user not found in context")
	}

	entries, err := s.commonService.ListEntries(ctx, userID.(string), req.GetTags())
	if err != nil {
		return nil, err
	}

	pbEntries := make([]*pmpb.Entry, len(entries))
	for i, entry := range entries {
		pbEntries[i] = convertEntryToProto(entry)
	}

	responseBuilder := pmpb.ListEntriesResponse_builder{
		Entries:    pbEntries,
		TotalCount: int32(len(pbEntries)),
	}
	return responseBuilder.Build(), nil
}

// GetEntry - gets a single entry by ID.
func (s *PMGRPCService) GetEntry(ctx context.Context, req *pmpb.GetEntryRequest) (*pmpb.GetEntryResponse, error) {
	// Extract user ID from context (from JWT token)
	userID := ctx.Value("user_id")

	entryID := req.GetEntryId()
	if entryID == "" {
		return nil, status.Error(codes.InvalidArgument, "entry_id is required")
	}

	entry, err := s.commonService.GetEntry(ctx, entryID)
	if err != nil {
		return nil, err
	}
	// Check if user_id from jwt == user_id for entry
	if entry.UserID != userID.(string) {
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	pbEntry := convertEntryToProto(entry)

	responseBuilder := pmpb.GetEntryResponse_builder{
		Entry: pbEntry,
	}
	return responseBuilder.Build(), nil
}

// CreateEntry - creates a new entry.
func (s *PMGRPCService) CreateEntry(ctx context.Context, req *pmpb.CreateEntryRequest) (*pmpb.CreateEntryResponse, error) {
	entry := req.GetEntry()
	if entry == nil {
		return nil, status.Error(codes.InvalidArgument, "entry is required")
	}

	modelEntry := convertProtoToEntry(entry)

	err := s.commonService.SetEntry(ctx, modelEntry)
	if err != nil {
		return nil, err
	}

	pbEntry := convertEntryToProto(modelEntry)

	responseBuilder := pmpb.CreateEntryResponse_builder{
		Entry: pbEntry,
	}
	return responseBuilder.Build(), nil
}

// UpdateEntry - updates an existing entry.
func (s *PMGRPCService) UpdateEntry(ctx context.Context, req *pmpb.UpdateEntryRequest) (*pmpb.UpdateEntryResponse, error) {
	entry := req.GetEntry()
	if entry == nil {
		return nil, status.Error(codes.InvalidArgument, "entry is required")
	}

	// Validate entry ID
	if entry.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "entry id is required")
	}

	modelEntry := convertProtoToEntry(entry)

	err := s.commonService.SetEntry(ctx, modelEntry)
	if err != nil {
		return nil, err
	}

	pbEntry := convertEntryToProto(modelEntry)

	responseBuilder := pmpb.UpdateEntryResponse_builder{
		Entry: pbEntry,
	}
	return responseBuilder.Build(), nil
}

// DeleteEntry - deletes an entry.
func (s *PMGRPCService) DeleteEntry(ctx context.Context, req *pmpb.DeleteEntryRequest) (*pmpb.DeleteEntryResponse, error) {
	userID := ctx.Value("user_id")

	entryID := req.GetEntryId()
	if entryID == "" {
		return nil, status.Error(codes.InvalidArgument, "entry_id is required")
	}

	// Get entry first to check authorization
	entry, err := s.commonService.GetEntry(ctx, entryID)
	if err != nil {
		return nil, err
	}

	// Check authorization - user can only delete their own entries
	if entry.UserID != userID.(string) {
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	err = s.commonService.DeleteEntry(ctx, entryID)
	if err != nil {
		return nil, err
	}
	return &pmpb.DeleteEntryResponse{}, nil
}

// convertProtoToEntry converts a proto Entry to a model Entry
func convertProtoToEntry(entry *pmpb.Entry) model.Entry {
	meta := make(model.Meta)
	if entry.GetMeta() != nil {
		for k, v := range entry.GetMeta().GetFields() {
			if v.GetStringValue() != "" {
				meta[k] = v.GetStringValue()
			}
		}
	}

	var expiresAt *time.Time
	if entry.GetExpiresAt() != nil {
		t := entry.GetExpiresAt().AsTime()
		expiresAt = &t
	}

	return model.Entry{
		ID:            entry.GetId(),
		UserID:        entry.GetUserId(),
		Title:         entry.GetTitle(),
		Description:   entry.GetDescription(),
		Tags:          entry.GetTags(),
		Type:          model.EntryType(entry.GetEntryType()),
		Meta:          meta,
		EncryptedBlob: entry.GetEncryptedBlob(),
		CreatedAt:     entry.GetCreatedAt().AsTime(),
		UpdatedAt:     entry.GetUpdatedAt().AsTime(),
		ExpiresAt:     expiresAt,
		Version:       int64(entry.GetVersion()),
	}
}

// convertEntryToProto converts a model Entry to a proto Entry
func convertEntryToProto(entry model.Entry) *pmpb.Entry {
	meta := make(map[string]*structpb.Value)
	for k, v := range entry.Meta {
		meta[k] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: v}}
	}

	var expiresAt *timestamppb.Timestamp
	if entry.ExpiresAt != nil {
		expiresAt = timestamppb.New(*entry.ExpiresAt)
	}

	builder := pmpb.Entry_builder{
		Id:            entry.ID,
		UserId:        entry.UserID,
		Title:         entry.Title,
		Description:   entry.Description,
		Tags:          entry.Tags,
		EntryType:     pmpb.Entry_EntryType(entry.Type),
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: entry.EncryptedBlob,
		CreatedAt:     timestamppb.New(entry.CreatedAt),
		UpdatedAt:     timestamppb.New(entry.UpdatedAt),
		ExpiresAt:     expiresAt,
		Version:       uint32(entry.Version),
	}
	return builder.Build()
}

// Sync - synchronizes entries for a user.
func (s *PMGRPCService) Sync(ctx context.Context, req *pmpb.SyncRequest) (*pmpb.SyncResponse, error) {
	userID := ctx.Value("user_id")

	// Get sync timestamp from request (client's last sync time)
	since := req.GetSince().AsTime()

	// Get sync log entries for the user since the given time
	logs, err := s.commonService.GetSyncLog(ctx, userID.(string), since, 1000)
	if err != nil {
		return nil, err
	}

	// Get the actual entries for each sync log entry
	entries := make([]model.Entry, 0, len(logs))
	for _, log := range logs {
		entry, err := s.commonService.GetEntry(ctx, log.EntryID)
		if err != nil {
			// Skip entries that couldn't be retrieved
			continue
		}
		// Check authorization
		if entry.UserID != userID.(string) {
			continue
		}
		entries = append(entries, entry)
	}

	pbEntries := make([]*pmpb.Entry, len(entries))
	for i, entry := range entries {
		pbEntries[i] = convertEntryToProto(entry)
	}

	now := timestamppb.Now()

	responseBuilder := pmpb.SyncResponse_builder{
		Entries:    pbEntries,
		LastSync:   now,
		ReadOnly:   false,
		TotalCount: int32(len(pbEntries)),
	}
	return responseBuilder.Build(), nil
}
