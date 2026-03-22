package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Schera-ole/password_manager/internal/client/input"
	"github.com/Schera-ole/password_manager/internal/shared/models"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Helper functions for update
func formatEntryTypeForUpdate(entryType models.EntryType) string {
	switch entryType {
	case models.EntryTypeLogin:
		return "login"
	case models.EntryTypeText:
		return "text"
	case models.EntryTypeBinary:
		return "binary"
	case models.EntryTypeCard:
		return "card"
	default:
		return "unknown"
	}
}

func formatTagsForUpdate(tags []string) string {
	if len(tags) == 0 {
		return "(none)"
	}
	return strings.Join(tags, ", ")
}

// promptForUpdate prompts for a string value, returning the new value or the default if empty
func promptForUpdate(label string, defaultValue string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultValue)
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

// entryToProto converts models.Entry to protobuf Entry
func entryToProto(entry *models.Entry) *pmpb.Entry {
	// Convert tags
	tags := make([]string, len(entry.Tags))
	copy(tags, entry.Tags)

	// Convert meta to structpb.Struct (models.Meta is map[string]string, need map[string]any)
	metaMap := make(map[string]any, len(entry.Meta))
	for k, v := range entry.Meta {
		metaMap[k] = v
	}
	meta, err := structpb.NewStruct(metaMap)
	if err != nil {
		// Fallback to empty struct if conversion fails
		meta = &structpb.Struct{}
	}

	// Convert timestamps
	createdAt := timestamppb.New(entry.CreatedAt)
	updatedAt := timestamppb.New(entry.UpdatedAt)

	// Build the entry using builder
	entryPB := pmpb.Entry_builder{
		Id:            entry.ID,
		UserId:        entry.UserID,
		Title:         entry.Title,
		Description:   entry.Description,
		Tags:          tags,
		EntryType:     pmpb.Entry_EntryType(entry.Type),
		Meta:          meta,
		EncryptedBlob: entry.EncryptedBlob,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       uint32(entry.Version),
	}

	// Set expires_at if present
	if entry.ExpiresAt != nil {
		entryPB.ExpiresAt = timestamppb.New(*entry.ExpiresAt)
	}

	// Build the final entry
	return entryPB.Build()
}

// promptForEntryInput prompts the user for entry data interactively
func promptForEntryInput() (*input.EntryInput, error) {
	// Title (required)
	title, err := input.ReadTitle("Enter entry title: ")
	if err != nil {
		return nil, fmt.Errorf("read title: %w", err)
	}

	// Entry type (required)
	entryType, err := input.ReadEntryType("Select entry type:")
	if err != nil {
		return nil, fmt.Errorf("read entry type: %w", err)
	}

	// Description (optional)
	description, err := input.ReadDescription("Enter description (optional, press Enter to skip): ")
	if err != nil {
		return nil, fmt.Errorf("read description: %w", err)
	}

	// Tags (optional)
	tags, err := input.ReadTags("Enter tags (comma-separated, press Enter to skip): ")
	if err != nil {
		return nil, fmt.Errorf("read tags: %w", err)
	}

	// Meta (optional)
	meta, err := input.ReadMeta("Enter meta key-value pairs (optional, press Enter to skip):")
	if err != nil {
		return nil, fmt.Errorf("read meta: %w", err)
	}

	// Data (required - sensitive)
	data, err := input.ReadDataInteractive(entryType, "Enter data: ")
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	return &input.EntryInput{
		Title:       title,
		Description: description,
		Tags:        tags,
		EntryType:   entryType,
		Meta:        meta,
		Data:        data,
	}, nil
}

// protoStructToMeta converts google.protobuf.Struct to Meta (map[string]string)
func protoStructToMeta(structpb *structpb.Struct) models.Meta {
	if structpb == nil {
		return nil
	}
	meta := make(models.Meta)
	for k, v := range structpb.GetFields() {
		if v != nil {
			meta[k] = v.GetStringValue()
		}
	}
	return meta
}

// isNetworkError checks if the error is a network-related error
func isNetworkError(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	// gRPC network errors
	return st.Code() == codes.Unavailable ||
		st.Code() == codes.DeadlineExceeded ||
		st.Code() == codes.Unknown
}
