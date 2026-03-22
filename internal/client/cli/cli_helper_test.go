package cli

import (
	"testing"
	"time"

	"github.com/Schera-ole/password_manager/internal/shared/models"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestFormatEntryTypeForUpdate(t *testing.T) {
	tests := []struct {
		name      string
		entryType models.EntryType
		expected  string
	}{
		{
			name:      "EntryTypeLogin",
			entryType: models.EntryTypeLogin,
			expected:  "login",
		},
		{
			name:      "EntryTypeText",
			entryType: models.EntryTypeText,
			expected:  "text",
		},
		{
			name:      "EntryTypeBinary",
			entryType: models.EntryTypeBinary,
			expected:  "binary",
		},
		{
			name:      "EntryTypeCard",
			entryType: models.EntryTypeCard,
			expected:  "card",
		},
		{
			name:      "Unknown type",
			entryType: models.EntryType(999),
			expected:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatEntryTypeForUpdate(tt.entryType)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatTagsForUpdate(t *testing.T) {
	tests := []struct {
		name     string
		tags     []string
		expected string
	}{
		{
			name:     "Empty tags",
			tags:     []string{},
			expected: "(none)",
		},
		{
			name:     "Single tag",
			tags:     []string{"work"},
			expected: "work",
		},
		{
			name:     "Multiple tags",
			tags:     []string{"work", "dev", "github"},
			expected: "work, dev, github",
		},
		{
			name:     "Tags with spaces",
			tags:     []string{"work ", " dev", " github "},
			expected: "work ,  dev,  github ", // strings.Join preserves leading/trailing spaces
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTagsForUpdate(tt.tags)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestProtoStructToMeta(t *testing.T) {
	tests := []struct {
		name     string
		structpb *structpb.Struct
		expected models.Meta
	}{
		{
			name:     "Nil struct",
			structpb: nil,
			expected: nil,
		},
		{
			name:     "Empty struct",
			structpb: &structpb.Struct{},
			expected: models.Meta{},
		},
		{
			name: "Single field",
			structpb: func() *structpb.Struct {
				s, _ := structpb.NewStruct(map[string]any{
					"key1": "value1",
				})
				return s
			}(),
			expected: models.Meta{
				"key1": "value1",
			},
		},
		{
			name: "Multiple fields",
			structpb: func() *structpb.Struct {
				s, _ := structpb.NewStruct(map[string]any{
					"username": "user",
					"password": "pass",
				})
				return s
			}(),
			expected: models.Meta{
				"username": "user",
				"password": "pass",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := protoStructToMeta(tt.structpb)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d fields, got %d", len(tt.expected), len(result))
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("Expected %q for key %q, got %q", v, k, result[k])
				}
			}
		})
	}
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Unavailable error",
			err:      status.Error(codes.Unavailable, "connection unavailable"),
			expected: true,
		},
		{
			name:     "DeadlineExceeded error",
			err:      status.Error(codes.DeadlineExceeded, "deadline exceeded"),
			expected: true,
		},
		{
			name:     "Unknown error",
			err:      status.Error(codes.Unknown, "unknown error"),
			expected: true,
		},
		{
			name:     "InvalidArgument error",
			err:      status.Error(codes.InvalidArgument, "invalid argument"),
			expected: false,
		},
		{
			name:     "Not a gRPC error",
			err:      nil,
			expected: false,
		},
		{
			name:     "Regular error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNetworkError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestEntryToProto(t *testing.T) {
	// Create a test entry
	createdAt := time.Now()
	updatedAt := time.Now()
	expiresAt := createdAt.Add(24 * time.Hour)

	entry := &models.Entry{
		ID:            "test-entry-id",
		UserID:        "user@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{"tag1", "tag2"},
		Type:          models.EntryTypeLogin,
		Meta:          models.Meta{"username": "testuser"},
		EncryptedBlob: []byte("encrypted-data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		ExpiresAt:     &expiresAt,
		Version:       1,
	}

	protoEntry := entryToProto(entry)

	// Verify the converted entry
	if protoEntry.GetId() != entry.ID {
		t.Errorf("Expected ID %q, got %q", entry.ID, protoEntry.GetId())
	}

	if protoEntry.GetUserId() != entry.UserID {
		t.Errorf("Expected UserID %q, got %q", entry.UserID, protoEntry.GetUserId())
	}

	if protoEntry.GetTitle() != entry.Title {
		t.Errorf("Expected Title %q, got %q", entry.Title, protoEntry.GetTitle())
	}

	if protoEntry.GetDescription() != entry.Description {
		t.Errorf("Expected Description %q, got %q", entry.Description, protoEntry.GetDescription())
	}

	if len(protoEntry.GetTags()) != len(entry.Tags) {
		t.Errorf("Expected %d tags, got %d", len(entry.Tags), len(protoEntry.GetTags()))
	}

	if protoEntry.GetEntryType() != pmpb.Entry_EntryType(entry.Type) {
		t.Errorf("Expected EntryType %v, got %v", entry.Type, protoEntry.GetEntryType())
	}

	if protoEntry.GetVersion() != uint32(entry.Version) {
		t.Errorf("Expected Version %d, got %d", entry.Version, protoEntry.GetVersion())
	}

	// Verify meta
	meta := protoEntry.GetMeta()
	if meta == nil {
		t.Error("Expected meta to be non-nil")
	} else {
		if meta.GetFields()["username"].GetStringValue() != entry.Meta["username"] {
			t.Errorf("Expected meta username %q, got %q", entry.Meta["username"], meta.GetFields()["username"].GetStringValue())
		}
	}
}

func TestEntryToProto_EmptyTags(t *testing.T) {
	entry := &models.Entry{
		ID:            "test-entry-id",
		UserID:        "user@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          models.EntryTypeText,
		Meta:          models.Meta{},
		EncryptedBlob: []byte("encrypted-data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Version:       1,
	}

	protoEntry := entryToProto(entry)

	if len(protoEntry.GetTags()) != 0 {
		t.Errorf("Expected 0 tags, got %d", len(protoEntry.GetTags()))
	}
}

func TestEntryToProto_NoExpiresAt(t *testing.T) {
	entry := &models.Entry{
		ID:            "test-entry-id",
		UserID:        "user@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          models.EntryTypeText,
		Meta:          models.Meta{},
		EncryptedBlob: []byte("encrypted-data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	protoEntry := entryToProto(entry)

	if protoEntry.GetExpiresAt() != nil {
		t.Errorf("Expected ExpiresAt to be nil, got %v", protoEntry.GetExpiresAt())
	}
}
