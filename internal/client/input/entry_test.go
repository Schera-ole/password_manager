package input

import (
	"testing"

	"github.com/Schera-ole/password_manager/internal/shared/models"
)

func TestBuildEntryFromInput(t *testing.T) {
	input := EntryInput{
		Title:       "Test Entry",
		Description: "Test Description",
		Tags:        []string{"tag1", "tag2"},
		EntryType:   models.EntryTypeLogin,
		Meta:        models.Meta{"key": "value"},
		Data:        []byte("test data"),
	}

	entry, err := BuildEntryFromInput(input, "user@example.com")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if entry.Title != input.Title {
		t.Errorf("Expected Title %q, got %q", input.Title, entry.Title)
	}

	if entry.Description != input.Description {
		t.Errorf("Expected Description %q, got %q", input.Description, entry.Description)
	}

	if len(entry.Tags) != len(input.Tags) {
		t.Errorf("Expected %d tags, got %d", len(input.Tags), len(entry.Tags))
	}

	if entry.Type != input.EntryType {
		t.Errorf("Expected EntryType %v, got %v", input.EntryType, entry.Type)
	}

	if entry.Meta["key"] != input.Meta["key"] {
		t.Errorf("Expected Meta key %q, got %q", input.Meta["key"], entry.Meta["key"])
	}

	if entry.EncryptedBlob != nil {
		// BuildEntryFromInput just assigns data, check if it's not nil
	} else {
		t.Error("Expected EncryptedBlob to be non-nil")
	}
}

func TestBuildEntryFromInput_EmptyTags(t *testing.T) {
	input := EntryInput{
		Title:       "Test Entry",
		Description: "Test Description",
		Tags:        []string{},
		EntryType:   models.EntryTypeText,
		Meta:        models.Meta{},
		Data:        []byte("test data"),
	}

	entry, err := BuildEntryFromInput(input, "user@example.com")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(entry.Tags) != 0 {
		t.Errorf("Expected 0 tags, got %d", len(entry.Tags))
	}
}

func TestBuildEntryFromInput_NoMeta(t *testing.T) {
	input := EntryInput{
		Title:       "Test Entry",
		Description: "Test Description",
		Tags:        []string{},
		EntryType:   models.EntryTypeBinary,
		Meta:        nil,
		Data:        []byte("test data"),
	}

	entry, err := BuildEntryFromInput(input, "user@example.com")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if entry.Meta != nil {
		t.Error("Expected Meta to be nil (function just assigns the input)")
	}
}

func TestBuildEntryFromInput_NoData(t *testing.T) {
	input := EntryInput{
		Title:       "Test Entry",
		Description: "Test Description",
		Tags:        []string{},
		EntryType:   models.EntryTypeCard,
		Meta:        models.Meta{},
		Data:        []byte{},
	}

	entry, err := BuildEntryFromInput(input, "user@example.com")

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(entry.EncryptedBlob) != 0 {
		t.Errorf("Expected empty EncryptedBlob, got %d bytes", len(entry.EncryptedBlob))
	}
}

func TestBuildEntryFromInput_DifferentEntryTypes(t *testing.T) {
	tests := []struct {
		name      string
		entryType models.EntryType
	}{
		{"Login", models.EntryTypeLogin},
		{"Text", models.EntryTypeText},
		{"Binary", models.EntryTypeBinary},
		{"Card", models.EntryTypeCard},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := EntryInput{
				Title:       "Test Entry",
				Description: "Test Description",
				Tags:        []string{},
				EntryType:   tt.entryType,
				Meta:        models.Meta{},
				Data:        []byte("test data"),
			}

			entry, err := BuildEntryFromInput(input, "user@example.com")

			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			if entry.Type != tt.entryType {
				t.Errorf("Expected EntryType %v, got %v", tt.entryType, entry.Type)
			}
		})
	}
}
