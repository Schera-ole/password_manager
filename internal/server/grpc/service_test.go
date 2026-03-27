package grpc

import (
	"testing"
	"time"

	model "github.com/Schera-ole/password_manager/internal/shared/models"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConvertProtoToEntry(t *testing.T) {
	// Create proto entry using builder
	meta := make(map[string]*structpb.Value)
	meta["key"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "value"}}

	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{"tag1", "tag2"},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	if modelEntry.ID != "entry-1" {
		t.Errorf("Expected ID 'entry-1', got '%s'", modelEntry.ID)
	}

	if modelEntry.UserID != "user1@example.com" {
		t.Errorf("Expected UserID 'user1@example.com', got '%s'", modelEntry.UserID)
	}

	if modelEntry.Title != "Test Entry" {
		t.Errorf("Expected Title 'Test Entry', got '%s'", modelEntry.Title)
	}

	if modelEntry.Description != "Test Description" {
		t.Errorf("Expected Description 'Test Description', got '%s'", modelEntry.Description)
	}

	if len(modelEntry.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(modelEntry.Tags))
	}

	if modelEntry.Type != model.EntryTypeLogin {
		t.Errorf("Expected EntryTypeLogin, got %v", modelEntry.Type)
	}

	if modelEntry.Meta["key"] != "value" {
		t.Errorf("Expected meta key 'value', got '%s'", modelEntry.Meta["key"])
	}
}

func TestConvertProtoToEntry_EmptyMeta(t *testing.T) {
	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          nil,
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	if modelEntry.ID != "entry-1" {
		t.Errorf("Expected ID 'entry-1', got '%s'", modelEntry.ID)
	}

	if modelEntry.Meta == nil {
		t.Error("Expected meta to be initialized")
	}
}

func TestConvertProtoToEntry_NoExpiresAt(t *testing.T) {
	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: map[string]*structpb.Value{}},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	if modelEntry.ExpiresAt != nil {
		t.Error("Expected ExpiresAt to be nil")
	}
}

func TestConvertEntryToProto(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{"tag1", "tag2"},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{"key": "value"},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if entry.GetId() != "entry-1" {
		t.Errorf("Expected ID 'entry-1', got '%s'", entry.GetId())
	}

	if entry.GetUserId() != "user1@example.com" {
		t.Errorf("Expected UserID 'user1@example.com', got '%s'", entry.GetUserId())
	}

	if entry.GetTitle() != "Test Entry" {
		t.Errorf("Expected Title 'Test Entry', got '%s'", entry.GetTitle())
	}

	if entry.GetDescription() != "Test Description" {
		t.Errorf("Expected Description 'Test Description', got '%s'", entry.GetDescription())
	}

	if len(entry.GetTags()) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(entry.GetTags()))
	}

	if entry.GetEntryType() != pmpb.Entry_ENTRY_TYPE_LOGIN {
		t.Errorf("Expected ENTRY_TYPE_LOGIN, got %v", entry.GetEntryType())
	}
}

func TestConvertEntryToProto_WithExpiresAt(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     &expiresAt,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if entry.GetExpiresAt() == nil {
		t.Error("Expected ExpiresAt to be set")
	}
}

func TestConvertEntryToProto_EmptyMeta(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if entry.GetMeta() == nil {
		t.Error("Expected Meta to be set")
	}
}

func TestConvertEntryToProto_MultipleTags(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{"tag1", "tag2", "tag3"},
		Type:          model.EntryTypeText,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if len(entry.GetTags()) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(entry.GetTags()))
	}
}

func TestConvertEntryToProto_DifferentEntryTypes(t *testing.T) {
	entryTypes := []model.EntryType{
		model.EntryTypeLogin,
		model.EntryTypeText,
		model.EntryTypeBinary,
		model.EntryTypeCard,
	}

	for _, entryType := range entryTypes {
		modelEntry := model.Entry{
			ID:            "entry-1",
			UserID:        "user1@example.com",
			Title:         "Test Entry",
			Description:   "Test Description",
			Tags:          []string{},
			Type:          entryType,
			Meta:          model.Meta{},
			EncryptedBlob: []byte("encrypted data"),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			ExpiresAt:     nil,
			Version:       1,
		}

		entry := convertEntryToProto(modelEntry)

		if entry.GetEntryType() != pmpb.Entry_EntryType(entryType) {
			t.Errorf("Expected EntryType %v, got %v", entryType, entry.GetEntryType())
		}
	}
}

func TestConvertProtoToEntry_MultipleTags(t *testing.T) {
	meta := make(map[string]*structpb.Value)
	meta["key"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "value"}}

	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{"tag1", "tag2", "tag3"},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	if len(modelEntry.Tags) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(modelEntry.Tags))
	}
}

func TestConvertProtoToEntry_DifferentEntryTypes(t *testing.T) {
	entryTypes := []pmpb.Entry_EntryType{
		pmpb.Entry_ENTRY_TYPE_LOGIN,
		pmpb.Entry_ENTRY_TYPE_TEXT,
		pmpb.Entry_ENTRY_TYPE_BINARY,
		pmpb.Entry_ENTRY_TYPE_CARD,
	}

	for _, entryType := range entryTypes {
		meta := make(map[string]*structpb.Value)
		createdAt := timestamppb.Now()
		updatedAt := timestamppb.Now()

		entryBuilder := pmpb.Entry_builder{
			Id:            "entry-1",
			UserId:        "user1@example.com",
			Title:         "Test Entry",
			Description:   "Test Description",
			Tags:          []string{},
			EntryType:     entryType,
			Meta:          &structpb.Struct{Fields: meta},
			EncryptedBlob: []byte("encrypted data"),
			CreatedAt:     createdAt,
			UpdatedAt:     updatedAt,
			Version:       1,
		}
		entry := entryBuilder.Build()

		modelEntry := convertProtoToEntry(entry)

		if modelEntry.Type != model.EntryType(entryType) {
			t.Errorf("Expected EntryType %v, got %v", entryType, modelEntry.Type)
		}
	}
}

func TestConvertProtoToEntry_WithExpiresAt(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	meta := make(map[string]*structpb.Value)
	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		ExpiresAt:     timestamppb.New(expiresAt),
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	if modelEntry.ExpiresAt == nil {
		t.Error("Expected ExpiresAt to be set")
	} else {
		// Check that the expiresAt time is correctly converted
		if modelEntry.ExpiresAt.Sub(expiresAt) > time.Second {
			t.Error("ExpiresAt time mismatch")
		}
	}
}

func TestConvertProtoToEntry_WithMeta(t *testing.T) {
	meta := make(map[string]*structpb.Value)
	meta["key1"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "value1"}}
	meta["key2"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "value2"}}

	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	if len(modelEntry.Meta) != 2 {
		t.Errorf("Expected 2 meta fields, got %d", len(modelEntry.Meta))
	}

	if modelEntry.Meta["key1"] != "value1" {
		t.Errorf("Expected meta key1 'value1', got '%s'", modelEntry.Meta["key1"])
	}

	if modelEntry.Meta["key2"] != "value2" {
		t.Errorf("Expected meta key2 'value2', got '%s'", modelEntry.Meta["key2"])
	}
}

func TestConvertProtoToEntry_EmptyTags(t *testing.T) {
	meta := make(map[string]*structpb.Value)
	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	if len(modelEntry.Tags) != 0 {
		t.Errorf("Expected 0 tags, got %d", len(modelEntry.Tags))
	}
}

func TestConvertProtoToEntry_EmptyMetaFields(t *testing.T) {
	meta := make(map[string]*structpb.Value)
	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	// Meta should be initialized even if empty
	if modelEntry.Meta == nil {
		t.Error("Expected meta to be initialized")
	}
}

func TestConvertEntryToProto_WithEmptyTags(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if len(entry.GetTags()) != 0 {
		t.Errorf("Expected 0 tags, got %d", len(entry.GetTags()))
	}
}

func TestConvertEntryToProto_WithEmptyMeta(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	// Meta should be initialized even if empty
	if entry.GetMeta() == nil {
		t.Error("Expected Meta to be set")
	}
}

func TestConvertEntryToProto_WithEmptyDescription(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if entry.GetDescription() != "" {
		t.Errorf("Expected empty description, got '%s'", entry.GetDescription())
	}
}

func TestConvertEntryToProto_WithEmptyTitle(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if entry.GetTitle() != "" {
		t.Errorf("Expected empty title, got '%s'", entry.GetTitle())
	}
}

func TestConvertEntryToProto_WithEmptyID(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if entry.GetId() != "" {
		t.Errorf("Expected empty ID, got '%s'", entry.GetId())
	}
}

func TestConvertEntryToProto_WithEmptyUserID(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if entry.GetUserId() != "" {
		t.Errorf("Expected empty UserID, got '%s'", entry.GetUserId())
	}
}

func TestConvertEntryToProto_WithEmptyEncryptedBlob(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte{},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if len(entry.GetEncryptedBlob()) != 0 {
		t.Errorf("Expected empty encrypted blob, got %d bytes", len(entry.GetEncryptedBlob()))
	}
}

func TestConvertEntryToProto_WithLargeVersion(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       999999,
	}

	entry := convertEntryToProto(modelEntry)

	if entry.GetVersion() != 999999 {
		t.Errorf("Expected version 999999, got %d", entry.GetVersion())
	}
}

func TestConvertEntryToProto_WithComplexMeta(t *testing.T) {
	modelEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{"key1": "value1", "key2": "value2", "key3": "value3"},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	entry := convertEntryToProto(modelEntry)

	if len(entry.GetMeta().GetFields()) != 3 {
		t.Errorf("Expected 3 meta fields, got %d", len(entry.GetMeta().GetFields()))
	}
}

func TestConvertProtoToEntry_WithComplexMeta(t *testing.T) {
	meta := make(map[string]*structpb.Value)
	meta["key1"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "value1"}}
	meta["key2"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "value2"}}
	meta["key3"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "value3"}}

	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	entryBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	entry := entryBuilder.Build()

	modelEntry := convertProtoToEntry(entry)

	if len(modelEntry.Meta) != 3 {
		t.Errorf("Expected 3 meta fields, got %d", len(modelEntry.Meta))
	}
}

func TestConvertEntryToProto_RoundTrip(t *testing.T) {
	originalEntry := model.Entry{
		ID:            "entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{"tag1", "tag2"},
		Type:          model.EntryTypeLogin,
		Meta:          model.Meta{"key": "value"},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     nil,
		Version:       1,
	}

	// Convert to proto
	protoEntry := convertEntryToProto(originalEntry)

	// Convert back to model
	modelEntry := convertProtoToEntry(protoEntry)

	if modelEntry.ID != originalEntry.ID {
		t.Errorf("ID mismatch: expected '%s', got '%s'", originalEntry.ID, modelEntry.ID)
	}

	if modelEntry.UserID != originalEntry.UserID {
		t.Errorf("UserID mismatch: expected '%s', got '%s'", originalEntry.UserID, modelEntry.UserID)
	}

	if modelEntry.Title != originalEntry.Title {
		t.Errorf("Title mismatch: expected '%s', got '%s'", originalEntry.Title, modelEntry.Title)
	}

	if modelEntry.Description != originalEntry.Description {
		t.Errorf("Description mismatch: expected '%s', got '%s'", originalEntry.Description, modelEntry.Description)
	}

	if len(modelEntry.Tags) != len(originalEntry.Tags) {
		t.Errorf("Tags length mismatch: expected %d, got %d", len(originalEntry.Tags), len(modelEntry.Tags))
	}

	if modelEntry.Type != originalEntry.Type {
		t.Errorf("Type mismatch: expected %v, got %v", originalEntry.Type, modelEntry.Type)
	}

	if modelEntry.Meta["key"] != originalEntry.Meta["key"] {
		t.Errorf("Meta mismatch: expected '%s', got '%s'", originalEntry.Meta["key"], modelEntry.Meta["key"])
	}

	if modelEntry.EncryptedBlob[0] != originalEntry.EncryptedBlob[0] {
		t.Errorf("EncryptedBlob mismatch")
	}

	if modelEntry.Version != originalEntry.Version {
		t.Errorf("Version mismatch: expected %d, got %d", originalEntry.Version, modelEntry.Version)
	}
}

func TestConvertProtoToEntry_RoundTrip(t *testing.T) {
	meta := make(map[string]*structpb.Value)
	meta["key"] = &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "value"}}

	createdAt := timestamppb.Now()
	updatedAt := timestamppb.Now()

	originalBuilder := pmpb.Entry_builder{
		Id:            "entry-1",
		UserId:        "user1@example.com",
		Title:         "Test Entry",
		Description:   "Test Description",
		Tags:          []string{"tag1", "tag2"},
		EntryType:     pmpb.Entry_ENTRY_TYPE_LOGIN,
		Meta:          &structpb.Struct{Fields: meta},
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		Version:       1,
	}
	originalEntry := originalBuilder.Build()

	// Convert to model
	modelEntry := convertProtoToEntry(originalEntry)

	// Convert back to proto
	protoEntry := convertEntryToProto(modelEntry)

	if protoEntry.GetId() != originalEntry.GetId() {
		t.Errorf("ID mismatch: expected '%s', got '%s'", originalEntry.GetId(), protoEntry.GetId())
	}

	if protoEntry.GetUserId() != originalEntry.GetUserId() {
		t.Errorf("UserID mismatch: expected '%s', got '%s'", originalEntry.GetUserId(), protoEntry.GetUserId())
	}

	if protoEntry.GetTitle() != originalEntry.GetTitle() {
		t.Errorf("Title mismatch: expected '%s', got '%s'", originalEntry.GetTitle(), protoEntry.GetTitle())
	}

	if protoEntry.GetDescription() != originalEntry.GetDescription() {
		t.Errorf("Description mismatch: expected '%s', got '%s'", originalEntry.GetDescription(), protoEntry.GetDescription())
	}

	if len(protoEntry.GetTags()) != len(originalEntry.GetTags()) {
		t.Errorf("Tags length mismatch: expected %d, got %d", len(originalEntry.GetTags()), len(protoEntry.GetTags()))
	}

	if protoEntry.GetEntryType() != originalEntry.GetEntryType() {
		t.Errorf("EntryType mismatch: expected %v, got %v", originalEntry.GetEntryType(), protoEntry.GetEntryType())
	}

	if len(protoEntry.GetMeta().GetFields()) != len(originalEntry.GetMeta().GetFields()) {
		t.Errorf("Meta fields length mismatch: expected %d, got %d", len(originalEntry.GetMeta().GetFields()), len(protoEntry.GetMeta().GetFields()))
	}

	if len(protoEntry.GetEncryptedBlob()) != len(originalEntry.GetEncryptedBlob()) {
		t.Errorf("EncryptedBlob length mismatch: expected %d, got %d", len(originalEntry.GetEncryptedBlob()), len(protoEntry.GetEncryptedBlob()))
	}

	if protoEntry.GetVersion() != originalEntry.GetVersion() {
		t.Errorf("Version mismatch: expected %d, got %d", originalEntry.GetVersion(), protoEntry.GetVersion())
	}
}
