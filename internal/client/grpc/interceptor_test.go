package grpc

import (
	"context"
	"testing"
)

func TestWithPassword(t *testing.T) {
	ctx := context.Background()
	password := "test-password"

	ctx = WithPassword(ctx, password)

	loadedPassword, ok := GetPassword(ctx)
	if !ok {
		t.Error("Expected password to be in context")
	}

	if loadedPassword != password {
		t.Errorf("Expected password to be '%s', got: '%s'", password, loadedPassword)
	}
}

func TestWithPassword_EmptyPassword(t *testing.T) {
	ctx := context.Background()
	password := ""

	ctx = WithPassword(ctx, password)

	loadedPassword, ok := GetPassword(ctx)
	if !ok {
		t.Error("Expected password to be in context")
	}

	if loadedPassword != password {
		t.Errorf("Expected password to be empty string, got: '%s'", loadedPassword)
	}
}

func TestGetPassword(t *testing.T) {
	ctx := context.Background()
	password := "test-password"

	ctx = WithPassword(ctx, password)

	loadedPassword, ok := GetPassword(ctx)
	if !ok {
		t.Error("Expected password to be in context")
	}

	if loadedPassword != password {
		t.Errorf("Expected password to be '%s', got: '%s'", password, loadedPassword)
	}
}

func TestGetPassword_NotFound(t *testing.T) {
	ctx := context.Background()

	loadedPassword, ok := GetPassword(ctx)
	if ok {
		t.Error("Expected password to not be in context")
	}

	if loadedPassword != "" {
		t.Errorf("Expected empty password, got: '%s'", loadedPassword)
	}
}

func TestGetPasswordOrError(t *testing.T) {
	ctx := context.Background()
	password := "test-password"

	ctx = WithPassword(ctx, password)

	loadedPassword, err := GetPasswordOrError(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if loadedPassword != password {
		t.Errorf("Expected password to be '%s', got: '%s'", password, loadedPassword)
	}
}

func TestGetPasswordOrError_NotFound(t *testing.T) {
	ctx := context.Background()

	loadedPassword, err := GetPasswordOrError(ctx)
	if err == nil {
		t.Error("Expected error when password not in context")
	}

	if loadedPassword != "" {
		t.Errorf("Expected empty password, got: '%s'", loadedPassword)
	}
}

func TestGetPasswordOrError_ErrorMessage(t *testing.T) {
	ctx := context.Background()

	_, err := GetPasswordOrError(ctx)
	if err == nil {
		t.Error("Expected error when password not in context")
		return
	}

	expectedMsg := "password not found in context"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got: '%s'", expectedMsg, err.Error())
	}
}
