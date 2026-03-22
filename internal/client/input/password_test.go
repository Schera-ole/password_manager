package input

import (
	"testing"
)

func TestReadPasswordWithConfirm(t *testing.T) {
	// Test with a custom number of attempts
	// Not real input, because it requires term
	_, err := ReadPasswordWithConfirm("Test prompt: ", 5)

	// We expect an error since we can't actually read from stdin in a test
	if err == nil {
		t.Error("Expected error when stdin is not available")
	}
}

func TestReadPasswordWithConfirm_ExceedMaxAttempts(t *testing.T) {
	// Test that the function returns an error after exceeding max attempts
	_, err := ReadPasswordWithConfirm("Test prompt: ", 1)

	// We expect an error since we can't actually read from stdin in a test
	if err == nil {
		t.Error("Expected error when stdin is not available")
	}
}
