package input

import (
	"fmt"
	"os"

	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"golang.org/x/term"
)

const (
	defaultMaxAttempts = 3
)

// ReadPassword reads a password from stdin without echo.
func ReadPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("stdin is not a terminal")
	}
	return term.ReadPassword(int(os.Stdin.Fd()))
}

// ReadPasswordWithConfirm reads a password twice for confirmation.
func ReadPasswordWithConfirm(prompt string, maxAttempts int) (string, error) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		fmt.Fprint(os.Stderr, prompt)
		pwd1, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}
		fmt.Fprintln(os.Stderr)

		fmt.Fprint(os.Stderr, "Confirm password: ")
		pwd2, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			crypto.ZeroMemory(pwd1)
			return "", fmt.Errorf("reading password confirmation: %w", err)
		}
		fmt.Fprintln(os.Stderr)

		if string(pwd1) == string(pwd2) {
			defer crypto.ZeroMemory(pwd1)
			defer crypto.ZeroMemory(pwd2)
			return string(pwd1), nil
		}

		crypto.ZeroMemory(pwd1)
		crypto.ZeroMemory(pwd2)

		if attempt < maxAttempts {
			fmt.Fprintln(os.Stderr, "Passwords do not match, try again")
		}
	}

	return "", fmt.Errorf("maximum password attempts exceeded")
}

// ReadPasswordWithConfirmDefault reads a password with default max 3 attempts.
func ReadPasswordWithConfirmDefault(prompt string) (string, error) {
	return ReadPasswordWithConfirm(prompt, defaultMaxAttempts)
}
