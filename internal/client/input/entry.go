package input

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/shared/models"
)

// EntryInput holds the data for creating a new entry
type EntryInput struct {
	Title       string
	Description string
	Tags        []string
	EntryType   models.EntryType
	Meta        models.Meta
	Data        []byte // Sensitive data (password, text, etc.)
}

// ReadTitle prompts for the entry title (required)
func ReadTitle(prompt string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, prompt)
		title, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading title: %w", err)
		}
		title = strings.TrimSpace(title)
		if title != "" {
			return title, nil
		}
		fmt.Fprintln(os.Stderr, "Title is required. Please enter a title.")
	}
}

// ReadDescription prompts for the entry description (optional)
func ReadDescription(prompt string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, prompt)
	description, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading description: %w", err)
	}
	return strings.TrimSpace(description), nil
}

// ReadTags prompts for tags (optional). Tags can be entered as comma-separated values or multiple prompts
func ReadTags(prompt string) ([]string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, prompt)
	tagsStr, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading tags: %w", err)
	}
	tagsStr = strings.TrimSpace(tagsStr)
	if tagsStr == "" {
		return []string{}, nil
	}

	// Split by comma and trim whitespace
	tags := strings.Split(tagsStr, ",")
	for i, tag := range tags {
		tags[i] = strings.TrimSpace(tag)
	}
	// Filter empty tags
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag != "" {
			result = append(result, tag)
		}
	}
	return result, nil
}

// ReadEntryType prompts for the entry type (required)
func ReadEntryType(prompt string) (models.EntryType, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Fprintln(os.Stderr, prompt)
		fmt.Fprintln(os.Stderr, "1) Login - for username/password entries")
		fmt.Fprintln(os.Stderr, "2) Text - for text notes")
		fmt.Fprintln(os.Stderr, "3) Binary - for file/binary data")
		fmt.Fprintln(os.Stderr, "4) Card - for card/financial data")
		fmt.Fprint(os.Stderr, "Select type (1-4): ")

		input, err := reader.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("reading entry type: %w", err)
		}

		input = strings.TrimSpace(input)
		switch input {
		case "1":
			return models.EntryTypeLogin, nil
		case "2":
			return models.EntryTypeText, nil
		case "3":
			return models.EntryTypeBinary, nil
		case "4":
			return models.EntryTypeCard, nil
		default:
			fmt.Fprintln(os.Stderr, "Invalid selection. Please enter 1-4.")
		}
	}
}

// ReadMeta prompts for key-value pairs (optional). Returns a map of string keys and values
func ReadMeta(prompt string) (models.Meta, error) {
	reader := bufio.NewReader(os.Stdin)
	meta := make(models.Meta)

	fmt.Fprintln(os.Stderr, prompt)
	fmt.Fprintln(os.Stderr, "Enter key-value pairs (empty line to finish):")

	for {
		fmt.Fprint(os.Stderr, "  Key (or empty to finish): ")
		key, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading meta key: %w", err)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			break
		}

		fmt.Fprint(os.Stderr, "  Value: ")
		value, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading meta value: %w", err)
		}
		value = strings.TrimSpace(value)

		meta[key] = value
	}

	return meta, nil
}

// ReadData prompts for the sensitive data based on entry type
func ReadData(entryType models.EntryType, prompt string) ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)

	// Display context based on type
	switch entryType {
	case models.EntryTypeLogin:
		fmt.Fprintln(os.Stderr, "\n--- Login Entry ---")
		fmt.Fprintln(os.Stderr, "Enter login data (JSON format recommended):")
		fmt.Fprintln(os.Stderr, "Example: {\"username\":\"user\",\"password\":\"pass\"}")
	case models.EntryTypeText:
		fmt.Fprintln(os.Stderr, "\n--- Text Entry ---")
		fmt.Fprintln(os.Stderr, "Enter text data:")
	case models.EntryTypeBinary:
		fmt.Fprintln(os.Stderr, "\n--- Binary Entry ---")
		fmt.Fprintln(os.Stderr, "Enter base64-encoded binary data:")
	case models.EntryTypeCard:
		fmt.Fprintln(os.Stderr, "\n--- Card Entry ---")
		fmt.Fprintln(os.Stderr, "Enter card data (JSON format recommended):")
		fmt.Fprintln(os.Stderr, "Example: {\"card_number\":\"****\",\"cvv\":\"***\",\"expiry\":\"MM/YY\"}")
	}

	fmt.Fprint(os.Stderr, prompt)
	data, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading data: %w", err)
	}

	return []byte(data), nil
}

// ReadDataInteractive prompts for data with confirmation for sensitive fields
func ReadDataInteractive(entryType models.EntryType, prompt string) ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)

	// Display context based on type
	switch entryType {
	case models.EntryTypeLogin:
		fmt.Fprintln(os.Stderr, "\n--- Login Entry ---")
		fmt.Fprintln(os.Stderr, "Enter login details:")

		fmt.Fprint(os.Stderr, "  Username: ")
		username, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading username: %w", err)
		}

		fmt.Fprint(os.Stderr, "  Password: ")
		password, err := ReadPassword("")
		if err != nil {
			return nil, fmt.Errorf("reading password: %w", err)
		}
		fmt.Fprintln(os.Stderr)

		// Build JSON-like structure
		data := fmt.Sprintf("{\"username\":\"%s\",\"password\":\"%s\"}",
			strings.TrimSpace(username), string(password))
		defer crypto.ZeroMemory(password)

		return []byte(data), nil

	case models.EntryTypeText:
		fmt.Fprintln(os.Stderr, "\n--- Text Entry ---")
		fmt.Fprintln(os.Stderr, "Enter text data (Ctrl+D to finish on Unix, Ctrl+Z on Windows):")

		var text strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			text.WriteString(line)
		}

		return []byte(text.String()), nil

	case models.EntryTypeBinary:
		fmt.Fprintln(os.Stderr, "\n--- Binary Entry ---")
		fmt.Fprintln(os.Stderr, "Enter base64-encoded binary data:")
		fmt.Fprint(os.Stderr, prompt)
		data, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading binary data: %w", err)
		}
		return []byte(strings.TrimSpace(data)), nil

	case models.EntryTypeCard:
		fmt.Fprintln(os.Stderr, "\n--- Card Entry ---")
		fmt.Fprintln(os.Stderr, "Enter card details:")

		fmt.Fprint(os.Stderr, "  Card Number: ")
		cardNum, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading card number: %w", err)
		}

		fmt.Fprint(os.Stderr, "  CVV: ")
		cvv, err := ReadPassword("")
		if err != nil {
			return nil, fmt.Errorf("reading CVV: %w", err)
		}
		fmt.Fprintln(os.Stderr)

		fmt.Fprint(os.Stderr, "  Expiry (MM/YY): ")
		expiry, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading expiry: %w", err)
		}

		// Build JSON-like structure
		data := fmt.Sprintf("{\"card_number\":\"%s\",\"cvv\":\"%s\",\"expiry\":\"%s\"}",
			strings.TrimSpace(cardNum), string(cvv), strings.TrimSpace(expiry))
		defer crypto.ZeroMemory(cvv)

		return []byte(data), nil
	}

	return nil, fmt.Errorf("unsupported entry type")
}

// BuildEntryFromInput creates a protobuf Entry from EntryInput
func BuildEntryFromInput(input EntryInput, userID string) (*models.Entry, error) {
	tags := make([]string, len(input.Tags))
	copy(tags, input.Tags)

	entry := &models.Entry{
		Title:         input.Title,
		Description:   input.Description,
		Tags:          tags,
		Type:          input.EntryType,
		Meta:          input.Meta,
		EncryptedBlob: input.Data,
		UserID:        userID,
	}

	return entry, nil
}
