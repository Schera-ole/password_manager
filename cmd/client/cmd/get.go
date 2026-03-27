package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/Schera-ole/password_manager/internal/shared/models"
	"github.com/spf13/cobra"
)

// formatEntryType converts EntryType enum to human-readable string
func formatEntryType(entryType models.EntryType) string {
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

// formatTags converts tags slice to comma-separated string
func formatTags(tags []string) string {
	if len(tags) == 0 {
		return "(none)"
	}
	return strings.Join(tags, ", ")
}

// formatMeta converts Meta map to formatted string
func formatMeta(meta models.Meta) string {
	if len(meta) == 0 {
		return "(none)"
	}
	var pairs []string
	for k, v := range meta {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(pairs, ", ")
}

// formatTime formats time with timezone info
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "(unset)"
	}
	return t.Format("2006-01-02 15:04:05 MST")
}

// formatEntry displays entry information in a clean, readable format
func formatEntry(entry models.Entry) string {
	lines := []string{
		fmt.Sprintf("Entry ID: %s", entry.ID),
		fmt.Sprintf("Title: %s", entry.Title),
		fmt.Sprintf("Type: %s", formatEntryType(entry.Type)),
		fmt.Sprintf("Tags: %s", formatTags(entry.Tags)),
		fmt.Sprintf("Description: %s", entry.Description),
		fmt.Sprintf("Meta: %s", formatMeta(entry.Meta)),
		fmt.Sprintf("Created At: %s", formatTime(entry.CreatedAt)),
		fmt.Sprintf("Updated At: %s", formatTime(entry.UpdatedAt)),
	}

	if entry.ExpiresAt != nil {
		lines = append(lines, fmt.Sprintf("Expires At: %s", formatTime(*entry.ExpiresAt)))
	}

	lines = append(lines, fmt.Sprintf("Version: %d", entry.Version))

	return strings.Join(lines, "\n")
}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get specific entry",
	Long: `Retrieve and display a specific entry from your password manager by its unique ID.

This command fetches an entry from your local storage and displays all its details including title, type, tags, description, metadata, and timestamps.
You'll be prompted to enter your master password for authentication before retrieving the entry.

Example:
	 client get 123e4567-e89b-12d3-a456-426614174000`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		entryID := args[0]
		appInstance := GetAppFromContext(cmd.Context())
		if appInstance == nil {
			return fmt.Errorf("failed to get app from context")
		}
		cliService := cli.NewCLIService(appInstance)

		// Prompt for password and add to context for gRPC interceptor
		ctx, err := promptPassword(cmd)
		if err != nil {
			return err
		}
		entry, err := cliService.GetEntry(ctx, entryID)
		if err != nil {
			return fmt.Errorf("failed to get entry: %w", err)
		}

		fmt.Println(formatEntry(entry))

		return nil
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
