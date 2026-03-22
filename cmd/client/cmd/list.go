package cmd

import (
	"fmt"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all entries",
	Long: `List all password entries stored in your password manager.

This command displays a summary of all your entries including their IDs, titles, and types.
For each entry, you'll see basic information like the title and description (if available).
You'll be prompted to enter your master password for authentication before listing the entries.

The list is retrieved from your local storage and reflects the state after the last synchronization with the server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		entries, err := cliService.ListEntries(ctx)
		if err != nil {
			return fmt.Errorf("failed to get entries: %w", err)
		}
		if len(entries) == 0 {
			fmt.Println("No entries found.")
			return nil
		}
		fmt.Printf("Found %d entries:\n\n", len(entries))
		for i, entry := range entries {
			fmt.Printf("%d. ID: %s, Title: %s (Type: %d)\n", i+1, entry.ID, entry.Title, entry.Type)
			if entry.Description != "" {
				fmt.Printf("   Description: %s\n", entry.Description)
			}
			fmt.Println()
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
