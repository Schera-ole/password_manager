package cmd

import (
	"fmt"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/spf13/cobra"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update existing entry",
	Long: `Update existing entry by ID.

This command prompts for all updated fields interactively.
Press Enter to keep current values for non-sensitive fields.

Examples:
  # Interactive mode
  client update <entry_id>
`,
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

		// Update the entry
		err = cliService.UpdateEntry(ctx, entryID)
		if err != nil {
			return fmt.Errorf("update entry: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
