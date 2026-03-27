package cmd

import (
	"fmt"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new entry",
	Long: `Create a new entry in the password manager.

This command supports both interactive and flag-based input:
- Interactive mode: prompts for all required and optional fields
- Flag mode: provide data via command-line flags (for non-sensitive data)

Examples:
  # Interactive mode
  client create

  # With flags (non-sensitive data only)
  client create --title "GitHub" --type login --tags "work,dev"
`,
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

		// Create the entry
		err = cliService.CreateEntry(ctx)
		if err != nil {
			return fmt.Errorf("create entry: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(createCmd)
}
