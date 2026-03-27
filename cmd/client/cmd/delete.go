package cmd

import (
	"fmt"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/spf13/cobra"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete specific entry",
	Long: `Delete a specific entry from your password manager by its unique ID.

This command permanently removes an entry from both your local storage and the remote server during the next synchronization.
Before deletion, you'll be prompted to enter your master password for authentication.

Example:
	 client delete 123e4567-e89b-12d3-a456-426614174000`,
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
		err = cliService.DeleteEntry(ctx, entryID)
		if err != nil {
			return fmt.Errorf("failed to delete entry: %w", err)
		}
		fmt.Println("Entry was successfully deleted.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)

}
