package cmd

import (
	"fmt"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/spf13/cobra"
)

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from password manager",
	Long: `Logout from the password manager and securely clear all local session data.

This command invalidates your current session by removing the JWT token and clearing any cached data from your local storage.
After logging out, you'll need to log in again with your credentials to access your password entries.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		appInstance := GetAppFromContext(cmd.Context())
		if appInstance == nil {
			return fmt.Errorf("failed to get app from context")
		}
		cliService := cli.NewCLIService(appInstance)
		err := cliService.Logout()
		if err != nil {
			return fmt.Errorf("logout failed: %w", err)
		}

		fmt.Println("Logout successful!")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
