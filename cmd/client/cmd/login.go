package cmd

import (
	"fmt"
	"os"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/client/input"
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to password manager",
	Long: `Login to password manager

This command will authenticate the user and establish a session.
Examples:
	client login --email test@example.com
	client login -e test@example.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		email, err := cmd.Flags().GetString("email")
		if err != nil {
			return fmt.Errorf("failed to get email flag: %w", err)
		}
		pwd, err := input.ReadPassword("Enter master password: ")
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}

		appInstance := GetAppFromContext(cmd.Context())
		if appInstance == nil {
			return fmt.Errorf("failed to get app from context")
		}
		cliService := cli.NewCLIService(appInstance)
		if err := cliService.Login(email, string(pwd)); err != nil {
			crypto.ZeroMemory(pwd)
			return fmt.Errorf("login failed: %w", err)
		}
		crypto.ZeroMemory(pwd)
		fmt.Fprintf(os.Stderr, "User with email %s login successfully\n", email)
		return nil
	},
}

func init() {
	loginCmd.Flags().StringP("email", "e", "", "email (as login name) (required)")
	_ = loginCmd.MarkFlagRequired("email")
	rootCmd.AddCommand(loginCmd)
}
