package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/Schera-ole/password_manager/internal/client/input"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new user",
	Long: `Register new user.
This command will register a new user with the provided email and password.
The password will be securely hashed and stored on the server.

Examples:
	client register --email test@example.com
	client register -e test@example.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		email, err := cmd.Flags().GetString("email")
		if err != nil {
			return fmt.Errorf("failed to get email flag: %w", err)
		}
		pwd, err := input.ReadPasswordWithConfirmDefault("Enter master password: ")
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}

		appInstance := GetAppFromContext(cmd.Context())
		if appInstance == nil {
			return fmt.Errorf("failed to get app from context")
		}
		cliService := cli.NewCLIService(appInstance)
		if err := cliService.Register(email, pwd); err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "User with email %s registered successfully\n", email)
		return nil
	},
}

func init() {
	registerCmd.Flags().StringP("email", "e", "", "email (as login name) (required)")
	_ = registerCmd.MarkFlagRequired("email")
	rootCmd.AddCommand(registerCmd)
}
