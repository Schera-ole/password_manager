package cmd

import (
	"fmt"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/spf13/cobra"
)

// syncCmd represents the sync command
var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize entries with the server",
	Long:  `Synchronize your local password entries with the remote server to ensure consistency across all your devices.`,
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

		if err := cliService.Sync(ctx); err != nil {
			return fmt.Errorf("failed to sync: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)
}
