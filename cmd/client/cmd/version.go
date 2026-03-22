/*
Copyright © 2026 Olga Leonteva
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// These variables will be set at build time using ldflags
var (
	buildVersion = "dev"
	buildDate    = "unknown"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number and build information",
	Long:  `Print the version number and build information of the password manager client`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Password Manager Client Version: %s\n", buildVersion)
		fmt.Printf("Build Date: %s\n", buildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
