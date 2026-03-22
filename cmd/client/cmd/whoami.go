package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/Schera-ole/password_manager/internal/client/cli"
	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/client/input"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

// whoamiCmd represents the whoami command
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Display current user authentication status and session information",
	Long: `Display detailed information about your current authentication status and session.

This command shows:
- Your user ID (email)
- Session expiration time
- Time remaining until session expires

It also provides warnings if your session has expired or is about to expire.
You'll be prompted to enter your master password to verify your identity before displaying this information.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		appInstance := GetAppFromContext(cmd.Context())
		if appInstance == nil {
			return fmt.Errorf("failed to get app from context")
		}
		cliService := cli.NewCLIService(appInstance)

		pwd, err := input.ReadPassword("Enter master password: ")
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
		defer crypto.ZeroMemory(pwd)

		token, err := cliService.GetJWT(string(pwd))
		if err != nil {
			// Token not found or decryption failed
			fmt.Fprintln(os.Stderr, "You are not logged in. Run `client login`.")
			return nil
		}
		claims, err := decodeJWTPayloadFast(token)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid token. Please run `client login` again.")
			return nil
		}
		printClaims(claims)
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0).UTC()
			if time.Now().After(expTime) {
				fmt.Fprintln(os.Stderr, "Warning: Token has expired. Run `client login` to refresh.")
			} else {
				fmt.Fprintf(os.Stderr, "Token expires in %s\n",
					time.Until(expTime).Round(time.Minute))
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}

func decodeJWTPayloadFast(token string) (jwt.MapClaims, error) {
	parsed, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	return parsed.Claims.(jwt.MapClaims), nil
}

// printClaims show information from jwt:
//
//	email → логин (email)
//	exp   → token expire time.
func printClaims(c jwt.MapClaims) {
	const (
		emailKey = "email"
		expKey   = "exp"
	)

	fmt.Println("Current session:")

	if v, ok := c[emailKey]; ok {
		fmt.Printf("  user_id: %s\n", v.(string))
	} else {
		fmt.Println("  user_id: <missing>")
	}
	if v, ok := c[expKey]; ok {
		ts := v.(float64)
		expTime := time.Unix(int64(ts), 0).UTC()
		fmt.Printf("  expires_at: %s\n", expTime.Format(time.RFC3339))
		return
	}

	fmt.Println("  expires_at: <missing>")
}
