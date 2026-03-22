// Package errors provides common error types used throughout the pm system.
package errors

import "errors"

var (
	// Database errors
	ErrDatabaseConnection = errors.New("database connection failed")
	ErrTransactionFailed  = errors.New("transaction failed")
	ErrQueryExecution     = errors.New("query execution failed")

	// Storage errors
	ErrStorageUnavailable = errors.New("storage unavailable")
)
