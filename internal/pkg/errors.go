package pkg

import (
	"errors"
	"fmt"
	"net/http"
)

// Custom error types
var (
	// Authentication errors
	ErrInvalidCredentials  = NewAppError("INVALID_CREDENTIALS", "Invalid email or password", http.StatusUnauthorized)
	ErrInvalidToken        = NewAppError("INVALID_TOKEN", "Invalid or expired token", http.StatusUnauthorized)
	ErrTokenExpired        = NewAppError("TOKEN_EXPIRED", "Token has expired", http.StatusUnauthorized)
	ErrInvalidRefreshToken = NewAppError("INVALID_REFRESH_TOKEN", "Invalid refresh token", http.StatusUnauthorized)
	ErrEmailNotVerified    = NewAppError("EMAIL_NOT_VERIFIED", "Email address not verified", http.StatusUnauthorized)
	ErrAccountSuspended    = NewAppError("ACCOUNT_SUSPENDED", "Account has been suspended", http.StatusForbidden)
	ErrTwoFactorRequired   = NewAppError("2FA_REQUIRED", "Two-factor authentication required", http.StatusUnauthorized)
	ErrInvalid2FACode      = NewAppError("INVALID_2FA_CODE", "Invalid two-factor authentication code", http.StatusUnauthorized)

	// Authorization errors
	ErrForbidden               = NewAppError("FORBIDDEN", "Access denied", http.StatusForbidden)
	ErrInsufficientPermissions = NewAppError("INSUFFICIENT_PERMISSIONS", "Insufficient permissions", http.StatusForbidden)
	ErrAdminRequired           = NewAppError("ADMIN_REQUIRED", "Admin privileges required", http.StatusForbidden)

	// User errors
	ErrUserNotFound         = NewAppError("USER_NOT_FOUND", "User not found", http.StatusNotFound)
	ErrUserAlreadyExists    = NewAppError("USER_ALREADY_EXISTS", "User already exists", http.StatusConflict)
	ErrEmailAlreadyTaken    = NewAppError("EMAIL_ALREADY_TAKEN", "Email address already taken", http.StatusConflict)
	ErrUsernameAlreadyTaken = NewAppError("USERNAME_ALREADY_TAKEN", "Username already taken", http.StatusConflict)
	ErrWeakPassword         = NewAppError("WEAK_PASSWORD", "Password does not meet requirements", http.StatusBadRequest)

	// File errors
	ErrFileNotFound      = NewAppError("FILE_NOT_FOUND", "File not found", http.StatusNotFound)
	ErrFileAlreadyExists = NewAppError("FILE_ALREADY_EXISTS", "File already exists", http.StatusConflict)
	ErrFileTooLarge      = NewAppError("FILE_TOO_LARGE", "File size exceeds limit", http.StatusRequestEntityTooLarge)
	ErrInvalidFileType   = NewAppError("INVALID_FILE_TYPE", "File type not allowed", http.StatusBadRequest)
	ErrFileUploadFailed  = NewAppError("FILE_UPLOAD_FAILED", "File upload failed", http.StatusInternalServerError)
	ErrFileCorrupted     = NewAppError("FILE_CORRUPTED", "File is corrupted", http.StatusBadRequest)
	ErrVirusDetected     = NewAppError("VIRUS_DETECTED", "Virus detected in file", http.StatusBadRequest)

	// Folder errors
	ErrFolderNotFound      = NewAppError("FOLDER_NOT_FOUND", "Folder not found", http.StatusNotFound)
	ErrFolderAlreadyExists = NewAppError("FOLDER_ALREADY_EXISTS", "Folder already exists", http.StatusConflict)
	ErrFolderNotEmpty      = NewAppError("FOLDER_NOT_EMPTY", "Folder is not empty", http.StatusBadRequest)
	ErrInvalidFolderPath   = NewAppError("INVALID_FOLDER_PATH", "Invalid folder path", http.StatusBadRequest)

	// Storage errors
	ErrStorageQuotaExceeded    = NewAppError("STORAGE_QUOTA_EXCEEDED", "Storage quota exceeded", http.StatusPaymentRequired)
	ErrStorageProviderError    = NewAppError("STORAGE_PROVIDER_ERROR", "Storage provider error", http.StatusInternalServerError)
	ErrStorageConnectionFailed = NewAppError("STORAGE_CONNECTION_FAILED", "Failed to connect to storage", http.StatusInternalServerError)

	// Sharing errors
	ErrShareNotFound         = NewAppError("SHARE_NOT_FOUND", "Share link not found", http.StatusNotFound)
	ErrShareExpired          = NewAppError("SHARE_EXPIRED", "Share link has expired", http.StatusGone)
	ErrSharePasswordRequired = NewAppError("SHARE_PASSWORD_REQUIRED", "Share password required", http.StatusUnauthorized)
	ErrInvalidSharePassword  = NewAppError("INVALID_SHARE_PASSWORD", "Invalid share password", http.StatusUnauthorized)
	ErrShareLimitExceeded    = NewAppError("SHARE_LIMIT_EXCEEDED", "Share download limit exceeded", http.StatusForbidden)

	// Subscription errors
	ErrSubscriptionNotFound = NewAppError("SUBSCRIPTION_NOT_FOUND", "Subscription not found", http.StatusNotFound)
	ErrSubscriptionExpired  = NewAppError("SUBSCRIPTION_EXPIRED", "Subscription has expired", http.StatusPaymentRequired)
	ErrSubscriptionCanceled = NewAppError("SUBSCRIPTION_CANCELED", "Subscription has been canceled", http.StatusPaymentRequired)
	ErrPlanNotFound         = NewAppError("PLAN_NOT_FOUND", "Subscription plan not found", http.StatusNotFound)
	ErrInvalidPlan          = NewAppError("INVALID_PLAN", "Invalid subscription plan", http.StatusBadRequest)

	// Payment errors
	ErrPaymentFailed        = NewAppError("PAYMENT_FAILED", "Payment processing failed", http.StatusPaymentRequired)
	ErrPaymentNotFound      = NewAppError("PAYMENT_NOT_FOUND", "Payment not found", http.StatusNotFound)
	ErrInvalidPaymentMethod = NewAppError("INVALID_PAYMENT_METHOD", "Invalid payment method", http.StatusBadRequest)
	ErrPaymentProviderError = NewAppError("PAYMENT_PROVIDER_ERROR", "Payment provider error", http.StatusInternalServerError)
	ErrInsufficientFunds    = NewAppError("INSUFFICIENT_FUNDS", "Insufficient funds", http.StatusPaymentRequired)

	// Validation errors
	ErrValidationFailed = NewAppError("VALIDATION_FAILED", "Validation failed", http.StatusBadRequest)
	ErrInvalidInput     = NewAppError("INVALID_INPUT", "Invalid input data", http.StatusBadRequest)
	ErrMissingField     = NewAppError("MISSING_FIELD", "Required field is missing", http.StatusBadRequest)
	ErrInvalidFormat    = NewAppError("INVALID_FORMAT", "Invalid format", http.StatusBadRequest)

	// Rate limiting errors
	ErrRateLimitExceeded = NewAppError("RATE_LIMIT_EXCEEDED", "Rate limit exceeded", http.StatusTooManyRequests)
	ErrTooManyRequests   = NewAppError("TOO_MANY_REQUESTS", "Too many requests", http.StatusTooManyRequests)

	// System errors
	ErrInternalServer     = NewAppError("INTERNAL_SERVER_ERROR", "Internal server error", http.StatusInternalServerError)
	ErrServiceUnavailable = NewAppError("SERVICE_UNAVAILABLE", "Service temporarily unavailable", http.StatusServiceUnavailable)
	ErrDatabaseError      = NewAppError("DATABASE_ERROR", "Database error", http.StatusInternalServerError)
	ErrMaintenanceMode    = NewAppError("MAINTENANCE_MODE", "System is in maintenance mode", http.StatusServiceUnavailable)
)

// AppError represents an application-specific error
type AppError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	StatusCode int                    `json:"status_code"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Cause      error                  `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %s)", e.Code, e.Message, e.Cause.Error())
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	e.Details = details
	return e
}

// WithCause adds a cause to the error
func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	return e
}

// NewAppError creates a new application error
func NewAppError(code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Details:    make(map[string]interface{}),
	}
}

// ValidationError represents validation errors
type ValidationError struct {
	Field   string      `json:"field"`
	Message string      `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

// Error implements the error interface
func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "validation failed"
	}
	return fmt.Sprintf("validation failed: %s", ve[0].Message)
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string, value interface{}) ValidationError {
	return ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	}
}

// IsAppError checks if error is an AppError
func IsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

// WrapError wraps an error with an AppError
func WrapError(err error, code, message string, statusCode int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Cause:      err,
		Details:    make(map[string]interface{}),
	}
}
