package pkg

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// APIResponse represents a standard API response
type APIResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorInfo  `json:"error,omitempty"`
	Meta      *Meta       `json:"meta,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// ErrorInfo represents error information
type ErrorInfo struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// Meta represents response metadata
type Meta struct {
	RequestID string      `json:"request_id,omitempty"`
	Version   string      `json:"version,omitempty"`
	Runtime   string      `json:"runtime,omitempty"`
	Extra     interface{} `json:"extra,omitempty"`
}

// SuccessResponse sends a successful response
func SuccessResponse(c *gin.Context, statusCode int, message string, data interface{}) {
	response := APIResponse{
		Success:   true,
		Message:   message,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	// Add request ID if available
	if requestID, exists := c.Get("request_id"); exists {
		if response.Meta == nil {
			response.Meta = &Meta{}
		}
		response.Meta.RequestID = requestID.(string)
	}

	c.JSON(statusCode, response)
}

// ErrorResponse sends an error response
func ErrorResponse(c *gin.Context, statusCode int, code, message string, details interface{}) {
	response := APIResponse{
		Success: false,
		Message: "Request failed",
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
			Details: details,
		},
		Timestamp: time.Now().UTC(),
	}

	// Add request ID if available
	if requestID, exists := c.Get("request_id"); exists {
		if response.Meta == nil {
			response.Meta = &Meta{}
		}
		response.Meta.RequestID = requestID.(string)
	}

	c.JSON(statusCode, response)
}

// ErrorResponseFromAppError sends an error response from AppError
func ErrorResponseFromAppError(c *gin.Context, err *AppError) {
	ErrorResponse(c, err.StatusCode, err.Code, err.Message, err.Details)
}

// ValidationErrorResponse sends a validation error response
func ValidationErrorResponse(c *gin.Context, errors ValidationErrors) {
	ErrorResponse(c, http.StatusBadRequest, "VALIDATION_FAILED", "Validation failed", errors)
}

// PaginatedResponse sends a paginated response
func PaginatedResponse(c *gin.Context, message string, result *PaginationResult) {
	response := APIResponse{
		Success: true,
		Message: message,
		Data:    result.Data,
		Meta: &Meta{
			Extra: result.Pagination,
		},
		Timestamp: time.Now().UTC(),
	}

	// Add request ID if available
	if requestID, exists := c.Get("request_id"); exists {
		response.Meta.RequestID = requestID.(string)
	}

	c.JSON(http.StatusOK, response)
}

// CreatedResponse sends a created response
func CreatedResponse(c *gin.Context, message string, data interface{}) {
	SuccessResponse(c, http.StatusCreated, message, data)
}

// UpdatedResponse sends an updated response
func UpdatedResponse(c *gin.Context, message string, data interface{}) {
	SuccessResponse(c, http.StatusOK, message, data)
}

// DeletedResponse sends a deleted response
func DeletedResponse(c *gin.Context, message string) {
	SuccessResponse(c, http.StatusOK, message, nil)
}

// NotFoundResponse sends a not found response
func NotFoundResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusNotFound, "NOT_FOUND", message, nil)
}

// UnauthorizedResponse sends an unauthorized response
func UnauthorizedResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", message, nil)
}

// ForbiddenResponse sends a forbidden response
func ForbiddenResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", message, nil)
}

// ConflictResponse sends a conflict response
func ConflictResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusConflict, "CONFLICT", message, nil)
}

// InternalServerErrorResponse sends an internal server error response
func InternalServerErrorResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", message, nil)
}

// BadRequestResponse sends a bad request response
func BadRequestResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusBadRequest, "BAD_REQUEST", message, nil)
}

// RateLimitResponse sends a rate limit exceeded response
func RateLimitResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", message, nil)
}

// ServiceUnavailableResponse sends a service unavailable response
func ServiceUnavailableResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", message, nil)
}
