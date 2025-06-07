package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	LogLevel        pkg.LogLevel  `json:"log_level"`
	LogRequests     bool          `json:"log_requests"`
	LogResponses    bool          `json:"log_responses"`
	LogHeaders      bool          `json:"log_headers"`
	LogBody         bool          `json:"log_body"`
	LogSQL          bool          `json:"log_sql"`
	MaxBodySize     int64         `json:"max_body_size"`
	SkipPaths       []string      `json:"skip_paths"`
	SensitiveFields []string      `json:"sensitive_fields"`
	EnableMetrics   bool          `json:"enable_metrics"`
	SlowThreshold   time.Duration `json:"slow_threshold"`
}

// LoggingMiddleware handles request/response logging
type LoggingMiddleware struct {
	config *LoggingConfig
	logger *pkg.Logger
}

// RequestLog represents a request log entry
type RequestLog struct {
	RequestID     string                 `json:"request_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Method        string                 `json:"method"`
	Path          string                 `json:"path"`
	Query         string                 `json:"query,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	IP            string                 `json:"ip"`
	UserID        string                 `json:"user_id,omitempty"`
	Headers       map[string]string      `json:"headers,omitempty"`
	Body          string                 `json:"body,omitempty"`
	ContentType   string                 `json:"content_type,omitempty"`
	ContentLength int64                  `json:"content_length,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ResponseLog represents a response log entry
type ResponseLog struct {
	RequestID    string                 `json:"request_id"`
	Timestamp    time.Time              `json:"timestamp"`
	StatusCode   int                    `json:"status_code"`
	ResponseTime time.Duration          `json:"response_time"`
	ResponseSize int                    `json:"response_size"`
	Headers      map[string]string      `json:"headers,omitempty"`
	Body         string                 `json:"body,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// LogResponseWriter wraps gin.ResponseWriter to capture response data
type LogResponseWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	size       int
}

// Write captures response data and writes to original ResponseWriter
func (w *LogResponseWriter) Write(data []byte) (int, error) {
	// Write to buffer for logging
	if w.body != nil {
		w.body.Write(data)
	}

	// Write to original ResponseWriter
	n, err := w.ResponseWriter.Write(data)
	w.size += n
	return n, err
}

// WriteHeader captures status code and writes to original ResponseWriter
func (w *LogResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Status returns the captured status code
func (w *LogResponseWriter) Status() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

// Size returns the size of the response body
func (w *LogResponseWriter) Size() int {
	return w.size
}

// Body returns the captured response body
func (w *LogResponseWriter) Body() string {
	if w.body != nil {
		return w.body.String()
	}
	return ""
}

// NewLoggingMiddleware creates a new logging middleware
func NewLoggingMiddleware(config *LoggingConfig, logger *pkg.Logger) *LoggingMiddleware {
	if config == nil {
		config = DefaultLoggingConfig()
	}

	// Set defaults
	if config.MaxBodySize == 0 {
		config.MaxBodySize = 64 * 1024 // 64KB default
	}

	if config.SlowThreshold == 0 {
		config.SlowThreshold = 2 * time.Second
	}

	if len(config.SensitiveFields) == 0 {
		config.SensitiveFields = []string{
			"password", "token", "authorization", "cookie", "x-api-key",
			"credit_card", "ssn", "social_security", "passport",
		}
	}

	return &LoggingMiddleware{
		config: config,
		logger: logger,
	}
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		LogLevel:      pkg.LevelInfo,
		LogRequests:   true,
		LogResponses:  true,
		LogHeaders:    true,
		LogBody:       false,
		LogSQL:        true,
		MaxBodySize:   64 * 1024,
		EnableMetrics: true,
		SlowThreshold: 2 * time.Second,
		SkipPaths: []string{
			"/health", "/metrics", "/favicon.ico",
		},
		SensitiveFields: []string{
			"password", "token", "authorization", "cookie", "x-api-key",
			"credit_card", "ssn", "social_security", "passport",
		},
	}
}

// Handler returns the logging middleware handler
func (lm *LoggingMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip logging for configured paths
		if lm.shouldSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Generate request ID
		requestID := lm.generateRequestID()
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		// Start timing
		start := time.Now()

		// Prepare request logging
		var requestLog *RequestLog
		if lm.config.LogRequests {
			requestLog = lm.prepareRequestLog(c, requestID)

			// Capture request body if enabled
			if lm.config.LogBody && c.Request.Body != nil {
				originalBody := lm.captureRequestBody(c)
				if len(originalBody) > 0 {
					requestLog.Body = lm.sanitizeBody(string(originalBody))
				}
			}

			// Log the request
			lm.logRequest(requestLog)
		}

		// Prepare response capture
		var logWriter *LogResponseWriter
		if lm.config.LogResponses {
			logWriter = &LogResponseWriter{
				ResponseWriter: c.Writer,
				body:           &bytes.Buffer{},
				statusCode:     http.StatusOK,
				size:           0,
			}
			c.Writer = logWriter
		}

		// Process the request
		c.Next()

		// Calculate response time
		responseTime := time.Since(start)

		// Log response if enabled
		if lm.config.LogResponses && logWriter != nil {
			responseLog := lm.prepareResponseLog(c, requestID, logWriter, responseTime)
			lm.logResponse(responseLog)
		}

		// Log performance metrics
		if lm.config.EnableMetrics {
			lm.logMetrics(c, requestID, responseTime, logWriter)
		}

		// Log slow requests
		if responseTime > lm.config.SlowThreshold {
			lm.logSlowRequest(c, requestID, responseTime)
		}
	}
}

// prepareRequestLog creates a request log entry
func (lm *LoggingMiddleware) prepareRequestLog(c *gin.Context, requestID string) *RequestLog {
	log := &RequestLog{
		RequestID:     requestID,
		Timestamp:     time.Now(),
		Method:        c.Request.Method,
		Path:          c.Request.URL.Path,
		Query:         c.Request.URL.RawQuery,
		UserAgent:     c.GetHeader("User-Agent"),
		IP:            c.ClientIP(),
		ContentType:   c.GetHeader("Content-Type"),
		ContentLength: c.Request.ContentLength,
		Metadata:      make(map[string]interface{}),
	}

	// Add user ID if available
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(primitive.ObjectID); ok {
			log.UserID = uid.Hex()
		} else if uid, ok := userID.(string); ok {
			log.UserID = uid
		}
	}

	// Add headers if enabled
	if lm.config.LogHeaders {
		log.Headers = lm.sanitizeHeaders(c.Request.Header)
	}

	// Add additional metadata
	log.Metadata["request_size"] = c.Request.ContentLength
	log.Metadata["protocol"] = c.Request.Proto
	log.Metadata["host"] = c.Request.Host

	return log
}

// prepareResponseLog creates a response log entry
func (lm *LoggingMiddleware) prepareResponseLog(c *gin.Context, requestID string, w *LogResponseWriter, responseTime time.Duration) *ResponseLog {
	log := &ResponseLog{
		RequestID:    requestID,
		Timestamp:    time.Now(),
		StatusCode:   w.Status(),
		ResponseTime: responseTime,
		ResponseSize: w.Size(),
		Metadata:     make(map[string]interface{}),
	}

	// Add headers if enabled
	if lm.config.LogHeaders {
		headerMap := make(map[string][]string)
		for k, v := range c.Writer.Header() {
			headerMap[k] = v
		}
		log.Headers = lm.sanitizeHeaders(headerMap)
	}

	// Add response body if enabled and size is reasonable
	if lm.config.LogBody && w.body != nil && w.body.Len() > 0 && int64(w.body.Len()) <= lm.config.MaxBodySize {
		log.Body = lm.sanitizeBody(w.Body())
	}

	// Add error information if present
	if len(c.Errors) > 0 {
		log.Error = c.Errors.String()
	}

	// Add additional metadata
	log.Metadata["response_time_ms"] = responseTime.Milliseconds()
	log.Metadata["response_time_ns"] = responseTime.Nanoseconds()
	log.Metadata["is_slow"] = responseTime > lm.config.SlowThreshold

	return log
}

// captureRequestBody captures and restores request body
func (lm *LoggingMiddleware) captureRequestBody(c *gin.Context) []byte {
	if c.Request.Body == nil {
		return nil
	}

	// Read body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		lm.logger.Error("Failed to read request body", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	// Restore body for further processing
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	// Limit body size for logging
	if int64(len(body)) > lm.config.MaxBodySize {
		truncated := body[:lm.config.MaxBodySize]
		return append(truncated, []byte("... [truncated]")...)
	}

	return body
}

// sanitizeHeaders removes sensitive headers
func (lm *LoggingMiddleware) sanitizeHeaders(headers map[string][]string) map[string]string {
	sanitized := make(map[string]string)

	for name, values := range headers {
		key := strings.ToLower(name)

		// Check if header is sensitive
		if lm.isSensitiveField(key) {
			sanitized[name] = "[REDACTED]"
		} else {
			sanitized[name] = strings.Join(values, ", ")
		}
	}

	return sanitized
}

// sanitizeBody removes sensitive data from body
func (lm *LoggingMiddleware) sanitizeBody(body string) string {
	if body == "" {
		return body
	}

	// Try to parse as JSON and sanitize fields
	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err == nil {
		sanitized := lm.sanitizeData(data)
		if sanitizedBytes, err := json.Marshal(sanitized); err == nil {
			return string(sanitizedBytes)
		}
	}

	// If not JSON, apply basic sanitization
	sanitized := body
	for _, field := range lm.config.SensitiveFields {
		// Basic pattern matching for key-value pairs
		patterns := []string{
			fmt.Sprintf(`"%s"\s*:\s*"[^"]*"`, field),
			fmt.Sprintf(`'%s'\s*:\s*'[^']*'`, field),
			fmt.Sprintf(`%s\s*=\s*[^\s&]*`, field),
		}

		for _, pattern := range patterns {
			replacement := fmt.Sprintf(`"%s":"[REDACTED]"`, field)
			sanitized = strings.ReplaceAll(sanitized, pattern, replacement)
		}
	}

	return sanitized
}

// sanitizeData recursively sanitizes data structures
func (lm *LoggingMiddleware) sanitizeData(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		sanitized := make(map[string]interface{})
		for key, value := range v {
			if lm.isSensitiveField(strings.ToLower(key)) {
				sanitized[key] = "[REDACTED]"
			} else {
				sanitized[key] = lm.sanitizeData(value)
			}
		}
		return sanitized
	case []interface{}:
		sanitized := make([]interface{}, len(v))
		for i, item := range v {
			sanitized[i] = lm.sanitizeData(item)
		}
		return sanitized
	default:
		return v
	}
}

// isSensitiveField checks if a field name is sensitive
func (lm *LoggingMiddleware) isSensitiveField(fieldName string) bool {
	fieldName = strings.ToLower(fieldName)
	for _, sensitive := range lm.config.SensitiveFields {
		if strings.Contains(fieldName, strings.ToLower(sensitive)) {
			return true
		}
	}
	return false
}

// logRequest logs the request
func (lm *LoggingMiddleware) logRequest(log *RequestLog) {
	logData := map[string]interface{}{
		"request_id":     log.RequestID,
		"method":         log.Method,
		"path":           log.Path,
		"ip":             log.IP,
		"user_id":        log.UserID,
		"content_type":   log.ContentType,
		"content_length": log.ContentLength,
	}

	if log.Query != "" {
		logData["query"] = log.Query
	}
	if log.UserAgent != "" {
		logData["user_agent"] = log.UserAgent
	}
	if log.Headers != nil {
		logData["headers"] = log.Headers
	}
	if log.Body != "" {
		logData["body"] = log.Body
	}
	if log.Metadata != nil {
		logData["metadata"] = log.Metadata
	}

	lm.logger.Info("HTTP Request", logData)
}

// logResponse logs the response
func (lm *LoggingMiddleware) logResponse(log *ResponseLog) {
	level := pkg.LevelInfo
	if log.StatusCode >= 500 {
		level = pkg.LevelError
	} else if log.StatusCode >= 400 {
		level = pkg.LevelWarn
	}

	message := fmt.Sprintf("HTTP Response [%d]", log.StatusCode)

	logData := map[string]interface{}{
		"request_id":    log.RequestID,
		"status_code":   log.StatusCode,
		"response_time": log.ResponseTime.String(),
		"response_size": log.ResponseSize,
	}

	if log.Headers != nil {
		logData["headers"] = log.Headers
	}
	if log.Body != "" {
		logData["body"] = log.Body
	}
	if log.Error != "" {
		logData["error"] = log.Error
	}
	if log.Metadata != nil {
		logData["metadata"] = log.Metadata
	}

	switch level {
	case pkg.LevelError:
		lm.logger.Error(message, logData)
	case pkg.LevelWarn:
		lm.logger.Warn(message, logData)
	default:
		lm.logger.Info(message, logData)
	}
}

// logMetrics logs performance metrics
func (lm *LoggingMiddleware) logMetrics(c *gin.Context, requestID string, responseTime time.Duration, w *LogResponseWriter) {
	statusCode := http.StatusOK
	responseSize := 0

	if w != nil {
		statusCode = w.Status()
		responseSize = w.Size()
	} else {
		statusCode = c.Writer.Status()
		responseSize = c.Writer.Size()
	}

	lm.logger.Info("Request Metrics", map[string]interface{}{
		"request_id":       requestID,
		"method":           c.Request.Method,
		"path":             c.Request.URL.Path,
		"status_code":      statusCode,
		"response_time_ms": responseTime.Milliseconds(),
		"response_time_us": responseTime.Microseconds(),
		"request_size":     c.Request.ContentLength,
		"response_size":    responseSize,
		"user_id":          lm.getUserID(c),
		"is_authenticated": lm.isAuthenticated(c),
		"is_admin":         lm.isAdmin(c),
	})
}

// logSlowRequest logs slow requests
func (lm *LoggingMiddleware) logSlowRequest(c *gin.Context, requestID string, responseTime time.Duration) {
	lm.logger.Warn("Slow Request Detected", map[string]interface{}{
		"request_id":       requestID,
		"method":           c.Request.Method,
		"path":             c.Request.URL.Path,
		"response_time":    responseTime.String(),
		"response_time_ms": responseTime.Milliseconds(),
		"threshold_ms":     lm.config.SlowThreshold.Milliseconds(),
		"user_id":          lm.getUserID(c),
		"ip":               c.ClientIP(),
		"user_agent":       c.GetHeader("User-Agent"),
	})
}

// shouldSkipPath checks if path should be skipped from logging
func (lm *LoggingMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range lm.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// generateRequestID generates a unique request ID
func (lm *LoggingMiddleware) generateRequestID() string {
	token, err := pkg.GenerateSecureToken(8)
	if err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	return "req_" + token
}

// getUserID extracts user ID from context
func (lm *LoggingMiddleware) getUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(primitive.ObjectID); ok {
			return uid.Hex()
		} else if uid, ok := userID.(string); ok {
			return uid
		}
	}
	return ""
}

// isAuthenticated checks if request is authenticated
func (lm *LoggingMiddleware) isAuthenticated(c *gin.Context) bool {
	_, exists := c.Get("user_id")
	return exists
}

// isAdmin checks if user is admin
func (lm *LoggingMiddleware) isAdmin(c *gin.Context) bool {
	_, exists := c.Get("admin_user")
	return exists
}

// getRequestID gets request ID from context
func (lm *LoggingMiddleware) getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		if rid, ok := requestID.(string); ok {
			return rid
		}
	}
	return "unknown"
}

// ErrorLogging middleware specifically for error logging
func (lm *LoggingMiddleware) ErrorLogging() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Log any errors that occurred during request processing
		if len(c.Errors) > 0 {
			requestID := lm.getRequestID(c)

			for _, err := range c.Errors {
				lm.logger.Error("Request Error", map[string]interface{}{
					"request_id": requestID,
					"error":      err.Error(),
					"error_type": err.Type,
					"method":     c.Request.Method,
					"path":       c.Request.URL.Path,
					"user_id":    lm.getUserID(c),
					"ip":         c.ClientIP(),
					"metadata":   err.Meta,
				})
			}
		}
	}
}

// PanicLogging middleware for panic recovery and logging
func (lm *LoggingMiddleware) PanicLogging() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				requestID := lm.getRequestID(c)

				lm.logger.Error("Panic Recovered", map[string]interface{}{
					"request_id": requestID,
					"panic":      fmt.Sprintf("%v", err),
					"method":     c.Request.Method,
					"path":       c.Request.URL.Path,
					"user_id":    lm.getUserID(c),
					"ip":         c.ClientIP(),
					"user_agent": c.GetHeader("User-Agent"),
				})

				// Return internal server error
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":      "Internal server error",
					"request_id": requestID,
				})
				c.Abort()
			}
		}()

		c.Next()
	}
}

// StructuredLogging middleware for structured log output
func (lm *LoggingMiddleware) StructuredLogging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get client IP
		clientIP := c.ClientIP()

		// Get request ID
		requestID := lm.getRequestID(c)

		// Create structured log entry
		logEntry := map[string]interface{}{
			"timestamp":     start.Format(time.RFC3339),
			"request_id":    requestID,
			"level":         "info",
			"method":        c.Request.Method,
			"path":          path,
			"status_code":   c.Writer.Status(),
			"latency":       latency.String(),
			"latency_ms":    latency.Milliseconds(),
			"client_ip":     clientIP,
			"user_agent":    c.Request.UserAgent(),
			"user_id":       lm.getUserID(c),
			"request_size":  c.Request.ContentLength,
			"response_size": c.Writer.Size(),
		}

		if raw != "" {
			logEntry["query"] = raw
		}

		// Add error information if present
		if len(c.Errors) > 0 {
			logEntry["level"] = "error"
			logEntry["errors"] = c.Errors.String()
		}

		// Log based on status code
		statusCode := c.Writer.Status()
		if statusCode >= 500 {
			lm.logger.Error("HTTP Request", logEntry)
		} else if statusCode >= 400 {
			lm.logger.Warn("HTTP Request", logEntry)
		} else {
			lm.logger.Info("HTTP Request", logEntry)
		}
	}
}
