package middleware

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// RecoveryConfig represents recovery middleware configuration
type RecoveryConfig struct {
	EnableStackTrace    bool         `json:"enable_stack_trace"`
	EnableDetailedError bool         `json:"enable_detailed_error"`
	LogPanics           bool         `json:"log_panics"`
	LogLevel            pkg.LogLevel `json:"log_level"`
	NotifyAdmins        bool         `json:"notify_admins"`
	MaxStackFrames      int          `json:"max_stack_frames"`
	SkipFrames          int          `json:"skip_frames"`
	EnableMetrics       bool         `json:"enable_metrics"`
	EmailAlerts         bool         `json:"email_alerts"`
	SlackAlerts         bool         `json:"slack_alerts"`
	CustomErrorPage     string       `json:"custom_error_page"`
	GracefulShutdown    bool         `json:"graceful_shutdown"`
	MaxConcurrentPanics int          `json:"max_concurrent_panics"`
}

// RecoveryMiddleware handles panic recovery and error management
type RecoveryMiddleware struct {
	config        *RecoveryConfig
	logger        *pkg.Logger
	notifier      ErrorNotifier
	panicCounter  int
	lastPanicTime time.Time
}

// ErrorNotifier interface for sending error notifications
type ErrorNotifier interface {
	NotifyPanic(ctx *gin.Context, panicInfo *PanicInfo) error
	NotifyAdmins(message string, details map[string]interface{}) error
}

// PanicInfo represents panic information
type PanicInfo struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id"`
	Error     interface{}            `json:"error"`
	Stack     string                 `json:"stack"`
	Request   *RequestInfo           `json:"request"`
	User      *UserInfo              `json:"user,omitempty"`
	System    *SystemInfo            `json:"system"`
	Recovery  *RecoveryInfo          `json:"recovery"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// RequestInfo represents request information during panic
type RequestInfo struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Query       string            `json:"query"`
	Headers     map[string]string `json:"headers"`
	UserAgent   string            `json:"user_agent"`
	IP          string            `json:"ip"`
	ContentType string            `json:"content_type"`
	Referer     string            `json:"referer"`
}

// UserInfo represents user information during panic
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// SystemInfo represents system information during panic
type SystemInfo struct {
	GoVersion    string            `json:"go_version"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	NumCPU       int               `json:"num_cpu"`
	NumGoroutine int               `json:"num_goroutine"`
	MemStats     *runtime.MemStats `json:"mem_stats,omitempty"`
}

// RecoveryInfo represents recovery action information
type RecoveryInfo struct {
	Action     string        `json:"action"`
	Successful bool          `json:"successful"`
	Duration   time.Duration `json:"duration"`
	Message    string        `json:"message"`
}

// NewRecoveryMiddleware creates a new recovery middleware
func NewRecoveryMiddleware(config *RecoveryConfig, logger *pkg.Logger, notifier ErrorNotifier) *RecoveryMiddleware {
	if config == nil {
		config = DefaultRecoveryConfig()
	}

	// Set defaults
	if config.MaxStackFrames == 0 {
		config.MaxStackFrames = 50
	}
	if config.SkipFrames == 0 {
		config.SkipFrames = 3
	}
	if config.MaxConcurrentPanics == 0 {
		config.MaxConcurrentPanics = 10
	}

	return &RecoveryMiddleware{
		config:   config,
		logger:   logger,
		notifier: notifier,
	}
}

// DefaultRecoveryConfig returns default recovery configuration
func DefaultRecoveryConfig() *RecoveryConfig {
	return &RecoveryConfig{
		EnableStackTrace:    true,
		EnableDetailedError: false, // Set to false in production
		LogPanics:           true,
		LogLevel:            pkg.LevelError,
		NotifyAdmins:        true,
		MaxStackFrames:      50,
		SkipFrames:          3,
		EnableMetrics:       true,
		EmailAlerts:         true,
		SlackAlerts:         false,
		GracefulShutdown:    true,
		MaxConcurrentPanics: 10,
	}
}

// ProductionRecoveryConfig returns production-safe recovery configuration
func ProductionRecoveryConfig() *RecoveryConfig {
	return &RecoveryConfig{
		EnableStackTrace:    false,
		EnableDetailedError: false,
		LogPanics:           true,
		LogLevel:            pkg.LevelError,
		NotifyAdmins:        true,
		MaxStackFrames:      20,
		SkipFrames:          3,
		EnableMetrics:       true,
		EmailAlerts:         true,
		SlackAlerts:         true,
		GracefulShutdown:    true,
		MaxConcurrentPanics: 5,
	}
}

// Handler returns the recovery middleware handler
func (rm *RecoveryMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				rm.handlePanic(c, err)
			}
		}()

		c.Next()
	}
}

// handlePanic handles panic recovery
func (rm *RecoveryMiddleware) handlePanic(c *gin.Context, err interface{}) {
	panicStart := time.Now()

	// Check for panic flooding
	if rm.isPanicFlooding() {
		rm.handlePanicFlooding(c, err)
		return
	}

	// Increment panic counter
	rm.panicCounter++
	rm.lastPanicTime = time.Now()

	// Check if connection is broken
	var brokenPipe bool
	if ne, ok := err.(*net.OpError); ok {
		if se, ok := ne.Err.(*os.SyscallError); ok {
			errStr := strings.ToLower(se.Error())
			if strings.Contains(errStr, "broken pipe") || strings.Contains(errStr, "connection reset by peer") {
				brokenPipe = true
			}
		}
	}

	// Generate panic ID
	panicID := rm.generatePanicID()

	// Collect panic information
	panicInfo := rm.collectPanicInfo(c, err, panicID)

	// Log panic
	if rm.config.LogPanics {
		rm.logPanic(panicInfo, brokenPipe)
	}

	// Record metrics
	if rm.config.EnableMetrics {
		rm.recordPanicMetrics(panicInfo)
	}

	// Send notifications
	if rm.config.NotifyAdmins && !brokenPipe {
		go func() {
			if rm.notifier != nil {
				if err := rm.notifier.NotifyPanic(c, panicInfo); err != nil {
					rm.logger.Error("Failed to send panic notification", map[string]interface{}{
						"error":    err.Error(),
						"panic_id": panicID,
					})
				}
			}
		}()
	}

	// Attempt graceful recovery
	if rm.config.GracefulShutdown {
		recovery := rm.attemptGracefulRecovery(c, panicInfo)
		panicInfo.Recovery = recovery
	}

	// Set recovery headers
	c.Header("X-Panic-ID", panicID)
	c.Header("X-Recovery-Time", time.Since(panicStart).String())

	// Handle broken pipe connections gracefully
	if brokenPipe {
		rm.logger.Warn("Broken pipe detected during panic", map[string]interface{}{
			"panic_id": panicID,
			"error":    fmt.Sprintf("%v", err),
			"ip":       c.ClientIP(),
		})
		c.Abort()
		return
	}

	// Send error response
	rm.sendErrorResponse(c, panicInfo)
}

// collectPanicInfo collects comprehensive panic information
func (rm *RecoveryMiddleware) collectPanicInfo(c *gin.Context, err interface{}, panicID string) *PanicInfo {
	now := time.Now()

	// Get stack trace
	stack := string(debug.Stack())
	if rm.config.MaxStackFrames > 0 {
		stack = rm.limitStackTrace(stack, rm.config.MaxStackFrames)
	}

	// Collect request information
	requestInfo := &RequestInfo{
		Method:      c.Request.Method,
		Path:        c.Request.URL.Path,
		Query:       c.Request.URL.RawQuery,
		Headers:     rm.sanitizeHeaders(c.Request.Header),
		UserAgent:   c.GetHeader("User-Agent"),
		IP:          c.ClientIP(),
		ContentType: c.GetHeader("Content-Type"),
		Referer:     c.GetHeader("Referer"),
	}

	// Collect user information if available
	var userInfo *UserInfo
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(primitive.ObjectID); ok {
			userInfo = &UserInfo{
				ID: uid.Hex(),
			}

			// Get additional user info if available
			if user, exists := c.Get("user"); exists {
				if u, ok := user.(*interface{}); ok {
					// Extract user details safely
					userInfo.Email = rm.extractUserEmail(u)
					userInfo.Role = rm.extractUserRole(u)
				}
			}
		}
	}

	// Collect system information
	systemInfo := rm.collectSystemInfo()

	// Get request ID
	requestID := ""
	if rid, exists := c.Get("request_id"); exists {
		requestID = rid.(string)
	}

	return &PanicInfo{
		ID:        panicID,
		Timestamp: now,
		RequestID: requestID,
		Error:     err,
		Stack:     stack,
		Request:   requestInfo,
		User:      userInfo,
		System:    systemInfo,
		Metadata: map[string]interface{}{
			"goroutines":    runtime.NumGoroutine(),
			"panic_counter": rm.panicCounter,
			"last_panic_at": rm.lastPanicTime,
		},
	}
}

// collectSystemInfo collects system information
func (rm *RecoveryMiddleware) collectSystemInfo() *SystemInfo {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &SystemInfo{
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		MemStats:     &memStats,
	}
}

// logPanic logs panic information
func (rm *RecoveryMiddleware) logPanic(panicInfo *PanicInfo, brokenPipe bool) {
	logData := map[string]interface{}{
		"panic_id":    panicInfo.ID,
		"request_id":  panicInfo.RequestID,
		"error":       panicInfo.Error,
		"method":      panicInfo.Request.Method,
		"path":        panicInfo.Request.Path,
		"ip":          panicInfo.Request.IP,
		"user_agent":  panicInfo.Request.UserAgent,
		"goroutines":  panicInfo.System.NumGoroutine,
		"broken_pipe": brokenPipe,
		"timestamp":   panicInfo.Timestamp,
	}

	if panicInfo.User != nil {
		logData["user_id"] = panicInfo.User.ID
		logData["user_email"] = panicInfo.User.Email
	}

	if rm.config.EnableStackTrace {
		logData["stack"] = panicInfo.Stack
	}

	// Log with appropriate level
	switch rm.config.LogLevel {
	case pkg.LevelError:
		rm.logger.Error("Panic recovered", logData)
	case pkg.LevelWarn:
		rm.logger.Warn("Panic recovered", logData)
	default:
		rm.logger.Info("Panic recovered", logData)
	}
}

// attemptGracefulRecovery attempts to recover gracefully
func (rm *RecoveryMiddleware) attemptGracefulRecovery(c *gin.Context, panicInfo *PanicInfo) *RecoveryInfo {
	start := time.Now()

	recovery := &RecoveryInfo{
		Action: "graceful_response",
	}

	defer func() {
		recovery.Duration = time.Since(start)
	}()

	// Try to clean up any partial responses
	if !c.Writer.Written() {
		recovery.Successful = true
		recovery.Message = "Successfully prepared error response"
	} else {
		recovery.Successful = false
		recovery.Message = "Response already written, cannot recover gracefully"
	}

	return recovery
}

// sendErrorResponse sends appropriate error response
func (rm *RecoveryMiddleware) sendErrorResponse(c *gin.Context, panicInfo *PanicInfo) {
	// Don't send response if already written
	if c.Writer.Written() {
		c.Abort()
		return
	}

	statusCode := http.StatusInternalServerError
	message := "Internal server error"

	var details map[string]interface{}

	if rm.config.EnableDetailedError {
		// Include more details in development
		details = map[string]interface{}{
			"panic_id":  panicInfo.ID,
			"timestamp": panicInfo.Timestamp,
			"error":     fmt.Sprintf("%v", panicInfo.Error),
		}

		if rm.config.EnableStackTrace {
			details["stack"] = panicInfo.Stack
		}
	} else {
		// Minimal details in production
		details = map[string]interface{}{
			"panic_id":  panicInfo.ID,
			"timestamp": panicInfo.Timestamp,
		}
	}

	// Check if custom error page is configured
	if rm.config.CustomErrorPage != "" {
		c.HTML(statusCode, rm.config.CustomErrorPage, gin.H{
			"PanicID": panicInfo.ID,
			"Message": message,
			"Details": details,
		})
	} else {
		// Send JSON error response
		pkg.ErrorResponse(c, statusCode, "INTERNAL_SERVER_ERROR", message, details)
	}

	c.Abort()
}

// isPanicFlooding checks if there's panic flooding
func (rm *RecoveryMiddleware) isPanicFlooding() bool {
	if rm.panicCounter >= rm.config.MaxConcurrentPanics {
		if time.Since(rm.lastPanicTime) < time.Minute {
			return true
		}
		// Reset counter if it's been a while
		rm.panicCounter = 0
	}
	return false
}

// handlePanicFlooding handles panic flooding scenario
func (rm *RecoveryMiddleware) handlePanicFlooding(c *gin.Context, err interface{}) {
	rm.logger.Error("Panic flooding detected", map[string]interface{}{
		"panic_count":     rm.panicCounter,
		"max_panics":      rm.config.MaxConcurrentPanics,
		"last_panic_time": rm.lastPanicTime,
		"current_error":   fmt.Sprintf("%v", err),
	})

	// Send service unavailable
	pkg.ServiceUnavailableResponse(c, "Service temporarily unavailable due to system issues")
	c.Abort()

	// Notify admins of flooding
	if rm.notifier != nil {
		go rm.notifier.NotifyAdmins("Panic flooding detected", map[string]interface{}{
			"panic_count": rm.panicCounter,
			"max_panics":  rm.config.MaxConcurrentPanics,
		})
	}
}

// recordPanicMetrics records panic metrics
func (rm *RecoveryMiddleware) recordPanicMetrics(panicInfo *PanicInfo) {
	// This would integrate with your metrics system
	rm.logger.Info("Panic metrics", map[string]interface{}{
		"panic_id":     panicInfo.ID,
		"path":         panicInfo.Request.Path,
		"method":       panicInfo.Request.Method,
		"goroutines":   panicInfo.System.NumGoroutine,
		"memory_usage": panicInfo.System.MemStats.Alloc,
		"panic_count":  rm.panicCounter,
	})
}

// limitStackTrace limits stack trace to specified number of frames
func (rm *RecoveryMiddleware) limitStackTrace(stack string, maxFrames int) string {
	lines := strings.Split(stack, "\n")
	if len(lines) <= maxFrames*2 { // Each frame has 2 lines
		return stack
	}

	// Keep first few lines (header) and limit frames
	result := make([]string, 0, maxFrames*2+3)

	// Add header lines
	headerLines := 2
	for i := 0; i < headerLines && i < len(lines); i++ {
		result = append(result, lines[i])
	}

	// Add limited frames (skip frames as configured)
	frameCount := 0
	for i := headerLines + rm.config.SkipFrames*2; i < len(lines) && frameCount < maxFrames; i += 2 {
		if i+1 < len(lines) {
			result = append(result, lines[i], lines[i+1])
			frameCount++
		}
	}

	if frameCount >= maxFrames {
		result = append(result, "... [truncated]")
	}

	return strings.Join(result, "\n")
}

// sanitizeHeaders removes sensitive headers
func (rm *RecoveryMiddleware) sanitizeHeaders(headers map[string][]string) map[string]string {
	sanitized := make(map[string]string)

	sensitiveHeaders := []string{
		"authorization", "cookie", "x-api-key", "x-auth-token",
	}

	for name, values := range headers {
		key := strings.ToLower(name)

		// Check if header is sensitive
		isSensitive := false
		for _, sensitive := range sensitiveHeaders {
			if strings.Contains(key, sensitive) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			sanitized[name] = "[REDACTED]"
		} else {
			sanitized[name] = strings.Join(values, ", ")
		}
	}

	return sanitized
}

// generatePanicID generates a unique panic ID
func (rm *RecoveryMiddleware) generatePanicID() string {
	token, err := pkg.GenerateSecureToken(8)
	if err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("panic_%d", time.Now().UnixNano())
	}
	return "panic_" + token
}

// extractUserEmail safely extracts user email
func (rm *RecoveryMiddleware) extractUserEmail(user interface{}) string {
	// Safe type assertion and field extraction
	// Implementation depends on your user model
	return ""
}

// extractUserRole safely extracts user role
func (rm *RecoveryMiddleware) extractUserRole(user interface{}) string {
	// Safe type assertion and field extraction
	// Implementation depends on your user model
	return ""
}

// CustomRecovery allows custom recovery function
func (rm *RecoveryMiddleware) CustomRecovery(recovery func(*gin.Context, interface{})) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				recovery(c, err)
			}
		}()

		c.Next()
	}
}

// HealthCheck middleware that monitors system health during panics
func (rm *RecoveryMiddleware) HealthCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Monitor system health
		goroutines := runtime.NumGoroutine()

		// Check for concerning conditions
		if goroutines > 10000 { // Configurable threshold
			rm.logger.Warn("High goroutine count detected", map[string]interface{}{
				"goroutines": goroutines,
				"path":       c.Request.URL.Path,
			})
		}

		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		// Check memory usage
		if memStats.Alloc > 1024*1024*1024 { // 1GB threshold
			rm.logger.Warn("High memory usage detected", map[string]interface{}{
				"memory_mb":  memStats.Alloc / 1024 / 1024,
				"goroutines": goroutines,
				"path":       c.Request.URL.Path,
			})
		}

		c.Next()
	}
}

// TimeoutRecovery handles request timeouts gracefully
func (rm *RecoveryMiddleware) TimeoutRecovery(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		done := make(chan bool, 1)

		go func() {
			defer func() {
				if err := recover(); err != nil {
					rm.handlePanic(c, err)
				}
				done <- true
			}()

			c.Next()
		}()

		select {
		case <-done:
			// Request completed normally
		case <-time.After(timeout):
			// Request timed out
			rm.logger.Warn("Request timeout", map[string]interface{}{
				"timeout": timeout.String(),
				"path":    c.Request.URL.Path,
				"method":  c.Request.Method,
				"ip":      c.ClientIP(),
			})

			if !c.Writer.Written() {
				pkg.ErrorResponse(c, http.StatusRequestTimeout, "REQUEST_TIMEOUT",
					"Request timed out", map[string]interface{}{
						"timeout": timeout.String(),
					})
			}
			c.Abort()
		}
	}
}
