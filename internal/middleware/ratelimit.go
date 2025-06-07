package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled          bool                     `json:"enabled"`
	DefaultLimit     int                      `json:"default_limit"`
	DefaultWindow    time.Duration            `json:"default_window"`
	BurstLimit       int                      `json:"burst_limit"`
	SkipPaths        []string                 `json:"skip_paths"`
	SkipIPs          []string                 `json:"skip_ips"`
	EndpointLimits   map[string]EndpointLimit `json:"endpoint_limits"`
	UserTypeLimits   map[string]UserTypeLimit `json:"user_type_limits"`
	CustomHeaders    bool                     `json:"custom_headers"`
	StoreType        string                   `json:"store_type"` // "memory", "redis"
	CleanupInterval  time.Duration            `json:"cleanup_interval"`
	BlockDuration    time.Duration            `json:"block_duration"`
	EnableBlacklist  bool                     `json:"enable_blacklist"`
	WhitelistEnabled bool                     `json:"whitelist_enabled"`
	Whitelist        []string                 `json:"whitelist"`
}

// EndpointLimit represents rate limit for specific endpoint
type EndpointLimit struct {
	Path    string        `json:"path"`
	Method  string        `json:"method"`
	Limit   int           `json:"limit"`
	Window  time.Duration `json:"window"`
	BurstOk bool          `json:"burst_ok"`
	PerUser bool          `json:"per_user"`
}

// UserTypeLimit represents rate limit for user types
type UserTypeLimit struct {
	UserType string        `json:"user_type"`
	Limit    int           `json:"limit"`
	Window   time.Duration `json:"window"`
	Burst    int           `json:"burst"`
}

// RateLimitStore interface for different storage backends
type RateLimitStore interface {
	Get(ctx context.Context, key string) (int, time.Time, error)
	Set(ctx context.Context, key string, count int, expiry time.Time) error
	Increment(ctx context.Context, key string, expiry time.Time) (int, error)
	Delete(ctx context.Context, key string) error
	IsBlocked(ctx context.Context, key string) (bool, time.Time, error)
	Block(ctx context.Context, key string, duration time.Duration) error
	Cleanup(ctx context.Context) error
}

// RateLimitMiddleware handles rate limiting
type RateLimitMiddleware struct {
	config *RateLimitConfig
	store  RateLimitStore
	logger *pkg.Logger
}

// RateLimitInfo represents current rate limit status
type RateLimitInfo struct {
	Limit      int           `json:"limit"`
	Remaining  int           `json:"remaining"`
	ResetTime  time.Time     `json:"reset_time"`
	Window     time.Duration `json:"window"`
	Blocked    bool          `json:"blocked"`
	BlockUntil time.Time     `json:"block_until,omitempty"`
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(config *RateLimitConfig, store RateLimitStore, logger *pkg.Logger) *RateLimitMiddleware {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	// Set defaults
	if config.DefaultLimit == 0 {
		config.DefaultLimit = 1000
	}
	if config.DefaultWindow == 0 {
		config.DefaultWindow = time.Hour
	}
	if config.BurstLimit == 0 {
		config.BurstLimit = config.DefaultLimit / 10
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 10 * time.Minute
	}
	if config.BlockDuration == 0 {
		config.BlockDuration = 15 * time.Minute
	}

	middleware := &RateLimitMiddleware{
		config: config,
		store:  store,
		logger: logger,
	}

	// Start cleanup routine if using memory store
	if config.StoreType == "memory" {
		go middleware.startCleanupRoutine()
	}

	return middleware
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Enabled:         true,
		DefaultLimit:    1000,
		DefaultWindow:   time.Hour,
		BurstLimit:      100,
		CustomHeaders:   true,
		StoreType:       "memory",
		CleanupInterval: 10 * time.Minute,
		BlockDuration:   15 * time.Minute,
		EnableBlacklist: true,
		SkipPaths: []string{
			"/health", "/metrics", "/favicon.ico",
		},
		EndpointLimits: map[string]EndpointLimit{
			"POST:/api/auth/login": {
				Path:    "/api/auth/login",
				Method:  "POST",
				Limit:   5,
				Window:  time.Minute,
				BurstOk: false,
				PerUser: false,
			},
			"POST:/api/auth/register": {
				Path:    "/api/auth/register",
				Method:  "POST",
				Limit:   3,
				Window:  time.Minute,
				BurstOk: false,
				PerUser: false,
			},
			"POST:/api/files/upload": {
				Path:    "/api/files/upload",
				Method:  "POST",
				Limit:   100,
				Window:  time.Hour,
				BurstOk: true,
				PerUser: true,
			},
		},
		UserTypeLimits: map[string]UserTypeLimit{
			"free": {
				UserType: "free",
				Limit:    100,
				Window:   time.Hour,
				Burst:    10,
			},
			"premium": {
				UserType: "premium",
				Limit:    1000,
				Window:   time.Hour,
				Burst:    100,
			},
			"admin": {
				UserType: "admin",
				Limit:    10000,
				Window:   time.Hour,
				Burst:    1000,
			},
		},
	}
}

// Handler returns the rate limiting middleware handler
func (rlm *RateLimitMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rlm.config.Enabled {
			c.Next()
			return
		}

		// Skip rate limiting for configured paths
		if rlm.shouldSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Check whitelist
		if rlm.config.WhitelistEnabled && rlm.isWhitelisted(c.ClientIP()) {
			c.Next()
			return
		}

		// Skip rate limiting for configured IPs
		if rlm.shouldSkipIP(c.ClientIP()) {
			c.Next()
			return
		}

		// Get rate limit key
		key := rlm.getRateLimitKey(c)

		// Check if blocked
		if blocked, blockUntil, err := rlm.store.IsBlocked(c.Request.Context(), key); err == nil && blocked {
			rlm.handleBlocked(c, blockUntil)
			return
		}

		// Get applicable limits
		limit, window := rlm.getApplicableLimits(c)

		// Check rate limit
		info, err := rlm.checkRateLimit(c.Request.Context(), key, limit, window)
		if err != nil {
			rlm.logger.Error("Rate limit check failed", map[string]interface{}{
				"error": err.Error(),
				"key":   key,
			})
			// On error, allow request but log
			c.Next()
			return
		}

		// Set rate limit headers
		if rlm.config.CustomHeaders {
			rlm.setRateLimitHeaders(c, info)
		}

		// Check if limit exceeded
		if info.Remaining <= 0 {
			rlm.handleRateLimitExceeded(c, info, key)
			return
		}

		// Log rate limit info for monitoring
		rlm.logRateLimitInfo(c, info, key)

		c.Next()
	}
}

// IPRateLimit middleware for IP-based rate limiting
func (rlm *RateLimitMiddleware) IPRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rlm.config.Enabled {
			c.Next()
			return
		}

		ip := c.ClientIP()
		key := "ip:" + ip

		info, err := rlm.checkRateLimit(c.Request.Context(), key, limit, window)
		if err != nil {
			rlm.logger.Error("IP rate limit check failed", map[string]interface{}{
				"error": err.Error(),
				"ip":    ip,
			})
			c.Next()
			return
		}

		if rlm.config.CustomHeaders {
			rlm.setRateLimitHeaders(c, info)
		}

		if info.Remaining <= 0 {
			rlm.logger.Warn("IP rate limit exceeded", map[string]interface{}{
				"ip":         ip,
				"limit":      limit,
				"window":     window.String(),
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
				"user_agent": c.GetHeader("User-Agent"),
			})

			pkg.RateLimitResponse(c, "IP rate limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}

// UserRateLimit middleware for user-based rate limiting
func (rlm *RateLimitMiddleware) UserRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rlm.config.Enabled {
			c.Next()
			return
		}

		userID, exists := c.Get("user_id")
		if !exists {
			// No user context, skip user rate limiting
			c.Next()
			return
		}

		uid := userID.(primitive.ObjectID)
		key := "user:" + uid.Hex()

		info, err := rlm.checkRateLimit(c.Request.Context(), key, limit, window)
		if err != nil {
			rlm.logger.Error("User rate limit check failed", map[string]interface{}{
				"error":   err.Error(),
				"user_id": uid.Hex(),
			})
			c.Next()
			return
		}

		if rlm.config.CustomHeaders {
			rlm.setRateLimitHeaders(c, info)
		}

		if info.Remaining <= 0 {
			rlm.logger.Warn("User rate limit exceeded", map[string]interface{}{
				"user_id": uid.Hex(),
				"limit":   limit,
				"window":  window.String(),
				"path":    c.Request.URL.Path,
				"method":  c.Request.Method,
			})

			pkg.RateLimitResponse(c, "User rate limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}

// EndpointRateLimit middleware for endpoint-specific rate limiting
func (rlm *RateLimitMiddleware) EndpointRateLimit(path, method string, limit int, window time.Duration, perUser bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rlm.config.Enabled {
			c.Next()
			return
		}

		// Check if this matches the endpoint
		if c.Request.Method != method || !strings.HasPrefix(c.Request.URL.Path, path) {
			c.Next()
			return
		}

		var key string
		if perUser {
			if userID, exists := c.Get("user_id"); exists {
				uid := userID.(primitive.ObjectID)
				key = fmt.Sprintf("endpoint:%s:%s:%s", method, path, uid.Hex())
			} else {
				key = fmt.Sprintf("endpoint:%s:%s:%s", method, path, c.ClientIP())
			}
		} else {
			key = fmt.Sprintf("endpoint:%s:%s:%s", method, path, c.ClientIP())
		}

		info, err := rlm.checkRateLimit(c.Request.Context(), key, limit, window)
		if err != nil {
			rlm.logger.Error("Endpoint rate limit check failed", map[string]interface{}{
				"error":  err.Error(),
				"key":    key,
				"path":   path,
				"method": method,
			})
			c.Next()
			return
		}

		if rlm.config.CustomHeaders {
			rlm.setRateLimitHeaders(c, info)
		}

		if info.Remaining <= 0 {
			rlm.logger.Warn("Endpoint rate limit exceeded", map[string]interface{}{
				"key":    key,
				"path":   path,
				"method": method,
				"limit":  limit,
				"window": window.String(),
			})

			pkg.RateLimitResponse(c, "Endpoint rate limit exceeded")
			c.Abort()
			return
		}

		c.Next()
	}
}

// BruteForceProtection middleware for brute force protection
func (rlm *RateLimitMiddleware) BruteForceProtection(maxAttempts int, blockDuration time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rlm.config.Enabled {
			c.Next()
			return
		}

		// Only apply to authentication endpoints
		if !rlm.isAuthEndpoint(c.Request.URL.Path) {
			c.Next()
			return
		}

		ip := c.ClientIP()
		key := "bruteforce:" + ip

		// Check if IP is blocked
		if blocked, blockUntil, err := rlm.store.IsBlocked(c.Request.Context(), key); err == nil && blocked {
			rlm.logger.Warn("Brute force protection: IP blocked", map[string]interface{}{
				"ip":          ip,
				"block_until": blockUntil,
				"path":        c.Request.URL.Path,
			})

			pkg.ErrorResponse(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
				fmt.Sprintf("IP blocked due to too many failed attempts. Try again after %s",
					blockUntil.Format(time.RFC3339)), nil)
			c.Abort()
			return
		}

		c.Next()

		// Check if authentication failed
		if c.Writer.Status() == http.StatusUnauthorized {
			// Increment failed attempts
			count, err := rlm.store.Increment(c.Request.Context(), key, time.Now().Add(blockDuration))
			if err != nil {
				rlm.logger.Error("Failed to increment brute force counter", map[string]interface{}{
					"error": err.Error(),
					"ip":    ip,
				})
				return
			}

			rlm.logger.Warn("Failed authentication attempt", map[string]interface{}{
				"ip":       ip,
				"attempts": count,
				"path":     c.Request.URL.Path,
				"max":      maxAttempts,
			})

			// Block IP if max attempts reached
			if count >= maxAttempts {
				err := rlm.store.Block(c.Request.Context(), key, blockDuration)
				if err != nil {
					rlm.logger.Error("Failed to block IP", map[string]interface{}{
						"error": err.Error(),
						"ip":    ip,
					})
				} else {
					rlm.logger.Warn("IP blocked due to brute force", map[string]interface{}{
						"ip":       ip,
						"attempts": count,
						"duration": blockDuration.String(),
					})
				}
			}
		} else if c.Writer.Status() == http.StatusOK {
			// Clear failed attempts on successful auth
			rlm.store.Delete(c.Request.Context(), key)
		}
	}
}

// checkRateLimit checks and updates rate limit for a key
func (rlm *RateLimitMiddleware) checkRateLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitInfo, error) {
	now := time.Now()
	expiry := now.Add(window)

	// Increment counter
	count, err := rlm.store.Increment(ctx, key, expiry)
	if err != nil {
		return nil, err
	}

	// Calculate remaining
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time
	resetTime := now.Add(window)
	if count == 1 {
		// First request in window
		resetTime = expiry
	}

	return &RateLimitInfo{
		Limit:     limit,
		Remaining: remaining,
		ResetTime: resetTime,
		Window:    window,
		Blocked:   remaining <= 0,
	}, nil
}

// getRateLimitKey generates rate limit key based on context
func (rlm *RateLimitMiddleware) getRateLimitKey(c *gin.Context) string {
	// Check for user-based rate limiting
	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(primitive.ObjectID)
		return "user:" + uid.Hex()
	}

	// Fall back to IP-based rate limiting
	return "ip:" + c.ClientIP()
}

// getApplicableLimits returns the applicable rate limits for the request
func (rlm *RateLimitMiddleware) getApplicableLimits(c *gin.Context) (int, time.Duration) {
	path := c.Request.URL.Path
	method := c.Request.Method
	endpointKey := method + ":" + path

	// Check for specific endpoint limits
	if endpointLimit, exists := rlm.config.EndpointLimits[endpointKey]; exists {
		return endpointLimit.Limit, endpointLimit.Window
	}

	// Check for user type limits
	if userType := rlm.getUserType(c); userType != "" {
		if userLimit, exists := rlm.config.UserTypeLimits[userType]; exists {
			return userLimit.Limit, userLimit.Window
		}
	}

	// Return default limits
	return rlm.config.DefaultLimit, rlm.config.DefaultWindow
}

// getUserType determines user type for rate limiting
func (rlm *RateLimitMiddleware) getUserType(c *gin.Context) string {
	user, exists := c.Get("user")
	if !exists {
		return "anonymous"
	}

	u := user.(*models.User)

	// Check if admin
	if u.Role == models.RoleAdmin {
		return "admin"
	}

	// Check subscription status
	if u.Subscription != nil && u.Subscription.Status == "active" {
		return "premium"
	}

	return "free"
}

// setRateLimitHeaders sets rate limit headers in response
func (rlm *RateLimitMiddleware) setRateLimitHeaders(c *gin.Context, info *RateLimitInfo) {
	c.Header("X-RateLimit-Limit", strconv.Itoa(info.Limit))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(info.ResetTime.Unix(), 10))
	c.Header("X-RateLimit-Window", info.Window.String())

	if info.Blocked {
		c.Header("Retry-After", strconv.FormatInt(int64(time.Until(info.ResetTime).Seconds()), 10))
	}
}

// handleRateLimitExceeded handles rate limit exceeded scenario
func (rlm *RateLimitMiddleware) handleRateLimitExceeded(c *gin.Context, info *RateLimitInfo, key string) {
	// Log rate limit exceeded
	rlm.logger.Warn("Rate limit exceeded", map[string]interface{}{
		"key":      key,
		"limit":    info.Limit,
		"window":   info.Window.String(),
		"reset_at": info.ResetTime,
		"path":     c.Request.URL.Path,
		"method":   c.Request.Method,
		"ip":       c.ClientIP(),
		"user_id":  rlm.getUserID(c),
	})

	// Block if enabled and threshold exceeded
	if rlm.config.EnableBlacklist {
		// This is a simple implementation - you might want more sophisticated logic
		rlm.store.Block(c.Request.Context(), key, rlm.config.BlockDuration)
	}

	// Return rate limit error
	pkg.ErrorResponse(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED",
		"Rate limit exceeded. Try again later.", map[string]interface{}{
			"limit":    info.Limit,
			"window":   info.Window.String(),
			"reset_at": info.ResetTime.Unix(),
		})
	c.Abort()
}

// handleBlocked handles blocked requests
func (rlm *RateLimitMiddleware) handleBlocked(c *gin.Context, blockUntil time.Time) {
	rlm.logger.Warn("Blocked request", map[string]interface{}{
		"ip":          c.ClientIP(),
		"block_until": blockUntil,
		"path":        c.Request.URL.Path,
		"method":      c.Request.Method,
	})

	retryAfter := int64(time.Until(blockUntil).Seconds())
	c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))

	pkg.ErrorResponse(c, http.StatusTooManyRequests, "BLOCKED",
		fmt.Sprintf("Request blocked. Try again after %s", blockUntil.Format(time.RFC3339)),
		map[string]interface{}{
			"block_until": blockUntil.Unix(),
		})
	c.Abort()
}

// shouldSkipPath checks if path should be skipped from rate limiting
func (rlm *RateLimitMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range rlm.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// shouldSkipIP checks if IP should be skipped from rate limiting
func (rlm *RateLimitMiddleware) shouldSkipIP(ip string) bool {
	for _, skipIP := range rlm.config.SkipIPs {
		if ip == skipIP {
			return true
		}
	}
	return false
}

// isWhitelisted checks if IP is whitelisted
func (rlm *RateLimitMiddleware) isWhitelisted(ip string) bool {
	for _, whiteIP := range rlm.config.Whitelist {
		if ip == whiteIP {
			return true
		}
	}
	return false
}

// isAuthEndpoint checks if path is an authentication endpoint
func (rlm *RateLimitMiddleware) isAuthEndpoint(path string) bool {
	authPaths := []string{
		"/api/auth/login",
		"/api/auth/register",
		"/api/auth/reset-password",
		"/api/auth/verify-email",
	}

	for _, authPath := range authPaths {
		if strings.HasPrefix(path, authPath) {
			return true
		}
	}
	return false
}

// getUserID extracts user ID from context
func (rlm *RateLimitMiddleware) getUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(primitive.ObjectID); ok {
			return uid.Hex()
		}
	}
	return ""
}

// logRateLimitInfo logs rate limit information for monitoring
func (rlm *RateLimitMiddleware) logRateLimitInfo(c *gin.Context, info *RateLimitInfo, key string) {
	// Only log if remaining is low or for monitoring purposes
	if info.Remaining <= info.Limit/10 { // Log when 90% consumed
		rlm.logger.Info("Rate limit status", map[string]interface{}{
			"key":       key,
			"limit":     info.Limit,
			"remaining": info.Remaining,
			"window":    info.Window.String(),
			"path":      c.Request.URL.Path,
			"method":    c.Request.Method,
			"user_id":   rlm.getUserID(c),
		})
	}
}

// startCleanupRoutine starts the cleanup routine for memory store
func (rlm *RateLimitMiddleware) startCleanupRoutine() {
	ticker := time.NewTicker(rlm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		err := rlm.store.Cleanup(context.Background())
		if err != nil {
			rlm.logger.Error("Rate limit cleanup failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}
}

// GetRateLimitInfo returns current rate limit info for a key
func (rlm *RateLimitMiddleware) GetRateLimitInfo(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitInfo, error) {
	count, resetTime, err := rlm.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitInfo{
		Limit:     limit,
		Remaining: remaining,
		ResetTime: resetTime,
		Window:    window,
		Blocked:   remaining <= 0,
	}, nil
}
