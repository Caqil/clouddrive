package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/gin-gonic/gin"
)

// CORSConfig represents CORS configuration
type CORSConfig struct {
	AllowOrigins     []string      `json:"allow_origins"`
	AllowMethods     []string      `json:"allow_methods"`
	AllowHeaders     []string      `json:"allow_headers"`
	ExposeHeaders    []string      `json:"expose_headers"`
	AllowCredentials bool          `json:"allow_credentials"`
	MaxAge           time.Duration `json:"max_age"`
	AllowWildcard    bool          `json:"allow_wildcard"`
	AllowBrowserExt  bool          `json:"allow_browser_ext"`
	AllowWebSockets  bool          `json:"allow_websockets"`
}

// CORSMiddleware handles Cross-Origin Resource Sharing
type CORSMiddleware struct {
	config *CORSConfig
	logger *pkg.Logger
}

// NewCORSMiddleware creates a new CORS middleware with configuration
func NewCORSMiddleware(config *CORSConfig, logger *pkg.Logger) *CORSMiddleware {
	// Set default values if not provided
	if config == nil {
		config = DefaultCORSConfig()
	}

	// Validate and set defaults
	if len(config.AllowMethods) == 0 {
		config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	}

	if len(config.AllowHeaders) == 0 {
		config.AllowHeaders = []string{
			"Origin", "Content-Length", "Content-Type", "Authorization",
			"X-Requested-With", "X-API-Key", "X-Upload-Content-Length",
			"X-Upload-Content-Type", "X-Upload-Offset", "Cache-Control",
		}
	}

	if config.MaxAge == 0 {
		config.MaxAge = 12 * time.Hour
	}

	return &CORSMiddleware{
		config: config,
		logger: logger,
	}
}

// DefaultCORSConfig returns default CORS configuration
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowOrigins: []string{"http://localhost:3000", "http://localhost:8080"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders: []string{
			"Origin", "Content-Length", "Content-Type", "Authorization",
			"X-Requested-With", "X-API-Key", "Accept", "Cache-Control",
			"X-Upload-Content-Length", "X-Upload-Content-Type", "X-Upload-Offset",
		},
		ExposeHeaders: []string{
			"Content-Length", "Access-Control-Allow-Origin",
			"Access-Control-Allow-Headers", "Cache-Control",
			"Content-Language", "Content-Type", "Expires",
			"Last-Modified", "Pragma", "X-Upload-Offset",
		},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
		AllowWildcard:    false,
		AllowBrowserExt:  false,
		AllowWebSockets:  true,
	}
}

// ProductionCORSConfig returns production-safe CORS configuration
func ProductionCORSConfig(allowedOrigins []string) *CORSConfig {
	return &CORSConfig{
		AllowOrigins: allowedOrigins,
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders: []string{
			"Origin", "Content-Length", "Content-Type", "Authorization",
			"X-Requested-With", "X-API-Key", "Accept", "Cache-Control",
		},
		ExposeHeaders: []string{
			"Content-Length", "Content-Type", "Cache-Control",
		},
		AllowCredentials: true,
		MaxAge:           6 * time.Hour,
		AllowWildcard:    false,
		AllowBrowserExt:  false,
		AllowWebSockets:  false,
	}
}

// Handler returns the CORS middleware handler
func (cm *CORSMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Log CORS request for debugging
		cm.logger.Debug("CORS request", map[string]interface{}{
			"origin":  origin,
			"method":  c.Request.Method,
			"path":    c.Request.URL.Path,
			"headers": c.Request.Header,
		})

		// Check if origin is allowed
		if !cm.isOriginAllowed(origin) {
			cm.logger.Warn("CORS: Origin not allowed", map[string]interface{}{
				"origin":          origin,
				"allowed_origins": cm.config.AllowOrigins,
				"path":            c.Request.URL.Path,
				"method":          c.Request.Method,
				"user_agent":      c.GetHeader("User-Agent"),
			})

			// For security, we still need to handle preflight requests
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}

			// Block the request
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Origin not allowed by CORS policy",
			})
			return
		}

		// Set CORS headers
		cm.setCORSHeaders(c, origin)

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			cm.handlePreflight(c)
			return
		}

		// Process the actual request
		c.Next()
	}
}

// isOriginAllowed checks if the origin is allowed
func (cm *CORSMiddleware) isOriginAllowed(origin string) bool {
	// Allow empty origin for same-origin requests
	if origin == "" {
		return true
	}

	// Check exact matches
	for _, allowedOrigin := range cm.config.AllowOrigins {
		if allowedOrigin == "*" && cm.config.AllowWildcard {
			return true
		}
		if allowedOrigin == origin {
			return true
		}

		// Check wildcard subdomains (e.g., *.example.com)
		if strings.HasPrefix(allowedOrigin, "*.") {
			domain := strings.TrimPrefix(allowedOrigin, "*.")
			if strings.HasSuffix(origin, "."+domain) || origin == domain {
				return true
			}
		}
	}

	// Allow browser extensions if configured
	if cm.config.AllowBrowserExt && cm.isBrowserExtension(origin) {
		return true
	}

	return false
}

// isBrowserExtension checks if origin is from a browser extension
func (cm *CORSMiddleware) isBrowserExtension(origin string) bool {
	extensionPrefixes := []string{
		"chrome-extension://",
		"moz-extension://",
		"safari-extension://",
		"ms-browser-extension://",
	}

	for _, prefix := range extensionPrefixes {
		if strings.HasPrefix(origin, prefix) {
			return true
		}
	}

	return false
}

// setCORSHeaders sets the appropriate CORS headers
func (cm *CORSMiddleware) setCORSHeaders(c *gin.Context, origin string) {
	// Set Access-Control-Allow-Origin
	if cm.config.AllowWildcard && len(cm.config.AllowOrigins) == 1 && cm.config.AllowOrigins[0] == "*" {
		c.Header("Access-Control-Allow-Origin", "*")
	} else if origin != "" {
		c.Header("Access-Control-Allow-Origin", origin)
	}

	// Set Access-Control-Allow-Credentials
	if cm.config.AllowCredentials {
		c.Header("Access-Control-Allow-Credentials", "true")
	}

	// Set Access-Control-Expose-Headers
	if len(cm.config.ExposeHeaders) > 0 {
		c.Header("Access-Control-Expose-Headers", strings.Join(cm.config.ExposeHeaders, ", "))
	}

	// Set Vary header to ensure proper caching
	vary := c.GetHeader("Vary")
	if vary == "" {
		c.Header("Vary", "Origin")
	} else if !strings.Contains(vary, "Origin") {
		c.Header("Vary", vary+", Origin")
	}
}

// handlePreflight handles OPTIONS preflight requests
func (cm *CORSMiddleware) handlePreflight(c *gin.Context) {
	// Set Access-Control-Allow-Methods
	if len(cm.config.AllowMethods) > 0 {
		c.Header("Access-Control-Allow-Methods", strings.Join(cm.config.AllowMethods, ", "))
	}

	// Set Access-Control-Allow-Headers
	requestHeaders := c.GetHeader("Access-Control-Request-Headers")
	if requestHeaders != "" {
		// Validate requested headers
		if cm.areHeadersAllowed(requestHeaders) {
			c.Header("Access-Control-Allow-Headers", requestHeaders)
		} else {
			// Use configured allowed headers
			c.Header("Access-Control-Allow-Headers", strings.Join(cm.config.AllowHeaders, ", "))
		}
	} else if len(cm.config.AllowHeaders) > 0 {
		c.Header("Access-Control-Allow-Headers", strings.Join(cm.config.AllowHeaders, ", "))
	}

	// Set Access-Control-Max-Age
	if cm.config.MaxAge > 0 {
		c.Header("Access-Control-Max-Age", strconv.Itoa(int(cm.config.MaxAge.Seconds())))
	}

	// Log preflight request
	cm.logger.Debug("CORS preflight handled", map[string]interface{}{
		"origin":            c.GetHeader("Origin"),
		"requested_method":  c.GetHeader("Access-Control-Request-Method"),
		"requested_headers": c.GetHeader("Access-Control-Request-Headers"),
	})

	c.AbortWithStatus(http.StatusNoContent)
}

// areHeadersAllowed checks if all requested headers are allowed
func (cm *CORSMiddleware) areHeadersAllowed(requestHeaders string) bool {
	headers := strings.Split(requestHeaders, ",")

	for _, header := range headers {
		header = strings.TrimSpace(header)
		if !cm.isHeaderAllowed(header) {
			return false
		}
	}

	return true
}

// isHeaderAllowed checks if a specific header is allowed
func (cm *CORSMiddleware) isHeaderAllowed(header string) bool {
	header = strings.ToLower(strings.TrimSpace(header))

	// Always allow simple headers
	simpleHeaders := []string{
		"accept", "accept-language", "content-language", "content-type",
	}

	for _, simple := range simpleHeaders {
		if header == simple {
			return true
		}
	}

	// Check configured allowed headers
	for _, allowed := range cm.config.AllowHeaders {
		if strings.ToLower(allowed) == header {
			return true
		}
	}

	return false
}

// SecurityHeaders middleware adds security headers
func (cm *CORSMiddleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data: https:; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'"
		c.Header("Content-Security-Policy", csp)

		// Strict Transport Security (HTTPS only)
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Permissions Policy
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		c.Next()
	}
}

// RestrictedCORS middleware for admin endpoints with stricter CORS
func (cm *CORSMiddleware) RestrictedCORS(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if origin is in the restricted allowed list
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}

		if !allowed && origin != "" {
			cm.logger.Warn("Restricted CORS: Origin not allowed", map[string]interface{}{
				"origin":          origin,
				"allowed_origins": allowedOrigins,
				"path":            c.Request.URL.Path,
			})
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Origin not allowed for this endpoint",
			})
			return
		}

		// Set basic CORS headers
		if origin != "" && allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight
		if c.Request.Method == "OPTIONS" {
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
			c.Header("Access-Control-Max-Age", "3600")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// WebSocketCORS middleware for WebSocket connections
func (cm *CORSMiddleware) WebSocketCORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !cm.config.AllowWebSockets {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "WebSocket connections not allowed",
			})
			return
		}

		origin := c.Request.Header.Get("Origin")

		if !cm.isOriginAllowed(origin) {
			cm.logger.Warn("WebSocket CORS: Origin not allowed", map[string]interface{}{
				"origin": origin,
			})
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Origin not allowed for WebSocket connection",
			})
			return
		}

		c.Next()
	}
}

// DynamicCORS middleware that gets CORS config from database/settings
func (cm *CORSMiddleware) DynamicCORS(getConfig func() *CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get dynamic configuration
		config := getConfig()
		if config == nil {
			config = cm.config // fallback to default
		}

		// Temporarily update middleware config
		originalConfig := cm.config
		cm.config = config

		// Process request with dynamic config
		cm.Handler()(c)

		// Restore original config
		cm.config = originalConfig
	}
}

// CORSWithMetrics middleware that tracks CORS metrics
func (cm *CORSMiddleware) CORSWithMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		method := c.Request.Method

		// Track CORS request
		defer func() {
			// Log metrics
			cm.logger.Info("CORS request processed", map[string]interface{}{
				"origin":  origin,
				"method":  method,
				"path":    c.Request.URL.Path,
				"status":  c.Writer.Status(),
				"allowed": c.Writer.Status() != http.StatusForbidden,
			})
		}()

		// Process CORS
		cm.Handler()(c)
	}
}
