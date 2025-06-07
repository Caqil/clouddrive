package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AuthMiddleware handles authentication for protected routes
type AuthMiddleware struct {
	jwtManager *pkg.JWTManager
	userRepo   repository.UserRepository
	logger     *pkg.Logger
	redis      RedisClient // For session management and blacklisting
}

// RedisClient interface for Redis operations
type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Del(ctx context.Context, keys ...string) error
	Exists(ctx context.Context, keys ...string) (int64, error)
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(jwtManager *pkg.JWTManager, userRepo repository.UserRepository, logger *pkg.Logger, redis RedisClient) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager: jwtManager,
		userRepo:   userRepo,
		logger:     logger,
		redis:      redis,
	}
}

// RequireAuth middleware that validates JWT tokens and sets user context
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.logger.Debug("Auth middleware: No authorization header provided")
			pkg.UnauthorizedResponse(c, "Authorization header required")
			c.Abort()
			return
		}

		// Extract Bearer token
		token := pkg.ExtractTokenFromHeader(authHeader)
		if token == "" {
			m.logger.Debug("Auth middleware: Invalid authorization header format")
			pkg.UnauthorizedResponse(c, "Invalid authorization header format")
			c.Abort()
			return
		}

		// Check if token is blacklisted
		if m.isTokenBlacklisted(c.Request.Context(), token) {
			m.logger.Debug("Auth middleware: Token is blacklisted", map[string]interface{}{
				"token_prefix": token[:min(len(token), 10)] + "...",
			})
			pkg.UnauthorizedResponse(c, "Token has been revoked")
			c.Abort()
			return
		}

		// Validate JWT token
		claims, err := m.jwtManager.ValidateToken(token)
		if err != nil {
			m.logger.Debug("Auth middleware: Token validation failed", map[string]interface{}{
				"error": err.Error(),
			})

			// Determine error type for better response
			appErr, ok := pkg.IsAppError(err) // Capture both return values
			if ok {                           // Use the boolean value in the if condition
				if appErr.Code == "TOKEN_EXPIRED" {
					pkg.ErrorResponse(c, http.StatusUnauthorized, "TOKEN_EXPIRED", "Token has expired", nil)
				} else {
					pkg.UnauthorizedResponse(c, "Invalid token")
				}
			} else {
				pkg.UnauthorizedResponse(c, "Invalid token")
			}
			c.Abort()
			return
		}

		// Verify token type
		if claims.TokenType != pkg.TokenTypeAccess {
			m.logger.Debug("Auth middleware: Invalid token type", map[string]interface{}{
				"token_type": claims.TokenType,
			})
			pkg.UnauthorizedResponse(c, "Invalid token type")
			c.Abort()
			return
		}

		// Get user from database to verify account status
		user, err := m.userRepo.GetByID(c.Request.Context(), claims.UserID)
		if err != nil {
			m.logger.Error("Auth middleware: Failed to get user", map[string]interface{}{
				"user_id": claims.UserID.Hex(),
				"error":   err.Error(),
			})
			pkg.UnauthorizedResponse(c, "User not found")
			c.Abort()
			return
		}

		// Check if user account is active
		if user.Status != models.StatusActive {
			m.logger.Warn("Auth middleware: Inactive user attempted access", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"status":  string(user.Status),
			})
			pkg.ForbiddenResponse(c, "Account is not active")
			c.Abort()
			return
		}

		// Check if email is verified (if required)
		if !user.EmailVerified {
			m.logger.Warn("Auth middleware: Unverified user attempted access", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"email":   user.Email,
			})
			pkg.ErrorResponse(c, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "Email verification required", nil)
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", user.ID)
		c.Set("user", user)
		c.Set("user_email", user.Email)
		c.Set("user_role", user.Role)
		c.Set("session_id", claims.SessionID)
		c.Set("token", token)

		// Update last activity timestamp in Redis
		m.updateUserActivity(c.Request.Context(), user.ID, claims.SessionID)

		m.logger.Debug("Auth middleware: Authentication successful", map[string]interface{}{
			"user_id": user.ID.Hex(),
			"email":   user.Email,
		})

		c.Next()
	}
}

// OptionalAuth middleware that sets user context if valid token is provided
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No auth header, continue as anonymous user
			c.Set("user_id", nil)
			c.Set("user", nil)
			c.Next()
			return
		}

		token := pkg.ExtractTokenFromHeader(authHeader)
		if token == "" {
			c.Set("user_id", nil)
			c.Set("user", nil)
			c.Next()
			return
		}

		// Try to validate token, but don't fail if invalid
		claims, err := m.jwtManager.ValidateToken(token)
		if err != nil {
			c.Set("user_id", nil)
			c.Set("user", nil)
			c.Next()
			return
		}

		// Get user
		user, err := m.userRepo.GetByID(c.Request.Context(), claims.UserID)
		if err != nil || user.Status != models.StatusActive {
			c.Set("user_id", nil)
			c.Set("user", nil)
			c.Next()
			return
		}

		// Set user context
		c.Set("user_id", user.ID)
		c.Set("user", user)
		c.Set("user_email", user.Email)
		c.Set("user_role", user.Role)

		c.Next()
	}
}

// RequireRole middleware that checks user role
func (m *AuthMiddleware) RequireRole(requiredRole models.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			pkg.UnauthorizedResponse(c, "Authentication required")
			c.Abort()
			return
		}

		role := userRole.(models.UserRole)
		if role != requiredRole {
			m.logger.Warn("Role middleware: Insufficient role", map[string]interface{}{
				"user_role":     string(role),
				"required_role": string(requiredRole),
			})
			pkg.ForbiddenResponse(c, "Insufficient role")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireEmailVerified middleware that ensures email is verified
func (m *AuthMiddleware) RequireEmailVerified() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			pkg.UnauthorizedResponse(c, "Authentication required")
			c.Abort()
			return
		}

		u := user.(*models.User)
		if !u.EmailVerified {
			pkg.ErrorResponse(c, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "Email verification required", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireTwoFactor middleware for 2FA protected routes
func (m *AuthMiddleware) RequireTwoFactor() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			pkg.UnauthorizedResponse(c, "Authentication required")
			c.Abort()
			return
		}

		u := user.(*models.User)

		// Check if 2FA is enabled for user
		if !u.TwoFactorEnabled {
			// 2FA not enabled, continue
			c.Next()
			return
		}

		// Check if current session has 2FA verification
		sessionID, exists := c.Get("session_id")
		if !exists {
			pkg.UnauthorizedResponse(c, "Session required")
			c.Abort()
			return
		}

		// Check 2FA status in Redis
		twoFAKey := "2fa:" + sessionID.(string)
		verified, err := m.redis.Get(c.Request.Context(), twoFAKey)
		if err != nil || verified != "true" {
			pkg.ErrorResponse(c, http.StatusForbidden, "2FA_REQUIRED", "Two-factor authentication required", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireActiveSubscription middleware for subscription-protected features
func (m *AuthMiddleware) RequireActiveSubscription() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			pkg.UnauthorizedResponse(c, "Authentication required")
			c.Abort()
			return
		}

		u := user.(*models.User)

		// Check if user has active subscription
		if u.Subscription == nil {
			pkg.ErrorResponse(c, http.StatusPaymentRequired, "SUBSCRIPTION_REQUIRED", "Active subscription required", nil)
			c.Abort()
			return
		}

		// Check if subscription is active and not expired
		if u.Subscription.Status != "active" || u.Subscription.ExpiresAt.Before(time.Now()) {
			pkg.ErrorResponse(c, http.StatusPaymentRequired, "SUBSCRIPTION_EXPIRED", "Subscription has expired", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByUser middleware for user-specific rate limiting
func (m *AuthMiddleware) RateLimitByUser(requests int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			// No user context, apply IP-based rate limiting
			c.Next()
			return
		}

		uid := userID.(primitive.ObjectID)
		key := "rate_limit:user:" + uid.Hex()

		// Check current request count
		count, err := m.redis.Get(c.Request.Context(), key)
		if err != nil {
			// Key doesn't exist, create it
			m.redis.Set(c.Request.Context(), key, "1", window)
			c.Next()
			return
		}

		// Convert count to int
		currentCount := pkg.Conversions.StringToInt(count, 0)
		if currentCount >= requests {
			m.logger.Warn("Rate limit exceeded for user", map[string]interface{}{
				"user_id": uid.Hex(),
				"count":   currentCount,
				"limit":   requests,
			})
			pkg.RateLimitResponse(c, "Rate limit exceeded")
			c.Abort()
			return
		}

		// Increment counter
		newCount := currentCount + 1
		m.redis.Set(c.Request.Context(), key, newCount, window)

		c.Next()
	}
}

// SessionTimeout middleware that checks session timeout
func (m *AuthMiddleware) SessionTimeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, exists := c.Get("session_id")
		if !exists {
			c.Next()
			return
		}

		// Check last activity time
		activityKey := "activity:" + sessionID.(string)
		lastActivity, err := m.redis.Get(c.Request.Context(), activityKey)
		if err != nil {
			// No activity record, session expired
			pkg.ErrorResponse(c, http.StatusUnauthorized, "SESSION_EXPIRED", "Session has expired", nil)
			c.Abort()
			return
		}

		// Parse last activity time
		lastTime, err := time.Parse(time.RFC3339, lastActivity)
		if err != nil || time.Since(lastTime) > timeout {
			// Session expired
			m.invalidateSession(c.Request.Context(), sessionID.(string))
			pkg.ErrorResponse(c, http.StatusUnauthorized, "SESSION_EXPIRED", "Session has expired", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAPIKey middleware for API key authentication
func (m *AuthMiddleware) RequireAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		if apiKey == "" {
			pkg.UnauthorizedResponse(c, "API key required")
			c.Abort()
			return
		}

		// Hash the API key for lookup
		hashedKey := pkg.HashString(apiKey)

		// Find user by API key (this would be implemented in user repository)
		user, err := m.findUserByAPIKey(c.Request.Context(), hashedKey)
		if err != nil {
			m.logger.Warn("Invalid API key used", map[string]interface{}{
				"api_key_prefix": apiKey[:min(len(apiKey), 8)] + "...",
				"ip":             c.ClientIP(),
			})
			pkg.UnauthorizedResponse(c, "Invalid API key")
			c.Abort()
			return
		}

		// Check if user account is active
		if user.Status != models.StatusActive {
			pkg.ForbiddenResponse(c, "Account is not active")
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", user.ID)
		c.Set("user", user)
		c.Set("auth_method", "api_key")

		// Update API key last used time
		m.updateAPIKeyUsage(c.Request.Context(), user.ID, hashedKey)

		c.Next()
	}
}

// Helper methods

// isTokenBlacklisted checks if token is in blacklist
func (m *AuthMiddleware) isTokenBlacklisted(ctx context.Context, token string) bool {
	key := "blacklist:" + pkg.HashString(token)
	exists, err := m.redis.Exists(ctx, key)
	return err == nil && exists > 0
}

// updateUserActivity updates user's last activity timestamp
func (m *AuthMiddleware) updateUserActivity(ctx context.Context, userID primitive.ObjectID, sessionID string) {
	activityKey := "activity:" + sessionID
	m.redis.Set(ctx, activityKey, time.Now().Format(time.RFC3339), 24*time.Hour)

	// Also update user's last activity in database periodically
	lastActivityKey := "last_activity:" + userID.Hex()
	lastUpdate, _ := m.redis.Get(ctx, lastActivityKey)

	// Update database every 5 minutes to reduce DB load
	if lastUpdate == "" || time.Since(parseTime(lastUpdate)) > 5*time.Minute {
		go func() {
			updates := map[string]interface{}{
				"last_login_at": time.Now(),
			}
			m.userRepo.Update(context.Background(), userID, updates)
			m.redis.Set(context.Background(), lastActivityKey, time.Now().Format(time.RFC3339), time.Hour)
		}()
	}
}

// invalidateSession invalidates a user session
func (m *AuthMiddleware) invalidateSession(ctx context.Context, sessionID string) {
	activityKey := "activity:" + sessionID
	twoFAKey := "2fa:" + sessionID
	m.redis.Del(ctx, activityKey, twoFAKey)
}

// findUserByAPIKey finds user by API key hash
func (m *AuthMiddleware) findUserByAPIKey(ctx context.Context, hashedKey string) (*models.User, error) {
	// This would be implemented in the user repository
	// For now, return an error as it's not implemented
	return nil, pkg.ErrUserNotFound
}

// updateAPIKeyUsage updates API key last used timestamp
func (m *AuthMiddleware) updateAPIKeyUsage(ctx context.Context, userID primitive.ObjectID, hashedKey string) {
	// Update API key last used time in database
	go func() {
		// This would update the API key's last_used_at field
		// Implementation depends on how API keys are stored
	}()
}

// BlacklistToken adds a token to the blacklist
func (m *AuthMiddleware) BlacklistToken(ctx context.Context, token string, expiry time.Duration) error {
	key := "blacklist:" + pkg.HashString(token)
	return m.redis.Set(ctx, key, "1", expiry)
}

// Utility functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseTime(timeStr string) time.Time {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return time.Time{}
	}
	return t
}
