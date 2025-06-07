package handlers

import (
	"net/http"
	"strings"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AuthHandler struct {
	authService *services.AuthService
	userService *services.UserService
}

func NewAuthHandler(authService *services.AuthService, userService *services.UserService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		userService: userService,
	}
}

// LoginRequest represents login request payload
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Remember bool   `json:"remember"`
}

// RegisterRequest represents registration request payload
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username" binding:"required,min=3,max=50"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"firstName" binding:"required,min=1,max=50"`
	LastName  string `json:"lastName" binding:"required,min=1,max=50"`
}

// PasswordResetRequest represents password reset request payload
type PasswordResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents reset password request payload
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required,min=8"`
}

// ChangePasswordRequest represents change password request payload
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required,min=8"`
}

// VerifyEmailRequest represents email verification request payload
type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

// RefreshTokenRequest represents refresh token request payload
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

// Login authenticates user and returns tokens
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	loginReq := &services.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
		Remember: req.Remember,
	}

	response, err := h.authService.Login(c.Request.Context(), loginReq, ip, userAgent)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to login")
		return
	}

	if response.RequiresMFA {
		pkg.SuccessResponse(c, http.StatusOK, "Two-factor authentication required", gin.H{
			"requiresMFA": true,
			"user":        response.User,
		})
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Login successful", gin.H{
		"user":      response.User,
		"tokens":    response.Tokens,
		"sessionId": response.SessionID,
	})
}

// Register creates new user account
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	registerReq := &services.RegisterRequest{
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	user, err := h.authService.Register(c.Request.Context(), registerReq, ip, userAgent)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to register user")
		return
	}

	pkg.CreatedResponse(c, "User registered successfully. Please check your email for verification.", user)
}

// RefreshToken generates new access token using refresh token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	tokens, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.UnauthorizedResponse(c, "Invalid refresh token")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Token refreshed successfully", tokens)
}

// VerifyEmail verifies user email address
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	err := h.authService.VerifyEmail(c.Request.Context(), req.Token)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.BadRequestResponse(c, "Failed to verify email")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Email verified successfully", nil)
}

// RequestPasswordReset sends password reset email
func (h *AuthHandler) RequestPasswordReset(c *gin.Context) {
	var req PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	err := h.authService.RequestPasswordReset(c.Request.Context(), req.Email)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to send password reset email")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Password reset email sent if account exists", nil)
}

// ResetPassword resets user password using token
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	err := h.authService.ResetPassword(c.Request.Context(), req.Token, req.NewPassword)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.BadRequestResponse(c, "Failed to reset password")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Password reset successfully", nil)
}

// ChangePassword changes user password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID := getUserIDFromContext(c)
	if userID == primitive.NilObjectID {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	err := h.authService.ChangePassword(c.Request.Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.BadRequestResponse(c, "Failed to change password")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Password changed successfully", nil)
}

// Logout invalidates user session
func (h *AuthHandler) Logout(c *gin.Context) {
	userID := getUserIDFromContext(c)
	if userID == primitive.NilObjectID {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	err := h.authService.Logout(c.Request.Context(), userID, ip, userAgent)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to logout")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Logged out successfully", nil)
}

// GetProfile returns current user profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID := getUserIDFromContext(c)
	if userID == primitive.NilObjectID {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	user, err := h.userService.GetProfile(c.Request.Context(), userID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get user profile")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Profile retrieved successfully", user)
}

// ValidateToken validates JWT token and returns user info
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		pkg.UnauthorizedResponse(c, "Authorization header required")
		return
	}

	token := pkg.ExtractTokenFromHeader(authHeader)
	if token == "" {
		pkg.UnauthorizedResponse(c, "Invalid authorization format")
		return
	}

	claims, err := h.authService.ValidateToken(c.Request.Context(), token)
	if err != nil {
		pkg.UnauthorizedResponse(c, "Invalid token")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Token is valid", gin.H{
		"userId":    claims.UserID,
		"email":     claims.Email,
		"role":      claims.Role,
		"tokenType": claims.TokenType,
		"expiresAt": claims.ExpiresAt,
	})
}

// AuthMiddleware validates JWT token and sets user context
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			pkg.UnauthorizedResponse(c, "Authorization header required")
			c.Abort()
			return
		}

		token := pkg.ExtractTokenFromHeader(authHeader)
		if token == "" {
			pkg.UnauthorizedResponse(c, "Invalid authorization format")
			c.Abort()
			return
		}

		claims, err := h.authService.ValidateToken(c.Request.Context(), token)
		if err != nil {
			pkg.UnauthorizedResponse(c, "Invalid or expired token")
			c.Abort()
			return
		}

		// Set user context
		c.Set("userID", claims.UserID)
		c.Set("userEmail", claims.Email)
		c.Set("userRole", claims.Role)
		c.Set("tokenType", claims.TokenType)

		c.Next()
	}
}

// OptionalAuthMiddleware validates JWT token if present but doesn't require it
func (h *AuthHandler) OptionalAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		token := pkg.ExtractTokenFromHeader(authHeader)
		if token == "" {
			c.Next()
			return
		}

		claims, err := h.authService.ValidateToken(c.Request.Context(), token)
		if err != nil {
			c.Next()
			return
		}

		// Set user context
		c.Set("userID", claims.UserID)
		c.Set("userEmail", claims.Email)
		c.Set("userRole", claims.Role)
		c.Set("tokenType", claims.TokenType)

		c.Next()
	}
}

// AdminOnlyMiddleware ensures only admin users can access the endpoint
func (h *AuthHandler) AdminOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("userRole")
		if !exists {
			pkg.UnauthorizedResponse(c, "Authentication required")
			c.Abort()
			return
		}

		if userRole != string(models.RoleAdmin) {
			pkg.ForbiddenResponse(c, "Admin privileges required")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitMiddleware implements basic rate limiting
func (h *AuthHandler) RateLimitMiddleware(requestsPerMinute int) gin.HandlerFunc {
	return func(c *gin.Context) {
		// This would integrate with a Redis-based rate limiter
		// For now, we'll skip implementation but the structure is here
		c.Next()
	}
}

// CORSMiddleware handles CORS headers
func (h *AuthHandler) CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow all origins for development, in production this should be restricted
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		// Log the origin for monitoring
		if origin != "" {
			c.Set("origin", origin)
		}

		c.Next()
	}
}

// getUserIDFromContext extracts user ID from gin context
func getUserIDFromContext(c *gin.Context) primitive.ObjectID {
	userID, exists := c.Get("userID")
	if !exists {
		return primitive.NilObjectID
	}

	if id, ok := userID.(primitive.ObjectID); ok {
		return id
	}

	return primitive.NilObjectID
}

// getUserRoleFromContext extracts user role from gin context
func getUserRoleFromContext(c *gin.Context) string {
	userRole, exists := c.Get("userRole")
	if !exists {
		return ""
	}

	if role, ok := userRole.(string); ok {
		return role
	}

	return ""
}

// isAuthenticated checks if user is authenticated
func isAuthenticated(c *gin.Context) bool {
	userID := getUserIDFromContext(c)
	return userID != primitive.NilObjectID
}

// isAdmin checks if user has admin role
func isAdmin(c *gin.Context) bool {
	userRole := getUserRoleFromContext(c)
	return userRole == string(models.RoleAdmin)
}

// extractClientInfo extracts client information from request
func extractClientInfo(c *gin.Context) (ip string, userAgent string) {
	ip = c.ClientIP()
	userAgent = c.GetHeader("User-Agent")

	// Handle X-Forwarded-For header for proxy setups
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		// Take the first IP from the comma-separated list
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip = strings.TrimSpace(ips[0])
		}
	}

	// Handle X-Real-IP header
	if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
		ip = realIP
	}

	return ip, userAgent
}
