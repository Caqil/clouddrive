package admin

import (
	"net/http"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AuthHandler struct {
	authService  *services.AuthService
	userService  *services.UserService
	adminService *services.AdminService
}

func NewAuthHandler(authService *services.AuthService, userService *services.UserService, adminService *services.AdminService) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		userService:  userService,
		adminService: adminService,
	}
}

type AdminLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	Remember bool   `json:"remember"`
}

type AdminLoginResponse struct {
	User      *models.User   `json:"user"`
	Tokens    *pkg.TokenPair `json:"tokens"`
	SessionID string         `json:"sessionId"`
}

// Login authenticates admin user
func (h *AuthHandler) Login(c *gin.Context) {
	var req AdminLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	// Use the existing auth service login
	loginReq := &services.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
		Remember: req.Remember,
	}

	loginResp, err := h.authService.Login(c.Request.Context(), loginReq, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Verify user has admin role
	if loginResp.User.Role != models.RoleAdmin {
		pkg.ForbiddenResponse(c, "Admin access required")
		return
	}

	response := &AdminLoginResponse{
		User:      loginResp.User,
		Tokens:    loginResp.Tokens,
		SessionID: loginResp.SessionID,
	}

	pkg.SuccessResponse(c, http.StatusOK, "Admin login successful", response)
}

// Logout logs out admin user
func (h *AuthHandler) Logout(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Not authenticated")
		return
	}

	err := h.authService.Logout(c.Request.Context(), userID.(primitive.ObjectID), c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Admin logout successful", nil)
}

// RefreshToken refreshes admin access token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refreshToken" validate:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	tokens, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Token refreshed successfully", tokens)
}

// GetProfile gets admin user profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Not authenticated")
		return
	}

	profile, err := h.userService.GetProfile(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Verify admin role
	if profile.Role != models.RoleAdmin {
		pkg.ForbiddenResponse(c, "Admin access required")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Admin profile retrieved successfully", profile)
}

// UpdateProfile updates admin user profile
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Not authenticated")
		return
	}

	var req services.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	updatedProfile, err := h.userService.UpdateProfile(c.Request.Context(), userID.(primitive.ObjectID), &req)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Admin profile updated successfully", updatedProfile)
}

// ChangePassword changes admin password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Not authenticated")
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword" validate:"required"`
		NewPassword     string `json:"newPassword" validate:"required,strongpassword"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	err := h.authService.ChangePassword(c.Request.Context(), userID.(primitive.ObjectID), req.CurrentPassword, req.NewPassword)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Password changed successfully", nil)
}

// GetAdminStats gets admin-specific statistics
func (h *AuthHandler) GetAdminStats(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Not authenticated")
		return
	}

	// Get system stats using admin service
	stats, err := h.adminService.GetSystemStats(c.Request.Context())
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Add admin-specific information
	adminStats := map[string]interface{}{
		"system":    stats,
		"admin_id":  userID,
		"timestamp": time.Now(),
	}

	pkg.SuccessResponse(c, http.StatusOK, "Admin statistics retrieved successfully", adminStats)
}

// ValidateSession validates admin session
func (h *AuthHandler) ValidateSession(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Not authenticated")
		return
	}

	sessionData := map[string]interface{}{
		"user_id":   userID,
		"timestamp": time.Now(),
		"ip":        c.ClientIP(),
		"valid":     true,
	}

	pkg.SuccessResponse(c, http.StatusOK, "Session is valid", sessionData)
}
