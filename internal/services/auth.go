package services

import (
	"context"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AuthService handles authentication operations
type AuthService struct {
	userRepo      repository.UserRepository
	auditRepo     repository.AuditLogRepository
	analyticsRepo repository.AnalyticsRepository
	jwtManager    *pkg.JWTManager
	emailService  EmailService
}

// NewAuthService creates a new auth service
func NewAuthService(
	userRepo repository.UserRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
	jwtManager *pkg.JWTManager,
	emailService EmailService,
) *AuthService {
	return &AuthService{
		userRepo:      userRepo,
		auditRepo:     auditRepo,
		analyticsRepo: analyticsRepo,
		jwtManager:    jwtManager,
		emailService:  emailService,
	}
}

// LoginRequest represents login request data
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	Remember bool   `json:"remember"`
}

// RegisterRequest represents registration request data
type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Username  string `json:"username" validate:"required,min=3,max=50"`
	Password  string `json:"password" validate:"required,strongpassword"`
	FirstName string `json:"firstName" validate:"required,min=1,max=50"`
	LastName  string `json:"lastName" validate:"required,min=1,max=50"`
}

// LoginResponse represents login response
type LoginResponse struct {
	User        *models.User   `json:"user"`
	Tokens      *pkg.TokenPair `json:"tokens"`
	SessionID   string         `json:"sessionId"`
	RequiresMFA bool           `json:"requiresMFA"`
}

// Login authenticates user and returns tokens
func (s *AuthService) Login(ctx context.Context, req *LoginRequest, ip, userAgent string) (*LoginResponse, error) {
	// Validate request
	if err := pkg.DefaultValidator.Validate(req); err != nil {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		// Log failed login attempt
		s.logAuditEvent(ctx, nil, models.AuditActionLoginFailure, "user", primitive.NilObjectID, ip, userAgent, false, "Invalid email")
		return nil, pkg.ErrInvalidCredentials
	}

	// Check if user is active
	if user.Status != models.StatusActive {
		s.logAuditEvent(ctx, &user.ID, models.AuditActionLoginFailure, "user", user.ID, ip, userAgent, false, "Account suspended")
		return nil, pkg.ErrAccountSuspended
	}

	// Verify password
	if !pkg.VerifyPassword(req.Password, user.Password) {
		s.logAuditEvent(ctx, &user.ID, models.AuditActionLoginFailure, "user", user.ID, ip, userAgent, false, "Invalid password")
		return nil, pkg.ErrInvalidCredentials
	}

	// Check if email is verified
	if !user.EmailVerified {
		return nil, pkg.ErrEmailNotVerified
	}

	// Check if 2FA is required
	if user.TwoFactorEnabled {
		return &LoginResponse{
			User:        user,
			RequiresMFA: true,
		}, nil
	}

	// Generate session ID
	sessionID, err := pkg.GenerateSecureToken(32)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Generate tokens
	tokens, err := s.jwtManager.GenerateTokenPair(user.ID, user.Email, string(user.Role), sessionID)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Update user login info
	updates := map[string]interface{}{
		"last_login_at": time.Now(),
		"last_login_ip": ip,
		"login_count":   user.LoginCount + 1,
	}
	if err := s.userRepo.Update(ctx, user.ID, updates); err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Log successful login
	s.logAuditEvent(ctx, &user.ID, models.AuditActionUserLogin, "user", user.ID, ip, userAgent, true, "")
	s.trackAnalytics(ctx, &user.ID, models.EventTypeUserLogin, "login", ip, userAgent)

	// Remove password from response
	user.Password = ""

	return &LoginResponse{
		User:      user,
		Tokens:    tokens,
		SessionID: sessionID,
	}, nil
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, req *RegisterRequest, ip, userAgent string) (*models.User, error) {
	// Validate request
	if err := pkg.DefaultValidator.Validate(req); err != nil {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Check if email already exists
	if _, err := s.userRepo.GetByEmail(ctx, req.Email); err == nil {
		return nil, pkg.ErrEmailAlreadyTaken
	}

	// Check if username already exists
	if _, err := s.userRepo.GetByUsername(ctx, req.Username); err == nil {
		return nil, pkg.ErrUsernameAlreadyTaken
	}

	// Hash password
	hashedPassword, err := pkg.HashPassword(req.Password)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Create user
	user := &models.User{
		Email:        req.Email,
		Username:     req.Username,
		Password:     hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         models.RoleUser,
		Status:       models.StatusActive,
		StorageLimit: 5 * 1024 * 1024 * 1024, // 5GB default
		Timezone:     "UTC",
		Language:     "en",
		Preferences: models.UserPreferences{
			Theme:         "light",
			Notifications: true,
			EmailUpdates:  true,
			DefaultView:   "list",
		},
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Generate email verification token
	verifyToken, err := s.jwtManager.GenerateVerificationToken(user.ID, user.Email)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Send verification email
	if err := s.emailService.SendVerificationEmail(ctx, user.Email, user.FirstName, verifyToken); err != nil {
		// Log error but don't fail registration
		pkg.DefaultValidator.Validate(map[string]interface{}{"email_error": err.Error()})
	}

	// Log registration
	s.logAuditEvent(ctx, &user.ID, models.AuditActionUserRegister, "user", user.ID, ip, userAgent, true, "")
	s.trackAnalytics(ctx, &user.ID, models.EventTypeUserRegister, "register", ip, userAgent)

	// Remove password from response
	user.Password = ""

	return user, nil
}

// RefreshToken generates new access token using refresh token
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*pkg.TokenPair, error) {
	tokens, err := s.jwtManager.RefreshToken(refreshToken)
	if err != nil {
		return nil, pkg.ErrInvalidRefreshToken.WithCause(err)
	}

	return tokens, nil
}

// VerifyEmail verifies user's email address
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	// Validate verification token
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return pkg.ErrInvalidToken.WithCause(err)
	}

	if claims.TokenType != pkg.TokenTypeVerify {
		return pkg.ErrInvalidToken
	}

	// Update user email verification status
	updates := map[string]interface{}{
		"email_verified":    true,
		"email_verified_at": time.Now(),
	}

	if err := s.userRepo.Update(ctx, claims.UserID, updates); err != nil {
		return err
	}

	// Log email verification
	s.logAuditEvent(ctx, &claims.UserID, models.AuditActionEmailVerify, "user", claims.UserID, "", "", true, "")

	return nil
}

// RequestPasswordReset sends password reset email
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		// Don't reveal if email exists or not
		return nil
	}

	// Generate reset token
	resetToken, err := s.jwtManager.GenerateResetToken(user.ID, user.Email)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}

	// Send reset email
	if err := s.emailService.SendPasswordResetEmail(ctx, user.Email, user.FirstName, resetToken); err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}

	// Log password reset request
	s.logAuditEvent(ctx, &user.ID, models.AuditActionPasswordReset, "user", user.ID, "", "", true, "Password reset requested")

	return nil
}

// ResetPassword resets user password using token
func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate reset token
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return pkg.ErrInvalidToken.WithCause(err)
	}

	if claims.TokenType != pkg.TokenTypeReset {
		return pkg.ErrInvalidToken
	}

	// Validate new password
	if !pkg.Validations.IsStrongPassword(newPassword) {
		return pkg.ErrWeakPassword
	}

	// Hash new password
	hashedPassword, err := pkg.HashPassword(newPassword)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}

	// Update user password
	updates := map[string]interface{}{
		"password": hashedPassword,
	}

	if err := s.userRepo.Update(ctx, claims.UserID, updates); err != nil {
		return err
	}

	// Log password change
	s.logAuditEvent(ctx, &claims.UserID, models.AuditActionPasswordChange, "user", claims.UserID, "", "", true, "Password reset completed")

	return nil
}

// ChangePassword changes user password
func (s *AuthService) ChangePassword(ctx context.Context, userID primitive.ObjectID, oldPassword, newPassword string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify old password
	if !pkg.VerifyPassword(oldPassword, user.Password) {
		return pkg.ErrInvalidCredentials
	}

	// Validate new password
	if !pkg.Validations.IsStrongPassword(newPassword) {
		return pkg.ErrWeakPassword
	}

	// Hash new password
	hashedPassword, err := pkg.HashPassword(newPassword)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}

	// Update password
	updates := map[string]interface{}{
		"password": hashedPassword,
	}

	if err := s.userRepo.Update(ctx, userID, updates); err != nil {
		return err
	}

	// Log password change
	s.logAuditEvent(ctx, &userID, models.AuditActionPasswordChange, "user", userID, "", "", true, "")

	return nil
}

// ValidateToken validates and returns token claims
func (s *AuthService) ValidateToken(ctx context.Context, token string) (*pkg.TokenClaims, error) {
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	// Verify user still exists and is active
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, pkg.ErrInvalidToken
	}

	if user.Status != models.StatusActive {
		return nil, pkg.ErrAccountSuspended
	}

	return claims, nil
}

// Logout invalidates user session
func (s *AuthService) Logout(ctx context.Context, userID primitive.ObjectID, ip, userAgent string) error {
	// Log logout
	s.logAuditEvent(ctx, &userID, models.AuditActionUserLogout, "user", userID, ip, userAgent, true, "")
	s.trackAnalytics(ctx, &userID, models.EventTypeUserLogout, "logout", ip, userAgent)

	return nil
}

// logAuditEvent logs an audit event
func (s *AuthService) logAuditEvent(ctx context.Context, userID *primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, ip, userAgent string, success bool, errorMsg string) {
	auditLog := &models.AuditLog{
		UserID:    userID,
		Action:    action,
		Resource:  models.AuditResource{Type: resourceType, ID: resourceID},
		IP:        ip,
		UserAgent: userAgent,
		Success:   success,
		Severity:  models.AuditSeverityMedium,
		Timestamp: time.Now(),
	}

	if !success {
		auditLog.ErrorMessage = errorMsg
		auditLog.Severity = models.AuditSeverityHigh
	}

	s.auditRepo.Create(ctx, auditLog)
}

// trackAnalytics tracks analytics event
func (s *AuthService) trackAnalytics(ctx context.Context, userID *primitive.ObjectID, eventType models.AnalyticsEventType, action, ip, userAgent string) {
	analytics := &models.Analytics{
		UserID:    userID,
		EventType: eventType,
		Action:    action,
		IP:        ip,
		UserAgent: userAgent,
		Timestamp: time.Now(),
	}

	s.analyticsRepo.Create(ctx, analytics)
}
