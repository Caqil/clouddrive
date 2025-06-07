package services

import (
	"context"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserService handles user operations
type UserService struct {
	userRepo      repository.UserRepository
	fileRepo      repository.FileRepository
	folderRepo    repository.FolderRepository
	auditRepo     repository.AuditLogRepository
	analyticsRepo repository.AnalyticsRepository
}

// NewUserService creates a new user service
func NewUserService(
	userRepo repository.UserRepository,
	fileRepo repository.FileRepository,
	folderRepo repository.FolderRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
) *UserService {
	return &UserService{
		userRepo:      userRepo,
		fileRepo:      fileRepo,
		folderRepo:    folderRepo,
		auditRepo:     auditRepo,
		analyticsRepo: analyticsRepo,
	}
}

// UpdateProfileRequest represents profile update request
type UpdateProfileRequest struct {
	FirstName string `json:"firstName" validate:"required,min=1,max=50"`
	LastName  string `json:"lastName" validate:"required,min=1,max=50"`
	Bio       string `json:"bio" validate:"max=500"`
	Phone     string `json:"phone" validate:"omitempty,phone"`
	Timezone  string `json:"timezone" validate:"omitempty,timezone"`
	Language  string `json:"language" validate:"omitempty,language"`
}

// UpdatePreferencesRequest represents preferences update request
type UpdatePreferencesRequest struct {
	Theme          string `json:"theme" validate:"oneof=light dark"`
	Notifications  bool   `json:"notifications"`
	EmailUpdates   bool   `json:"emailUpdates"`
	DefaultView    string `json:"defaultView" validate:"oneof=list grid"`
	AutoBackup     bool   `json:"autoBackup"`
	ShareByDefault bool   `json:"shareByDefault"`
}

// UserStats represents user statistics
type UserStats struct {
	StorageUsed    int64   `json:"storageUsed"`
	StorageLimit   int64   `json:"storageLimit"`
	FilesCount     int64   `json:"filesCount"`
	FoldersCount   int64   `json:"foldersCount"`
	SharesCount    int64   `json:"sharesCount"`
	StoragePercent float64 `json:"storagePercent"`
}

// GetProfile retrieves user profile
func (s *UserService) GetProfile(ctx context.Context, userID primitive.ObjectID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Remove sensitive information
	user.Password = ""
	user.TwoFactorSecret = ""

	return user, nil
}

// UpdateProfile updates user profile
func (s *UserService) UpdateProfile(ctx context.Context, userID primitive.ObjectID, req *UpdateProfileRequest) (*models.User, error) {
	// Validate request
	if err := pkg.DefaultValidator.Validate(req); err != nil {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Get current user
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Prepare updates
	updates := map[string]interface{}{
		"first_name": req.FirstName,
		"last_name":  req.LastName,
		"bio":        req.Bio,
	}

	if req.Phone != "" {
		updates["phone"] = req.Phone
	}
	if req.Timezone != "" {
		updates["timezone"] = req.Timezone
	}
	if req.Language != "" {
		updates["language"] = req.Language
	}

	// Update user
	if err := s.userRepo.Update(ctx, userID, updates); err != nil {
		return nil, err
	}

	// Log profile update
	s.logAuditEvent(ctx, userID, models.AuditActionUserUpdate, "user", userID, true, "Profile updated")

	// Get updated user
	return s.GetProfile(ctx, userID)
}

// UpdatePreferences updates user preferences
func (s *UserService) UpdatePreferences(ctx context.Context, userID primitive.ObjectID, req *UpdatePreferencesRequest) error {
	// Validate request
	if err := pkg.DefaultValidator.Validate(req); err != nil {
		return pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Prepare preferences update
	preferences := models.UserPreferences{
		Theme:          req.Theme,
		Notifications:  req.Notifications,
		EmailUpdates:   req.EmailUpdates,
		DefaultView:    req.DefaultView,
		AutoBackup:     req.AutoBackup,
		ShareByDefault: req.ShareByDefault,
	}

	updates := map[string]interface{}{
		"preferences": preferences,
	}

	// Update user
	if err := s.userRepo.Update(ctx, userID, updates); err != nil {
		return err
	}

	// Log preferences update
	s.logAuditEvent(ctx, userID, models.AuditActionUserUpdate, "user", userID, true, "Preferences updated")

	return nil
}

// GetUserStats retrieves user statistics
func (s *UserService) GetUserStats(ctx context.Context, userID primitive.ObjectID) (*UserStats, error) {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get storage usage
	storageUsed, err := s.fileRepo.GetStorageByUser(ctx, userID)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Calculate storage percentage
	storagePercent := float64(0)
	if user.StorageLimit > 0 {
		storagePercent = (float64(storageUsed) / float64(user.StorageLimit)) * 100
	}

	// Get files count
	filesParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, filesCount, err := s.fileRepo.ListByUser(ctx, userID, filesParams)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Get folders count
	foldersParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, foldersCount, err := s.folderRepo.ListByUser(ctx, userID, foldersParams)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	return &UserStats{
		StorageUsed:    storageUsed,
		StorageLimit:   user.StorageLimit,
		FilesCount:     filesCount,
		FoldersCount:   foldersCount,
		StoragePercent: storagePercent,
	}, nil
}

// UpdateAvatar updates user avatar
func (s *UserService) UpdateAvatar(ctx context.Context, userID primitive.ObjectID, avatarURL string) error {
	updates := map[string]interface{}{
		"avatar": avatarURL,
	}

	if err := s.userRepo.Update(ctx, userID, updates); err != nil {
		return err
	}

	// Log avatar update
	s.logAuditEvent(ctx, userID, models.AuditActionUserUpdate, "user", userID, true, "Avatar updated")

	return nil
}

// DeactivateAccount deactivates user account
func (s *UserService) DeactivateAccount(ctx context.Context, userID primitive.ObjectID) error {
	updates := map[string]interface{}{
		"status": models.StatusInactive,
	}

	if err := s.userRepo.Update(ctx, userID, updates); err != nil {
		return err
	}

	// Log account deactivation
	s.logAuditEvent(ctx, userID, models.AuditActionUserUpdate, "user", userID, true, "Account deactivated")

	return nil
}

// DeleteAccount permanently deletes user account
func (s *UserService) DeleteAccount(ctx context.Context, userID primitive.ObjectID) error {
	// Soft delete user
	if err := s.userRepo.SoftDelete(ctx, userID); err != nil {
		return err
	}

	// Log account deletion
	s.logAuditEvent(ctx, userID, models.AuditActionUserDelete, "user", userID, true, "Account deleted")

	return nil
}

// logAuditEvent logs an audit event
func (s *UserService) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
	auditLog := &models.AuditLog{
		UserID:    &userID,
		Action:    action,
		Resource:  models.AuditResource{Type: resourceType, ID: resourceID},
		Success:   success,
		Severity:  models.AuditSeverityLow,
		Timestamp: time.Now(),
	}

	if !success {
		auditLog.ErrorMessage = message
		auditLog.Severity = models.AuditSeverityMedium
	}

	s.auditRepo.Create(ctx, auditLog)
}
