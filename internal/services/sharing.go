package services

import (
	"context"
	"fmt"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// SharingService handles file and folder sharing
type SharingService struct {
	shareRepo     repository.ShareRepository
	fileRepo      repository.FileRepository
	folderRepo    repository.FolderRepository
	auditRepo     repository.AuditLogRepository
	analyticsRepo repository.AnalyticsRepository
	emailService  EmailService
}

// NewSharingService creates a new sharing service
func NewSharingService(
	shareRepo repository.ShareRepository,
	fileRepo repository.FileRepository,
	folderRepo repository.FolderRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
	emailService EmailService,
) *SharingService {
	return &SharingService{
		shareRepo:     shareRepo,
		fileRepo:      fileRepo,
		folderRepo:    folderRepo,
		auditRepo:     auditRepo,
		analyticsRepo: analyticsRepo,
		emailService:  emailService,
	}
}

// CreateShareRequest represents share creation request
type CreateShareRequest struct {
	ResourceType   models.ShareResourceType `json:"resourceType" validate:"required,oneof=file folder"`
	ResourceID     primitive.ObjectID       `json:"resourceId" validate:"required"`
	ShareType      models.ShareType         `json:"shareType" validate:"required,oneof=public private internal"`
	Permission     models.SharePermission   `json:"permission" validate:"required,oneof=view download edit comment"`
	Password       string                   `json:"password,omitempty"`
	ExpiresAt      *time.Time               `json:"expiresAt,omitempty"`
	MaxDownloads   int                      `json:"maxDownloads,omitempty"`
	AllowedIPs     []string                 `json:"allowedIPs,omitempty"`
	AllowedDomains []string                 `json:"allowedDomains,omitempty"`
	NotifyOnAccess bool                     `json:"notifyOnAccess"`
	CustomMessage  string                   `json:"customMessage"`
	Recipients     []string                 `json:"recipients,omitempty"`
}

// ShareResponse represents share response
type ShareResponse struct {
	*models.Share
	ShareURL     string `json:"shareUrl"`
	ResourceName string `json:"resourceName"`
}

// CreateShare creates a new share
func (s *SharingService) CreateShare(ctx context.Context, userID primitive.ObjectID, req *CreateShareRequest) (*ShareResponse, error) {
	// Validate request
	if err := pkg.DefaultValidator.Validate(req); err != nil {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Verify resource ownership and get resource name
	var resourceName string
	switch req.ResourceType {
	case models.ShareResourceFile:
		file, err := s.fileRepo.GetByID(ctx, req.ResourceID)
		if err != nil {
			return nil, err
		}
		if file.UserID != userID {
			return nil, pkg.ErrForbidden
		}
		resourceName = file.Name
	case models.ShareResourceFolder:
		folder, err := s.folderRepo.GetByID(ctx, req.ResourceID)
		if err != nil {
			return nil, err
		}
		if folder.UserID != userID {
			return nil, pkg.ErrForbidden
		}
		resourceName = folder.Name
	default:
		return nil, pkg.ErrInvalidInput
	}

	// Generate share token
	token, err := pkg.GenerateSecureToken(32)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Hash password if provided
	var hashedPassword string
	if req.Password != "" {
		hashedPassword, err = pkg.HashPassword(req.Password)
		if err != nil {
			return nil, pkg.ErrInternalServer.WithCause(err)
		}
	}

	// Create recipients
	var recipients []models.ShareRecipient
	for _, email := range req.Recipients {
		recipients = append(recipients, models.ShareRecipient{
			Email:     email,
			InvitedAt: time.Now(),
		})
	}

	// Create share
	share := &models.Share{
		Token:          token,
		ResourceType:   req.ResourceType,
		ResourceID:     req.ResourceID,
		UserID:         userID,
		ShareType:      req.ShareType,
		Permission:     req.Permission,
		Password:       hashedPassword,
		HasPassword:    req.Password != "",
		ExpiresAt:      req.ExpiresAt,
		MaxDownloads:   req.MaxDownloads,
		AllowedIPs:     req.AllowedIPs,
		AllowedDomains: req.AllowedDomains,
		IsActive:       true,
		NotifyOnAccess: req.NotifyOnAccess,
		CustomMessage:  req.CustomMessage,
		Recipients:     recipients,
	}

	if err := s.shareRepo.Create(ctx, share); err != nil {
		return nil, err
	}

	// Send share notifications
	if len(req.Recipients) > 0 {
		shareURL := fmt.Sprintf("/share/%s", token)
		for _, email := range req.Recipients {
			message := fmt.Sprintf("A file has been shared with you: %s", resourceName)
			if req.CustomMessage != "" {
				message = req.CustomMessage
			}
			s.emailService.SendNotificationEmail(ctx, email, "File Shared", message)
		}
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionShareCreate, string(req.ResourceType), req.ResourceID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeFileShare, "create", req.ResourceID, resourceName)

	return &ShareResponse{
		Share:        share,
		ShareURL:     fmt.Sprintf("/share/%s", token),
		ResourceName: resourceName,
	}, nil
}

// GetShare retrieves share by token
func (s *SharingService) GetShare(ctx context.Context, token string) (*ShareResponse, error) {
	share, err := s.shareRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check if share is active
	if !share.IsActive {
		return nil, pkg.ErrShareNotFound
	}

	// Check if share has expired
	if share.ExpiresAt != nil && share.ExpiresAt.Before(time.Now()) {
		return nil, pkg.ErrShareExpired
	}

	// Check download limit
	if share.MaxDownloads > 0 && share.DownloadCount >= share.MaxDownloads {
		return nil, pkg.ErrShareLimitExceeded
	}

	// Get resource name
	var resourceName string
	switch share.ResourceType {
	case models.ShareResourceFile:
		file, err := s.fileRepo.GetByID(ctx, share.ResourceID)
		if err != nil {
			return nil, err
		}
		resourceName = file.Name
	case models.ShareResourceFolder:
		folder, err := s.folderRepo.GetByID(ctx, share.ResourceID)
		if err != nil {
			return nil, err
		}
		resourceName = folder.Name
	}

	return &ShareResponse{
		Share:        share,
		ShareURL:     fmt.Sprintf("/share/%s", token),
		ResourceName: resourceName,
	}, nil
}

// AccessShare accesses a shared resource
func (s *SharingService) AccessShare(ctx context.Context, token, password, ip, userAgent string) (*ShareResponse, error) {
	share, err := s.GetShare(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check password if required
	if share.HasPassword {
		if password == "" {
			return nil, pkg.ErrSharePasswordRequired
		}
		if !pkg.VerifyPassword(password, share.Password) {
			return nil, pkg.ErrInvalidSharePassword
		}
	}

	// Check IP restrictions
	if len(share.AllowedIPs) > 0 {
		allowed := false
		for _, allowedIP := range share.AllowedIPs {
			if ip == allowedIP {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, pkg.ErrForbidden
		}
	}

	// Log access
	access := models.ShareAccess{
		IP:         ip,
		UserAgent:  userAgent,
		AccessedAt: time.Now(),
		Action:     "view",
	}

	s.shareRepo.AddAccessLog(ctx, share.ID, access)
	s.shareRepo.UpdateViewCount(ctx, share.ID)

	// Send notification if enabled
	if share.NotifyOnAccess {
		message := fmt.Sprintf("Your shared file '%s' was accessed", share.ResourceName)
		// Get share owner and send notification
		// This would require getting user email - simplified for brevity
	}

	// Track analytics
	s.trackAnalytics(ctx, primitive.NilObjectID, models.EventTypeShareAccess, "view", share.ResourceID, share.ResourceName)

	return share, nil
}

// DownloadSharedResource downloads a shared resource
func (s *SharingService) DownloadSharedResource(ctx context.Context, token, password, ip, userAgent string) (string, error) {
	// Access share first
	share, err := s.AccessShare(ctx, token, password, ip, userAgent)
	if err != nil {
		return "", err
	}

	// Check download permission
	if share.Permission == models.SharePermissionView {
		return "", pkg.ErrForbidden
	}

	// Update download count
	s.shareRepo.UpdateDownloadCount(ctx, share.ID)

	// Log download access
	access := models.ShareAccess{
		IP:         ip,
		UserAgent:  userAgent,
		AccessedAt: time.Now(),
		Action:     "download",
	}
	s.shareRepo.AddAccessLog(ctx, share.ID, access)

	// For files, return download URL
	if share.ResourceType == models.ShareResourceFile {
		file, err := s.fileRepo.GetByID(ctx, share.ResourceID)
		if err != nil {
			return "", err
		}

		// This would integrate with storage service to get download URL
		downloadURL := fmt.Sprintf("/api/files/%s/download", file.ID.Hex())
		return downloadURL, nil
	}

	// For folders, create zip and return download URL
	// This would be implemented to zip folder contents
	return "", pkg.ErrInternalServer
}

// ListUserShares lists user's shares
func (s *SharingService) ListUserShares(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*ShareResponse, int64, error) {
	shares, total, err := s.shareRepo.ListByUser(ctx, userID, params)
	if err != nil {
		return nil, 0, err
	}

	var responses []*ShareResponse
	for _, share := range shares {
		// Get resource name
		var resourceName string
		switch share.ResourceType {
		case models.ShareResourceFile:
			if file, err := s.fileRepo.GetByID(ctx, share.ResourceID); err == nil {
				resourceName = file.Name
			}
		case models.ShareResourceFolder:
			if folder, err := s.folderRepo.GetByID(ctx, share.ResourceID); err == nil {
				resourceName = folder.Name
			}
		}

		responses = append(responses, &ShareResponse{
			Share:        share,
			ShareURL:     fmt.Sprintf("/share/%s", share.Token),
			ResourceName: resourceName,
		})
	}

	return responses, total, nil
}

// UpdateShare updates share settings
func (s *SharingService) UpdateShare(ctx context.Context, userID primitive.ObjectID, shareID primitive.ObjectID, updates map[string]interface{}) (*ShareResponse, error) {
	// Get share and verify ownership
	share, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return nil, err
	}

	if share.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Hash password if being updated
	if password, exists := updates["password"]; exists {
		if pwd, ok := password.(string); ok && pwd != "" {
			hashedPassword, err := pkg.HashPassword(pwd)
			if err != nil {
				return nil, pkg.ErrInternalServer.WithCause(err)
			}
			updates["password"] = hashedPassword
			updates["has_password"] = true
		} else {
			updates["password"] = ""
			updates["has_password"] = false
		}
	}

	// Update share
	if err := s.shareRepo.Update(ctx, shareID, updates); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionShareUpdate, string(share.ResourceType), share.ResourceID, true, "")

	// Get updated share
	updatedShare, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return nil, err
	}

	// Get resource name
	var resourceName string
	switch updatedShare.ResourceType {
	case models.ShareResourceFile:
		if file, err := s.fileRepo.GetByID(ctx, updatedShare.ResourceID); err == nil {
			resourceName = file.Name
		}
	case models.ShareResourceFolder:
		if folder, err := s.folderRepo.GetByID(ctx, updatedShare.ResourceID); err == nil {
			resourceName = folder.Name
		}
	}

	return &ShareResponse{
		Share:        updatedShare,
		ShareURL:     fmt.Sprintf("/share/%s", updatedShare.Token),
		ResourceName: resourceName,
	}, nil
}

// DeleteShare deletes a share
func (s *SharingService) DeleteShare(ctx context.Context, userID primitive.ObjectID, shareID primitive.ObjectID) error {
	// Get share and verify ownership
	share, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return err
	}

	if share.UserID != userID {
		return pkg.ErrForbidden
	}

	// Soft delete share
	if err := s.shareRepo.SoftDelete(ctx, shareID); err != nil {
		return err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionShareDelete, string(share.ResourceType), share.ResourceID, true, "")

	return nil
}

// CleanupExpiredShares removes expired shares
func (s *SharingService) CleanupExpiredShares(ctx context.Context) error {
	expiredShares, err := s.shareRepo.GetExpiredShares(ctx)
	if err != nil {
		return err
	}

	for _, share := range expiredShares {
		s.shareRepo.SoftDelete(ctx, share.ID)
	}

	return nil
}

// logAuditEvent logs an audit event
func (s *SharingService) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
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

// trackAnalytics tracks analytics event
func (s *SharingService) trackAnalytics(ctx context.Context, userID primitive.ObjectID, eventType models.AnalyticsEventType, action string, resourceID primitive.ObjectID, resourceName string) {
	analytics := &models.Analytics{
		UserID:    &userID,
		EventType: eventType,
		Action:    action,
		Resource: models.AnalyticsResource{
			Type: "share",
			ID:   resourceID,
			Name: resourceName,
		},
		Timestamp: time.Now(),
	}

	s.analyticsRepo.Create(ctx, analytics)
}
