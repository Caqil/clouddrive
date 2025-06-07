package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// SharingService handles file and folder sharing
type SharingService struct {
	userRepo      repository.UserRepository
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

	// Build share URL
	shareURL := fmt.Sprintf("/share/%s", token)

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
		for _, email := range req.Recipients {
			// Prepare notification message
			message := fmt.Sprintf("A %s has been shared with you: %s\n\nAccess it here: %s",
				req.ResourceType, resourceName, shareURL)

			// Use custom message if provided
			if req.CustomMessage != "" {
				message = fmt.Sprintf("%s\n\nMessage from sender: %s\n\nAccess it here: %s",
					req.CustomMessage, resourceName, shareURL)
			}

			// Add password hint if share is password protected
			if req.Password != "" {
				message += "\n\nNote: This share is password protected. The sender should provide you with the password separately."
			}

			// Add expiration info if set
			if req.ExpiresAt != nil {
				message += fmt.Sprintf("\n\nThis share will expire on: %s",
					req.ExpiresAt.Format("2006-01-02 15:04:05 UTC"))
			}

			// Send notification email asynchronously
			go func(recipientEmail string) {
				if err := s.emailService.SendNotificationEmail(ctx, recipientEmail,
					fmt.Sprintf("%s Shared: %s", strings.Title(string(req.ResourceType)), resourceName),
					message); err != nil {
					// Log email sending error but don't fail the share creation
					s.logAuditEvent(ctx, userID, models.AuditActionShareCreate, "email",
						primitive.NilObjectID, false,
						fmt.Sprintf("Failed to send share notification to %s: %v", recipientEmail, err))
				}
			}(email)
		}
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionShareCreate, string(req.ResourceType), req.ResourceID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeFileShare, "create", req.ResourceID, resourceName)

	return &ShareResponse{
		Share:        share,
		ShareURL:     shareURL,
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
			return nil, pkg.ErrForbidden.WithDetails(map[string]interface{}{
				"message": "Access denied: IP address not allowed",
			})
		}
	}

	// Check domain restrictions (extract domain from user agent or referrer)
	if len(share.AllowedDomains) > 0 {
		// Extract domain from IP or implement domain checking logic
		// This could be enhanced to check the referrer header or implement
		// more sophisticated domain validation
		allowed := false

		// For now, we'll check if the user agent contains allowed domains
		// In a real implementation, you might want to check the referrer header
		// or implement reverse DNS lookup for IP-to-domain mapping
		userAgentLower := strings.ToLower(userAgent)
		for _, allowedDomain := range share.AllowedDomains {
			if strings.Contains(userAgentLower, strings.ToLower(allowedDomain)) {
				allowed = true
				break
			}
		}

		if !allowed {
			return nil, pkg.ErrForbidden.WithDetails(map[string]interface{}{
				"message": "Access denied: Domain not allowed",
			})
		}
	}

	// Extract additional info from user agent for better tracking
	var country, city string
	// In a real implementation, you might use a GeoIP service like MaxMind
	// to get location information from the IP address
	// For now, we'll leave these empty or use placeholder values
	if ip != "" {
		// Placeholder for GeoIP lookup
		// country, city = geoIPLookup(ip)
	}

	// Log access with enhanced information
	access := models.ShareAccess{
		IP:         ip,
		UserAgent:  userAgent,
		Country:    country,
		City:       city,
		AccessedAt: time.Now(),
		Action:     "view",
	}

	// Add access log and update view count
	if err := s.shareRepo.AddAccessLog(ctx, share.ID, access); err != nil {
		// Log error but don't fail the request
		s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "share", share.ID, false, fmt.Sprintf("Failed to log access: %v", err))
	}

	if err := s.shareRepo.UpdateViewCount(ctx, share.ID); err != nil {
		// Log error but don't fail the request
		s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "share", share.ID, false, fmt.Sprintf("Failed to update view count: %v", err))
	}

	// Send notification if enabled
	if share.NotifyOnAccess {
		// Get share owner information
		shareOwner, err := s.userRepo.GetByID(ctx, share.UserID)
		if err != nil {
			// Log error but don't fail the share access
			s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "share", share.ID, false, fmt.Sprintf("Failed to get share owner for notification: %v", err))
		} else {
			// Get resource name for the notification
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

			// Send notification email
			subject := "Share Access Notification"
			message := fmt.Sprintf(
				"Your shared %s '%s' was accessed.\n\n"+
					"Access Details:\n"+
					"- Time: %s\n"+
					"- IP Address: %s\n"+
					"- User Agent: %s\n"+
					"- Location: %s, %s\n\n"+
					"If this was not expected, you can revoke the share link in your dashboard.",
				share.ResourceType,
				resourceName,
				access.AccessedAt.Format("2006-01-02 15:04:05 UTC"),
				ip,
				userAgent,
				city,
				country,
			)

			// Send notification asynchronously to not block the share access
			go func() {
				if err := s.emailService.SendNotificationEmail(context.Background(), shareOwner.Email, subject, message); err != nil {
					// Log email sending error
					s.logAuditEvent(context.Background(), share.UserID, models.AuditActionShareAccess, "share", share.ID, false, fmt.Sprintf("Failed to send access notification: %v", err))
				}
			}()
		}
	}

	// Track analytics
	s.trackAnalytics(ctx, primitive.NilObjectID, models.EventTypeShareAccess, "view", share.ResourceID, share.ResourceName)

	// Log successful access in audit log
	s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "share", share.ID, true, fmt.Sprintf("Share accessed from IP: %s", ip))

	return share, nil
}

// Helper function to extract domain from referrer or user agent
func (s *SharingService) extractDomainFromRequest(userAgent, referrer string) string {
	// Check referrer first
	if referrer != "" {
		// Parse the referrer URL to extract domain
		if strings.HasPrefix(referrer, "http://") || strings.HasPrefix(referrer, "https://") {
			parts := strings.Split(referrer, "/")
			if len(parts) >= 3 {
				domain := parts[2]
				// Remove port if present
				if colonIndex := strings.Index(domain, ":"); colonIndex != -1 {
					domain = domain[:colonIndex]
				}
				return domain
			}
		}
	}

	// Fallback to extracting domain hints from user agent
	// This is less reliable but can be useful for mobile apps
	userAgentLower := strings.ToLower(userAgent)

	// Common patterns in user agents that might indicate domain/app
	if strings.Contains(userAgentLower, "example.com") {
		return "example.com"
	}

	// Add more domain extraction logic as needed
	return ""
}

// Enhanced tracking method for share access
func (s *SharingService) trackShareAccess(ctx context.Context, share *models.Share, ip, userAgent, action string) {
	metadata := map[string]interface{}{
		"ip":         ip,
		"user_agent": userAgent,
		"action":     action,
		"share_type": share.ShareType,
		"permission": share.Permission,
	}

	analytics := &models.Analytics{
		UserID:    nil, // Anonymous access
		EventType: models.EventTypeShareAccess,
		Action:    action,
		Resource: models.AnalyticsResource{
			Type: "share",
			ID:   share.ID,
			Name: share.CustomMessage, // Use custom message as name for shares
		},
		Metadata:  metadata,
		IP:        ip,
		UserAgent: userAgent,
		Timestamp: time.Now(),
	}

	s.analyticsRepo.Create(ctx, analytics)
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
