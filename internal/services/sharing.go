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
	userRepo repository.UserRepository,
	shareRepo repository.ShareRepository,
	fileRepo repository.FileRepository,
	folderRepo repository.FolderRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
	emailService EmailService,
) *SharingService {
	return &SharingService{
		userRepo:      userRepo,
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

// BulkCreateShareRequest represents bulk share creation request
type BulkCreateShareRequest struct {
	ResourceTypes  []models.ShareResourceType `json:"resourceTypes" validate:"required"`
	ResourceIDs    []primitive.ObjectID       `json:"resourceIds" validate:"required"`
	ShareType      models.ShareType           `json:"shareType" validate:"required,oneof=public private internal"`
	Permission     models.SharePermission     `json:"permission" validate:"required,oneof=view download edit comment"`
	Password       string                     `json:"password,omitempty"`
	ExpiresAt      *time.Time                 `json:"expiresAt,omitempty"`
	MaxDownloads   int                        `json:"maxDownloads,omitempty"`
	AllowedIPs     []string                   `json:"allowedIPs,omitempty"`
	AllowedDomains []string                   `json:"allowedDomains,omitempty"`
	NotifyOnAccess bool                       `json:"notifyOnAccess"`
	CustomMessage  string                     `json:"customMessage"`
	Recipients     []string                   `json:"recipients,omitempty"`
}

// ShareResponse represents share response
type ShareResponse struct {
	*models.Share
	ShareURL     string `json:"shareUrl"`
	ResourceName string `json:"resourceName"`
}

// SharingOverview represents user's sharing activity overview
type SharingOverview struct {
	TotalShares        int64                 `json:"totalShares"`
	ActiveShares       int64                 `json:"activeShares"`
	ExpiredShares      int64                 `json:"expiredShares"`
	TotalViews         int64                 `json:"totalViews"`
	TotalDownloads     int64                 `json:"totalDownloads"`
	RecentActivity     []*models.ShareAccess `json:"recentActivity"`
	SharesByType       map[string]int64      `json:"sharesByType"`
	SharesByPermission map[string]int64      `json:"sharesByPermission"`
}

// ShareStatistics represents share statistics
type ShareStatistics struct {
	ShareID        primitive.ObjectID    `json:"shareId"`
	TotalViews     int                   `json:"totalViews"`
	TotalDownloads int                   `json:"totalDownloads"`
	UniqueVisitors int                   `json:"uniqueVisitors"`
	AccessLog      []*models.ShareAccess `json:"accessLog"`
	TopCountries   map[string]int        `json:"topCountries"`
	AccessPattern  map[string]int        `json:"accessPattern"` // hourly access pattern
}

// BulkShareResult represents bulk share creation result
type BulkShareResult struct {
	Successful []ShareResponse `json:"successful"`
	Failed     []struct {
		ResourceID primitive.ObjectID `json:"resourceId"`
		Error      string             `json:"error"`
	} `json:"failed"`
	TotalCreated int `json:"totalCreated"`
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

	// Build share model
	share := &models.Share{
		Token:          token,
		ResourceType:   req.ResourceType,
		ResourceID:     req.ResourceID,
		UserID:         userID,
		ShareType:      req.ShareType,
		Permission:     req.Permission,
		HasPassword:    req.Password != "",
		ExpiresAt:      req.ExpiresAt,
		MaxDownloads:   req.MaxDownloads,
		AllowedIPs:     req.AllowedIPs,
		AllowedDomains: req.AllowedDomains,
		IsActive:       true,
		NotifyOnAccess: req.NotifyOnAccess,
		CustomMessage:  req.CustomMessage,
		Recipients:     make([]models.ShareRecipient, 0),
		AccessLog:      make([]models.ShareAccess, 0),
	}

	// Hash password if provided
	if req.Password != "" {
		hashedPassword, err := pkg.HashPassword(req.Password)
		if err != nil {
			return nil, pkg.ErrInternalServer.WithCause(err)
		}
		share.Password = hashedPassword
	}

	// Add recipients
	for _, email := range req.Recipients {
		recipient := models.ShareRecipient{
			Email:     email,
			InvitedAt: time.Now(),
		}

		// Try to find user by email
		if user, err := s.userRepo.GetByEmail(ctx, email); err == nil {
			recipient.UserID = &user.ID
			recipient.Name = user.FirstName
		}

		share.Recipients = append(share.Recipients, recipient)
	}

	// Create share
	if err := s.shareRepo.Create(ctx, share); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionShareCreate, string(req.ResourceType), req.ResourceID, true, "")

	// Send email notifications if recipients provided
	if len(req.Recipients) > 0 {
		s.sendShareNotifications(ctx, share, resourceName, req.Recipients)
	}

	return &ShareResponse{
		Share:        share,
		ShareURL:     fmt.Sprintf("/share/%s", share.Token),
		ResourceName: resourceName,
	}, nil
}

// GetShare retrieves share by token
func (s *SharingService) GetShare(ctx context.Context, token string) (*ShareResponse, error) {
	share, err := s.shareRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check if share is expired
	if share.ExpiresAt != nil && share.ExpiresAt.Before(time.Now()) {
		return nil, pkg.ErrShareExpired
	}

	// Check if share is active
	if !share.IsActive {
		return nil, pkg.ErrShareNotFound
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

// GetUserShare retrieves share by ID for a specific user
func (s *SharingService) GetUserShare(ctx context.Context, userID, shareID primitive.ObjectID) (*ShareResponse, error) {
	share, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return nil, err
	}

	if share.UserID != userID {
		return nil, pkg.ErrForbidden
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
		ShareURL:     fmt.Sprintf("/share/%s", share.Token),
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

	// Check domain restrictions
	if len(share.AllowedDomains) > 0 {
		allowed := false
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

	// Log access
	access := models.ShareAccess{
		IP:         ip,
		UserAgent:  userAgent,
		AccessedAt: time.Now(),
		Action:     "view",
	}

	if err := s.shareRepo.AddAccessLog(ctx, share.ID, access); err != nil {
		s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "share", share.ID, false, fmt.Sprintf("Failed to log access: %v", err))
	}

	if err := s.shareRepo.UpdateViewCount(ctx, share.ID); err != nil {
		s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "share", share.ID, false, fmt.Sprintf("Failed to update view count: %v", err))
	}

	// Send notification if enabled
	if share.NotifyOnAccess {
		s.sendAccessNotification(ctx, share.Share, ip, userAgent)
	}

	return share, nil
}

// DownloadShare generates download URL for shared resource
func (s *SharingService) DownloadShare(ctx context.Context, token, password, ip, userAgent string) (string, error) {
	share, err := s.AccessShare(ctx, token, password, ip, userAgent)
	if err != nil {
		return "", err
	}

	// Check if download permission is allowed
	if share.Permission != models.SharePermissionDownload && share.Permission != models.SharePermissionEdit {
		return "", pkg.ErrForbidden.WithDetails(map[string]interface{}{
			"message": "Download not allowed for this share",
		})
	}

	// Update download count
	if err := s.shareRepo.UpdateDownloadCount(ctx, share.ID); err != nil {
		s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "share", share.ID, false, fmt.Sprintf("Failed to update download count: %v", err))
	}

	// Generate download URL based on resource type
	switch share.ResourceType {
	case models.ShareResourceFile:
		file, err := s.fileRepo.GetByID(ctx, share.ResourceID)
		if err != nil {
			return "", err
		}
		// This would integrate with storage service to get download URL
		downloadURL := fmt.Sprintf("/api/files/%s/download", file.ID.Hex())
		return downloadURL, nil
	case models.ShareResourceFolder:
		// For folders, create zip and return download URL
		// This would be implemented to zip folder contents
		return "", pkg.ErrInternalServer
	}

	return "", pkg.ErrInvalidInput
}

// ListUserShares lists user's shares
func (s *SharingService) ListUserShares(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*ShareResponse, int64, error) {
	shares, total, err := s.shareRepo.ListByUser(ctx, userID, params)
	if err != nil {
		return nil, 0, err
	}

	var responses []*ShareResponse
	for _, share := range shares {
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
	return s.GetUserShare(ctx, userID, shareID)
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

// RevokeAllShares revokes all shares for a resource
func (s *SharingService) RevokeAllShares(ctx context.Context, userID primitive.ObjectID, resourceType models.ShareResourceType, resourceID primitive.ObjectID) (int, error) {
	// Verify user owns the resource
	switch resourceType {
	case models.ShareResourceFile:
		file, err := s.fileRepo.GetByID(ctx, resourceID)
		if err != nil {
			return 0, err
		}
		if file.UserID != userID {
			return 0, pkg.ErrForbidden
		}
	case models.ShareResourceFolder:
		folder, err := s.folderRepo.GetByID(ctx, resourceID)
		if err != nil {
			return 0, err
		}
		if folder.UserID != userID {
			return 0, pkg.ErrForbidden
		}
	}

	// Get all shares for the resource
	shares, err := s.shareRepo.ListByResource(ctx, resourceType, resourceID)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, share := range shares {
		if err := s.shareRepo.SoftDelete(ctx, share.ID); err != nil {
			continue // Log error but continue with others
		}
		count++
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionShareDelete, string(resourceType), resourceID, true, fmt.Sprintf("Revoked %d shares", count))

	return count, nil
}

// GetSharingOverview gets overview of user's sharing activity
func (s *SharingService) GetSharingOverview(ctx context.Context, userID primitive.ObjectID) (*SharingOverview, error) {
	// Get user shares with no pagination limit to calculate totals
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000, // High limit to get most shares
	}

	shares, totalShares, err := s.shareRepo.ListByUser(ctx, userID, params)
	if err != nil {
		return nil, err
	}

	overview := &SharingOverview{
		TotalShares:        totalShares,
		SharesByType:       make(map[string]int64),
		SharesByPermission: make(map[string]int64),
		RecentActivity:     make([]*models.ShareAccess, 0),
	}

	var totalViews, totalDownloads int64
	activeShares := int64(0)
	expiredShares := int64(0)

	for _, share := range shares {
		// Count by type
		overview.SharesByType[string(share.ShareType)]++

		// Count by permission
		overview.SharesByPermission[string(share.Permission)]++

		// Count views and downloads
		totalViews += int64(share.ViewCount)
		totalDownloads += int64(share.DownloadCount)

		// Check if active or expired
		if share.ExpiresAt != nil && share.ExpiresAt.Before(time.Now()) {
			expiredShares++
		} else if share.IsActive {
			activeShares++
		}

		// Collect recent activity (last 10 access logs)
		if len(share.AccessLog) > 0 {
			for i := len(share.AccessLog) - 1; i >= 0 && len(overview.RecentActivity) < 10; i-- {
				overview.RecentActivity = append(overview.RecentActivity, &share.AccessLog[i])
			}
		}
	}

	overview.ActiveShares = activeShares
	overview.ExpiredShares = expiredShares
	overview.TotalViews = totalViews
	overview.TotalDownloads = totalDownloads

	return overview, nil
}

// GetShareLink gets or regenerates a share link
func (s *SharingService) GetShareLink(ctx context.Context, userID, shareID primitive.ObjectID, regenerate bool) (string, error) {
	share, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return "", err
	}

	if share.UserID != userID {
		return "", pkg.ErrForbidden
	}

	if regenerate {
		// Generate new token
		newToken, err := pkg.GenerateSecureToken(32)
		if err != nil {
			return "", pkg.ErrInternalServer.WithCause(err)
		}

		updates := map[string]interface{}{
			"token": newToken,
		}

		if err := s.shareRepo.Update(ctx, shareID, updates); err != nil {
			return "", err
		}

		// Log audit event
		s.logAuditEvent(ctx, userID, models.AuditActionShareUpdate, "share", shareID, true, "Regenerated share link")

		return fmt.Sprintf("/share/%s", newToken), nil
	}

	return fmt.Sprintf("/share/%s", share.Token), nil
}

// ValidateAccess validates access to a shared resource
func (s *SharingService) ValidateAccess(ctx context.Context, token, password, ip, userAgent string) (*ShareResponse, error) {
	return s.AccessShare(ctx, token, password, ip, userAgent)
}

// GetShareStatistics retrieves share statistics
func (s *SharingService) GetShareStatistics(ctx context.Context, userID, shareID primitive.ObjectID) (*ShareStatistics, error) {
	share, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return nil, err
	}

	if share.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Calculate unique visitors
	uniqueIPs := make(map[string]bool)
	topCountries := make(map[string]int)
	accessPattern := make(map[string]int)

	for _, access := range share.AccessLog {
		uniqueIPs[access.IP] = true
		if access.Country != "" {
			topCountries[access.Country]++
		}

		// Group by hour for access pattern
		hour := access.AccessedAt.Format("15")
		accessPattern[hour]++
	}

	stats := &ShareStatistics{
		ShareID:        shareID,
		TotalViews:     share.ViewCount,
		TotalDownloads: share.DownloadCount,
		UniqueVisitors: len(uniqueIPs),
		AccessLog:      make([]*models.ShareAccess, len(share.AccessLog)),
		TopCountries:   topCountries,
		AccessPattern:  accessPattern,
	}

	// Convert access log
	for i, access := range share.AccessLog {
		stats.AccessLog[i] = &access
	}

	return stats, nil
}

// GetShareAccessLogs retrieves share access logs
func (s *SharingService) GetShareAccessLogs(ctx context.Context, userID, shareID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.ShareAccess, int64, error) {
	share, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return nil, 0, err
	}

	if share.UserID != userID {
		return nil, 0, pkg.ErrForbidden
	}

	// For pagination, we need to slice the access log
	total := int64(len(share.AccessLog))
	start := (params.Page - 1) * params.Limit
	end := start + params.Limit

	if start >= int(total) {
		return []*models.ShareAccess{}, total, nil
	}

	if end > int(total) {
		end = int(total)
	}

	// Reverse order to show most recent first
	logs := make([]*models.ShareAccess, 0)
	for i := len(share.AccessLog) - 1; i >= 0; i-- {
		logs = append(logs, &share.AccessLog[i])
	}

	// Apply pagination
	pagedLogs := logs[start:end]

	return pagedLogs, total, nil
}

// BulkCreateShares creates multiple shares at once
func (s *SharingService) BulkCreateShares(ctx context.Context, userID primitive.ObjectID, req *BulkCreateShareRequest) (*BulkShareResult, error) {
	result := &BulkShareResult{
		Successful: make([]ShareResponse, 0),
		Failed: make([]struct {
			ResourceID primitive.ObjectID `json:"resourceId"`
			Error      string             `json:"error"`
		}, 0),
		TotalCreated: 0,
	}

	for i, resourceID := range req.ResourceIDs {
		if i >= len(req.ResourceTypes) {
			break
		}

		createReq := &CreateShareRequest{
			ResourceType:   req.ResourceTypes[i],
			ResourceID:     resourceID,
			ShareType:      req.ShareType,
			Permission:     req.Permission,
			Password:       req.Password,
			ExpiresAt:      req.ExpiresAt,
			MaxDownloads:   req.MaxDownloads,
			AllowedIPs:     req.AllowedIPs,
			AllowedDomains: req.AllowedDomains,
			NotifyOnAccess: req.NotifyOnAccess,
			CustomMessage:  req.CustomMessage,
			Recipients:     req.Recipients,
		}

		share, err := s.CreateShare(ctx, userID, createReq)
		if err != nil {
			result.Failed = append(result.Failed, struct {
				ResourceID primitive.ObjectID `json:"resourceId"`
				Error      string             `json:"error"`
			}{
				ResourceID: resourceID,
				Error:      err.Error(),
			})
		} else {
			result.Successful = append(result.Successful, *share)
			result.TotalCreated++
		}
	}

	return result, nil
}

// AddComment adds a comment to a shared resource
func (s *SharingService) AddComment(ctx context.Context, token, content, author, email, ip, userAgent string) (*models.ShareAccess, error) {
	share, err := s.shareRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check if comments are allowed
	if share.Permission != models.SharePermissionComment && share.Permission != models.SharePermissionEdit {
		return nil, pkg.ErrForbidden.WithDetails(map[string]interface{}{
			"message": "Comments not allowed for this share",
		})
	}

	// Create comment as access log entry
	comment := models.ShareAccess{
		IP:         ip,
		UserAgent:  userAgent,
		AccessedAt: time.Now(),
		Action:     "comment",
		Email:      email,
	}

	if err := s.shareRepo.AddAccessLog(ctx, share.ID, comment); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "share", share.ID, true, fmt.Sprintf("Comment by %s", author))

	return &comment, nil
}

// GetComments retrieves comments for a shared resource
func (s *SharingService) GetComments(ctx context.Context, token string, params *pkg.PaginationParams) ([]*models.ShareAccess, int64, error) {
	share, err := s.shareRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, 0, err
	}

	// Filter access log for comments only
	comments := make([]*models.ShareAccess, 0)
	for _, access := range share.AccessLog {
		if access.Action == "comment" {
			comments = append(comments, &access)
		}
	}

	total := int64(len(comments))
	start := (params.Page - 1) * params.Limit
	end := start + params.Limit

	if start >= int(total) {
		return []*models.ShareAccess{}, total, nil
	}

	if end > int(total) {
		end = int(total)
	}

	// Apply pagination (reverse order for newest first)
	paginatedComments := make([]*models.ShareAccess, 0)
	for i := len(comments) - 1; i >= 0; i-- {
		if len(paginatedComments) >= params.Limit {
			break
		}
		if len(paginatedComments) >= start {
			paginatedComments = append(paginatedComments, comments[i])
		}
	}

	return paginatedComments[start:end], total, nil
}

// AddRecipients adds recipients to an existing share
func (s *SharingService) AddRecipients(ctx context.Context, userID, shareID primitive.ObjectID, emails []string, message string, notifyByEmail bool) (*ShareResponse, error) {
	share, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return nil, err
	}

	if share.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Add new recipients
	newRecipients := make([]models.ShareRecipient, 0)
	for _, email := range emails {
		// Check if recipient already exists
		exists := false
		for _, existing := range share.Recipients {
			if existing.Email == email {
				exists = true
				break
			}
		}

		if !exists {
			recipient := models.ShareRecipient{
				Email:     email,
				InvitedAt: time.Now(),
			}

			// Try to find user by email
			if user, err := s.userRepo.GetByEmail(ctx, email); err == nil {
				recipient.UserID = &user.ID
				recipient.Name = user.FirstName
			}

			newRecipients = append(newRecipients, recipient)
		}
	}

	// Update share with new recipients
	allRecipients := append(share.Recipients, newRecipients...)
	updates := map[string]interface{}{
		"recipients": allRecipients,
	}

	if err := s.shareRepo.Update(ctx, shareID, updates); err != nil {
		return nil, err
	}

	// Send notifications if requested
	if notifyByEmail && len(newRecipients) > 0 {
		resourceName := s.getResourceName(ctx, share.ResourceType, share.ResourceID)
		s.sendShareNotifications(ctx, share, resourceName, emails)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionShareUpdate, "share", shareID, true, fmt.Sprintf("Added %d recipients", len(newRecipients)))

	return s.GetUserShare(ctx, userID, shareID)
}

// RemoveRecipients removes recipients from a share
func (s *SharingService) RemoveRecipients(ctx context.Context, userID, shareID primitive.ObjectID, emails []string) (*ShareResponse, error) {
	share, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return nil, err
	}

	if share.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Filter out recipients to remove
	filteredRecipients := make([]models.ShareRecipient, 0)
	removedCount := 0

	for _, recipient := range share.Recipients {
		shouldRemove := false
		for _, email := range emails {
			if recipient.Email == email {
				shouldRemove = true
				removedCount++
				break
			}
		}

		if !shouldRemove {
			filteredRecipients = append(filteredRecipients, recipient)
		}
	}

	// Update share
	updates := map[string]interface{}{
		"recipients": filteredRecipients,
	}

	if err := s.shareRepo.Update(ctx, shareID, updates); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionShareUpdate, "share", shareID, true, fmt.Sprintf("Removed %d recipients", removedCount))

	return s.GetUserShare(ctx, userID, shareID)
}

// CloneShare creates a copy of an existing share with new settings
func (s *SharingService) CloneShare(ctx context.Context, userID, shareID primitive.ObjectID, overrides interface{}) (*ShareResponse, error) {
	originalShare, err := s.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return nil, err
	}

	if originalShare.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Create new share request based on original
	createReq := &CreateShareRequest{
		ResourceType:   originalShare.ResourceType,
		ResourceID:     originalShare.ResourceID,
		ShareType:      originalShare.ShareType,
		Permission:     originalShare.Permission,
		Password:       "", // Don't copy password
		ExpiresAt:      originalShare.ExpiresAt,
		MaxDownloads:   originalShare.MaxDownloads,
		AllowedIPs:     originalShare.AllowedIPs,
		AllowedDomains: originalShare.AllowedDomains,
		NotifyOnAccess: originalShare.NotifyOnAccess,
		CustomMessage:  originalShare.CustomMessage,
		Recipients:     make([]string, 0), // Don't copy recipients
	}

	// Apply overrides if provided
	// This would require type assertion based on the overrides structure
	// For now, we'll create with original settings

	return s.CreateShare(ctx, userID, createReq)
}

// Helper methods

func (s *SharingService) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, details string) {
	auditLog := &models.AuditLog{
		UserID:    &userID,
		Action:    action,
		Resource:  models.AuditResource{Type: resourceType, ID: resourceID},
		Success:   success,
		Severity:  models.AuditSeverityLow,
		Timestamp: time.Now(),
	}

	if !success {
		auditLog.ErrorMessage = details
		auditLog.Severity = models.AuditSeverityMedium
	}

	// Log audit event (ignore errors as this shouldn't fail the main operation)
	s.auditRepo.Create(ctx, auditLog)
}

func (s *SharingService) getResourceName(ctx context.Context, resourceType models.ShareResourceType, resourceID primitive.ObjectID) string {
	switch resourceType {
	case models.ShareResourceFile:
		if file, err := s.fileRepo.GetByID(ctx, resourceID); err == nil {
			return file.Name
		}
	case models.ShareResourceFolder:
		if folder, err := s.folderRepo.GetByID(ctx, resourceID); err == nil {
			return folder.Name
		}
	}
	return "Unknown"
}

func (s *SharingService) sendShareNotifications(ctx context.Context, share *models.Share, resourceName string, emails []string) {
	// Send email notifications to recipients
	subject := fmt.Sprintf("You've been shared a %s: %s", share.ResourceType, resourceName)
	shareURL := fmt.Sprintf("/share/%s", share.Token)

	for _, email := range emails {
		message := fmt.Sprintf(
			"You have been shared a %s titled '%s'.\n\n"+
				"Access the share: %s\n\n"+
				"Share details:\n"+
				"- Permission: %s\n"+
				"- Expires: %s\n\n"+
				"%s",
			share.ResourceType,
			resourceName,
			shareURL,
			share.Permission,
			func() string {
				if share.ExpiresAt != nil {
					return share.ExpiresAt.Format("2006-01-02 15:04:05")
				}
				return "Never"
			}(),
			share.CustomMessage,
		)

		// Send email (ignore errors as this shouldn't fail the share creation)
		if err := s.emailService.SendNotificationEmail(ctx, email, subject, message); err != nil {
			s.logAuditEvent(ctx, share.UserID, models.AuditActionShareAccess, "email", share.ID, false, fmt.Sprintf("Failed to send notification to %s: %v", email, err))
		}
	}
}

func (s *SharingService) sendAccessNotification(ctx context.Context, share *models.Share, ip, userAgent string) {
	// Get share owner
	shareOwner, err := s.userRepo.GetByID(ctx, share.UserID)
	if err != nil {
		return
	}

	resourceName := s.getResourceName(ctx, share.ResourceType, share.ResourceID)

	subject := "Share Access Notification"
	message := fmt.Sprintf(
		"Your shared %s '%s' was accessed.\n\n"+
			"Access Details:\n"+
			"- Time: %s\n"+
			"- IP Address: %s\n"+
			"- User Agent: %s\n\n"+
			"If this was not expected, you can revoke the share link in your dashboard.",
		share.ResourceType,
		resourceName,
		time.Now().Format("2006-01-02 15:04:05"),
		ip,
		userAgent,
	)

	// Send notification email (ignore errors)
	s.emailService.SendNotificationEmail(ctx, shareOwner.Email, subject, message)
}
