package handlers

import (
	"net/http"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// SharingHandler handles file and folder sharing operations
type SharingHandler struct {
	sharingService *services.SharingService
}

// NewSharingHandler creates a new sharing handler
func NewSharingHandler(sharingService *services.SharingService) *SharingHandler {
	return &SharingHandler{
		sharingService: sharingService,
	}
}

// CreateShare creates a new share link
func (h *SharingHandler) CreateShare(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type CreateShareRequest struct {
		ResourceType   models.ShareResourceType `json:"resourceType" binding:"required"`
		ResourceID     string                   `json:"resourceId" binding:"required"`
		ShareType      models.ShareType         `json:"shareType" binding:"required"`
		Permission     models.SharePermission   `json:"permission" binding:"required"`
		Password       string                   `json:"password,omitempty"`
		ExpiresAt      *time.Time               `json:"expiresAt,omitempty"`
		MaxDownloads   int                      `json:"maxDownloads,omitempty"`
		AllowedIPs     []string                 `json:"allowedIPs,omitempty"`
		AllowedDomains []string                 `json:"allowedDomains,omitempty"`
		NotifyOnAccess bool                     `json:"notifyOnAccess"`
		CustomMessage  string                   `json:"customMessage,omitempty"`
		Recipients     []string                 `json:"recipients,omitempty"`
	}

	var req CreateShareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	// Convert string resource ID to ObjectID
	resourceID, err := primitive.ObjectIDFromHex(req.ResourceID)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid resource ID")
		return
	}

	// Create service request
	createReq := &services.CreateShareRequest{
		ResourceType:   req.ResourceType,
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

	share, err := h.sharingService.CreateShare(c.Request.Context(), userObjID, createReq)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to create share")
		return
	}

	pkg.CreatedResponse(c, "Share created successfully", share)
}

// GetShare retrieves share details by ID
func (h *SharingHandler) GetShare(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	share, err := h.sharingService.GetUserShare(c.Request.Context(), userObjID, shareID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get share")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Share retrieved successfully", share)
}

// GetShareByToken retrieves share details by token (public access)
func (h *SharingHandler) GetShareByToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		pkg.BadRequestResponse(c, "Share token is required")
		return
	}

	share, err := h.sharingService.GetShare(c.Request.Context(), token)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.NotFoundResponse(c, "Share not found")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Share retrieved successfully", share)
}

// AccessShare accesses a shared resource with validation
func (h *SharingHandler) AccessShare(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		pkg.BadRequestResponse(c, "Share token is required")
		return
	}

	password := c.Query("password")
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	share, err := h.sharingService.AccessShare(c.Request.Context(), token, password, clientIP, userAgent)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.UnauthorizedResponse(c, "Access denied")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Share accessed successfully", share)
}

// DownloadSharedResource downloads the shared resource
func (h *SharingHandler) DownloadSharedResource(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		pkg.BadRequestResponse(c, "Share token is required")
		return
	}

	password := c.Query("password")
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	downloadURL, err := h.sharingService.DownloadShare(c.Request.Context(), token, password, clientIP, userAgent)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to generate download")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Download URL generated successfully", map[string]interface{}{
		"downloadUrl": downloadURL,
	})
}

// ListUserShares lists all shares created by the user
func (h *SharingHandler) ListUserShares(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)
	params := pkg.NewPaginationParams(c)

	shares, total, err := h.sharingService.ListUserShares(c.Request.Context(), userObjID, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to list shares")
		return
	}

	result := pkg.NewPaginationResult(shares, total, params)
	pkg.PaginatedResponse(c, "Shares retrieved successfully", result)
}

// UpdateShare updates share settings
func (h *SharingHandler) UpdateShare(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type UpdateShareRequest struct {
		Permission     *models.SharePermission `json:"permission,omitempty"`
		Password       *string                 `json:"password,omitempty"`
		ExpiresAt      *time.Time              `json:"expiresAt,omitempty"`
		MaxDownloads   *int                    `json:"maxDownloads,omitempty"`
		AllowedIPs     []string                `json:"allowedIPs,omitempty"`
		AllowedDomains []string                `json:"allowedDomains,omitempty"`
		NotifyOnAccess *bool                   `json:"notifyOnAccess,omitempty"`
		CustomMessage  *string                 `json:"customMessage,omitempty"`
		IsActive       *bool                   `json:"isActive,omitempty"`
	}

	var req UpdateShareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	updates := make(map[string]interface{})
	if req.Permission != nil {
		updates["permission"] = *req.Permission
	}
	if req.Password != nil {
		updates["password"] = *req.Password
	}
	if req.ExpiresAt != nil {
		updates["expires_at"] = *req.ExpiresAt
	}
	if req.MaxDownloads != nil {
		updates["max_downloads"] = *req.MaxDownloads
	}
	if req.AllowedIPs != nil {
		updates["allowed_ips"] = req.AllowedIPs
	}
	if req.AllowedDomains != nil {
		updates["allowed_domains"] = req.AllowedDomains
	}
	if req.NotifyOnAccess != nil {
		updates["notify_on_access"] = *req.NotifyOnAccess
	}
	if req.CustomMessage != nil {
		updates["custom_message"] = *req.CustomMessage
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}

	share, err := h.sharingService.UpdateShare(c.Request.Context(), userObjID, shareID, updates)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to update share")
		return
	}

	pkg.UpdatedResponse(c, "Share updated successfully", share)
}

// DeleteShare deletes a share
func (h *SharingHandler) DeleteShare(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	if err := h.sharingService.DeleteShare(c.Request.Context(), userObjID, shareID); err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to delete share")
		return
	}

	pkg.DeletedResponse(c, "Share deleted successfully")
}

// RevokeAllShares revokes all shares for a resource
func (h *SharingHandler) RevokeAllShares(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type RevokeAllRequest struct {
		ResourceType models.ShareResourceType `json:"resourceType" binding:"required"`
		ResourceID   string                   `json:"resourceId" binding:"required"`
	}

	var req RevokeAllRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	resourceID, err := primitive.ObjectIDFromHex(req.ResourceID)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid resource ID")
		return
	}

	count, err := h.sharingService.RevokeAllShares(c.Request.Context(), userObjID, req.ResourceType, resourceID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to revoke shares")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "All shares revoked successfully", map[string]interface{}{
		"revokedCount": count,
	})
}

// GetSharingOverview gets overview of user's sharing activity
func (h *SharingHandler) GetSharingOverview(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	overview, err := h.sharingService.GetSharingOverview(c.Request.Context(), userObjID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get sharing overview")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Sharing overview retrieved successfully", overview)
}

// GetShareLink gets or regenerates a share link
func (h *SharingHandler) GetShareLink(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)
	regenerate := c.Query("regenerate") == "true"

	shareLink, err := h.sharingService.GetShareLink(c.Request.Context(), userObjID, shareID, regenerate)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get share link")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Share link retrieved successfully", map[string]interface{}{
		"shareLink": shareLink,
		"shareId":   shareID.Hex(),
	})
}

// ValidateShareAccess validates access to a shared resource
func (h *SharingHandler) ValidateShareAccess(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		pkg.BadRequestResponse(c, "Share token is required")
		return
	}

	password := c.Query("password")
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	access, err := h.sharingService.ValidateAccess(c.Request.Context(), token, password, clientIP, userAgent)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.UnauthorizedResponse(c, "Access denied")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Access validated successfully", access)
}

// GetShareStatistics retrieves share statistics
func (h *SharingHandler) GetShareStatistics(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	stats, err := h.sharingService.GetShareStatistics(c.Request.Context(), userObjID, shareID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get share statistics")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Share statistics retrieved successfully", stats)
}

// GetShareAccessLogs retrieves share access logs
func (h *SharingHandler) GetShareAccessLogs(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)
	params := pkg.NewPaginationParams(c)

	logs, total, err := h.sharingService.GetShareAccessLogs(c.Request.Context(), userObjID, shareID, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get access logs")
		return
	}

	result := pkg.NewPaginationResult(logs, total, params)
	pkg.PaginatedResponse(c, "Access logs retrieved successfully", result)
}

// BulkCreateShares creates multiple shares at once
func (h *SharingHandler) BulkCreateShares(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type BulkShareRequest struct {
		Resources []struct {
			ResourceType models.ShareResourceType `json:"resourceType" binding:"required"`
			ResourceID   string                   `json:"resourceId" binding:"required"`
		} `json:"resources" binding:"required,min=1"`
		ShareType      models.ShareType       `json:"shareType" binding:"required"`
		Permission     models.SharePermission `json:"permission" binding:"required"`
		Password       string                 `json:"password,omitempty"`
		ExpiresAt      *time.Time             `json:"expiresAt,omitempty"`
		MaxDownloads   int                    `json:"maxDownloads,omitempty"`
		AllowedIPs     []string               `json:"allowedIPs,omitempty"`
		AllowedDomains []string               `json:"allowedDomains,omitempty"`
		NotifyOnAccess bool                   `json:"notifyOnAccess"`
		CustomMessage  string                 `json:"customMessage,omitempty"`
		Recipients     []string               `json:"recipients,omitempty"`
	}

	var req BulkShareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	// Convert resource IDs
	var resourceIDs []primitive.ObjectID
	var resourceTypes []models.ShareResourceType
	for _, resource := range req.Resources {
		resourceID, err := primitive.ObjectIDFromHex(resource.ResourceID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid resource ID: "+resource.ResourceID)
			return
		}
		resourceIDs = append(resourceIDs, resourceID)
		resourceTypes = append(resourceTypes, resource.ResourceType)
	}

	bulkReq := &services.BulkCreateShareRequest{
		ResourceTypes:  resourceTypes,
		ResourceIDs:    resourceIDs,
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

	result, err := h.sharingService.BulkCreateShares(c.Request.Context(), userObjID, bulkReq)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to create bulk shares")
		return
	}

	pkg.CreatedResponse(c, "Bulk shares created successfully", result)
}

// AddComment adds a comment to a shared resource
func (h *SharingHandler) AddComment(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		pkg.BadRequestResponse(c, "Share token is required")
		return
	}

	type AddCommentRequest struct {
		Content string `json:"content" binding:"required,min=1,max=1000"`
		Author  string `json:"author" binding:"required,min=1,max=100"`
		Email   string `json:"email" binding:"required,email"`
	}

	var req AddCommentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	comment, err := h.sharingService.AddComment(c.Request.Context(), token, req.Content, req.Author, req.Email, clientIP, userAgent)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to add comment")
		return
	}

	pkg.CreatedResponse(c, "Comment added successfully", comment)
}

// GetComments retrieves comments for a shared resource
func (h *SharingHandler) GetComments(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		pkg.BadRequestResponse(c, "Share token is required")
		return
	}

	params := pkg.NewPaginationParams(c)

	comments, total, err := h.sharingService.GetComments(c.Request.Context(), token, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get comments")
		return
	}

	result := pkg.NewPaginationResult(comments, total, params)
	pkg.PaginatedResponse(c, "Comments retrieved successfully", result)
}

// AddShareRecipients adds recipients to an existing share
func (h *SharingHandler) AddShareRecipients(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type AddRecipientsRequest struct {
		Recipients    []string `json:"recipients" binding:"required,min=1"`
		Message       string   `json:"message,omitempty"`
		NotifyByEmail bool     `json:"notifyByEmail"`
	}

	var req AddRecipientsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	share, err := h.sharingService.AddRecipients(c.Request.Context(), userObjID, shareID, req.Recipients, req.Message, req.NotifyByEmail)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to add recipients")
		return
	}

	pkg.UpdatedResponse(c, "Recipients added successfully", share)
}

// RemoveShareRecipients removes recipients from a share
func (h *SharingHandler) RemoveShareRecipients(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type RemoveRecipientsRequest struct {
		Recipients []string `json:"recipients" binding:"required,min=1"`
	}

	var req RemoveRecipientsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	share, err := h.sharingService.RemoveRecipients(c.Request.Context(), userObjID, shareID, req.Recipients)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to remove recipients")
		return
	}

	pkg.UpdatedResponse(c, "Recipients removed successfully", share)
}

// EnableShareNotifications enables notifications for a share
func (h *SharingHandler) EnableShareNotifications(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	updates := map[string]interface{}{
		"notify_on_access": true,
	}

	share, err := h.sharingService.UpdateShare(c.Request.Context(), userObjID, shareID, updates)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to enable notifications")
		return
	}

	pkg.UpdatedResponse(c, "Notifications enabled successfully", share)
}

// DisableShareNotifications disables notifications for a share
func (h *SharingHandler) DisableShareNotifications(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	updates := map[string]interface{}{
		"notify_on_access": false,
	}

	share, err := h.sharingService.UpdateShare(c.Request.Context(), userObjID, shareID, updates)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to disable notifications")
		return
	}

	pkg.UpdatedResponse(c, "Notifications disabled successfully", share)
}

// GetExpiredShares retrieves expired shares for the user
func (h *SharingHandler) GetExpiredShares(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)
	params := pkg.NewPaginationParams(c)

	// Add filter for expired shares
	if params.Filter == nil {
		params.Filter = make(map[string]interface{})
	}
	params.Filter["expired"] = "true"

	shares, total, err := h.sharingService.ListUserShares(c.Request.Context(), userObjID, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to list expired shares")
		return
	}

	result := pkg.NewPaginationResult(shares, total, params)
	pkg.PaginatedResponse(c, "Expired shares retrieved successfully", result)
}

// ExtendShareExpiry extends the expiration date of a share
func (h *SharingHandler) ExtendShareExpiry(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type ExtendExpiryRequest struct {
		ExpiresAt *time.Time `json:"expiresAt" binding:"required"`
		Days      *int       `json:"days,omitempty"`
		Hours     *int       `json:"hours,omitempty"`
	}

	var req ExtendExpiryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	var expiresAt time.Time
	if req.ExpiresAt != nil {
		expiresAt = *req.ExpiresAt
	} else {
		// Calculate new expiry based on days/hours
		now := time.Now()
		if req.Days != nil {
			now = now.AddDate(0, 0, *req.Days)
		}
		if req.Hours != nil {
			now = now.Add(time.Duration(*req.Hours) * time.Hour)
		}
		expiresAt = now
	}

	updates := map[string]interface{}{
		"expires_at": expiresAt,
	}

	share, err := h.sharingService.UpdateShare(c.Request.Context(), userObjID, shareID, updates)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to extend share expiry")
		return
	}

	pkg.UpdatedResponse(c, "Share expiry extended successfully", share)
}

// CloneShare creates a copy of an existing share with new settings
func (h *SharingHandler) CloneShare(c *gin.Context) {
	shareIDStr := c.Param("id")
	shareID, err := primitive.ObjectIDFromHex(shareIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid share ID")
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type CloneShareRequest struct {
		ShareType      *models.ShareType       `json:"shareType,omitempty"`
		Permission     *models.SharePermission `json:"permission,omitempty"`
		Password       *string                 `json:"password,omitempty"`
		ExpiresAt      *time.Time              `json:"expiresAt,omitempty"`
		MaxDownloads   *int                    `json:"maxDownloads,omitempty"`
		AllowedIPs     []string                `json:"allowedIPs,omitempty"`
		AllowedDomains []string                `json:"allowedDomains,omitempty"`
		NotifyOnAccess *bool                   `json:"notifyOnAccess,omitempty"`
		CustomMessage  *string                 `json:"customMessage,omitempty"`
	}

	var req CloneShareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	share, err := h.sharingService.CloneShare(c.Request.Context(), userObjID, shareID, req)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to clone share")
		return
	}

	pkg.CreatedResponse(c, "Share cloned successfully", share)
}
