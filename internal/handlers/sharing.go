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
	sharingService   *services.SharingService
	fileService      *services.FileService
	folderService    *services.FolderService
	userService      *services.UserService
	analyticsService *services.AnalyticsService
	auditService     *services.AuditService
}

// NewSharingHandler creates a new sharing handler
func NewSharingHandler(
	sharingService *services.SharingService,
	fileService *services.FileService,
	folderService *services.FolderService,
	userService *services.UserService,
	analyticsService *services.AnalyticsService,
	auditService *services.AuditService,
) *SharingHandler {
	return &SharingHandler{
		sharingService:   sharingService,
		fileService:      fileService,
		folderService:    folderService,
		userService:      userService,
		analyticsService: analyticsService,
		auditService:     auditService,
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
		ResourceType  models.ShareResourceType `json:"resourceType" binding:"required"`
		ResourceID    string                   `json:"resourceId" binding:"required"`
		ShareType     models.ShareType         `json:"shareType" binding:"required"`
		Permission    models.SharePermission   `json:"permission" binding:"required"`
		Password      string                   `json:"password"`
		ExpiresAt     *time.Time               `json:"expiresAt"`
		MaxDownloads  *int                     `json:"maxDownloads"`
		AllowComments bool                     `json:"allowComments"`
		RequireSignup bool                     `json:"requireSignup"`
		SharedWith    []string                 `json:"sharedWith"` // email addresses
		Message       string                   `json:"message"`
		NotifyByEmail bool                     `json:"notifyByEmail"`
	}

	var req CreateShareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	resourceID, err := primitive.ObjectIDFromHex(req.ResourceID)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid resource ID")
		return
	}

	// Verify user owns the resource
	if req.ResourceType == models.ShareResourceTypeFile {
		file, err := h.fileService.GetFile(c.Request.Context(), userObjID, resourceID)
		if err != nil {
			if appErr, ok := pkg.IsAppError(err); ok {
				pkg.ErrorResponseFromAppError(c, appErr)
				return
			}
			pkg.NotFoundResponse(c, "File not found")
			return
		}
		if file.UserID != userObjID {
			pkg.ForbiddenResponse(c, "Access denied")
			return
		}
	} else if req.ResourceType == models.ShareResourceTypeFolder {
		folder, err := h.folderService.GetFolder(c.Request.Context(), userObjID, resourceID)
		if err != nil {
			if appErr, ok := pkg.IsAppError(err); ok {
				pkg.ErrorResponseFromAppError(c, appErr)
				return
			}
			pkg.NotFoundResponse(c, "Folder not found")
			return
		}
		if folder.UserID != userObjID {
			pkg.ForbiddenResponse(c, "Access denied")
			return
		}
	}

	createReq := &services.CreateShareRequest{
		UserID:        userObjID,
		ResourceType:  req.ResourceType,
		ResourceID:    resourceID,
		ShareType:     req.ShareType,
		Permission:    req.Permission,
		Password:      req.Password,
		ExpiresAt:     req.ExpiresAt,
		MaxDownloads:  req.MaxDownloads,
		AllowComments: req.AllowComments,
		RequireSignup: req.RequireSignup,
		SharedWith:    req.SharedWith,
		Message:       req.Message,
		NotifyByEmail: req.NotifyByEmail,
		ClientIP:      c.ClientIP(),
		UserAgent:     c.GetHeader("User-Agent"),
	}

	share, err := h.sharingService.CreateShare(c.Request.Context(), createReq)
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

	share, err := h.sharingService.GetShare(c.Request.Context(), userObjID, shareID)
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

// GetShareByToken retrieves share details by token (public access)
func (h *SharingHandler) GetShareByToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		pkg.BadRequestResponse(c, "Share token is required")
		return
	}

	password := c.Query("password")
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	share, err := h.sharingService.GetShareByToken(c.Request.Context(), token, password, clientIP, userAgent)
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

// ListShares lists user's shares with pagination and filters
func (h *SharingHandler) ListShares(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)
	params := pkg.NewPaginationParams(c)

	// Add filters
	if resourceType := c.Query("resourceType"); resourceType != "" {
		params.Filter["resource_type"] = resourceType
	}
	if shareType := c.Query("shareType"); shareType != "" {
		params.Filter["share_type"] = shareType
	}
	if status := c.Query("status"); status != "" {
		params.Filter["status"] = status
	}

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

// GetSharedWithMe lists shares that have been shared with the current user
func (h *SharingHandler) GetSharedWithMe(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)
	params := pkg.NewPaginationParams(c)

	// Get user email for filtering
	user, err := h.userService.GetUser(c.Request.Context(), userObjID)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to get user information")
		return
	}

	shares, total, err := h.sharingService.GetSharedWithUser(c.Request.Context(), user.Email, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get shared items")
		return
	}

	result := pkg.NewPaginationResult(shares, total, params)
	pkg.PaginatedResponse(c, "Shared items retrieved successfully", result)
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
		Permission    *models.SharePermission `json:"permission"`
		Password      *string                 `json:"password"`
		ExpiresAt     *time.Time              `json:"expiresAt"`
		MaxDownloads  *int                    `json:"maxDownloads"`
		AllowComments *bool                   `json:"allowComments"`
		RequireSignup *bool                   `json:"requireSignup"`
		Status        *models.ShareStatus     `json:"status"`
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
	if req.AllowComments != nil {
		updates["allow_comments"] = *req.AllowComments
	}
	if req.RequireSignup != nil {
		updates["require_signup"] = *req.RequireSignup
	}
	if req.Status != nil {
		updates["status"] = *req.Status
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
		Message       string   `json:"message"`
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

// BulkCreateShares creates multiple shares at once
func (h *SharingHandler) BulkCreateShares(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	type BulkShareRequest struct {
		ResourceIDs   []string                 `json:"resourceIds" binding:"required,min=1"`
		ResourceType  models.ShareResourceType `json:"resourceType" binding:"required"`
		ShareType     models.ShareType         `json:"shareType" binding:"required"`
		Permission    models.SharePermission   `json:"permission" binding:"required"`
		Password      string                   `json:"password"`
		ExpiresAt     *time.Time               `json:"expiresAt"`
		MaxDownloads  *int                     `json:"maxDownloads"`
		AllowComments bool                     `json:"allowComments"`
		RequireSignup bool                     `json:"requireSignup"`
		SharedWith    []string                 `json:"sharedWith"`
		Message       string                   `json:"message"`
		NotifyByEmail bool                     `json:"notifyByEmail"`
	}

	var req BulkShareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.ValidationErrorResponse(c, pkg.ValidationErrors{
			{Field: "validation", Message: err.Error()},
		})
		return
	}

	var successful []interface{}
	var failed []map[string]interface{}

	for _, idStr := range req.ResourceIDs {
		resourceID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"resourceId": idStr,
				"error":      "Invalid resource ID",
			})
			continue
		}

		createReq := &services.CreateShareRequest{
			UserID:        userObjID,
			ResourceType:  req.ResourceType,
			ResourceID:    resourceID,
			ShareType:     req.ShareType,
			Permission:    req.Permission,
			Password:      req.Password,
			ExpiresAt:     req.ExpiresAt,
			MaxDownloads:  req.MaxDownloads,
			AllowComments: req.AllowComments,
			RequireSignup: req.RequireSignup,
			SharedWith:    req.SharedWith,
			Message:       req.Message,
			NotifyByEmail: req.NotifyByEmail,
			ClientIP:      c.ClientIP(),
			UserAgent:     c.GetHeader("User-Agent"),
		}

		share, err := h.sharingService.CreateShare(c.Request.Context(), createReq)
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"resourceId": idStr,
				"error":      err.Error(),
			})
		} else {
			successful = append(successful, share)
		}
	}

	pkg.SuccessResponse(c, http.StatusOK, "Bulk share creation completed", map[string]interface{}{
		"successful": successful,
		"failed":     failed,
		"total":      len(req.ResourceIDs),
	})
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

// CopyShareLink regenerates and returns a new share link
func (h *SharingHandler) CopyShareLink(c *gin.Context) {
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
