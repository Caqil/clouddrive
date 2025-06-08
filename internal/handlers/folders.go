package handlers

import (
	"net/http"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// FolderHandler handles folder management operations
type FolderHandler struct {
	folderService *services.FolderService
	fileService   *services.FileService
}

// NewFolderHandler creates a new folder handler
func NewFolderHandler(
	folderService *services.FolderService,
	fileService *services.FileService,
) *FolderHandler {
	return &FolderHandler{
		folderService: folderService,
		fileService:   fileService,
	}
}

// ============================================================================
// REQUEST/RESPONSE STRUCTURES
// ============================================================================

// CreateFolderRequest represents folder creation request
type CreateFolderRequest struct {
	Name        string   `json:"name" binding:"required,min=1,max=255"`
	ParentID    *string  `json:"parentId,omitempty"`
	IsPublic    bool     `json:"isPublic"`
	Color       string   `json:"color"`
	Description string   `json:"description" binding:"max=500"`
	Tags        []string `json:"tags"`
}

// UpdateFolderRequest represents folder update request
type UpdateFolderRequest struct {
	Name        *string   `json:"name,omitempty" binding:"omitempty,min=1,max=255"`
	Color       *string   `json:"color,omitempty"`
	Description *string   `json:"description,omitempty" binding:"omitempty,max=500"`
	Tags        *[]string `json:"tags,omitempty"`
	IsPublic    *bool     `json:"isPublic,omitempty"`
}

// MoveFolderRequest represents folder move request
type MoveFolderRequest struct {
	ParentID *string `json:"parentId"` // null for root
}

// RenameRequest represents folder rename request
type RenameRequest struct {
	Name string `json:"name" binding:"required,min=1,max=255"`
}

// CopyFolderRequest represents folder copy request
type CopyFolderRequest struct {
	ParentID *string `json:"parentId,omitempty"`
	Name     string  `json:"name,omitempty"`
}

// BulkFolderRequest represents bulk folder operations
type BulkFolderRequest struct {
	FolderIDs []string `json:"folderIds" binding:"required,min=1"`
	Action    string   `json:"action" binding:"required"`
	ParentID  *string  `json:"parentId,omitempty"`
}

// ============================================================================
// CORE FOLDER OPERATIONS
// ============================================================================

// CreateFolder creates a new folder
func (h *FolderHandler) CreateFolder(c *gin.Context) {
	var req CreateFolderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Parse parent ID if provided
	var parentID *primitive.ObjectID
	if req.ParentID != nil && *req.ParentID != "" {
		id, err := primitive.ObjectIDFromHex(*req.ParentID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid parent folder ID")
			return
		}
		parentID = &id
	}

	// Create service request - matching exact service struct
	createReq := &services.CreateFolderRequest{
		Name:        req.Name,
		ParentID:    parentID,
		IsPublic:    req.IsPublic,
		Color:       req.Color,
		Description: req.Description,
		Tags:        req.Tags,
	}

	// Create folder using service
	folder, err := h.folderService.CreateFolder(c.Request.Context(), userObjID, createReq)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to create folder")
		return
	}

	pkg.CreatedResponse(c, "Folder created successfully", folder)
}

// GetFolder retrieves folder details by ID
func (h *FolderHandler) GetFolder(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get folder using service
	folder, err := h.folderService.GetFolder(c.Request.Context(), userObjID, folderID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve folder")
		return
	}

	// Check for additional data requests
	includeStats := c.Query("includeStats") == "true"
	response := map[string]interface{}{
		"folder": folder,
	}

	if includeStats {
		stats, err := h.folderService.GetFolderStatistics(c.Request.Context(), userObjID, folderID)
		if err == nil {
			response["stats"] = stats
		}
	}

	pkg.SuccessResponse(c, http.StatusOK, "Folder retrieved successfully", response)
}

// ListFolders lists user's folders with pagination and filters
func (h *FolderHandler) ListFolders(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get pagination parameters
	params := pkg.NewPaginationParams(c)

	// Handle special cases
	parentIDStr := c.Query("parentId")
	isFavorite := c.Query("favorite") == "true"
	isRoot := c.Query("root") == "true"

	var folders []*models.Folder
	var total int64
	var err error

	if isRoot {
		// Get root folders
		folders, total, err = h.folderService.GetRootFolders(c.Request.Context(), userObjID, params)
	} else if isFavorite {
		// Get favorite folders
		folders, total, err = h.folderService.GetFavoriteFolders(c.Request.Context(), userObjID, params)
	} else if parentIDStr != "" {
		// Filter by parent - add to params filter
		parentID, parseErr := primitive.ObjectIDFromHex(parentIDStr)
		if parseErr != nil {
			pkg.BadRequestResponse(c, "Invalid parent folder ID")
			return
		}

		// Add parent filter to params
		if params.Filter == nil {
			params.Filter = make(map[string]interface{})
		}
		params.Filter["parent_id"] = parentID

		folders, total, err = h.folderService.ListFolders(c.Request.Context(), userObjID, params)
	} else {
		// List all folders
		folders, total, err = h.folderService.ListFolders(c.Request.Context(), userObjID, params)
	}

	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to list folders")
		return
	}

	result := pkg.NewPaginationResult(folders, total, params)
	pkg.PaginatedResponse(c, "Folders retrieved successfully", result)
}

// GetFolderContents retrieves folder contents (files and subfolders)
func (h *FolderHandler) GetFolderContents(c *gin.Context) {
	folderIDStr := c.Param("id")

	// Handle root folder case
	if folderIDStr == "root" {
		h.GetRootContents(c)
		return
	}

	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get pagination parameters
	params := pkg.NewPaginationParams(c)

	// Get folder contents using service
	contents, err := h.folderService.GetFolderContents(c.Request.Context(), userObjID, folderID, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve folder contents")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Folder contents retrieved successfully", contents)
}

// GetRootContents gets root folder contents
func (h *FolderHandler) GetRootContents(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)
	params := pkg.NewPaginationParams(c)

	// Get root folders
	folders, folderTotal, err := h.folderService.GetRootFolders(c.Request.Context(), userObjID, params)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to retrieve root folders")
		return
	}

	// Get root files (files with no folder_id)
	fileParams := pkg.NewPaginationParams(c)
	if fileParams.Filter == nil {
		fileParams.Filter = make(map[string]interface{})
	}
	fileParams.Filter["folder_id"] = nil

	files, fileTotal, err := h.fileService.ListFiles(c.Request.Context(), userObjID, fileParams)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to retrieve root files")
		return
	}

	contents := map[string]interface{}{
		"folder":       nil,
		"subfolders":   folders,
		"files":        files,
		"totalFiles":   fileTotal,
		"totalFolders": folderTotal,
		"path":         "/",
	}

	pkg.SuccessResponse(c, http.StatusOK, "Root contents retrieved successfully", contents)
}

// UpdateFolder updates folder information
func (h *FolderHandler) UpdateFolder(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	var req UpdateFolderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Build updates map for service
	updates := make(map[string]interface{})

	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Color != nil {
		updates["color"] = *req.Color
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Tags != nil {
		updates["tags"] = *req.Tags
	}
	if req.IsPublic != nil {
		updates["is_public"] = *req.IsPublic
	}

	// Update folder using service
	folder, err := h.folderService.UpdateFolder(c.Request.Context(), userObjID, folderID, updates)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to update folder")
		return
	}

	pkg.UpdatedResponse(c, "Folder updated successfully", folder)
}

// RenameFolder renames a folder
func (h *FolderHandler) RenameFolder(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	var req RenameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Rename folder using service
	folder, err := h.folderService.RenameFolder(c.Request.Context(), userObjID, folderID, req.Name)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to rename folder")
		return
	}

	pkg.UpdatedResponse(c, "Folder renamed successfully", folder)
}

// MoveFolder moves a folder to a new parent
func (h *FolderHandler) MoveFolder(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	var req MoveFolderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Parse new parent ID
	var newParentID *primitive.ObjectID
	if req.ParentID != nil && *req.ParentID != "" {
		id, err := primitive.ObjectIDFromHex(*req.ParentID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid parent folder ID")
			return
		}
		newParentID = &id
	}

	// Move folder using service
	folder, err := h.folderService.MoveFolder(c.Request.Context(), userObjID, folderID, newParentID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to move folder")
		return
	}

	pkg.UpdatedResponse(c, "Folder moved successfully", folder)
}

// CopyFolder creates a copy of a folder
func (h *FolderHandler) CopyFolder(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	var req CopyFolderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Parse destination parent ID
	var parentID *primitive.ObjectID
	if req.ParentID != nil && *req.ParentID != "" {
		id, err := primitive.ObjectIDFromHex(*req.ParentID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid parent folder ID")
			return
		}
		parentID = &id
	}

	// Copy folder using service
	newFolder, err := h.folderService.CopyFolder(c.Request.Context(), userObjID, folderID, parentID, req.Name)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to copy folder")
		return
	}

	pkg.CreatedResponse(c, "Folder copied successfully", newFolder)
}

// DeleteFolder deletes a folder
func (h *FolderHandler) DeleteFolder(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Check for force delete
	force := c.Query("force") == "true"

	if force {
		// Force delete using service
		err = h.folderService.ForceDeleteFolder(c.Request.Context(), userObjID, folderID)
	} else {
		// Regular soft delete using service
		err = h.folderService.DeleteFolder(c.Request.Context(), userObjID, folderID)
	}

	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to delete folder")
		return
	}

	pkg.DeletedResponse(c, "Folder deleted successfully")
}

// RestoreFolder restores a deleted folder
func (h *FolderHandler) RestoreFolder(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Restore folder using service
	folder, err := h.folderService.RestoreFolder(c.Request.Context(), userObjID, folderID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to restore folder")
		return
	}

	pkg.UpdatedResponse(c, "Folder restored successfully", folder)
}

// ============================================================================
// FOLDER ORGANIZATION & FEATURES
// ============================================================================

// ToggleFavorite toggles folder favorite status
func (h *FolderHandler) ToggleFavorite(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Toggle favorite using service
	folder, err := h.folderService.ToggleFavorite(c.Request.Context(), userObjID, folderID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to toggle favorite")
		return
	}

	message := "Added to favorites"
	if !folder.IsFavorite {
		message = "Removed from favorites"
	}

	pkg.UpdatedResponse(c, message, folder)
}

// SearchFolders searches user's folders
func (h *FolderHandler) SearchFolders(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		pkg.BadRequestResponse(c, "Search query is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get pagination parameters and set search
	params := pkg.NewPaginationParams(c)
	params.Search = query

	// Apply additional filters
	if tags := c.QueryArray("tags"); len(tags) > 0 {
		if params.Filter == nil {
			params.Filter = make(map[string]interface{})
		}
		params.Filter["tags"] = map[string]interface{}{"$in": tags}
	}

	if color := c.Query("color"); color != "" {
		if params.Filter == nil {
			params.Filter = make(map[string]interface{})
		}
		params.Filter["color"] = color
	}

	// Search folders using service
	folders, total, err := h.folderService.ListFolders(c.Request.Context(), userObjID, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Search failed")
		return
	}

	result := pkg.NewPaginationResult(folders, total, params)
	pkg.PaginatedResponse(c, "Search completed successfully", result)
}

// GetFolderTree retrieves complete folder tree structure
func (h *FolderHandler) GetFolderTree(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get folder tree using service
	tree, err := h.folderService.GetFolderTree(c.Request.Context(), userObjID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve folder tree")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Folder tree retrieved successfully", tree)
}

// GetFolderStatistics retrieves folder statistics
func (h *FolderHandler) GetFolderStatistics(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get statistics using service
	stats, err := h.folderService.GetFolderStatistics(c.Request.Context(), userObjID, folderID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve statistics")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Statistics retrieved successfully", stats)
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

// BulkOperations performs bulk operations on folders
func (h *FolderHandler) BulkOperations(c *gin.Context) {
	var req BulkFolderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Convert string IDs to ObjectIDs
	folderIDs := make([]primitive.ObjectID, len(req.FolderIDs))
	for i, idStr := range req.FolderIDs {
		id, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid folder ID: "+idStr)
			return
		}
		folderIDs[i] = id
	}

	var result *services.BulkOperationResult
	var err error

	switch req.Action {
	case "delete":
		result, err = h.folderService.BulkDeleteFolders(c.Request.Context(), userObjID, folderIDs)
	case "move":
		if req.ParentID == nil {
			pkg.BadRequestResponse(c, "Parent ID required for move operation")
			return
		}
		parentID, parseErr := primitive.ObjectIDFromHex(*req.ParentID)
		if parseErr != nil {
			pkg.BadRequestResponse(c, "Invalid parent folder ID")
			return
		}
		result, err = h.folderService.BulkMoveFolders(c.Request.Context(), userObjID, folderIDs, parentID)
	default:
		pkg.BadRequestResponse(c, "Invalid bulk action: "+req.Action)
		return
	}

	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Bulk operation failed")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Bulk operation completed successfully", result)
}

// ============================================================================
// TRASH/RECYCLE BIN OPERATIONS
// ============================================================================

// GetDeletedFolders retrieves user's deleted folders
func (h *FolderHandler) GetDeletedFolders(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)
	params := pkg.NewPaginationParams(c)

	// Get deleted folders using service
	folders, total, err := h.folderService.GetDeletedFolders(c.Request.Context(), userObjID, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve deleted folders")
		return
	}

	result := pkg.NewPaginationResult(folders, total, params)
	pkg.PaginatedResponse(c, "Deleted folders retrieved successfully", result)
}

// EmptyTrash permanently deletes all folders in trash
func (h *FolderHandler) EmptyTrash(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Empty trash using service
	count, err := h.folderService.EmptyTrash(c.Request.Context(), userObjID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to empty trash")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Trash emptied successfully", map[string]interface{}{
		"deletedCount": count,
	})
}

// ============================================================================
// UTILITY METHODS
// ============================================================================

// CreateRootFolder creates root folder for user
func (h *FolderHandler) CreateRootFolder(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Create root folder using service
	folder, err := h.folderService.CreateRootFolder(c.Request.Context(), userObjID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to create root folder")
		return
	}

	pkg.CreatedResponse(c, "Root folder created successfully", folder)
}

// GetFolderTemplates retrieves available folder templates
func (h *FolderHandler) GetFolderTemplates(c *gin.Context) {
	templates := map[string]interface{}{
		"project": map[string]interface{}{
			"name":        "Project Folder",
			"description": "Organized structure for project management",
			"subfolders":  []string{"Documents", "Images", "Resources", "Archive"},
			"color":       "#4CAF50",
			"tags":        []string{"project", "work"},
		},
		"photography": map[string]interface{}{
			"name":        "Photography Workflow",
			"description": "Professional photography organization",
			"subfolders":  []string{"RAW", "Edited", "Published", "Archive"},
			"color":       "#FF9800",
			"tags":        []string{"photography", "media"},
		},
		"documents": map[string]interface{}{
			"name":        "Document Organization",
			"description": "General document filing system",
			"subfolders":  []string{"Personal", "Work", "Legal", "Financial"},
			"color":       "#2196F3",
			"tags":        []string{"documents", "files"},
		},
		"media": map[string]interface{}{
			"name":        "Media Collection",
			"description": "Multimedia content organization",
			"subfolders":  []string{"Videos", "Audio", "Images", "Graphics"},
			"color":       "#9C27B0",
			"tags":        []string{"media", "content"},
		},
	}

	pkg.SuccessResponse(c, http.StatusOK, "Folder templates retrieved successfully", templates)
}
