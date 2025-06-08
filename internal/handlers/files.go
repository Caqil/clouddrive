package handlers

import (
	"net/http"

	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// FileHandler handles file management operations
type FileHandler struct {
	fileService   *services.FileService
	folderService *services.FolderService
}

// NewFileHandler creates a new file handler
func NewFileHandler(fileService *services.FileService, folderService *services.FolderService) *FileHandler {
	return &FileHandler{
		fileService:   fileService,
		folderService: folderService,
	}
}

// ListFiles lists user's files with pagination and filters
func (h *FileHandler) ListFiles(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get pagination parameters
	params := pkg.NewPaginationParams(c)

	// Get folder ID if specified
	if folderIDStr := c.Query("folderId"); folderIDStr != "" {
		folderID, err := primitive.ObjectIDFromHex(folderIDStr)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid folder ID")
			return
		}

		// List files in specific folder
		files, total, err := h.fileService.ListFilesByFolder(c.Request.Context(), userObjID, folderID, params)
		if err != nil {
			if appErr, ok := pkg.IsAppError(err); ok {
				pkg.ErrorResponseFromAppError(c, appErr)
				return
			}
			pkg.InternalServerErrorResponse(c, "Failed to list files")
			return
		}

		result := pkg.NewPaginationResult(files, total, params)
		pkg.PaginatedResponse(c, "Files retrieved successfully", result)
		return
	}

	// List all user files
	files, total, err := h.fileService.ListFiles(c.Request.Context(), userObjID, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to list files")
		return
	}

	result := pkg.NewPaginationResult(files, total, params)
	pkg.PaginatedResponse(c, "Files retrieved successfully", result)
}

// GetFile gets file details by ID
func (h *FileHandler) GetFile(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get file
	file, err := h.fileService.GetFile(c.Request.Context(), userObjID, fileID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.NotFoundResponse(c, "File not found")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "File retrieved successfully", file)
}

// UpdateFile updates file metadata
func (h *FileHandler) UpdateFile(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	type UpdateFileRequest struct {
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		IsPublic    *bool    `json:"isPublic"`
		IsFavorite  *bool    `json:"isFavorite"`
	}

	var req UpdateFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Prepare updates
	updates := make(map[string]interface{})
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Tags != nil {
		updates["tags"] = req.Tags
	}
	if req.IsPublic != nil {
		updates["is_public"] = *req.IsPublic
	}
	if req.IsFavorite != nil {
		updates["is_favorite"] = *req.IsFavorite
	}

	// Update file
	file, err := h.fileService.UpdateFile(c.Request.Context(), userObjID, fileID, updates)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to update file")
		return
	}

	pkg.UpdatedResponse(c, "File updated successfully", file)
}

// RenameFile renames a file
func (h *FileHandler) RenameFile(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	type RenameRequest struct {
		Name string `json:"name" binding:"required,min=1,max=255"`
	}

	var req RenameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Rename file
	file, err := h.fileService.RenameFile(c.Request.Context(), userObjID, fileID, req.Name)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to rename file")
		return
	}

	pkg.UpdatedResponse(c, "File renamed successfully", file)
}

// MoveFile moves file to different folder
func (h *FileHandler) MoveFile(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	type MoveRequest struct {
		FolderID *string `json:"folderId"` // nil for root folder
	}

	var req MoveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Parse target folder ID
	var targetFolderID *primitive.ObjectID
	if req.FolderID != nil {
		id, err := primitive.ObjectIDFromHex(*req.FolderID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid target folder ID")
			return
		}
		targetFolderID = &id
	}

	// Move file
	file, err := h.fileService.MoveFile(c.Request.Context(), userObjID, fileID, targetFolderID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to move file")
		return
	}

	pkg.UpdatedResponse(c, "File moved successfully", file)
}

// CopyFile copies a file
func (h *FileHandler) CopyFile(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	type CopyRequest struct {
		FolderID *string `json:"folderId"` // nil for root folder
		Name     string  `json:"name"`     // optional new name
	}

	var req CopyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Parse target folder ID if provided
	var targetFolderID *primitive.ObjectID
	if req.FolderID != nil && *req.FolderID != "" {
		id, err := primitive.ObjectIDFromHex(*req.FolderID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid target folder ID")
			return
		}
		targetFolderID = &id
	}

	// Copy the file using the file service
	copiedFile, err := h.fileService.CopyFile(c.Request.Context(), userObjID, fileID, targetFolderID, req.Name)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to copy file")
		return
	}

	pkg.CreatedResponse(c, "File copied successfully", copiedFile)
}

// DeleteFile deletes a file
func (h *FileHandler) DeleteFile(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Delete file
	if err := h.fileService.DeleteFile(c.Request.Context(), userObjID, fileID); err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to delete file")
		return
	}

	pkg.DeletedResponse(c, "File deleted successfully")
}

// ToggleFavorite toggles file favorite status
func (h *FileHandler) ToggleFavorite(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Toggle favorite
	file, err := h.fileService.ToggleFavorite(c.Request.Context(), userObjID, fileID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to toggle favorite")
		return
	}

	pkg.UpdatedResponse(c, "Favorite status updated", file)
}

// SearchFiles searches user's files
func (h *FileHandler) SearchFiles(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		pkg.BadRequestResponse(c, "Search query is required")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get pagination parameters
	params := pkg.NewPaginationParams(c)

	// Search files
	files, total, err := h.fileService.SearchFiles(c.Request.Context(), userObjID, query, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Search failed")
		return
	}

	result := pkg.NewPaginationResult(files, total, params)
	pkg.PaginatedResponse(c, "Search completed successfully", result)
}

// GetRecentFiles gets user's recent files
func (h *FileHandler) GetRecentFiles(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get limit from query parameter (default 20)
	limit := 20
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit := pkg.Conversions.StringToInt(limitStr, 20); parsedLimit > 0 && parsedLimit <= 100 {
			limit = parsedLimit
		}
	}

	// Get recent files
	files, err := h.fileService.GetRecentFiles(c.Request.Context(), userObjID, limit)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get recent files")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Recent files retrieved successfully", files)
}

// GetFavoriteFiles gets user's favorite files
func (h *FileHandler) GetFavoriteFiles(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get favorite files
	files, err := h.fileService.GetFavoriteFiles(c.Request.Context(), userObjID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to get favorite files")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Favorite files retrieved successfully", files)
}

// GetFileVersions gets file version history
func (h *FileHandler) GetFileVersions(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get file to check ownership
	file, err := h.fileService.GetFile(c.Request.Context(), userObjID, fileID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.NotFoundResponse(c, "File not found")
		return
	}

	// Return file versions
	pkg.SuccessResponse(c, http.StatusOK, "File versions retrieved successfully", file.Versions)
}

// RestoreFileVersion restores a file to a specific version
func (h *FileHandler) RestoreFileVersion(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	versionIDStr := c.Param("versionId")
	versionID, err := primitive.ObjectIDFromHex(versionIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid version ID")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// For now, return not implemented
	// In a real implementation, you would:
	// 1. Get the file and verify ownership
	// 2. Find the specified version
	// 3. Restore the file to that version
	// 4. Create a new version entry for the current state

	_ = userObjID
	_ = fileID
	_ = versionID

	pkg.InternalServerErrorResponse(c, "File version restore not yet implemented")
}

// GetFileMetadata gets detailed file metadata
func (h *FileHandler) GetFileMetadata(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get file
	file, err := h.fileService.GetFile(c.Request.Context(), userObjID, fileID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.NotFoundResponse(c, "File not found")
		return
	}

	// Return detailed metadata
	metadata := map[string]interface{}{
		"id":              file.ID,
		"name":            file.Name,
		"originalName":    file.OriginalName,
		"size":            file.Size,
		"mimeType":        file.MimeType,
		"extension":       file.Extension,
		"hash":            file.Hash,
		"checksum":        file.Checksum,
		"isEncrypted":     file.IsEncrypted,
		"isPublic":        file.IsPublic,
		"isFavorite":      file.IsFavorite,
		"description":     file.Description,
		"tags":            file.Tags,
		"metadata":        file.Metadata,
		"shareCount":      file.ShareCount,
		"downloadCount":   file.DownloadCount,
		"viewCount":       file.ViewCount,
		"lastAccessedAt":  file.LastAccessedAt,
		"lastModifiedAt":  file.LastModifiedAt,
		"virusScanStatus": file.VirusScanStatus,
		"virusScanResult": file.VirusScanResult,
		"createdAt":       file.CreatedAt,
		"updatedAt":       file.UpdatedAt,
	}

	pkg.SuccessResponse(c, http.StatusOK, "File metadata retrieved successfully", metadata)
}

// BulkDeleteFiles deletes multiple files
func (h *FileHandler) BulkDeleteFiles(c *gin.Context) {
	type BulkDeleteRequest struct {
		FileIDs []string `json:"fileIds" binding:"required,min=1"`
	}

	var req BulkDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Convert string IDs to ObjectIDs and delete each file
	var successful []string
	var failed []map[string]interface{}

	for _, idStr := range req.FileIDs {
		id, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"id":    idStr,
				"error": "Invalid file ID",
			})
			continue
		}

		if err := h.fileService.DeleteFile(c.Request.Context(), userObjID, id); err != nil {
			failed = append(failed, map[string]interface{}{
				"id":    idStr,
				"error": err.Error(),
			})
		} else {
			successful = append(successful, idStr)
		}
	}

	pkg.SuccessResponse(c, http.StatusOK, "Bulk delete completed", map[string]interface{}{
		"successful": successful,
		"failed":     failed,
		"total":      len(req.FileIDs),
	})
}

// BulkMoveFiles moves multiple files to a folder
func (h *FileHandler) BulkMoveFiles(c *gin.Context) {
	type BulkMoveRequest struct {
		FileIDs  []string `json:"fileIds" binding:"required,min=1"`
		FolderID *string  `json:"folderId"` // nil for root folder
	}

	var req BulkMoveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Parse target folder ID
	var targetFolderID *primitive.ObjectID
	if req.FolderID != nil {
		id, err := primitive.ObjectIDFromHex(*req.FolderID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid target folder ID")
			return
		}
		targetFolderID = &id
	}

	// Move each file
	var successful []string
	var failed []map[string]interface{}

	for _, idStr := range req.FileIDs {
		id, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"id":    idStr,
				"error": "Invalid file ID",
			})
			continue
		}

		if _, err := h.fileService.MoveFile(c.Request.Context(), userObjID, id, targetFolderID); err != nil {
			failed = append(failed, map[string]interface{}{
				"id":    idStr,
				"error": err.Error(),
			})
		} else {
			successful = append(successful, idStr)
		}
	}

	pkg.SuccessResponse(c, http.StatusOK, "Bulk move completed", map[string]interface{}{
		"successful": successful,
		"failed":     failed,
		"total":      len(req.FileIDs),
	})
}
