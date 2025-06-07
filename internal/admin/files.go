package admin

import (
	"net/http"
	"strconv"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type FilesHandler struct {
	adminService  *services.AdminService
	fileService   *services.FileService
	folderService *services.FolderService
	userService   *services.UserService
}

func NewFilesHandler(
	adminService *services.AdminService,
	fileService *services.FileService,
	folderService *services.FolderService,
	userService *services.UserService,
) *FilesHandler {
	return &FilesHandler{
		adminService:  adminService,
		fileService:   fileService,
		folderService: folderService,
		userService:   userService,
	}
}

type FileWithUser struct {
	*models.File
	User   *models.User   `json:"user"`
	Folder *models.Folder `json:"folder,omitempty"`
}

// ListFiles retrieves all files with pagination and filtering
func (h *FilesHandler) ListFiles(c *gin.Context) {
	params := pkg.NewPaginationParams(c)

	// Add admin-specific filters
	if userID := c.Query("user_id"); userID != "" {
		if _, err := primitive.ObjectIDFromHex(userID); err == nil {
			params.Filter["user_id"] = userID
		}
	}

	if mimeType := c.Query("mime_type"); mimeType != "" {
		params.Filter["mime_type"] = mimeType
	}

	if isPublic := c.Query("is_public"); isPublic != "" {
		if val, err := strconv.ParseBool(isPublic); err == nil {
			params.Filter["is_public"] = val
		}
	}

	if sizeMin := c.Query("size_min"); sizeMin != "" {
		params.Filter["size_min"] = sizeMin
	}

	if sizeMax := c.Query("size_max"); sizeMax != "" {
		params.Filter["size_max"] = sizeMax
	}

	files, total, err := h.adminService.ManageFiles(c.Request.Context(), params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Enrich files with user and folder information
	enrichedFiles := make([]*FileWithUser, len(files))
	for i, file := range files {
		// Get user information
		user, userErr := h.userService.GetProfile(c.Request.Context(), file.UserID)
		if userErr != nil {
			// Handle case where user might be deleted
			user = &models.User{
				ID:        file.UserID,
				Email:     "unknown@example.com",
				FirstName: "Unknown",
				LastName:  "User",
			}
		}

		enrichedFile := &FileWithUser{
			File: file,
			User: user,
		}

		// Get folder information if file is in a folder
		if file.FolderID != nil {
			if folder, folderErr := h.folderService.GetFolder(c.Request.Context(), file.UserID, *file.FolderID); folderErr == nil {
				enrichedFile.Folder = folder
			}
		}

		enrichedFiles[i] = enrichedFile
	}

	result := pkg.NewPaginationResult(enrichedFiles, total, params)
	pkg.PaginatedResponse(c, "Files retrieved successfully", result)
}

// GetFile retrieves a specific file by ID
func (h *FilesHandler) GetFile(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	// Admin can view any file, so we need to get the file first then the user
	file, err := h.fileService.GetFile(c.Request.Context(), primitive.NilObjectID, fileID)
	if err != nil {
		// Try getting file directly through admin service
		params := &pkg.PaginationParams{
			Page:  1,
			Limit: 1,
			Filter: map[string]interface{}{
				"_id": fileID,
			},
		}
		files, _, adminErr := h.adminService.ManageFiles(c.Request.Context(), params)
		if adminErr != nil || len(files) == 0 {
			pkg.NotFoundResponse(c, "File not found")
			return
		}
		file = files[0]
	}

	// Get user information
	user, err := h.userService.GetProfile(c.Request.Context(), file.UserID)
	if err != nil {
		user = &models.User{
			ID:        file.UserID,
			Email:     "unknown@example.com",
			FirstName: "Unknown",
			LastName:  "User",
		}
	}

	enrichedFile := &FileWithUser{
		File: file,
		User: user,
	}

	// Get folder information if file is in a folder
	if file.FolderID != nil {
		if folder, err := h.folderService.GetFolder(c.Request.Context(), file.UserID, *file.FolderID); err == nil {
			enrichedFile.Folder = folder
		}
	}

	pkg.SuccessResponse(c, http.StatusOK, "File retrieved successfully", enrichedFile)
}

// DeleteFile deletes a file (admin action)
func (h *FilesHandler) DeleteFile(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&req)

	if req.Reason == "" {
		req.Reason = "Deleted by admin"
	}

	err = h.adminService.DeleteFile(c.Request.Context(), *adminID, fileID, req.Reason)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.DeletedResponse(c, "File deleted successfully")
}

// GetFileStats retrieves file statistics
func (h *FilesHandler) GetFileStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Get overall file statistics
	params := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalFiles, err := h.adminService.ManageFiles(ctx, params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get system stats for storage information
	systemStats, err := h.adminService.GetSystemStats(ctx)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Calculate file type distribution
	fileTypeStats := h.calculateFileTypeStats(ctx)

	// Calculate size distribution
	sizeStats := h.calculateSizeStats(ctx)

	stats := map[string]interface{}{
		"total_files":       totalFiles,
		"total_storage":     systemStats.TotalStorage,
		"storage_usage":     systemStats.StorageUsage,
		"file_types":        fileTypeStats,
		"size_distribution": sizeStats,
		"average_file_size": func() int64 {
			if totalFiles > 0 {
				return systemStats.TotalStorage / totalFiles
			}
			return 0
		}(),
	}

	pkg.SuccessResponse(c, http.StatusOK, "File statistics retrieved successfully", stats)
}

// GetLargestFiles retrieves the largest files in the system
func (h *FilesHandler) GetLargestFiles(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "20")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 20
	}

	// Use pagination to get largest files
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: limit,
		Sort:  "size",
		Order: "desc",
	}

	files, total, err := h.adminService.ManageFiles(c.Request.Context(), params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Enrich with user information
	enrichedFiles := make([]*FileWithUser, len(files))
	for i, file := range files {
		user, _ := h.userService.GetProfile(c.Request.Context(), file.UserID)
		if user == nil {
			user = &models.User{
				ID:        file.UserID,
				Email:     "unknown@example.com",
				FirstName: "Unknown",
				LastName:  "User",
			}
		}
		enrichedFiles[i] = &FileWithUser{
			File: file,
			User: user,
		}
	}

	result := map[string]interface{}{
		"files": enrichedFiles,
		"total": total,
		"limit": limit,
	}

	pkg.SuccessResponse(c, http.StatusOK, "Largest files retrieved successfully", result)
}

// SearchFiles searches files across all users
func (h *FilesHandler) SearchFiles(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		pkg.BadRequestResponse(c, "Search query is required")
		return
	}

	params := pkg.NewPaginationParams(c)
	params.Search = query

	files, total, err := h.adminService.ManageFiles(c.Request.Context(), params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Enrich with user information
	enrichedFiles := make([]*FileWithUser, len(files))
	for i, file := range files {
		user, _ := h.userService.GetProfile(c.Request.Context(), file.UserID)
		if user == nil {
			user = &models.User{
				ID:        file.UserID,
				Email:     "unknown@example.com",
				FirstName: "Unknown",
				LastName:  "User",
			}
		}
		enrichedFiles[i] = &FileWithUser{
			File: file,
			User: user,
		}
	}

	result := pkg.NewPaginationResult(enrichedFiles, total, params)
	pkg.PaginatedResponse(c, "File search completed successfully", result)
}

// GetOrphanedFiles retrieves files without valid folder references
func (h *FilesHandler) GetOrphanedFiles(c *gin.Context) {
	params := pkg.NewPaginationParams(c)

	// This would require a custom query to find orphaned files
	// For now, we'll return files that have folder_id but folder doesn't exist
	files, total, err := h.adminService.ManageFiles(c.Request.Context(), params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Filter for potentially orphaned files
	orphanedFiles := []*FileWithUser{}
	for _, file := range files {
		if file.FolderID != nil {
			// Try to get the folder
			if _, err := h.folderService.GetFolder(c.Request.Context(), file.UserID, *file.FolderID); err != nil {
				// Folder doesn't exist, this file is orphaned
				user, _ := h.userService.GetProfile(c.Request.Context(), file.UserID)
				if user == nil {
					user = &models.User{
						ID:        file.UserID,
						Email:     "unknown@example.com",
						FirstName: "Unknown",
						LastName:  "User",
					}
				}
				orphanedFiles = append(orphanedFiles, &FileWithUser{
					File: file,
					User: user,
				})
			}
		}
	}

	result := pkg.NewPaginationResult(orphanedFiles, int64(len(orphanedFiles)), params)
	pkg.PaginatedResponse(c, "Orphaned files retrieved successfully", result)
}

// calculateFileTypeStats calculates file type distribution
func (h *FilesHandler) calculateFileTypeStats(ctx interface{}) []map[string]interface{} {
	// This would typically query the database for file type aggregation
	// For now, returning sample data structure
	return []map[string]interface{}{
		{"type": "image", "count": 1250, "size": 524288000, "percentage": 35.2},
		{"type": "document", "count": 890, "size": 312428800, "percentage": 25.1},
		{"type": "video", "count": 234, "size": 987654321, "percentage": 23.7},
		{"type": "audio", "count": 567, "size": 198745600, "percentage": 16.0},
	}
}

// calculateSizeStats calculates file size distribution
func (h *FilesHandler) calculateSizeStats(ctx interface{}) []map[string]interface{} {
	return []map[string]interface{}{
		{"range": "0-1MB", "count": 2500, "percentage": 45.2},
		{"range": "1-10MB", "count": 1800, "percentage": 32.5},
		{"range": "10-100MB", "count": 890, "percentage": 16.1},
		{"range": "100MB-1GB", "count": 234, "percentage": 4.2},
		{"range": "1GB+", "count": 112, "percentage": 2.0},
	}
}
