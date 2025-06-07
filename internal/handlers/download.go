package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// DownloadHandler handles file download operations
type DownloadHandler struct {
	fileService    *services.FileService
	folderService  *services.FolderService
	sharingService *services.SharingService
	storageService *services.StorageService
}

// NewDownloadHandler creates a new download handler
func NewDownloadHandler(
	fileService *services.FileService,
	folderService *services.FolderService,
	sharingService *services.SharingService,
	storageService *services.StorageService,
) *DownloadHandler {
	return &DownloadHandler{
		fileService:    fileService,
		folderService:  folderService,
		sharingService: sharingService,
		storageService: storageService,
	}
}

// DownloadFile handles single file download
func (h *DownloadHandler) DownloadFile(c *gin.Context) {
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

	// Get download URL from service
	downloadURL, err := h.fileService.DownloadFile(c.Request.Context(), userObjID, fileID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to prepare file download")
		return
	}

	// Check if client wants direct download or redirect
	if c.Query("redirect") == "true" {
		c.Redirect(http.StatusTemporaryRedirect, downloadURL)
		return
	}

	// Return download URL
	pkg.SuccessResponse(c, http.StatusOK, "Download URL generated", map[string]interface{}{
		"downloadUrl": downloadURL,
		"expiresIn":   3600, // 1 hour
	})
}

// StreamFile streams file content directly
func (h *DownloadHandler) StreamFile(c *gin.Context) {
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

	// Get file details
	file, err := h.fileService.GetFile(c.Request.Context(), userObjID, fileID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.NotFoundResponse(c, "File not found")
		return
	}

	// Get file content from storage
	reader, err := h.storageService.Download(c.Request.Context(), file.StoragePath)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to retrieve file content")
		return
	}
	defer reader.Close()

	// Set headers for file download
	c.Header("Content-Type", file.MimeType)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.Name))
	c.Header("Content-Length", strconv.FormatInt(file.Size, 10))

	// Handle range requests for partial content
	if rangeHeader := c.GetHeader("Range"); rangeHeader != "" {
		h.handleRangeRequest(c, reader, file, rangeHeader)
		return
	}

	// Stream file content
	c.DataFromReader(http.StatusOK, file.Size, file.MimeType, reader, map[string]string{
		"Content-Disposition": fmt.Sprintf(`attachment; filename="%s"`, file.Name),
	})
}

// DownloadMultipleFiles downloads multiple files as a ZIP archive
func (h *DownloadHandler) DownloadMultipleFiles(c *gin.Context) {
	type DownloadRequest struct {
		FileIDs []string `json:"fileIds" binding:"required,min=1"`
	}

	var req DownloadRequest
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

	// Convert string IDs to ObjectIDs
	fileIDs := make([]primitive.ObjectID, len(req.FileIDs))
	for i, idStr := range req.FileIDs {
		id, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			pkg.BadRequestResponse(c, fmt.Sprintf("Invalid file ID: %s", idStr))
			return
		}
		fileIDs[i] = id
	}

	// Validate file access
	var files []*services.File
	for _, fileID := range fileIDs {
		file, err := h.fileService.GetFile(c.Request.Context(), userObjID, fileID)
		if err != nil {
			continue // Skip files user doesn't have access to
		}
		files = append(files, file)
	}

	if len(files) == 0 {
		pkg.NotFoundResponse(c, "No accessible files found")
		return
	}

	// Create ZIP archive and stream it
	h.streamZipArchive(c, files, "files.zip")
}

// DownloadFolder downloads entire folder as ZIP
func (h *DownloadHandler) DownloadFolder(c *gin.Context) {
	folderIDStr := c.Param("id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid folder ID")
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get folder details
	folder, err := h.folderService.GetFolder(c.Request.Context(), userObjID, folderID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.NotFoundResponse(c, "Folder not found")
		return
	}

	// Get folder contents recursively
	contents, err := h.folderService.GetFolderContents(c.Request.Context(), userObjID, folderID, &pkg.PaginationParams{
		Page:  1,
		Limit: 1000, // Large limit to get all files
	})
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to get folder contents")
		return
	}

	// Extract files from contents
	filesInterface := contents["files"]
	files, ok := filesInterface.([]*services.File)
	if !ok || len(files) == 0 {
		pkg.BadRequestResponse(c, "No files found in folder")
		return
	}

	// Create ZIP with folder name
	zipName := fmt.Sprintf("%s.zip", folder.Name)
	h.streamZipArchive(c, files, zipName)
}

// DownloadSharedFile downloads a shared file
func (h *DownloadHandler) DownloadSharedFile(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		pkg.BadRequestResponse(c, "Share token is required")
		return
	}

	// Get password if provided
	password := c.Query("password")

	// Get client info
	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Download shared resource
	downloadURL, err := h.sharingService.DownloadSharedResource(c.Request.Context(), token, password, ip, userAgent)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to download shared file")
		return
	}

	// Check if client wants direct download or redirect
	if c.Query("redirect") == "true" {
		c.Redirect(http.StatusTemporaryRedirect, downloadURL)
		return
	}

	// Return download URL
	pkg.SuccessResponse(c, http.StatusOK, "Download URL generated", map[string]interface{}{
		"downloadUrl": downloadURL,
		"expiresIn":   3600, // 1 hour
	})
}

// GetDownloadHistory gets user's download history
func (h *DownloadHandler) GetDownloadHistory(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	// Get pagination parameters
	params := pkg.NewPaginationParams(c)

	// Add filter for download events
	params.Filter = map[string]interface{}{
		"event_type": "file_download",
		"user_id":    userID,
	}

	// This would need to be implemented in the analytics service
	// For now, return placeholder data
	pkg.SuccessResponse(c, http.StatusOK, "Download history retrieved", map[string]interface{}{
		"downloads": []interface{}{},
		"total":     0,
	})
}

// Helper methods

// handleRangeRequest handles HTTP range requests for partial content
func (h *DownloadHandler) handleRangeRequest(c *gin.Context, reader interface{}, file *services.File, rangeHeader string) {
	// Parse range header (e.g., "bytes=0-1023")
	rangeHeader = strings.TrimPrefix(rangeHeader, "bytes=")
	ranges := strings.Split(rangeHeader, "-")

	if len(ranges) != 2 {
		c.Header("Content-Range", fmt.Sprintf("bytes */%d", file.Size))
		c.Status(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	var start, end int64
	var err error

	// Parse start
	if ranges[0] != "" {
		start, err = strconv.ParseInt(ranges[0], 10, 64)
		if err != nil {
			c.Header("Content-Range", fmt.Sprintf("bytes */%d", file.Size))
			c.Status(http.StatusRequestedRangeNotSatisfiable)
			return
		}
	}

	// Parse end
	if ranges[1] != "" {
		end, err = strconv.ParseInt(ranges[1], 10, 64)
		if err != nil {
			c.Header("Content-Range", fmt.Sprintf("bytes */%d", file.Size))
			c.Status(http.StatusRequestedRangeNotSatisfiable)
			return
		}
	} else {
		end = file.Size - 1
	}

	// Validate range
	if start < 0 || end >= file.Size || start > end {
		c.Header("Content-Range", fmt.Sprintf("bytes */%d", file.Size))
		c.Status(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	contentLength := end - start + 1

	// Set partial content headers
	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, file.Size))
	c.Header("Accept-Ranges", "bytes")
	c.Header("Content-Length", strconv.FormatInt(contentLength, 10))
	c.Header("Content-Type", file.MimeType)

	// This is a simplified implementation
	// In a real implementation, you would need to seek to the start position
	// and limit reading to the requested range
	c.Status(http.StatusPartialContent)
}

// streamZipArchive creates and streams a ZIP archive of files
func (h *DownloadHandler) streamZipArchive(c *gin.Context, files []*services.File, zipName string) {
	// Set headers for ZIP download
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, zipName))
	c.Header("Transfer-Encoding", "chunked")

	// This is a simplified implementation
	// In a real implementation, you would:
	// 1. Create a zip.Writer that writes to the response writer
	// 2. For each file, download from storage and add to ZIP
	// 3. Stream the ZIP as it's being created

	// For now, return an error indicating this needs implementation
	pkg.InternalServerErrorResponse(c, "ZIP download not yet implemented")
}

// validateFileAccess checks if user has access to file
func (h *DownloadHandler) validateFileAccess(c *gin.Context, userID primitive.ObjectID, fileID primitive.ObjectID) (*services.File, error) {
	return h.fileService.GetFile(c.Request.Context(), userID, fileID)
}

// getContentType determines content type for download
func (h *DownloadHandler) getContentType(filename string) string {
	contentType := pkg.Files.GetMimeType(filename)
	if contentType == "" {
		return "application/octet-stream"
	}
	return contentType
}

// setDownloadHeaders sets appropriate headers for file download
func (h *DownloadHandler) setDownloadHeaders(c *gin.Context, filename string, size int64, mimeType string) {
	c.Header("Content-Type", mimeType)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Length", strconv.FormatInt(size, 10))
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
}
