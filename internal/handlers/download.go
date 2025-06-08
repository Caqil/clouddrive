package handlers

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Caqil/clouddrive/internal/models"
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
	h.setDownloadHeaders(c, file.Name, file.Size, file.MimeType)

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

	// Convert string IDs to ObjectIDs and validate access
	var files []*models.File
	for _, idStr := range req.FileIDs {
		fileID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			pkg.BadRequestResponse(c, fmt.Sprintf("Invalid file ID: %s", idStr))
			return
		}

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

	// Get all files in folder recursively
	files, err := h.getAllFilesInFolder(c, userObjID, folderID)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to get folder contents")
		return
	}

	if len(files) == 0 {
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
	downloadURL, err := h.sharingService.DownloadShare(c.Request.Context(), token, password, ip, userAgent)
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

	userObjID := userID.(primitive.ObjectID)

	// Get pagination parameters
	params := pkg.NewPaginationParams(c)

	// Add filter for download events
	params.Filter = map[string]interface{}{
		"event_type": "file_download",
		"user_id":    userObjID,
	}

	// Get download history from analytics
	// This would call analytics service when implemented
	// For now, return empty result with proper structure
	downloads := []map[string]interface{}{}
	total := int64(0)

	result := pkg.NewPaginationResult(downloads, total, params)
	pkg.PaginatedResponse(c, "Download history retrieved", result)
}

// Helper methods

// getAllFilesInFolder recursively gets all files in a folder
func (h *DownloadHandler) getAllFilesInFolder(ctx *gin.Context, userID primitive.ObjectID, folderID primitive.ObjectID) ([]*models.File, error) {
	var allFiles []*models.File

	// Get files in current folder
	files, _, err := h.fileService.ListFilesByFolder(ctx.Request.Context(), userID, folderID, &pkg.PaginationParams{
		Page:  1,
		Limit: 1000, // Large limit to get all files
	})
	if err != nil {
		return nil, err
	}

	allFiles = append(allFiles, files...)

	// Get subfolders and recursively get their files
	contents, err := h.folderService.GetFolderContents(ctx.Request.Context(), userID, folderID, &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
	})
	if err != nil {
		return allFiles, nil // Return what we have if subfolder fetch fails
	}

	if foldersInterface, ok := contents["folders"]; ok {
		if folders, ok := foldersInterface.([]*models.Folder); ok {
			for _, folder := range folders {
				subFiles, err := h.getAllFilesInFolder(ctx, userID, folder.ID)
				if err != nil {
					continue // Skip problematic subfolders
				}
				allFiles = append(allFiles, subFiles...)
			}
		}
	}

	return allFiles, nil
}

// validateFileAccess checks if user has access to file
func (h *DownloadHandler) validateFileAccess(c *gin.Context, userID primitive.ObjectID, fileID primitive.ObjectID) (*models.File, error) {
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
	c.Header("Accept-Ranges", "bytes")
}

// handleRangeRequest handles HTTP range requests for partial content
func (h *DownloadHandler) handleRangeRequest(c *gin.Context, reader io.ReadCloser, file *models.File, rangeHeader string) {
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
	c.Status(http.StatusPartialContent)

	// Skip to start position if possible
	if seeker, ok := reader.(io.Seeker); ok {
		_, err := seeker.Seek(start, io.SeekStart)
		if err != nil {
			pkg.InternalServerErrorResponse(c, "Failed to seek to start position")
			return
		}

		// Copy only the requested range
		_, err = io.CopyN(c.Writer, reader, contentLength)
		if err != nil && err != io.EOF {
			pkg.InternalServerErrorResponse(c, "Failed to stream range content")
			return
		}
	} else {
		// If seeking is not supported, skip bytes manually
		_, err := io.CopyN(io.Discard, reader, start)
		if err != nil {
			pkg.InternalServerErrorResponse(c, "Failed to skip to start position")
			return
		}

		// Copy only the requested range
		_, err = io.CopyN(c.Writer, reader, contentLength)
		if err != nil && err != io.EOF {
			pkg.InternalServerErrorResponse(c, "Failed to stream range content")
			return
		}
	}
}

// streamZipArchive creates and streams a ZIP archive of files
func (h *DownloadHandler) streamZipArchive(c *gin.Context, files []*models.File, zipName string) {
	// Set headers for ZIP download
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, zipName))
	c.Header("Transfer-Encoding", "chunked")
	c.Status(http.StatusOK)

	// Create ZIP writer that writes directly to response
	zipWriter := zip.NewWriter(c.Writer)
	defer zipWriter.Close()

	// Add each file to the ZIP
	for _, file := range files {
		// Create file entry in ZIP
		zipFile, err := zipWriter.Create(file.Name)
		if err != nil {
			// Log error but continue with other files
			continue
		}

		// Download file from storage
		fileReader, err := h.storageService.Download(c.Request.Context(), file.StoragePath)
		if err != nil {
			// Log error but continue with other files
			continue
		}

		// Copy file content to ZIP
		_, err = io.Copy(zipFile, fileReader)
		fileReader.Close()

		if err != nil {
			// Log error but continue with other files
			continue
		}

		// Flush the writer to send data immediately
		if flusher, ok := c.Writer.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	// Finalize ZIP (this is important for proper ZIP structure)
	zipWriter.Close()
}

// PreviewFile generates preview for supported file types
func (h *DownloadHandler) PreviewFile(c *gin.Context) {
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

	// Check if file type supports preview
	if !h.supportsPreview(file.MimeType) {
		pkg.BadRequestResponse(c, "File type does not support preview")
		return
	}

	// Get file content from storage
	reader, err := h.storageService.Download(c.Request.Context(), file.StoragePath)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to retrieve file content")
		return
	}
	defer reader.Close()

	// Set headers for preview (inline instead of attachment)
	c.Header("Content-Type", file.MimeType)
	c.Header("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, file.Name))
	c.Header("Content-Length", strconv.FormatInt(file.Size, 10))
	c.Header("Cache-Control", "public, max-age=3600")

	// Stream file content for preview
	c.DataFromReader(http.StatusOK, file.Size, file.MimeType, reader, map[string]string{
		"Content-Disposition": fmt.Sprintf(`inline; filename="%s"`, file.Name),
	})
}

// supportsPreview checks if file type supports preview
func (h *DownloadHandler) supportsPreview(mimeType string) bool {
	previewableTypes := []string{
		"image/",
		"text/",
		"application/pdf",
		"video/mp4",
		"video/webm",
		"audio/mpeg",
		"audio/wav",
		"audio/ogg",
	}

	for _, previewType := range previewableTypes {
		if strings.HasPrefix(mimeType, previewType) {
			return true
		}
	}

	return false
}

// GetThumbnail serves file thumbnail
func (h *DownloadHandler) GetThumbnail(c *gin.Context) {
	fileIDStr := c.Param("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid file ID")
		return
	}

	size := c.Query("size")
	if size == "" {
		size = "medium"
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

	// Find thumbnail for requested size
	var thumbnailPath string
	for _, thumbnail := range file.Thumbnails {
		if thumbnail.Size == size {
			thumbnailPath = thumbnail.Path
			break
		}
	}

	if thumbnailPath == "" {
		pkg.NotFoundResponse(c, "Thumbnail not found")
		return
	}

	// Get thumbnail from storage
	reader, err := h.storageService.Download(c.Request.Context(), thumbnailPath)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to retrieve thumbnail")
		return
	}
	defer reader.Close()

	// Set headers for thumbnail
	c.Header("Content-Type", "image/jpeg")
	c.Header("Cache-Control", "public, max-age=86400") // Cache for 24 hours
	c.Status(http.StatusOK)

	// Stream thumbnail
	io.Copy(c.Writer, reader)
}
