package services

import (
	"context"
	"fmt"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// FileService handles file operations
type FileService struct {
	fileRepo       repository.FileRepository
	folderRepo     repository.FolderRepository
	userRepo       repository.UserRepository
	auditRepo      repository.AuditLogRepository
	analyticsRepo  repository.AnalyticsRepository
	storageService *StorageService
}

// NewFileService creates a new file service
func NewFileService(
	fileRepo repository.FileRepository,
	folderRepo repository.FolderRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
	storageService *StorageService,
) *FileService {
	return &FileService{
		fileRepo:       fileRepo,
		folderRepo:     folderRepo,
		userRepo:       userRepo,
		auditRepo:      auditRepo,
		analyticsRepo:  analyticsRepo,
		storageService: storageService,
	}
}

// UploadRequest represents file upload request
type UploadRequest struct {
	File        multipart.File        `json:"-"`
	FileHeader  *multipart.FileHeader `json:"-"`
	FolderID    *primitive.ObjectID   `json:"folderId,omitempty"`
	Description string                `json:"description"`
	Tags        []string              `json:"tags"`
	IsPublic    bool                  `json:"isPublic"`
}

// UploadFile uploads a new file
func (s *FileService) UploadFile(ctx context.Context, userID primitive.ObjectID, req *UploadRequest) (*models.File, error) {
	// Get user to check storage limits
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Check storage quota
	if user.StorageUsed+req.FileHeader.Size > user.StorageLimit {
		return nil, pkg.ErrStorageQuotaExceeded
	}

	// Validate folder if specified
	var folder *models.Folder
	if req.FolderID != nil {
		folder, err = s.folderRepo.GetByID(ctx, *req.FolderID)
		if err != nil {
			return nil, err
		}

		// Check if user owns the folder
		if folder.UserID != userID {
			return nil, pkg.ErrForbidden
		}
	}

	// Generate file hash
	hashValue, err := pkg.HashFile(req.File)
	if err != nil {
		return nil, pkg.ErrInternalServer.WithCause(err)
	}

	// Check for duplicate files
	if existingFile, err := s.fileRepo.GetByHash(ctx, hashValue); err == nil {
		if existingFile.UserID == userID {
			return nil, pkg.ErrFileAlreadyExists
		}
	}

	// Generate storage key
	fileExt := filepath.Ext(req.FileHeader.Filename)
	storageKey := fmt.Sprintf("users/%s/%s%s", userID.Hex(), primitive.NewObjectID().Hex(), fileExt)

	// Upload to storage
	uploadResult, err := s.storageService.Upload(ctx, storageKey, req.File, req.FileHeader)
	if err != nil {
		return nil, err
	}

	// Build file path
	filePath := "/"
	if folder != nil {
		filePath = folder.Path + "/"
	}
	filePath += req.FileHeader.Filename

	// Create file record
	file := &models.File{
		Name:            req.FileHeader.Filename,
		OriginalName:    req.FileHeader.Filename,
		Path:            filePath,
		StoragePath:     storageKey,
		FolderID:        req.FolderID,
		UserID:          userID,
		Size:            req.FileHeader.Size,
		MimeType:        req.FileHeader.Header.Get("Content-Type"),
		Extension:       strings.TrimPrefix(fileExt, "."),
		Hash:            hashValue,
		IsPublic:        req.IsPublic,
		Description:     req.Description,
		Tags:            req.Tags,
		Metadata:        models.FileMetadata{},
		VirusScanStatus: models.ScanPending,
	}

	// Use upload result data if available
	if uploadResult != nil {
		// Store the actual uploaded size if different
		if uploadResult.Size > 0 {
			file.Size = uploadResult.Size
		}
		// Store ETag for integrity verification
		if uploadResult.ETag != "" {
			file.Checksum = uploadResult.ETag
		}
	}

	// Detect and set MIME type if not provided
	if file.MimeType == "" {
		file.MimeType = pkg.Files.GetMimeType(req.FileHeader.Filename)
	}

	// Save file record
	if err := s.fileRepo.Create(ctx, file); err != nil {
		// Cleanup uploaded file if database save fails
		s.storageService.Delete(ctx, storageKey)
		return nil, err
	}

	// Update user storage usage
	if err := s.userRepo.UpdateStorageUsed(ctx, userID, req.FileHeader.Size); err != nil {
		// Log error but don't fail the upload
		s.logError(ctx, userID, "Failed to update user storage usage", err)
	}

	// Update folder size if file is in a folder
	if folder != nil {
		updates := map[string]interface{}{
			"size":       folder.Size + req.FileHeader.Size,
			"file_count": folder.FileCount + 1,
		}
		s.folderRepo.Update(ctx, *req.FolderID, updates)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFileUpload, "file", file.ID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeFileUpload, "upload", file.ID, file.Name, &file.Size)

	return file, nil
}

// GetFile retrieves file by ID
func (s *FileService) GetFile(ctx context.Context, userID primitive.ObjectID, fileID primitive.ObjectID) (*models.File, error) {
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	// Check permissions
	if file.UserID != userID && !file.IsPublic {
		return nil, pkg.ErrForbidden
	}

	// Update view count
	s.fileRepo.UpdateViewCount(ctx, fileID)

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeFileView, "view", file.ID, file.Name, &file.Size)

	return file, nil
}

// ListFiles lists user's files with pagination
func (s *FileService) ListFiles(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	return s.fileRepo.ListByUser(ctx, userID, params)
}

// ListFilesByFolder lists files in a folder
func (s *FileService) ListFilesByFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	// Verify folder ownership
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, 0, err
	}

	if folder.UserID != userID {
		return nil, 0, pkg.ErrForbidden
	}

	return s.fileRepo.ListByFolder(ctx, folderID, params)
}

// SearchFiles searches user's files
func (s *FileService) SearchFiles(ctx context.Context, userID primitive.ObjectID, query string, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	return s.fileRepo.Search(ctx, userID, query, params)
}

// UpdateFile updates file metadata
func (s *FileService) UpdateFile(ctx context.Context, userID primitive.ObjectID, fileID primitive.ObjectID, updates map[string]interface{}) (*models.File, error) {
	// Get file and verify ownership
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	if file.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Update file
	if err := s.fileRepo.Update(ctx, fileID, updates); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFileUpdate, "file", fileID, true, "")

	// Get updated file
	return s.fileRepo.GetByID(ctx, fileID)
}

// RenameFile renames a file
func (s *FileService) RenameFile(ctx context.Context, userID primitive.ObjectID, fileID primitive.ObjectID, newName string) (*models.File, error) {
	// Get file and verify ownership
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	if file.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Sanitize filename
	newName = pkg.Files.SanitizeFilename(newName)
	if newName == "" {
		return nil, pkg.ErrInvalidInput.WithDetails(map[string]interface{}{
			"message": "Invalid filename",
		})
	}

	// Update file path
	newPath := filepath.Dir(file.Path) + "/" + newName

	updates := map[string]interface{}{
		"name": newName,
		"path": newPath,
	}

	if err := s.fileRepo.Update(ctx, fileID, updates); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFileRename, "file", fileID, true, fmt.Sprintf("Renamed to: %s", newName))

	// Get updated file
	return s.fileRepo.GetByID(ctx, fileID)
}

// MoveFile moves file to different folder
func (s *FileService) MoveFile(ctx context.Context, userID primitive.ObjectID, fileID primitive.ObjectID, targetFolderID *primitive.ObjectID) (*models.File, error) {
	// Get file and verify ownership
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	if file.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Verify target folder if specified
	var targetFolder *models.Folder
	if targetFolderID != nil {
		targetFolder, err = s.folderRepo.GetByID(ctx, *targetFolderID)
		if err != nil {
			return nil, err
		}

		if targetFolder.UserID != userID {
			return nil, pkg.ErrForbidden
		}
	}

	// Update file location
	newPath := "/"
	if targetFolder != nil {
		newPath = targetFolder.Path + "/"
	}
	newPath += file.Name

	updates := map[string]interface{}{
		"folder_id": targetFolderID,
		"path":      newPath,
	}

	if err := s.fileRepo.Update(ctx, fileID, updates); err != nil {
		return nil, err
	}

	// Update folder counts
	// Decrease old folder counts
	if file.FolderID != nil {
		oldUpdates := map[string]interface{}{
			"file_count": -1,
			"size":       -file.Size,
		}
		s.folderRepo.Update(ctx, *file.FolderID, oldUpdates)
	}

	// Increase new folder counts
	if targetFolderID != nil {
		newUpdates := map[string]interface{}{
			"file_count": 1,
			"size":       file.Size,
		}
		s.folderRepo.Update(ctx, *targetFolderID, newUpdates)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFileMove, "file", fileID, true, "")

	// Get updated file
	return s.fileRepo.GetByID(ctx, fileID)
}

// DeleteFile deletes a file
func (s *FileService) DeleteFile(ctx context.Context, userID primitive.ObjectID, fileID primitive.ObjectID) error {
	// Get file and verify ownership
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return err
	}

	if file.UserID != userID {
		return pkg.ErrForbidden
	}

	// Delete from storage
	if err := s.storageService.Delete(ctx, file.StoragePath); err != nil {
		// Log error but continue with database deletion
		s.logError(ctx, userID, "Failed to delete file from storage", err)
	}

	// Soft delete from database
	if err := s.fileRepo.SoftDelete(ctx, fileID); err != nil {
		return err
	}

	// Update user storage usage
	if err := s.userRepo.UpdateStorageUsed(ctx, userID, -file.Size); err != nil {
		s.logError(ctx, userID, "Failed to update user storage usage after deletion", err)
	}

	// Update folder counts if file was in a folder
	if file.FolderID != nil {
		updates := map[string]interface{}{
			"file_count": -1,
			"size":       -file.Size,
		}
		s.folderRepo.Update(ctx, *file.FolderID, updates)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFileDelete, "file", fileID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeFileDelete, "delete", file.ID, file.Name, &file.Size)

	return nil
}

// DownloadFile prepares file for download
func (s *FileService) DownloadFile(ctx context.Context, userID primitive.ObjectID, fileID primitive.ObjectID) (string, error) {
	// Get file and verify permissions
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return "", err
	}

	if file.UserID != userID && !file.IsPublic {
		return "", pkg.ErrForbidden
	}

	// Generate presigned URL for download
	downloadURL, err := s.storageService.GetPresignedURL(ctx, file.StoragePath, 3600) // 1 hour expiry
	if err != nil {
		return "", err
	}

	// Update download count
	s.fileRepo.UpdateDownloadCount(ctx, fileID)

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeFileDownload, "download", file.ID, file.Name, &file.Size)

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFileDownload, "file", fileID, true, "")

	return downloadURL, nil
}

// GetFavoriteFiles retrieves user's favorite files
func (s *FileService) GetFavoriteFiles(ctx context.Context, userID primitive.ObjectID) ([]*models.File, error) {
	return s.fileRepo.GetFavoriteFiles(ctx, userID)
}

// ToggleFavorite toggles file favorite status
func (s *FileService) ToggleFavorite(ctx context.Context, userID primitive.ObjectID, fileID primitive.ObjectID) (*models.File, error) {
	// Get file and verify ownership
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return nil, err
	}

	if file.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Toggle favorite status
	updates := map[string]interface{}{
		"is_favorite": !file.IsFavorite,
	}

	if err := s.fileRepo.Update(ctx, fileID, updates); err != nil {
		return nil, err
	}

	// Get updated file
	return s.fileRepo.GetByID(ctx, fileID)
}

// GetRecentFiles retrieves user's recent files
func (s *FileService) GetRecentFiles(ctx context.Context, userID primitive.ObjectID, limit int) ([]*models.File, error) {
	return s.fileRepo.GetRecentFiles(ctx, userID, limit)
}

// logAuditEvent logs an audit event
func (s *FileService) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
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
func (s *FileService) trackAnalytics(ctx context.Context, userID primitive.ObjectID, eventType models.AnalyticsEventType, action string, resourceID primitive.ObjectID, resourceName string, size *int64) {
	metadata := map[string]interface{}{
		"resource_name": resourceName,
	}
	if size != nil {
		metadata["size"] = *size
	}

	analytics := &models.Analytics{
		UserID:    &userID,
		EventType: eventType,
		Action:    action,
		Resource: models.AnalyticsResource{
			Type: "file",
			ID:   resourceID,
			Name: resourceName,
			Size: size,
		},
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	s.analyticsRepo.Create(ctx, analytics)
}

// logError logs an error
func (s *FileService) logError(ctx context.Context, userID primitive.ObjectID, message string, err error) {
	auditLog := &models.AuditLog{
		UserID:       &userID,
		Action:       models.AuditActionSecurityBreach,
		Success:      false,
		ErrorMessage: fmt.Sprintf("%s: %v", message, err),
		Severity:     models.AuditSeverityMedium,
		Timestamp:    time.Now(),
	}

	s.auditRepo.Create(ctx, auditLog)
}
