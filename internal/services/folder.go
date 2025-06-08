package services

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// FolderService handles folder operations
type FolderService struct {
	folderRepo    repository.FolderRepository
	fileRepo      repository.FileRepository
	userRepo      repository.UserRepository
	auditRepo     repository.AuditLogRepository
	analyticsRepo repository.AnalyticsRepository
}

// NewFolderService creates a new folder service
func NewFolderService(
	folderRepo repository.FolderRepository,
	fileRepo repository.FileRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
) *FolderService {
	return &FolderService{
		folderRepo:    folderRepo,
		fileRepo:      fileRepo,
		userRepo:      userRepo,
		auditRepo:     auditRepo,
		analyticsRepo: analyticsRepo,
	}
}

// CreateFolderRequest represents folder creation request
type CreateFolderRequest struct {
	Name        string              `json:"name" validate:"required,min=1,max=255"`
	ParentID    *primitive.ObjectID `json:"parentId,omitempty"`
	Description string              `json:"description" validate:"max=500"`
	Color       string              `json:"color" validate:"omitempty,color"`
	Tags        []string            `json:"tags"`
	IsPublic    bool                `json:"isPublic"`
}

// FolderTree represents folder tree structure
type FolderTree struct {
	*models.Folder
	Children []*FolderTree `json:"children"`
}

// FolderStatistics represents folder statistics
type FolderStatistics struct {
	TotalFiles     int64             `json:"totalFiles"`
	TotalFolders   int64             `json:"totalFolders"`
	TotalSize      int64             `json:"totalSize"`
	FilesByType    map[string]int64  `json:"filesByType"`
	RecentActivity []models.AuditLog `json:"recentActivity"`
	StorageUsage   int64             `json:"storageUsage"`
	LastModified   time.Time         `json:"lastModified"`
	ShareCount     int64             `json:"shareCount"`
	AccessCount    int64             `json:"accessCount"`
}

// BulkOperationResult represents bulk operation result
type BulkOperationResult struct {
	Successful []string                 `json:"successful"`
	Failed     []map[string]interface{} `json:"failed"`
	Total      int                      `json:"total"`
}

// ============================================================================
// CORE FOLDER OPERATIONS
// ============================================================================

// CreateFolder creates a new folder
func (s *FolderService) CreateFolder(ctx context.Context, userID primitive.ObjectID, req *CreateFolderRequest) (*models.Folder, error) {
	// Validate request
	if err := pkg.DefaultValidator.Validate(req); err != nil {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Sanitize folder name
	req.Name = pkg.Files.SanitizeFilename(req.Name)
	if req.Name == "" {
		return nil, pkg.ErrInvalidInput.WithDetails(map[string]interface{}{
			"message": "Invalid folder name",
		})
	}

	// Build folder path
	folderPath := "/"
	var parentFolder *models.Folder
	var err error

	if req.ParentID != nil {
		// Verify parent folder exists and user owns it
		parentFolder, err = s.folderRepo.GetByID(ctx, *req.ParentID)
		if err != nil {
			return nil, err
		}

		if parentFolder.UserID != userID {
			return nil, pkg.ErrForbidden
		}

		folderPath = parentFolder.Path + "/"
	}

	folderPath += req.Name

	// Check if folder already exists at this path
	if _, err := s.folderRepo.GetByPath(ctx, userID, folderPath); err == nil {
		return nil, pkg.ErrFolderAlreadyExists
	}

	// Create folder
	folder := &models.Folder{
		Name:        req.Name,
		Path:        folderPath,
		ParentID:    req.ParentID,
		UserID:      userID,
		IsPublic:    req.IsPublic,
		Color:       req.Color,
		Description: req.Description,
		Tags:        req.Tags,
	}

	if err := s.folderRepo.Create(ctx, folder); err != nil {
		return nil, err
	}

	// Update parent folder count if this is a subfolder
	if parentFolder != nil {
		updates := map[string]interface{}{
			"folder_count": parentFolder.FolderCount + 1,
		}
		s.folderRepo.Update(ctx, *req.ParentID, updates)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFolderCreate, "folder", folder.ID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeFolderCreate, "create", folder.ID, folder.Name)

	return folder, nil
}

// GetFolder retrieves folder by ID
func (s *FolderService) GetFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID) (*models.Folder, error) {
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}

	// Check permissions
	if folder.UserID != userID && !folder.IsPublic {
		return nil, pkg.ErrForbidden
	}

	return folder, nil
}

// ListFolders lists user's folders with pagination
func (s *FolderService) ListFolders(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Folder, int64, error) {
	return s.folderRepo.ListByUser(ctx, userID, params)
}

// GetFolderContents retrieves folder contents (files and subfolders)
func (s *FolderService) GetFolderContents(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID, params *pkg.PaginationParams) (map[string]interface{}, error) {
	// Verify folder ownership
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}

	if folder.UserID != userID && !folder.IsPublic {
		return nil, pkg.ErrForbidden
	}

	// Get subfolders
	subfolders, err := s.folderRepo.ListByParent(ctx, folderID)
	if err != nil {
		return nil, err
	}

	// Get files
	files, totalFiles, err := s.fileRepo.ListByFolder(ctx, folderID, params)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"folder":       folder,
		"subfolders":   subfolders,
		"files":        files,
		"totalFiles":   totalFiles,
		"totalFolders": len(subfolders),
	}, nil
}

// GetFolderTree retrieves complete folder tree for user
func (s *FolderService) GetFolderTree(ctx context.Context, userID primitive.ObjectID) ([]*FolderTree, error) {
	// Get all user folders
	folders, err := s.folderRepo.GetFolderTree(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Build tree structure
	folderMap := make(map[primitive.ObjectID]*FolderTree)
	var rootFolders []*FolderTree

	// Create folder nodes
	for _, folder := range folders {
		folderTree := &FolderTree{
			Folder:   folder,
			Children: make([]*FolderTree, 0),
		}
		folderMap[folder.ID] = folderTree

		if folder.ParentID == nil {
			rootFolders = append(rootFolders, folderTree)
		}
	}

	// Build parent-child relationships
	for _, folder := range folders {
		if folder.ParentID != nil {
			if parent, exists := folderMap[*folder.ParentID]; exists {
				parent.Children = append(parent.Children, folderMap[folder.ID])
			}
		}
	}

	return rootFolders, nil
}

// UpdateFolder updates folder metadata
func (s *FolderService) UpdateFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID, updates map[string]interface{}) (*models.Folder, error) {
	// Get folder and verify ownership
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}

	if folder.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Don't allow updating root folder name or path
	if folder.IsRoot {
		delete(updates, "name")
		delete(updates, "path")
		delete(updates, "parent_id")
	}

	// Add updated timestamp
	updates["updated_at"] = time.Now()

	// Update folder
	if err := s.folderRepo.Update(ctx, folderID, updates); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFolderUpdate, "folder", folderID, true, "")

	// Get updated folder
	return s.folderRepo.GetByID(ctx, folderID)
}

// RenameFolder renames a folder
func (s *FolderService) RenameFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID, newName string) (*models.Folder, error) {
	// Get folder and verify ownership
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}

	if folder.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Don't allow renaming root folder
	if folder.IsRoot {
		return nil, pkg.ErrForbidden.WithDetails(map[string]interface{}{
			"message": "Cannot rename root folder",
		})
	}

	// Sanitize folder name
	newName = pkg.Files.SanitizeFilename(newName)
	if newName == "" {
		return nil, pkg.ErrInvalidInput.WithDetails(map[string]interface{}{
			"message": "Invalid folder name",
		})
	}

	// Build new path
	newPath := filepath.Dir(folder.Path) + "/" + newName

	// Check if folder with new name already exists
	if _, err := s.folderRepo.GetByPath(ctx, userID, newPath); err == nil {
		return nil, pkg.ErrFolderAlreadyExists
	}

	// Update folder and all subfolders/files paths
	if err := s.updateFolderPaths(ctx, folder, newName, newPath); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFolderUpdate, "folder", folderID, true, fmt.Sprintf("Renamed to: %s", newName))

	// Get updated folder
	return s.folderRepo.GetByID(ctx, folderID)
}

// MoveFolder moves folder to different parent
func (s *FolderService) MoveFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID, targetParentID *primitive.ObjectID) (*models.Folder, error) {
	// Get folder and verify ownership
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}

	if folder.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Don't allow moving root folder
	if folder.IsRoot {
		return nil, pkg.ErrForbidden.WithDetails(map[string]interface{}{
			"message": "Cannot move root folder",
		})
	}

	// Verify target parent if specified
	var targetParent *models.Folder
	if targetParentID != nil {
		targetParent, err = s.folderRepo.GetByID(ctx, *targetParentID)
		if err != nil {
			return nil, err
		}

		if targetParent.UserID != userID {
			return nil, pkg.ErrForbidden
		}

		// Prevent moving folder into itself or its descendants
		if s.isFolderDescendant(ctx, folderID, *targetParentID) {
			return nil, pkg.ErrInvalidInput.WithDetails(map[string]interface{}{
				"message": "Cannot move folder into itself or its descendants",
			})
		}
	}

	// Build new path
	newPath := "/"
	if targetParent != nil {
		newPath = targetParent.Path + "/"
	}
	newPath += folder.Name

	// Check if folder already exists at target location
	if _, err := s.folderRepo.GetByPath(ctx, userID, newPath); err == nil {
		return nil, pkg.ErrFolderAlreadyExists
	}

	// Update folder paths
	if err := s.updateFolderPaths(ctx, folder, folder.Name, newPath); err != nil {
		return nil, err
	}

	// Update parent references
	updates := map[string]interface{}{
		"parent_id": targetParentID,
	}

	if err := s.folderRepo.Update(ctx, folderID, updates); err != nil {
		return nil, err
	}

	// Update folder counts
	// Decrease old parent count
	if folder.ParentID != nil {
		oldUpdates := map[string]interface{}{
			"folder_count": -1,
		}
		s.folderRepo.Update(ctx, *folder.ParentID, oldUpdates)
	}

	// Increase new parent count
	if targetParentID != nil {
		newUpdates := map[string]interface{}{
			"folder_count": 1,
		}
		s.folderRepo.Update(ctx, *targetParentID, newUpdates)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFolderMove, "folder", folderID, true, "")

	// Get updated folder
	return s.folderRepo.GetByID(ctx, folderID)
}

// DeleteFolder deletes a folder (soft delete)
func (s *FolderService) DeleteFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID) error {
	// Get folder and verify ownership
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return err
	}

	if folder.UserID != userID {
		return pkg.ErrForbidden
	}

	// Don't allow deleting root folder
	if folder.IsRoot {
		return pkg.ErrForbidden.WithDetails(map[string]interface{}{
			"message": "Cannot delete root folder",
		})
	}

	// Check if folder is empty (or force delete all contents)
	subfolders, err := s.folderRepo.ListByParent(ctx, folderID)
	if err != nil {
		return err
	}

	// Get files in folder
	filesParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, fileCount, err := s.fileRepo.ListByFolder(ctx, folderID, filesParams)
	if err != nil {
		return err
	}

	if len(subfolders) > 0 || fileCount > 0 {
		return pkg.ErrFolderNotEmpty
	}

	// Soft delete folder
	if err := s.folderRepo.SoftDelete(ctx, folderID); err != nil {
		return err
	}

	// Update parent folder count
	if folder.ParentID != nil {
		updates := map[string]interface{}{
			"folder_count": -1,
		}
		s.folderRepo.Update(ctx, *folder.ParentID, updates)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFolderDelete, "folder", folderID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeFolderDelete, "delete", folder.ID, folder.Name)

	return nil
}

// CreateRootFolder creates root folder for user
func (s *FolderService) CreateRootFolder(ctx context.Context, userID primitive.ObjectID) (*models.Folder, error) {
	// Check if root folder already exists
	if rootFolder, err := s.folderRepo.GetRootFolder(ctx, userID); err == nil {
		return rootFolder, nil
	}

	// Create root folder
	folder := &models.Folder{
		Name:     "My Files",
		Path:     "/",
		UserID:   userID,
		IsRoot:   true,
		IsPublic: false,
	}

	if err := s.folderRepo.Create(ctx, folder); err != nil {
		return nil, err
	}

	return folder, nil
}

// ============================================================================
// ADDITIONAL FOLDER OPERATIONS
// ============================================================================

// ToggleFavorite toggles folder favorite status
func (s *FolderService) ToggleFavorite(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID) (*models.Folder, error) {
	// Get folder and verify ownership
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}

	if folder.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Toggle favorite status
	updates := map[string]interface{}{
		"is_favorite": !folder.IsFavorite,
		"updated_at":  time.Now(),
	}

	if err := s.folderRepo.Update(ctx, folderID, updates); err != nil {
		return nil, err
	}

	// Log audit event
	action := "favorited"
	if folder.IsFavorite {
		action = "unfavorited"
	}
	s.logAuditEvent(ctx, userID, models.AuditActionFolderUpdate, "folder", folderID, true, fmt.Sprintf("Folder %s", action))

	// Get updated folder
	return s.folderRepo.GetByID(ctx, folderID)
}

// CopyFolder creates a copy of a folder
func (s *FolderService) CopyFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID, targetParentID *primitive.ObjectID, newName string) (*models.Folder, error) {
	// Get source folder and verify ownership
	sourceFolder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}

	if sourceFolder.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	// Use original name if no new name provided
	if newName == "" {
		newName = sourceFolder.Name + " (Copy)"
	}

	// Create copy request
	copyReq := &CreateFolderRequest{
		Name:        newName,
		ParentID:    targetParentID,
		Description: sourceFolder.Description,
		Color:       sourceFolder.Color,
		Tags:        sourceFolder.Tags,
		IsPublic:    false, // Copies are private by default
	}

	// Create the copy
	return s.CreateFolder(ctx, userID, copyReq)
}

// ForceDeleteFolder deletes folder and all its contents
func (s *FolderService) ForceDeleteFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID) error {
	// Get folder and verify ownership
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return err
	}

	if folder.UserID != userID {
		return pkg.ErrForbidden
	}

	if folder.IsRoot {
		return pkg.ErrForbidden.WithDetails(map[string]interface{}{
			"message": "Cannot delete root folder",
		})
	}

	// Delete all files in folder
	files, _, err := s.fileRepo.ListByFolder(ctx, folderID, &pkg.PaginationParams{Page: 1, Limit: 1000})
	if err != nil {
		return err
	}

	for _, file := range files {
		s.fileRepo.SoftDelete(ctx, file.ID)
	}

	// Delete all subfolders recursively
	subfolders, err := s.folderRepo.ListByParent(ctx, folderID)
	if err != nil {
		return err
	}

	for _, subfolder := range subfolders {
		s.ForceDeleteFolder(ctx, userID, subfolder.ID)
	}

	// Delete the folder itself
	return s.DeleteFolder(ctx, userID, folderID)
}

// RestoreFolder restores a deleted folder
func (s *FolderService) RestoreFolder(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID) (*models.Folder, error) {
	// Get folder (including deleted ones)
	folder, err := s.folderRepo.GetByID(ctx, folderID)
	if err != nil {
		return nil, err
	}

	if folder.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	if folder.DeletedAt == nil {
		return nil, pkg.ErrInvalidInput.WithDetails(map[string]interface{}{
			"message": "Folder is not deleted",
		})
	}

	// Restore folder
	updates := map[string]interface{}{
		"deleted_at": nil,
		"updated_at": time.Now(),
	}

	if err := s.folderRepo.Update(ctx, folderID, updates); err != nil {
		return nil, err
	}

	// Update parent folder count
	if folder.ParentID != nil {
		parentUpdates := map[string]interface{}{
			"folder_count": 1,
		}
		s.folderRepo.Update(ctx, *folder.ParentID, parentUpdates)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionFolderUpdate, "folder", folderID, true, "Folder restored")

	return s.folderRepo.GetByID(ctx, folderID)
}

// GetFolderStatistics calculates detailed folder statistics
func (s *FolderService) GetFolderStatistics(ctx context.Context, userID primitive.ObjectID, folderID primitive.ObjectID) (*FolderStatistics, error) {
	// Verify folder ownership
	folder, err := s.GetFolder(ctx, userID, folderID)
	if err != nil {
		return nil, err
	}

	stats := &FolderStatistics{
		TotalFiles:   folder.FileCount,
		TotalFolders: folder.FolderCount,
		TotalSize:    folder.Size,
		ShareCount:   folder.ShareCount,
		LastModified: folder.UpdatedAt,
	}

	// Calculate file types distribution
	// This would require a more complex query in a real implementation
	stats.FilesByType = make(map[string]int64)
	stats.FilesByType["document"] = 0
	stats.FilesByType["image"] = 0
	stats.FilesByType["video"] = 0
	stats.FilesByType["audio"] = 0
	stats.FilesByType["other"] = 0

	return stats, nil
}

// GetFavoriteFolders retrieves user's favorite folders
func (s *FolderService) GetFavoriteFolders(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Folder, int64, error) {
	// Add favorite filter
	originalFilter := params.Filter
	if originalFilter == nil {
		originalFilter = make(map[string]interface{})
	}

	params.Filter = map[string]interface{}{
		"user_id":     userID,
		"is_favorite": true,
		"deleted_at":  nil,
	}

	// Merge with existing filters
	for k, v := range originalFilter {
		params.Filter[k] = v
	}

	return s.folderRepo.ListByUser(ctx, userID, params)
}

// GetRootFolders retrieves user's root folders (folders with no parent)
func (s *FolderService) GetRootFolders(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Folder, int64, error) {
	// Add root filter
	originalFilter := params.Filter
	if originalFilter == nil {
		originalFilter = make(map[string]interface{})
	}

	params.Filter = map[string]interface{}{
		"user_id":    userID,
		"parent_id":  nil,
		"deleted_at": nil,
	}

	// Merge with existing filters
	for k, v := range originalFilter {
		params.Filter[k] = v
	}

	return s.folderRepo.ListByUser(ctx, userID, params)
}

// GetDeletedFolders retrieves user's deleted folders
func (s *FolderService) GetDeletedFolders(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Folder, int64, error) {
	// This would need a special repository method to include deleted folders
	// For now, return empty result
	return []*models.Folder{}, 0, nil
}

// EmptyTrash permanently deletes all deleted folders
func (s *FolderService) EmptyTrash(ctx context.Context, userID primitive.ObjectID) (int64, error) {
	// This would need a repository method to permanently delete all soft-deleted folders
	// For now, return 0
	return 0, nil
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

// BulkDeleteFolders deletes multiple folders
func (s *FolderService) BulkDeleteFolders(ctx context.Context, userID primitive.ObjectID, folderIDs []primitive.ObjectID) (*BulkOperationResult, error) {
	result := &BulkOperationResult{
		Successful: make([]string, 0),
		Failed:     make([]map[string]interface{}, 0),
		Total:      len(folderIDs),
	}

	for _, folderID := range folderIDs {
		err := s.DeleteFolder(ctx, userID, folderID)
		if err != nil {
			result.Failed = append(result.Failed, map[string]interface{}{
				"id":    folderID.Hex(),
				"error": err.Error(),
			})
		} else {
			result.Successful = append(result.Successful, folderID.Hex())
		}
	}

	return result, nil
}

// BulkMoveFolders moves multiple folders to a new parent
func (s *FolderService) BulkMoveFolders(ctx context.Context, userID primitive.ObjectID, folderIDs []primitive.ObjectID, targetParentID primitive.ObjectID) (*BulkOperationResult, error) {
	result := &BulkOperationResult{
		Successful: make([]string, 0),
		Failed:     make([]map[string]interface{}, 0),
		Total:      len(folderIDs),
	}

	for _, folderID := range folderIDs {
		_, err := s.MoveFolder(ctx, userID, folderID, &targetParentID)
		if err != nil {
			result.Failed = append(result.Failed, map[string]interface{}{
				"id":    folderID.Hex(),
				"error": err.Error(),
			})
		} else {
			result.Successful = append(result.Successful, folderID.Hex())
		}
	}

	return result, nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================

// updateFolderPaths updates folder and all its contents paths
func (s *FolderService) updateFolderPaths(ctx context.Context, folder *models.Folder, newName, newPath string) error {
	// Update current folder
	updates := map[string]interface{}{
		"name":       newName,
		"path":       newPath,
		"updated_at": time.Now(),
	}

	if err := s.folderRepo.Update(ctx, folder.ID, updates); err != nil {
		return err
	}

	// Update all subfolders paths recursively
	subfolders, err := s.folderRepo.ListByParent(ctx, folder.ID)
	if err != nil {
		return err
	}

	for _, subfolder := range subfolders {
		newSubPath := newPath + "/" + subfolder.Name
		if err := s.updateFolderPaths(ctx, subfolder, subfolder.Name, newSubPath); err != nil {
			return err
		}
	}

	// Update all files paths in this folder
	files, _, err := s.fileRepo.ListByFolder(ctx, folder.ID, &pkg.PaginationParams{Page: 1, Limit: 1000})
	if err != nil {
		return err
	}

	for _, file := range files {
		newFilePath := newPath + "/" + file.Name
		fileUpdates := map[string]interface{}{
			"path":       newFilePath,
			"updated_at": time.Now(),
		}
		s.fileRepo.Update(ctx, file.ID, fileUpdates)
	}

	return nil
}

// isFolderDescendant checks if target is a descendant of source folder
func (s *FolderService) isFolderDescendant(ctx context.Context, sourceFolderID, targetFolderID primitive.ObjectID) bool {
	if sourceFolderID == targetFolderID {
		return true
	}

	// Get all descendants of source folder
	descendants := s.getAllDescendants(ctx, sourceFolderID)
	for _, descendant := range descendants {
		if descendant == targetFolderID {
			return true
		}
	}

	return false
}

// getAllDescendants gets all descendant folder IDs
func (s *FolderService) getAllDescendants(ctx context.Context, folderID primitive.ObjectID) []primitive.ObjectID {
	var descendants []primitive.ObjectID

	subfolders, err := s.folderRepo.ListByParent(ctx, folderID)
	if err != nil {
		return descendants
	}

	for _, subfolder := range subfolders {
		descendants = append(descendants, subfolder.ID)
		// Recursively get descendants
		subDescendants := s.getAllDescendants(ctx, subfolder.ID)
		descendants = append(descendants, subDescendants...)
	}

	return descendants
}

// logAuditEvent logs an audit event
func (s *FolderService) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
	if s.auditRepo == nil {
		return
	}

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

	// Log audit event in background
	go func() {
		s.auditRepo.Create(context.Background(), auditLog)
	}()
}

// trackAnalytics tracks analytics event
func (s *FolderService) trackAnalytics(_ context.Context, userID primitive.ObjectID, eventType models.AnalyticsEventType, action string, resourceID primitive.ObjectID, resourceName string) {
	if s.analyticsRepo == nil {
		return
	}

	analytics := &models.Analytics{
		UserID:    &userID,
		EventType: eventType,
		Action:    action,
		Resource: models.AnalyticsResource{
			Type: "folder",
			ID:   resourceID,
			Name: resourceName,
		},
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Track analytics in background
	go func() {
		s.analyticsRepo.Create(context.Background(), analytics)
	}()
}
