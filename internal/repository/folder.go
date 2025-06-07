package repository

import (
	"context"
	"fmt"
	"time"

	"clouddrive/internal/models"
	"clouddrive/internal/pkg"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type folderRepository struct {
	*BaseRepository
}

// NewFolderRepository creates a new folder repository
func NewFolderRepository(mongodb *MongoDB) FolderRepository {
	return &folderRepository{
		BaseRepository: NewBaseRepository(mongodb, "folders"),
	}
}

// Create creates a new folder
func (r *folderRepository) Create(ctx context.Context, folder *models.Folder) error {
	folder.ID = primitive.NewObjectID()
	folder.CreatedAt = time.Now()
	folder.UpdatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, folder)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return pkg.ErrFolderAlreadyExists
		}
		return fmt.Errorf("failed to create folder: %w", err)
	}
	return nil
}

// GetByID retrieves folder by ID
func (r *folderRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.Folder, error) {
	var folder models.Folder
	filter := bson.M{"_id": id, "deleted_at": nil}

	err := r.collection.FindOne(ctx, filter).Decode(&folder)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrFolderNotFound
		}
		return nil, fmt.Errorf("failed to get folder by ID: %w", err)
	}

	return &folder, nil
}

// GetByPath retrieves folder by path
func (r *folderRepository) GetByPath(ctx context.Context, userID primitive.ObjectID, path string) (*models.Folder, error) {
	var folder models.Folder
	filter := bson.M{
		"user_id":    userID,
		"path":       path,
		"deleted_at": nil,
	}

	err := r.collection.FindOne(ctx, filter).Decode(&folder)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrFolderNotFound
		}
		return nil, fmt.Errorf("failed to get folder by path: %w", err)
	}

	return &folder, nil
}

// GetRootFolder retrieves user's root folder
func (r *folderRepository) GetRootFolder(ctx context.Context, userID primitive.ObjectID) (*models.Folder, error) {
	var folder models.Folder
	filter := bson.M{
		"user_id":    userID,
		"is_root":    true,
		"deleted_at": nil,
	}

	err := r.collection.FindOne(ctx, filter).Decode(&folder)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrFolderNotFound
		}
		return nil, fmt.Errorf("failed to get root folder: %w", err)
	}

	return &folder, nil
}

// Update updates folder data
func (r *folderRepository) Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	return r.BaseRepository.Update(ctx, filter, updates)
}

// Delete permanently deletes folder
func (r *folderRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	return r.BaseRepository.Delete(ctx, filter)
}

// List retrieves folders with pagination
func (r *folderRepository) List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Folder, int64, error) {
	var folders []*models.Folder
	filter := bson.M{"deleted_at": nil}

	// Add search filter
	if params.Search != "" {
		searchFilter := r.BuildSearchFilter(params.Search, []string{"name", "description", "tags"})
		filter = bson.M{"$and": []bson.M{filter, searchFilter}}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &folders)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list folders: %w", err)
	}

	return folders, total, nil
}

// ListByUser retrieves user's folders
func (r *folderRepository) ListByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Folder, int64, error) {
	var folders []*models.Folder
	filter := bson.M{"user_id": userID, "deleted_at": nil}

	// Add search filter
	if params.Search != "" {
		searchFilter := r.BuildSearchFilter(params.Search, []string{"name", "description", "tags"})
		filter = bson.M{"$and": []bson.M{filter, searchFilter}}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &folders)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list user folders: %w", err)
	}

	return folders, total, nil
}

// ListByParent retrieves folders by parent ID
func (r *folderRepository) ListByParent(ctx context.Context, parentID primitive.ObjectID) ([]*models.Folder, error) {
	var folders []*models.Folder
	filter := bson.M{"parent_id": parentID, "deleted_at": nil}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list folders by parent: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &folders); err != nil {
		return nil, fmt.Errorf("failed to decode folders: %w", err)
	}

	return folders, nil
}

// GetChildren retrieves folder children
func (r *folderRepository) GetChildren(ctx context.Context, folderID primitive.ObjectID) ([]*models.Folder, error) {
	return r.ListByParent(ctx, folderID)
}

// GetFolderTree retrieves complete folder tree for user
func (r *folderRepository) GetFolderTree(ctx context.Context, userID primitive.ObjectID) ([]*models.Folder, error) {
	var folders []*models.Folder
	filter := bson.M{"user_id": userID, "deleted_at": nil}

	opts := options.Find().SetSort(bson.M{"path": 1})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get folder tree: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &folders); err != nil {
		return nil, fmt.Errorf("failed to decode folders: %w", err)
	}

	return folders, nil
}

// UpdateSize updates folder size
func (r *folderRepository) UpdateSize(ctx context.Context, id primitive.ObjectID, size int64) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	update := bson.M{
		"$inc": bson.M{"size": size},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update folder size: %w", err)
	}

	return nil
}

// UpdateCounts updates folder file and folder counts
func (r *folderRepository) UpdateCounts(ctx context.Context, id primitive.ObjectID, fileCount, folderCount int64) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	update := bson.M{
		"$inc": bson.M{
			"file_count":   fileCount,
			"folder_count": folderCount,
		},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update folder counts: %w", err)
	}

	return nil
}

// SoftDelete soft deletes folder
func (r *folderRepository) SoftDelete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	return r.BaseRepository.SoftDelete(ctx, filter)
}

// GetDeletedFolders retrieves soft deleted folders
func (r *folderRepository) GetDeletedFolders(ctx context.Context, params *pkg.PaginationParams) ([]*models.Folder, int64, error) {
	var folders []*models.Folder
	filter := bson.M{"deleted_at": bson.M{"$ne": nil}}

	total, err := r.BaseRepository.List(ctx, filter, params, &folders)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get deleted folders: %w", err)
	}

	return folders, total, nil
}

// Restore restores soft deleted folder
func (r *folderRepository) Restore(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	updates := map[string]interface{}{
		"deleted_at": nil,
	}
	return r.BaseRepository.Update(ctx, filter, updates)
}
