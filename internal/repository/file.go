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

type fileRepository struct {
	*BaseRepository
}

// NewFileRepository creates a new file repository
func NewFileRepository(mongodb *MongoDB) FileRepository {
	return &fileRepository{
		BaseRepository: NewBaseRepository(mongodb, "files"),
	}
}

// Create creates a new file
func (r *fileRepository) Create(ctx context.Context, file *models.File) error {
	file.ID = primitive.NewObjectID()
	file.CreatedAt = time.Now()
	file.UpdatedAt = time.Now()
	file.LastModifiedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, file)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return pkg.ErrFileAlreadyExists
		}
		return fmt.Errorf("failed to create file: %w", err)
	}
	return nil
}

// GetByID retrieves file by ID
func (r *fileRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.File, error) {
	var file models.File
	filter := bson.M{"_id": id, "deleted_at": nil}

	err := r.collection.FindOne(ctx, filter).Decode(&file)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrFileNotFound
		}
		return nil, fmt.Errorf("failed to get file by ID: %w", err)
	}

	return &file, nil
}

// GetByPath retrieves file by path
func (r *fileRepository) GetByPath(ctx context.Context, userID primitive.ObjectID, path string) (*models.File, error) {
	var file models.File
	filter := bson.M{
		"user_id":    userID,
		"path":       path,
		"deleted_at": nil,
	}

	err := r.collection.FindOne(ctx, filter).Decode(&file)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrFileNotFound
		}
		return nil, fmt.Errorf("failed to get file by path: %w", err)
	}

	return &file, nil
}

// GetByHash retrieves file by hash
func (r *fileRepository) GetByHash(ctx context.Context, hash string) (*models.File, error) {
	var file models.File
	filter := bson.M{"hash": hash, "deleted_at": nil}

	err := r.collection.FindOne(ctx, filter).Decode(&file)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrFileNotFound
		}
		return nil, fmt.Errorf("failed to get file by hash: %w", err)
	}

	return &file, nil
}

// Update updates file data
func (r *fileRepository) Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	updates["last_modified_at"] = time.Now()
	return r.BaseRepository.Update(ctx, filter, updates)
}

// Delete permanently deletes file
func (r *fileRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	return r.BaseRepository.Delete(ctx, filter)
}

// List retrieves files with pagination
func (r *fileRepository) List(ctx context.Context, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	var files []*models.File
	filter := bson.M{"deleted_at": nil}

	// Add search filter
	if params.Search != "" {
		searchFilter := r.BuildSearchFilter(params.Search, []string{"name", "description", "tags"})
		filter = bson.M{"$and": []bson.M{filter, searchFilter}}
	}

	// Add filters
	for key, value := range params.Filter {
		switch key {
		case "mime_type", "extension", "is_public", "is_favorite":
			filter[key] = value
		case "size_min":
			if val, ok := value.(string); ok {
				if size := pkg.Conversions.StringToInt64(val, 0); size > 0 {
					filter["size"] = bson.M{"$gte": size}
				}
			}
		case "size_max":
			if val, ok := value.(string); ok {
				if size := pkg.Conversions.StringToInt64(val, 0); size > 0 {
					filter["size"] = bson.M{"$lte": size}
				}
			}
		}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &files)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list files: %w", err)
	}

	return files, total, nil
}

// ListByUser retrieves user's files
func (r *fileRepository) ListByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	var files []*models.File
	filter := bson.M{"user_id": userID, "deleted_at": nil}

	// Add search filter
	if params.Search != "" {
		searchFilter := r.BuildSearchFilter(params.Search, []string{"name", "description", "tags"})
		filter = bson.M{"$and": []bson.M{filter, searchFilter}}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &files)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list user files: %w", err)
	}

	return files, total, nil
}

// ListByFolder retrieves files in folder
func (r *fileRepository) ListByFolder(ctx context.Context, folderID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	var files []*models.File
	filter := bson.M{"folder_id": folderID, "deleted_at": nil}

	total, err := r.BaseRepository.List(ctx, filter, params, &files)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list folder files: %w", err)
	}

	return files, total, nil
}

// Search searches files by query
func (r *fileRepository) Search(ctx context.Context, userID primitive.ObjectID, query string, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	var files []*models.File

	filter := bson.M{
		"user_id":    userID,
		"deleted_at": nil,
		"$text":      bson.M{"$search": query},
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &files)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search files: %w", err)
	}

	return files, total, nil
}

// GetFilesByMimeType retrieves files by MIME type
func (r *fileRepository) GetFilesByMimeType(ctx context.Context, mimeType string) ([]*models.File, error) {
	var files []*models.File
	filter := bson.M{"mime_type": mimeType, "deleted_at": nil}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get files by MIME type: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &files); err != nil {
		return nil, fmt.Errorf("failed to decode files: %w", err)
	}

	return files, nil
}

// GetLargestFiles retrieves largest files
func (r *fileRepository) GetLargestFiles(ctx context.Context, limit int) ([]*models.File, error) {
	var files []*models.File

	opts := options.Find()
	opts.SetSort(bson.M{"size": -1})
	opts.SetLimit(int64(limit))

	filter := bson.M{"deleted_at": nil}

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get largest files: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &files); err != nil {
		return nil, fmt.Errorf("failed to decode files: %w", err)
	}

	return files, nil
}

// GetRecentFiles retrieves recent files for user
func (r *fileRepository) GetRecentFiles(ctx context.Context, userID primitive.ObjectID, limit int) ([]*models.File, error) {
	var files []*models.File

	opts := options.Find()
	opts.SetSort(bson.M{"created_at": -1})
	opts.SetLimit(int64(limit))

	filter := bson.M{"user_id": userID, "deleted_at": nil}

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent files: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &files); err != nil {
		return nil, fmt.Errorf("failed to decode files: %w", err)
	}

	return files, nil
}

// GetFavoriteFiles retrieves user's favorite files
func (r *fileRepository) GetFavoriteFiles(ctx context.Context, userID primitive.ObjectID) ([]*models.File, error) {
	var files []*models.File
	filter := bson.M{
		"user_id":     userID,
		"is_favorite": true,
		"deleted_at":  nil,
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get favorite files: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &files); err != nil {
		return nil, fmt.Errorf("failed to decode files: %w", err)
	}

	return files, nil
}

// UpdateDownloadCount increments download count
func (r *fileRepository) UpdateDownloadCount(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	update := bson.M{
		"$inc": bson.M{"download_count": 1},
		"$set": bson.M{
			"last_accessed_at": time.Now(),
			"updated_at":       time.Now(),
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update download count: %w", err)
	}

	return nil
}

// UpdateViewCount increments view count
func (r *fileRepository) UpdateViewCount(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	update := bson.M{
		"$inc": bson.M{"view_count": 1},
		"$set": bson.M{
			"last_accessed_at": time.Now(),
			"updated_at":       time.Now(),
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update view count: %w", err)
	}

	return nil
}

// GetTotalStorageUsed calculates total storage used
func (r *fileRepository) GetTotalStorageUsed(ctx context.Context) (int64, error) {
	pipeline := []bson.M{
		{"$match": bson.M{"deleted_at": nil}},
		{"$group": bson.M{
			"_id":   nil,
			"total": bson.M{"$sum": "$size"},
		}},
	}

	cursor, err := r.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return 0, fmt.Errorf("failed to calculate total storage: %w", err)
	}
	defer cursor.Close(ctx)

	var result struct {
		Total int64 `bson:"total"`
	}

	if cursor.Next(ctx) {
		if err := cursor.Decode(&result); err != nil {
			return 0, fmt.Errorf("failed to decode storage result: %w", err)
		}
	}

	return result.Total, nil
}

// GetStorageByUser calculates storage used by user
func (r *fileRepository) GetStorageByUser(ctx context.Context, userID primitive.ObjectID) (int64, error) {
	pipeline := []bson.M{
		{"$match": bson.M{"user_id": userID, "deleted_at": nil}},
		{"$group": bson.M{
			"_id":   nil,
			"total": bson.M{"$sum": "$size"},
		}},
	}

	cursor, err := r.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return 0, fmt.Errorf("failed to calculate user storage: %w", err)
	}
	defer cursor.Close(ctx)

	var result struct {
		Total int64 `bson:"total"`
	}

	if cursor.Next(ctx) {
		if err := cursor.Decode(&result); err != nil {
			return 0, fmt.Errorf("failed to decode storage result: %w", err)
		}
	}

	return result.Total, nil
}

// SoftDelete soft deletes file
func (r *fileRepository) SoftDelete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	return r.BaseRepository.SoftDelete(ctx, filter)
}

// GetDeletedFiles retrieves soft deleted files
func (r *fileRepository) GetDeletedFiles(ctx context.Context, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	var files []*models.File
	filter := bson.M{"deleted_at": bson.M{"$ne": nil}}

	total, err := r.BaseRepository.List(ctx, filter, params, &files)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get deleted files: %w", err)
	}

	return files, total, nil
}

// Restore restores soft deleted file
func (r *fileRepository) Restore(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	updates := map[string]interface{}{
		"deleted_at": nil,
	}
	return r.BaseRepository.Update(ctx, filter, updates)
}

// GetOrphanedFiles retrieves files without valid folder references
func (r *fileRepository) GetOrphanedFiles(ctx context.Context) ([]*models.File, error) {
	var files []*models.File

	// Get all files with folder_id that don't exist in folders collection
	pipeline := []bson.M{
		{"$match": bson.M{
			"folder_id":  bson.M{"$ne": nil},
			"deleted_at": nil,
		}},
		{"$lookup": bson.M{
			"from":         "folders",
			"localField":   "folder_id",
			"foreignField": "_id",
			"as":           "folder",
		}},
		{"$match": bson.M{"folder": bson.M{"$size": 0}}},
	}

	cursor, err := r.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to get orphaned files: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &files); err != nil {
		return nil, fmt.Errorf("failed to decode orphaned files: %w", err)
	}

	return files, nil
}
