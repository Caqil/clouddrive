package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type shareRepository struct {
	*BaseRepository
}

// NewShareRepository creates a new share repository
func NewShareRepository(mongodb *MongoDB) ShareRepository {
	return &shareRepository{
		BaseRepository: NewBaseRepository(mongodb, "shares"),
	}
}

// Create creates a new share
func (r *shareRepository) Create(ctx context.Context, share *models.Share) error {
	share.ID = primitive.NewObjectID()
	share.CreatedAt = time.Now()
	share.UpdatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, share)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
				"message": "Share token already exists",
			})
		}
		return fmt.Errorf("failed to create share: %w", err)
	}
	return nil
}

// GetByID retrieves share by ID
func (r *shareRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.Share, error) {
	var share models.Share
	filter := bson.M{"_id": id, "deleted_at": nil}

	err := r.collection.FindOne(ctx, filter).Decode(&share)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrShareNotFound
		}
		return nil, fmt.Errorf("failed to get share by ID: %w", err)
	}

	return &share, nil
}

// GetByToken retrieves share by token
func (r *shareRepository) GetByToken(ctx context.Context, token string) (*models.Share, error) {
	var share models.Share
	filter := bson.M{"token": token, "deleted_at": nil}

	err := r.collection.FindOne(ctx, filter).Decode(&share)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrShareNotFound
		}
		return nil, fmt.Errorf("failed to get share by token: %w", err)
	}

	// Check if share is expired
	if share.ExpiresAt != nil && share.ExpiresAt.Before(time.Now()) {
		return nil, pkg.ErrShareExpired
	}

	// Check if share is active
	if !share.IsActive {
		return nil, pkg.ErrShareNotFound
	}

	return &share, nil
}

// Update updates share data
func (r *shareRepository) Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	return r.BaseRepository.Update(ctx, filter, updates)
}

// Delete permanently deletes share
func (r *shareRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	return r.BaseRepository.Delete(ctx, filter)
}

// List retrieves shares with pagination
func (r *shareRepository) List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Share, int64, error) {
	var shares []*models.Share
	filter := bson.M{"deleted_at": nil}

	// Add search filter
	if params.Search != "" {
		searchFilter := r.BuildSearchFilter(params.Search, []string{"custom_message"})
		filter = bson.M{"$and": []bson.M{filter, searchFilter}}
	}

	// Add filters
	for key, value := range params.Filter {
		switch key {
		case "resource_type", "share_type", "permission", "is_active":
			filter[key] = value
		case "user_id":
			if userID, err := primitive.ObjectIDFromHex(value.(string)); err == nil {
				filter["user_id"] = userID
			}
		case "expired":
			if expired := pkg.Conversions.StringToBool(value.(string), false); expired {
				filter["expires_at"] = bson.M{"$lt": time.Now()}
			} else {
				filter["$or"] = []bson.M{
					{"expires_at": nil},
					{"expires_at": bson.M{"$gte": time.Now()}},
				}
			}
		}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &shares)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list shares: %w", err)
	}

	return shares, total, nil
}

// ListByUser retrieves user's shares
func (r *shareRepository) ListByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Share, int64, error) {
	var shares []*models.Share
	filter := bson.M{"user_id": userID, "deleted_at": nil}

	// Add search filter
	if params.Search != "" {
		searchFilter := r.BuildSearchFilter(params.Search, []string{"custom_message"})
		filter = bson.M{"$and": []bson.M{filter, searchFilter}}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &shares)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list user shares: %w", err)
	}

	return shares, total, nil
}

// ListByResource retrieves shares for a resource
func (r *shareRepository) ListByResource(ctx context.Context, resourceType models.ShareResourceType, resourceID primitive.ObjectID) ([]*models.Share, error) {
	var shares []*models.Share
	filter := bson.M{
		"resource_type": resourceType,
		"resource_id":   resourceID,
		"deleted_at":    nil,
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list shares by resource: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &shares); err != nil {
		return nil, fmt.Errorf("failed to decode shares: %w", err)
	}

	return shares, nil
}

// GetExpiredShares retrieves expired shares
func (r *shareRepository) GetExpiredShares(ctx context.Context) ([]*models.Share, error) {
	var shares []*models.Share
	filter := bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
		"is_active":  true,
		"deleted_at": nil,
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get expired shares: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &shares); err != nil {
		return nil, fmt.Errorf("failed to decode expired shares: %w", err)
	}

	return shares, nil
}

// UpdateDownloadCount increments download count
func (r *shareRepository) UpdateDownloadCount(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	update := bson.M{
		"$inc": bson.M{"download_count": 1},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update download count: %w", err)
	}

	return nil
}

// UpdateViewCount increments view count
func (r *shareRepository) UpdateViewCount(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	update := bson.M{
		"$inc": bson.M{"view_count": 1},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update view count: %w", err)
	}

	return nil
}

// AddAccessLog adds access log to share
func (r *shareRepository) AddAccessLog(ctx context.Context, id primitive.ObjectID, access models.ShareAccess) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	update := bson.M{
		"$push": bson.M{"access_log": access},
		"$set":  bson.M{"updated_at": time.Now()},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to add access log: %w", err)
	}

	return nil
}

// SoftDelete soft deletes share
func (r *shareRepository) SoftDelete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	return r.BaseRepository.SoftDelete(ctx, filter)
}
