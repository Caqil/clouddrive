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
)

type userRepository struct {
	*BaseRepository
}

// NewUserRepository creates a new user repository
func NewUserRepository(mongodb *MongoDB) UserRepository {
	return &userRepository{
		BaseRepository: NewBaseRepository(mongodb, "users"),
	}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, user *models.User) error {
	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	if user.StorageLimit == 0 {
		user.StorageLimit = 5 * 1024 * 1024 * 1024 // 5GB default
	}

	_, err := r.collection.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return pkg.ErrEmailAlreadyTaken
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetByID retrieves user by ID
func (r *userRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.User, error) {
	var user models.User
	filter := bson.M{"_id": id, "deleted_at": nil}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

// GetByEmail retrieves user by email
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	filter := bson.M{"email": email, "deleted_at": nil}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// GetByUsername retrieves user by username
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	filter := bson.M{"username": username, "deleted_at": nil}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return &user, nil
}

// Update updates user data
func (r *userRepository) Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	return r.BaseRepository.Update(ctx, filter, updates)
}

// Delete permanently deletes user
func (r *userRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	return r.BaseRepository.Delete(ctx, filter)
}

// List retrieves users with pagination
func (r *userRepository) List(ctx context.Context, params *pkg.PaginationParams) ([]*models.User, int64, error) {
	var users []*models.User
	filter := bson.M{"deleted_at": nil}

	// Add search filter
	if params.Search != "" {
		searchFilter := r.BuildSearchFilter(params.Search, []string{"email", "username", "first_name", "last_name"})
		filter = bson.M{"$and": []bson.M{filter, searchFilter}}
	}

	// Add additional filters
	for key, value := range params.Filter {
		if key == "role" || key == "status" {
			filter[key] = value
		}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &users)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	return users, total, nil
}

// Search searches users by query
func (r *userRepository) Search(ctx context.Context, query string, params *pkg.PaginationParams) ([]*models.User, int64, error) {
	var users []*models.User

	filter := bson.M{
		"deleted_at": nil,
		"$text":      bson.M{"$search": query},
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &users)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}

	return users, total, nil
}

// GetByOAuthProvider retrieves user by OAuth provider
func (r *userRepository) GetByOAuthProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	var user models.User
	filter := bson.M{
		"oauth_providers": bson.M{
			"$elemMatch": bson.M{
				"provider":    provider,
				"provider_id": providerID,
			},
		},
		"deleted_at": nil,
	}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by OAuth provider: %w", err)
	}

	return &user, nil
}

// UpdateStorageUsed updates user's storage usage
func (r *userRepository) UpdateStorageUsed(ctx context.Context, userID primitive.ObjectID, size int64) error {
	filter := bson.M{"_id": userID, "deleted_at": nil}
	update := bson.M{
		"$inc": bson.M{"storage_used": size},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update storage used: %w", err)
	}

	return nil
}

// GetActiveUsers gets count of active users since given time
func (r *userRepository) GetActiveUsers(ctx context.Context, since time.Time) (int64, error) {
	filter := bson.M{
		"last_login_at": bson.M{"$gte": since},
		"deleted_at":    nil,
	}

	count, err := r.collection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("failed to get active users count: %w", err)
	}

	return count, nil
}

// GetUsersByRole retrieves users by role
func (r *userRepository) GetUsersByRole(ctx context.Context, role models.UserRole) ([]*models.User, error) {
	var users []*models.User
	filter := bson.M{"role": role, "deleted_at": nil}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by role: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &users); err != nil {
		return nil, fmt.Errorf("failed to decode users: %w", err)
	}

	return users, nil
}

// SoftDelete soft deletes user
func (r *userRepository) SoftDelete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id, "deleted_at": nil}
	return r.BaseRepository.SoftDelete(ctx, filter)
}

// GetDeletedUsers retrieves soft deleted users
func (r *userRepository) GetDeletedUsers(ctx context.Context, params *pkg.PaginationParams) ([]*models.User, int64, error) {
	var users []*models.User
	filter := bson.M{"deleted_at": bson.M{"$ne": nil}}

	total, err := r.BaseRepository.List(ctx, filter, params, &users)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get deleted users: %w", err)
	}

	return users, total, nil
}

// Restore restores soft deleted user
func (r *userRepository) Restore(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	updates := map[string]interface{}{
		"deleted_at": nil,
	}
	return r.BaseRepository.Update(ctx, filter, updates)
}
