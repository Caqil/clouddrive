package repository

import (
	"context"
	"fmt"
	"time"

	"clouddrive/internal/pkg"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoDB client wrapper
type MongoDB struct {
	client   *mongo.Client
	database *mongo.Database
	dbName   string
}

// Connect establishes connection to MongoDB
func Connect(uri string) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping the database to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	// Extract database name from URI or use default
	dbName := "clouddrive"
	if clientOptions := options.Client().ApplyURI(uri); clientOptions.Auth != nil {
		if clientOptions.Auth.AuthSource != "" {
			dbName = clientOptions.Auth.AuthSource
		}
	}

	db := client.Database(dbName)

	mongoDB := &MongoDB{
		client:   client,
		database: db,
		dbName:   dbName,
	}

	// Create indexes
	if err := mongoDB.createIndexes(); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	return mongoDB, nil
}

// Disconnect closes the MongoDB connection
func (m *MongoDB) Disconnect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.client.Disconnect(ctx)
}

// Database returns the database instance
func (m *MongoDB) Database() *mongo.Database {
	return m.database
}

// Collection returns a collection instance
func (m *MongoDB) Collection(name string) *mongo.Collection {
	return m.database.Collection(name)
}

// createIndexes creates all necessary indexes
func (m *MongoDB) createIndexes() error {
	ctx := context.Background()

	// User indexes
	userIndexes := []mongo.IndexModel{
		{Keys: bson.M{"email": 1}, Options: options.Index().SetUnique(true)},
		{Keys: bson.M{"username": 1}, Options: options.Index().SetUnique(true)},
		{Keys: bson.M{"oauth_providers.provider": 1, "oauth_providers.provider_id": 1}},
		{Keys: bson.M{"created_at": -1}},
		{Keys: bson.M{"last_login_at": -1}},
		{Keys: bson.M{"role": 1}},
		{Keys: bson.M{"status": 1}},
	}
	if _, err := m.Collection("users").Indexes().CreateMany(ctx, userIndexes); err != nil {
		return fmt.Errorf("failed to create user indexes: %w", err)
	}

	// File indexes
	fileIndexes := []mongo.IndexModel{
		{Keys: bson.M{"user_id": 1, "path": 1}, Options: options.Index().SetUnique(true)},
		{Keys: bson.M{"user_id": 1, "folder_id": 1}},
		{Keys: bson.M{"hash": 1}},
		{Keys: bson.M{"mime_type": 1}},
		{Keys: bson.M{"created_at": -1}},
		{Keys: bson.M{"size": -1}},
		{Keys: bson.M{"name": "text", "description": "text"}},
		{Keys: bson.M{"is_favorite": 1}},
		{Keys: bson.M{"tags": 1}},
	}
	if _, err := m.Collection("files").Indexes().CreateMany(ctx, fileIndexes); err != nil {
		return fmt.Errorf("failed to create file indexes: %w", err)
	}

	// Folder indexes
	folderIndexes := []mongo.IndexModel{
		{Keys: bson.M{"user_id": 1, "path": 1}, Options: options.Index().SetUnique(true)},
		{Keys: bson.M{"user_id": 1, "parent_id": 1}},
		{Keys: bson.M{"parent_id": 1}},
		{Keys: bson.M{"user_id": 1, "is_root": 1}},
		{Keys: bson.M{"created_at": -1}},
	}
	if _, err := m.Collection("folders").Indexes().CreateMany(ctx, folderIndexes); err != nil {
		return fmt.Errorf("failed to create folder indexes: %w", err)
	}

	// Share indexes
	shareIndexes := []mongo.IndexModel{
		{Keys: bson.M{"token": 1}, Options: options.Index().SetUnique(true)},
		{Keys: bson.M{"user_id": 1}},
		{Keys: bson.M{"resource_type": 1, "resource_id": 1}},
		{Keys: bson.M{"expires_at": 1}},
		{Keys: bson.M{"created_at": -1}},
	}
	if _, err := m.Collection("shares").Indexes().CreateMany(ctx, shareIndexes); err != nil {
		return fmt.Errorf("failed to create share indexes: %w", err)
	}

	// Subscription indexes
	subscriptionIndexes := []mongo.IndexModel{
		{Keys: bson.M{"user_id": 1}, Options: options.Index().SetUnique(true)},
		{Keys: bson.M{"stripe_subscription_id": 1}},
		{Keys: bson.M{"paypal_subscription_id": 1}},
		{Keys: bson.M{"status": 1}},
		{Keys: bson.M{"current_period_end": 1}},
	}
	if _, err := m.Collection("subscriptions").Indexes().CreateMany(ctx, subscriptionIndexes); err != nil {
		return fmt.Errorf("failed to create subscription indexes: %w", err)
	}

	// Payment indexes
	paymentIndexes := []mongo.IndexModel{
		{Keys: bson.M{"user_id": 1}},
		{Keys: bson.M{"provider_payment_id": 1}},
		{Keys: bson.M{"status": 1}},
		{Keys: bson.M{"created_at": -1}},
		{Keys: bson.M{"invoice_id": 1}},
	}
	if _, err := m.Collection("payments").Indexes().CreateMany(ctx, paymentIndexes); err != nil {
		return fmt.Errorf("failed to create payment indexes: %w", err)
	}

	// Analytics indexes
	analyticsIndexes := []mongo.IndexModel{
		{Keys: bson.M{"user_id": 1, "timestamp": -1}},
		{Keys: bson.M{"event_type": 1, "timestamp": -1}},
		{Keys: bson.M{"timestamp": -1}},
		{Keys: bson.M{"resource.type": 1, "resource.id": 1}},
		{Keys: bson.M{"ip": 1}},
	}
	if _, err := m.Collection("analytics").Indexes().CreateMany(ctx, analyticsIndexes); err != nil {
		return fmt.Errorf("failed to create analytics indexes: %w", err)
	}

	// Audit log indexes
	auditIndexes := []mongo.IndexModel{
		{Keys: bson.M{"user_id": 1, "timestamp": -1}},
		{Keys: bson.M{"action": 1, "timestamp": -1}},
		{Keys: bson.M{"resource.type": 1, "resource.id": 1}},
		{Keys: bson.M{"severity": 1, "timestamp": -1}},
		{Keys: bson.M{"timestamp": -1}},
		{Keys: bson.M{"ip": 1}},
	}
	if _, err := m.Collection("audit_logs").Indexes().CreateMany(ctx, auditIndexes); err != nil {
		return fmt.Errorf("failed to create audit log indexes: %w", err)
	}

	// Admin settings indexes
	settingsIndexes := []mongo.IndexModel{
		{Keys: bson.M{"category": 1, "key": 1}, Options: options.Index().SetUnique(true)},
		{Keys: bson.M{"category": 1}},
		{Keys: bson.M{"is_public": 1}},
	}
	if _, err := m.Collection("admin_settings").Indexes().CreateMany(ctx, settingsIndexes); err != nil {
		return fmt.Errorf("failed to create settings indexes: %w", err)
	}

	return nil
}

// BaseRepository provides common repository functionality
type BaseRepository struct {
	collection *mongo.Collection
	mongodb    *MongoDB
}

// NewBaseRepository creates a new base repository
func NewBaseRepository(mongodb *MongoDB, collectionName string) *BaseRepository {
	return &BaseRepository{
		collection: mongodb.Collection(collectionName),
		mongodb:    mongodb,
	}
}

// Create inserts a document
func (r *BaseRepository) Create(ctx context.Context, document interface{}) error {
	_, err := r.collection.InsertOne(ctx, document)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return pkg.ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to create document: %w", err)
	}
	return nil
}

// GetByID retrieves a document by ID
func (r *BaseRepository) GetByID(ctx context.Context, id primitive.ObjectID, result interface{}) error {
	filter := bson.M{"_id": id}
	err := r.collection.FindOne(ctx, filter).Decode(result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return pkg.ErrUserNotFound
		}
		return fmt.Errorf("failed to get document by ID: %w", err)
	}
	return nil
}

// Update updates a document
func (r *BaseRepository) Update(ctx context.Context, filter bson.M, updates map[string]interface{}) error {
	updates["updated_at"] = time.Now()
	update := bson.M{"$set": updates}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update document: %w", err)
	}

	if result.MatchedCount == 0 {
		return pkg.ErrUserNotFound
	}

	return nil
}

// Delete deletes a document
func (r *BaseRepository) Delete(ctx context.Context, filter bson.M) error {
	result, err := r.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete document: %w", err)
	}

	if result.DeletedCount == 0 {
		return pkg.ErrUserNotFound
	}

	return nil
}

// SoftDelete performs soft delete
func (r *BaseRepository) SoftDelete(ctx context.Context, filter bson.M) error {
	updates := map[string]interface{}{
		"deleted_at": time.Now(),
		"updated_at": time.Now(),
	}
	return r.Update(ctx, filter, updates)
}

// List retrieves documents with pagination
func (r *BaseRepository) List(ctx context.Context, filter bson.M, params *pkg.PaginationParams, results interface{}) (int64, error) {
	// Count total documents
	total, err := r.collection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("failed to count documents: %w", err)
	}

	// Find options
	opts := options.Find()
	opts.SetSkip(int64(params.GetOffset()))
	opts.SetLimit(int64(params.Limit))

	// Sort
	sort := bson.M{params.Sort: params.GetSortDirection()}
	opts.SetSort(sort)

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return 0, fmt.Errorf("failed to find documents: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, results); err != nil {
		return 0, fmt.Errorf("failed to decode documents: %w", err)
	}

	return total, nil
}

// BuildSearchFilter builds search filter for text search
func (r *BaseRepository) BuildSearchFilter(query string, fields []string) bson.M {
	if query == "" {
		return bson.M{}
	}

	var orConditions []bson.M
	for _, field := range fields {
		orConditions = append(orConditions, bson.M{
			field: bson.M{"$regex": query, "$options": "i"},
		})
	}

	return bson.M{"$or": orConditions}
}

// NewRepositories creates all repository instances
func NewRepositories(mongodb *MongoDB) *Repository {
	return &Repository{
		User:         NewUserRepository(mongodb),
		File:         NewFileRepository(mongodb),
		Folder:       NewFolderRepository(mongodb),
		Share:        NewShareRepository(mongodb),
		Subscription: NewSubscriptionRepository(mongodb),
		Payment:      NewPaymentRepository(mongodb),
		Analytics:    NewAnalyticsRepository(mongodb),
		Admin:        NewAdminRepository(mongodb),
		AuditLog:     NewAuditLogRepository(mongodb),
	}
}
