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

type subscriptionRepository struct {
	*BaseRepository
	planCollection *mongo.Collection
}

// NewSubscriptionRepository creates a new subscription repository
func NewSubscriptionRepository(mongodb *MongoDB) SubscriptionRepository {
	return &subscriptionRepository{
		BaseRepository: NewBaseRepository(mongodb, "subscriptions"),
		planCollection: mongodb.Collection("subscription_plans"),
	}
}

// Create creates a new subscription
func (r *subscriptionRepository) Create(ctx context.Context, subscription *models.Subscription) error {
	subscription.ID = primitive.NewObjectID()
	subscription.CreatedAt = time.Now()
	subscription.UpdatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, subscription)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return pkg.ErrSubscriptionNotFound // User already has a subscription
		}
		return fmt.Errorf("failed to create subscription: %w", err)
	}
	return nil
}

// GetByID retrieves subscription by ID
func (r *subscriptionRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.Subscription, error) {
	var subscription models.Subscription
	filter := bson.M{"_id": id}

	err := r.collection.FindOne(ctx, filter).Decode(&subscription)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrSubscriptionNotFound
		}
		return nil, fmt.Errorf("failed to get subscription by ID: %w", err)
	}

	return &subscription, nil
}

// GetByUserID retrieves subscription by user ID
func (r *subscriptionRepository) GetByUserID(ctx context.Context, userID primitive.ObjectID) (*models.Subscription, error) {
	var subscription models.Subscription
	filter := bson.M{"user_id": userID}

	err := r.collection.FindOne(ctx, filter).Decode(&subscription)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrSubscriptionNotFound
		}
		return nil, fmt.Errorf("failed to get subscription by user ID: %w", err)
	}

	return &subscription, nil
}

// GetByStripeSubscriptionID retrieves subscription by Stripe subscription ID
func (r *subscriptionRepository) GetByStripeSubscriptionID(ctx context.Context, stripeID string) (*models.Subscription, error) {
	var subscription models.Subscription
	filter := bson.M{"stripe_subscription_id": stripeID}

	err := r.collection.FindOne(ctx, filter).Decode(&subscription)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrSubscriptionNotFound
		}
		return nil, fmt.Errorf("failed to get subscription by Stripe ID: %w", err)
	}

	return &subscription, nil
}

// GetByPayPalSubscriptionID retrieves subscription by PayPal subscription ID
func (r *subscriptionRepository) GetByPayPalSubscriptionID(ctx context.Context, paypalID string) (*models.Subscription, error) {
	var subscription models.Subscription
	filter := bson.M{"paypal_subscription_id": paypalID}

	err := r.collection.FindOne(ctx, filter).Decode(&subscription)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrSubscriptionNotFound
		}
		return nil, fmt.Errorf("failed to get subscription by PayPal ID: %w", err)
	}

	return &subscription, nil
}

// Update updates subscription data
func (r *subscriptionRepository) Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	filter := bson.M{"_id": id}
	return r.BaseRepository.Update(ctx, filter, updates)
}

// Delete permanently deletes subscription
func (r *subscriptionRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	return r.BaseRepository.Delete(ctx, filter)
}

// List retrieves subscriptions with pagination
func (r *subscriptionRepository) List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Subscription, int64, error) {
	var subscriptions []*models.Subscription
	filter := bson.M{}

	// Add filters
	for key, value := range params.Filter {
		if key == "status" {
			filter[key] = value
		}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &subscriptions)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	return subscriptions, total, nil
}

// GetActiveSubscriptions retrieves active subscriptions
func (r *subscriptionRepository) GetActiveSubscriptions(ctx context.Context) ([]*models.Subscription, error) {
	var subscriptions []*models.Subscription
	filter := bson.M{"status": models.SubscriptionStatusActive}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get active subscriptions: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &subscriptions); err != nil {
		return nil, fmt.Errorf("failed to decode subscriptions: %w", err)
	}

	return subscriptions, nil
}

// GetExpiringSubscriptions retrieves subscriptions expiring within days
func (r *subscriptionRepository) GetExpiringSubscriptions(ctx context.Context, days int) ([]*models.Subscription, error) {
	var subscriptions []*models.Subscription

	expiryDate := time.Now().AddDate(0, 0, days)
	filter := bson.M{
		"status": models.SubscriptionStatusActive,
		"current_period_end": bson.M{
			"$lte": expiryDate,
		},
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get expiring subscriptions: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &subscriptions); err != nil {
		return nil, fmt.Errorf("failed to decode subscriptions: %w", err)
	}

	return subscriptions, nil
}

// GetSubscriptionsByStatus retrieves subscriptions by status
func (r *subscriptionRepository) GetSubscriptionsByStatus(ctx context.Context, status models.SubscriptionStatus) ([]*models.Subscription, error) {
	var subscriptions []*models.Subscription
	filter := bson.M{"status": status}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscriptions by status: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &subscriptions); err != nil {
		return nil, fmt.Errorf("failed to decode subscriptions: %w", err)
	}

	return subscriptions, nil
}

// CreatePlan creates a new subscription plan
func (r *subscriptionRepository) CreatePlan(ctx context.Context, plan *models.SubscriptionPlan) error {
	plan.ID = primitive.NewObjectID()
	plan.CreatedAt = time.Now()
	plan.UpdatedAt = time.Now()

	_, err := r.planCollection.InsertOne(ctx, plan)
	if err != nil {
		return fmt.Errorf("failed to create subscription plan: %w", err)
	}
	return nil
}

// GetPlanByID retrieves subscription plan by ID
func (r *subscriptionRepository) GetPlanByID(ctx context.Context, id primitive.ObjectID) (*models.SubscriptionPlan, error) {
	var plan models.SubscriptionPlan
	filter := bson.M{"_id": id}

	err := r.planCollection.FindOne(ctx, filter).Decode(&plan)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrPlanNotFound
		}
		return nil, fmt.Errorf("failed to get subscription plan by ID: %w", err)
	}

	return &plan, nil
}

// GetActivePlans retrieves active subscription plans
func (r *subscriptionRepository) GetActivePlans(ctx context.Context) ([]*models.SubscriptionPlan, error) {
	var plans []*models.SubscriptionPlan
	filter := bson.M{"is_active": true}

	opts := options.Find().SetSort(bson.M{"sort_order": 1})

	cursor, err := r.planCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get active plans: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &plans); err != nil {
		return nil, fmt.Errorf("failed to decode plans: %w", err)
	}

	return plans, nil
}

// UpdatePlan updates subscription plan
func (r *subscriptionRepository) UpdatePlan(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	filter := bson.M{"_id": id}
	updates["updated_at"] = time.Now()
	update := bson.M{"$set": updates}

	result, err := r.planCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update subscription plan: %w", err)
	}

	if result.MatchedCount == 0 {
		return pkg.ErrPlanNotFound
	}

	return nil
}

// DeletePlan deletes subscription plan
func (r *subscriptionRepository) DeletePlan(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}

	result, err := r.planCollection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete subscription plan: %w", err)
	}

	if result.DeletedCount == 0 {
		return pkg.ErrPlanNotFound
	}

	return nil
}
