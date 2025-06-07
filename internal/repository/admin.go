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

type analyticsRepository struct {
	*BaseRepository
	summaryCollection       *mongo.Collection
	userAnalyticsCollection *mongo.Collection
}

// NewAnalyticsRepository creates a new analytics repository
func NewAnalyticsRepository(mongodb *MongoDB) AnalyticsRepository {
	return &analyticsRepository{
		BaseRepository:          NewBaseRepository(mongodb, "analytics"),
		summaryCollection:       mongodb.Collection("analytics_summaries"),
		userAnalyticsCollection: mongodb.Collection("user_analytics"),
	}
}

// Create creates a new analytics event
func (r *analyticsRepository) Create(ctx context.Context, analytics *models.Analytics) error {
	analytics.ID = primitive.NewObjectID()
	analytics.CreatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, analytics)
	if err != nil {
		return fmt.Errorf("failed to create analytics event: %w", err)
	}
	return nil
}

// GetByID retrieves analytics event by ID
func (r *analyticsRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.Analytics, error) {
	var analytics models.Analytics
	filter := bson.M{"_id": id}

	err := r.collection.FindOne(ctx, filter).Decode(&analytics)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrInternalServer
		}
		return nil, fmt.Errorf("failed to get analytics by ID: %w", err)
	}

	return &analytics, nil
}

// List retrieves analytics events with pagination
func (r *analyticsRepository) List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Analytics, int64, error) {
	var analytics []*models.Analytics
	filter := bson.M{}

	// Add filters
	for key, value := range params.Filter {
		switch key {
		case "event_type", "user_id", "ip":
			filter[key] = value
		case "date_from":
			if val, ok := value.(string); ok {
				if date, err := time.Parse("2006-01-02", val); err == nil {
					filter["timestamp"] = bson.M{"$gte": date}
				}
			}
		case "date_to":
			if val, ok := value.(string); ok {
				if date, err := time.Parse("2006-01-02", val); err == nil {
					if existing, exists := filter["timestamp"]; exists {
						filter["timestamp"] = bson.M{"$gte": existing.(bson.M)["$gte"], "$lte": date}
					} else {
						filter["timestamp"] = bson.M{"$lte": date}
					}
				}
			}
		}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &analytics)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list analytics: %w", err)
	}

	return analytics, total, nil
}

// GetByEventType retrieves analytics events by event type and time range
func (r *analyticsRepository) GetByEventType(ctx context.Context, eventType models.AnalyticsEventType, start, end time.Time) ([]*models.Analytics, error) {
	var analytics []*models.Analytics
	filter := bson.M{
		"event_type": eventType,
		"timestamp": bson.M{
			"$gte": start,
			"$lte": end,
		},
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get analytics by event type: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &analytics); err != nil {
		return nil, fmt.Errorf("failed to decode analytics: %w", err)
	}

	return analytics, nil
}

// GetByUser retrieves analytics events for a user
func (r *analyticsRepository) GetByUser(ctx context.Context, userID primitive.ObjectID, start, end time.Time) ([]*models.Analytics, error) {
	var analytics []*models.Analytics
	filter := bson.M{
		"user_id": userID,
		"timestamp": bson.M{
			"$gte": start,
			"$lte": end,
		},
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get analytics by user: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &analytics); err != nil {
		return nil, fmt.Errorf("failed to decode analytics: %w", err)
	}

	return analytics, nil
}

// CreateSummary creates analytics summary
func (r *analyticsRepository) CreateSummary(ctx context.Context, summary *models.AnalyticsSummary) error {
	summary.ID = primitive.NewObjectID()
	summary.CreatedAt = time.Now()
	summary.UpdatedAt = time.Now()

	_, err := r.summaryCollection.InsertOne(ctx, summary)
	if err != nil {
		return fmt.Errorf("failed to create analytics summary: %w", err)
	}
	return nil
}

// GetSummaryByDate retrieves analytics summary for a specific date
func (r *analyticsRepository) GetSummaryByDate(ctx context.Context, date time.Time) (*models.AnalyticsSummary, error) {
	var summary models.AnalyticsSummary

	// Create date range for the entire day
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	endOfDay := startOfDay.AddDate(0, 0, 1)

	filter := bson.M{
		"date": bson.M{
			"$gte": startOfDay,
			"$lt":  endOfDay,
		},
	}

	err := r.summaryCollection.FindOne(ctx, filter).Decode(&summary)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrInternalServer
		}
		return nil, fmt.Errorf("failed to get summary by date: %w", err)
	}

	return &summary, nil
}

// GetSummariesByPeriod retrieves analytics summaries for a period
func (r *analyticsRepository) GetSummariesByPeriod(ctx context.Context, start, end time.Time) ([]*models.AnalyticsSummary, error) {
	var summaries []*models.AnalyticsSummary
	filter := bson.M{
		"date": bson.M{
			"$gte": start,
			"$lte": end,
		},
	}

	opts := options.Find().SetSort(bson.M{"date": 1})

	cursor, err := r.summaryCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get summaries by period: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &summaries); err != nil {
		return nil, fmt.Errorf("failed to decode summaries: %w", err)
	}

	return summaries, nil
}

// UpdateSummary updates analytics summary
func (r *analyticsRepository) UpdateSummary(ctx context.Context, date time.Time, updates map[string]interface{}) error {
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	endOfDay := startOfDay.AddDate(0, 0, 1)

	filter := bson.M{
		"date": bson.M{
			"$gte": startOfDay,
			"$lt":  endOfDay,
		},
	}

	updates["updated_at"] = time.Now()
	update := bson.M{"$set": updates}

	_, err := r.summaryCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update analytics summary: %w", err)
	}

	return nil
}

// CreateUserAnalytics creates user analytics
func (r *analyticsRepository) CreateUserAnalytics(ctx context.Context, userAnalytics *models.UserAnalytics) error {
	userAnalytics.ID = primitive.NewObjectID()
	userAnalytics.CreatedAt = time.Now()
	userAnalytics.UpdatedAt = time.Now()

	_, err := r.userAnalyticsCollection.InsertOne(ctx, userAnalytics)
	if err != nil {
		return fmt.Errorf("failed to create user analytics: %w", err)
	}
	return nil
}

// GetUserAnalyticsByDate retrieves user analytics for specific date
func (r *analyticsRepository) GetUserAnalyticsByDate(ctx context.Context, userID primitive.ObjectID, date time.Time) (*models.UserAnalytics, error) {
	var userAnalytics models.UserAnalytics

	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	endOfDay := startOfDay.AddDate(0, 0, 1)

	filter := bson.M{
		"user_id": userID,
		"date": bson.M{
			"$gte": startOfDay,
			"$lt":  endOfDay,
		},
	}

	err := r.userAnalyticsCollection.FindOne(ctx, filter).Decode(&userAnalytics)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrInternalServer
		}
		return nil, fmt.Errorf("failed to get user analytics by date: %w", err)
	}

	return &userAnalytics, nil
}

// GetUserAnalyticsByPeriod retrieves user analytics for a period
func (r *analyticsRepository) GetUserAnalyticsByPeriod(ctx context.Context, userID primitive.ObjectID, start, end time.Time) ([]*models.UserAnalytics, error) {
	var userAnalytics []*models.UserAnalytics
	filter := bson.M{
		"user_id": userID,
		"date": bson.M{
			"$gte": start,
			"$lte": end,
		},
	}

	opts := options.Find().SetSort(bson.M{"date": 1})

	cursor, err := r.userAnalyticsCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get user analytics by period: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &userAnalytics); err != nil {
		return nil, fmt.Errorf("failed to decode user analytics: %w", err)
	}

	return userAnalytics, nil
}

// UpdateUserAnalytics updates user analytics
func (r *analyticsRepository) UpdateUserAnalytics(ctx context.Context, userID primitive.ObjectID, date time.Time, updates map[string]interface{}) error {
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	endOfDay := startOfDay.AddDate(0, 0, 1)

	filter := bson.M{
		"user_id": userID,
		"date": bson.M{
			"$gte": startOfDay,
			"$lt":  endOfDay,
		},
	}

	updates["updated_at"] = time.Now()
	update := bson.M{"$set": updates}

	_, err := r.userAnalyticsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update user analytics: %w", err)
	}

	return nil
}

// GetTopUsers retrieves top users by metric
func (r *analyticsRepository) GetTopUsers(ctx context.Context, metric string, limit int, start, end time.Time) ([]*models.UserAnalytics, error) {
	var userAnalytics []*models.UserAnalytics

	pipeline := []bson.M{
		{"$match": bson.M{
			"date": bson.M{
				"$gte": start,
				"$lte": end,
			},
		}},
		{"$group": bson.M{
			"_id":     "$user_id",
			"total":   bson.M{"$sum": "$" + metric},
			"user_id": bson.M{"$first": "$user_id"},
		}},
		{"$sort": bson.M{"total": -1}},
		{"$limit": limit},
	}

	cursor, err := r.userAnalyticsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to get top users: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &userAnalytics); err != nil {
		return nil, fmt.Errorf("failed to decode top users: %w", err)
	}

	return userAnalytics, nil
}

// GetEventCounts retrieves event counts for period
func (r *analyticsRepository) GetEventCounts(ctx context.Context, start, end time.Time) (map[string]int64, error) {
	pipeline := []bson.M{
		{"$match": bson.M{
			"timestamp": bson.M{
				"$gte": start,
				"$lte": end,
			},
		}},
		{"$group": bson.M{
			"_id":   "$event_type",
			"count": bson.M{"$sum": 1},
		}},
	}

	cursor, err := r.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to get event counts: %w", err)
	}
	defer cursor.Close(ctx)

	eventCounts := make(map[string]int64)

	for cursor.Next(ctx) {
		var result struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}

		if err := cursor.Decode(&result); err != nil {
			return nil, fmt.Errorf("failed to decode event count: %w", err)
		}

		eventCounts[result.ID] = result.Count
	}

	return eventCounts, nil
}
