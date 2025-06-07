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
	"go.mongodb.org/mongo-driver/mongo/options"
)

type adminRepository struct {
	*BaseRepository
}

// NewAdminRepository creates a new admin repository
func NewAdminRepository(mongodb *MongoDB) AdminRepository {
	return &adminRepository{
		BaseRepository: NewBaseRepository(mongodb, "admin_settings"),
	}
}

// CreateSettings creates new admin settings
func (r *adminRepository) CreateSettings(ctx context.Context, settings *models.AdminSettings) error {
	settings.ID = primitive.NewObjectID()
	settings.CreatedAt = time.Now()
	settings.UpdatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, settings)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
				"message": "Settings with this category and key already exist",
			})
		}
		return fmt.Errorf("failed to create admin settings: %w", err)
	}
	return nil
}

// GetSettings retrieves specific setting by category and key
func (r *adminRepository) GetSettings(ctx context.Context, category models.SettingsCategory, key string) (*models.AdminSettings, error) {
	var settings models.AdminSettings
	filter := bson.M{
		"category": category,
		"key":      key,
	}

	err := r.collection.FindOne(ctx, filter).Decode(&settings)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrInternalServer
		}
		return nil, fmt.Errorf("failed to get admin settings: %w", err)
	}

	return &settings, nil
}

// GetSettingsByCategory retrieves all settings in a category
func (r *adminRepository) GetSettingsByCategory(ctx context.Context, category models.SettingsCategory) ([]*models.AdminSettings, error) {
	var settings []*models.AdminSettings
	filter := bson.M{"category": category}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings by category: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &settings); err != nil {
		return nil, fmt.Errorf("failed to decode settings: %w", err)
	}

	return settings, nil
}

// UpdateSettings updates or creates a setting
func (r *adminRepository) UpdateSettings(ctx context.Context, category models.SettingsCategory, key string, value interface{}) error {
	filter := bson.M{
		"category": category,
		"key":      key,
	}

	update := bson.M{
		"$set": bson.M{
			"value":      value,
			"updated_at": time.Now(),
		},
		"$setOnInsert": bson.M{
			"_id":        primitive.NewObjectID(),
			"category":   category,
			"key":        key,
			"type":       inferSettingsType(value),
			"is_public":  false,
			"created_at": time.Now(),
		},
	}

	opts := options.UpdateOptions{}
	opts.SetUpsert(true)

	_, err := r.collection.UpdateOne(ctx, filter, update, &opts)
	if err != nil {
		return fmt.Errorf("failed to update admin settings: %w", err)
	}

	return nil
}

// DeleteSettings deletes a setting
func (r *adminRepository) DeleteSettings(ctx context.Context, category models.SettingsCategory, key string) error {
	filter := bson.M{
		"category": category,
		"key":      key,
	}

	result, err := r.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete admin settings: %w", err)
	}

	if result.DeletedCount == 0 {
		return pkg.ErrInternalServer
	}

	return nil
}

// GetAllSettings retrieves all settings
func (r *adminRepository) GetAllSettings(ctx context.Context) ([]*models.AdminSettings, error) {
	var settings []*models.AdminSettings

	cursor, err := r.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to get all settings: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &settings); err != nil {
		return nil, fmt.Errorf("failed to decode settings: %w", err)
	}

	return settings, nil
}

// GetPublicSettings retrieves public settings only
func (r *adminRepository) GetPublicSettings(ctx context.Context) ([]*models.AdminSettings, error) {
	var settings []*models.AdminSettings
	filter := bson.M{"is_public": true}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get public settings: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &settings); err != nil {
		return nil, fmt.Errorf("failed to decode settings: %w", err)
	}

	return settings, nil
}

// inferSettingsType infers the settings type from value
func inferSettingsType(value interface{}) models.SettingsType {
	switch value.(type) {
	case string:
		return models.SettingsTypeString
	case int, int32, int64, float32, float64:
		return models.SettingsTypeNumber
	case bool:
		return models.SettingsTypeBoolean
	case []interface{}:
		return models.SettingsTypeArray
	default:
		return models.SettingsTypeJSON
	}
}

// NewAuditLogRepository creates audit log repository (implement similar pattern)
func NewAuditLogRepository(mongodb *MongoDB) AuditLogRepository {
	return &auditLogRepository{
		BaseRepository: NewBaseRepository(mongodb, "audit_logs"),
	}
}

type auditLogRepository struct {
	*BaseRepository
}

// Create creates a new audit log entry
func (r *auditLogRepository) Create(ctx context.Context, log *models.AuditLog) error {
	log.ID = primitive.NewObjectID()
	log.CreatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, log)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

// GetByID retrieves audit log by ID
func (r *auditLogRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.AuditLog, error) {
	var log models.AuditLog
	filter := bson.M{"_id": id}

	err := r.collection.FindOne(ctx, filter).Decode(&log)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrInternalServer
		}
		return nil, fmt.Errorf("failed to get audit log by ID: %w", err)
	}

	return &log, nil
}

// List retrieves audit logs with pagination
func (r *auditLogRepository) List(ctx context.Context, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error) {
	var logs []*models.AuditLog
	filter := bson.M{}

	total, err := r.BaseRepository.List(ctx, filter, params, &logs)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}

	return logs, total, nil
}

// GetByUser retrieves audit logs for a user
func (r *auditLogRepository) GetByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error) {
	var logs []*models.AuditLog
	filter := bson.M{"user_id": userID}

	total, err := r.BaseRepository.List(ctx, filter, params, &logs)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs by user: %w", err)
	}

	return logs, total, nil
}

// GetByAction retrieves audit logs by action
func (r *auditLogRepository) GetByAction(ctx context.Context, action models.AuditAction, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error) {
	var logs []*models.AuditLog
	filter := bson.M{"action": action}

	total, err := r.BaseRepository.List(ctx, filter, params, &logs)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs by action: %w", err)
	}

	return logs, total, nil
}

// GetByResource retrieves audit logs for a resource
func (r *auditLogRepository) GetByResource(ctx context.Context, resourceType string, resourceID primitive.ObjectID) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	filter := bson.M{
		"resource.type": resourceType,
		"resource.id":   resourceID,
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs by resource: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &logs); err != nil {
		return nil, fmt.Errorf("failed to decode audit logs: %w", err)
	}

	return logs, nil
}

// GetBySeverity retrieves audit logs by severity
func (r *auditLogRepository) GetBySeverity(ctx context.Context, severity models.AuditSeverity, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error) {
	var logs []*models.AuditLog
	filter := bson.M{"severity": severity}

	total, err := r.BaseRepository.List(ctx, filter, params, &logs)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs by severity: %w", err)
	}

	return logs, total, nil
}

// GetByTimeRange retrieves audit logs by time range
func (r *auditLogRepository) GetByTimeRange(ctx context.Context, start, end time.Time, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error) {
	var logs []*models.AuditLog
	filter := bson.M{
		"timestamp": bson.M{
			"$gte": start,
			"$lte": end,
		},
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &logs)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs by time range: %w", err)
	}

	return logs, total, nil
}

// DeleteOldLogs deletes audit logs older than specified time
func (r *auditLogRepository) DeleteOldLogs(ctx context.Context, before time.Time) error {
	filter := bson.M{
		"timestamp": bson.M{"$lt": before},
	}

	_, err := r.collection.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete old audit logs: %w", err)
	}

	return nil
}
