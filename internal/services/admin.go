package services

import (
	"context"
	"fmt"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AdminService handles admin operations
type AdminService struct {
	adminRepo     repository.AdminRepository
	userRepo      repository.UserRepository
	fileRepo      repository.FileRepository
	analyticsRepo repository.AnalyticsRepository
	paymentRepo   repository.PaymentRepository
	auditRepo     repository.AuditLogRepository
}

// NewAdminService creates a new admin service
func NewAdminService(
	adminRepo repository.AdminRepository,
	userRepo repository.UserRepository,
	fileRepo repository.FileRepository,
	analyticsRepo repository.AnalyticsRepository,
	paymentRepo repository.PaymentRepository,
	auditRepo repository.AuditLogRepository,
) *AdminService {
	return &AdminService{
		adminRepo:     adminRepo,
		userRepo:      userRepo,
		fileRepo:      fileRepo,
		analyticsRepo: analyticsRepo,
		paymentRepo:   paymentRepo,
		auditRepo:     auditRepo,
	}
}

// SystemStats represents system statistics
type SystemStats struct {
	TotalUsers   int64   `json:"totalUsers"`
	ActiveUsers  int64   `json:"activeUsers"`
	TotalFiles   int64   `json:"totalFiles"`
	TotalStorage int64   `json:"totalStorage"`
	TotalRevenue int64   `json:"totalRevenue"`
	SystemHealth float64 `json:"systemHealth"`
	StorageUsage float64 `json:"storageUsage"`
	ErrorRate    float64 `json:"errorRate"`
}

// GetSystemStats retrieves system statistics
func (s *AdminService) GetSystemStats(ctx context.Context) (*SystemStats, error) {
	// Get user statistics
	userParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalUsers, err := s.userRepo.List(ctx, userParams)
	if err != nil {
		return nil, err
	}

	// Get active users (last 7 days)
	activeUsers, err := s.userRepo.GetActiveUsers(ctx, time.Now().AddDate(0, 0, -7))
	if err != nil {
		return nil, err
	}

	// Get file statistics
	fileParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalFiles, err := s.fileRepo.List(ctx, fileParams)
	if err != nil {
		return nil, err
	}

	// Get storage usage
	totalStorage, err := s.fileRepo.GetTotalStorageUsed(ctx)
	if err != nil {
		return nil, err
	}

	// Get revenue (last 30 days)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	totalRevenue, err := s.paymentRepo.GetRevenueByPeriod(ctx, thirtyDaysAgo, time.Now())
	if err != nil {
		return nil, err
	}

	// Calculate system health (simplified)
	systemHealth := 95.0 // This would be calculated based on various metrics

	// Calculate storage usage percentage (assuming 1TB limit)
	maxStorage := int64(1024 * 1024 * 1024 * 1024) // 1TB
	storageUsage := float64(totalStorage) / float64(maxStorage) * 100

	return &SystemStats{
		TotalUsers:   totalUsers,
		ActiveUsers:  activeUsers,
		TotalFiles:   totalFiles,
		TotalStorage: totalStorage,
		TotalRevenue: totalRevenue,
		SystemHealth: systemHealth,
		StorageUsage: storageUsage,
		ErrorRate:    2.5, // This would be calculated from error logs
	}, nil
}

// GetSettings retrieves admin settings by category
func (s *AdminService) GetSettings(ctx context.Context, category models.SettingsCategory) ([]*models.AdminSettings, error) {
	return s.adminRepo.GetSettingsByCategory(ctx, category)
}

// GetAllSettings retrieves all admin settings
func (s *AdminService) GetAllSettings(ctx context.Context) ([]*models.AdminSettings, error) {
	return s.adminRepo.GetAllSettings(ctx)
}

// UpdateSetting updates a specific setting
func (s *AdminService) UpdateSetting(ctx context.Context, adminID primitive.ObjectID, category models.SettingsCategory, key string, value interface{}) error {
	// Update setting
	if err := s.adminRepo.UpdateSettings(ctx, category, key, value); err != nil {
		return err
	}

	// Log audit event
	s.logAuditEvent(ctx, adminID, models.AuditActionSettingsUpdate, "settings", primitive.NilObjectID, true, fmt.Sprintf("Updated %s.%s", category, key))

	return nil
}

// ManageUsers provides user management functions
func (s *AdminService) ManageUsers(ctx context.Context, adminID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.User, int64, error) {
	users, total, err := s.userRepo.List(ctx, params)
	if err != nil {
		return nil, 0, err
	}

	// Remove sensitive information
	for _, user := range users {
		user.Password = ""
		user.TwoFactorSecret = ""
	}

	return users, total, nil
}

// SuspendUser suspends a user account
func (s *AdminService) SuspendUser(ctx context.Context, adminID, userID primitive.ObjectID, reason string) error {
	// Update user status
	updates := map[string]interface{}{
		"status": models.StatusSuspended,
	}

	if err := s.userRepo.Update(ctx, userID, updates); err != nil {
		return err
	}

	// Log audit event
	s.logAuditEvent(ctx, adminID, models.AuditActionUserSuspend, "user", userID, true, reason)

	return nil
}

// UnsuspendUser unsuspends a user account
func (s *AdminService) UnsuspendUser(ctx context.Context, adminID, userID primitive.ObjectID) error {
	// Update user status
	updates := map[string]interface{}{
		"status": models.StatusActive,
	}

	if err := s.userRepo.Update(ctx, userID, updates); err != nil {
		return err
	}

	// Log audit event
	s.logAuditEvent(ctx, adminID, models.AuditActionUserUnsuspend, "user", userID, true, "")

	return nil
}

// DeleteUser deletes a user account
func (s *AdminService) DeleteUser(ctx context.Context, adminID, userID primitive.ObjectID) error {
	// Soft delete user
	if err := s.userRepo.SoftDelete(ctx, userID); err != nil {
		return err
	}

	// Log audit event
	s.logAuditEvent(ctx, adminID, models.AuditActionUserDelete, "user", userID, true, "Admin deletion")

	return nil
}

// ManageFiles provides file management functions
func (s *AdminService) ManageFiles(ctx context.Context, params *pkg.PaginationParams) ([]*models.File, int64, error) {
	return s.fileRepo.List(ctx, params)
}

// DeleteFile deletes a file (admin action)
func (s *AdminService) DeleteFile(ctx context.Context, adminID, fileID primitive.ObjectID, reason string) error {
	// Get file
	file, err := s.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return err
	}

	// Soft delete file
	if err := s.fileRepo.SoftDelete(ctx, fileID); err != nil {
		return err
	}

	// Update user storage
	s.userRepo.UpdateStorageUsed(ctx, file.UserID, -file.Size)

	// Log audit event
	s.logAuditEvent(ctx, adminID, models.AuditActionFileDelete, "file", fileID, true, reason)

	return nil
}

// GetAuditLogs retrieves audit logs
func (s *AdminService) GetAuditLogs(ctx context.Context, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error) {
	return s.auditRepo.List(ctx, params)
}

// GetUserAuditLogs retrieves audit logs for specific user
func (s *AdminService) GetUserAuditLogs(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error) {
	return s.auditRepo.GetByUser(ctx, userID, params)
}

// CleanupOldData cleans up old system data
func (s *AdminService) CleanupOldData(ctx context.Context, adminID primitive.ObjectID) error {
	// Delete audit logs older than 1 year
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	if err := s.auditRepo.DeleteOldLogs(ctx, oneYearAgo); err != nil {
		return err
	}

	// Log cleanup action
	s.logAuditEvent(ctx, adminID, models.AuditActionSettingsUpdate, "system", primitive.NilObjectID, true, "Data cleanup performed")

	return nil
}

// ExportData exports system data
func (s *AdminService) ExportData(ctx context.Context, adminID primitive.ObjectID, dataType string, start, end time.Time) ([]byte, error) {
	// This would implement data export functionality
	// For now, return placeholder
	data := fmt.Sprintf("Export data for %s from %s to %s", dataType, start.Format("2006-01-02"), end.Format("2006-01-02"))

	// Log export action
	s.logAuditEvent(ctx, adminID, models.AuditActionSettingsUpdate, "export", primitive.NilObjectID, true, fmt.Sprintf("Exported %s data", dataType))

	return []byte(data), nil
}

// GetReports generates various admin reports
func (s *AdminService) GetReports(ctx context.Context, reportType string, start, end time.Time) (interface{}, error) {
	switch reportType {
	case "user_growth":
		return s.getUserGrowthReport(ctx, start, end)
	case "storage_usage":
		return s.getStorageUsageReport(ctx, start, end)
	case "revenue":
		return s.getRevenueReport(ctx, start, end)
	default:
		return nil, pkg.ErrInvalidInput
	}
}

// getUserGrowthReport generates user growth report
func (s *AdminService) getUserGrowthReport(ctx context.Context, start, end time.Time) (interface{}, error) {
	summaries, err := s.analyticsRepo.GetSummariesByPeriod(ctx, start, end)
	if err != nil {
		return nil, err
	}

	var report []map[string]interface{}
	for _, summary := range summaries {
		report = append(report, map[string]interface{}{
			"date":         summary.Date,
			"total_users":  summary.TotalUsers,
			"new_users":    summary.NewUsers,
			"active_users": summary.ActiveUsers,
		})
	}

	return report, nil
}

// getStorageUsageReport generates storage usage report
func (s *AdminService) getStorageUsageReport(ctx context.Context, start, end time.Time) (interface{}, error) {
	summaries, err := s.analyticsRepo.GetSummariesByPeriod(ctx, start, end)
	if err != nil {
		return nil, err
	}

	var report []map[string]interface{}
	for _, summary := range summaries {
		report = append(report, map[string]interface{}{
			"date":           summary.Date,
			"storage_used":   summary.StorageUsed,
			"files_uploaded": summary.FilesUploaded,
			"bandwidth_used": summary.BandwidthUsed,
		})
	}

	return report, nil
}

// getRevenueReport generates revenue report
func (s *AdminService) getRevenueReport(ctx context.Context, start, end time.Time) (interface{}, error) {
	summaries, err := s.analyticsRepo.GetSummariesByPeriod(ctx, start, end)
	if err != nil {
		return nil, err
	}

	var report []map[string]interface{}
	totalRevenue := int64(0)

	for _, summary := range summaries {
		totalRevenue += summary.TotalRevenue
		report = append(report, map[string]interface{}{
			"date":              summary.Date,
			"revenue":           summary.TotalRevenue,
			"new_subscriptions": summary.NewSubscriptions,
		})
	}

	return map[string]interface{}{
		"total_revenue": totalRevenue,
		"daily_data":    report,
	}, nil
}

// logAuditEvent logs an audit event
func (s *AdminService) logAuditEvent(ctx context.Context, adminID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
	auditLog := &models.AuditLog{
		AdminID:   &adminID,
		Action:    action,
		Resource:  models.AuditResource{Type: resourceType, ID: resourceID},
		Success:   success,
		Severity:  models.AuditSeverityMedium,
		Timestamp: time.Now(),
	}

	if !success {
		auditLog.ErrorMessage = message
		auditLog.Severity = models.AuditSeverityHigh
	}

	s.auditRepo.Create(ctx, auditLog)
}
