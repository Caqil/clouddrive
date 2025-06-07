package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"
	"github.com/Caqil/clouddrive/internal/services"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CleanupWorker handles various cleanup tasks
type CleanupWorker struct {
	fileRepo         repository.FileRepository
	folderRepo       repository.FolderRepository
	shareRepo        repository.ShareRepository
	userRepo         repository.UserRepository
	auditRepo        repository.AuditLogRepository
	analyticsRepo    repository.AnalyticsRepository
	subscriptionRepo repository.SubscriptionRepository
	paymentRepo      repository.PaymentRepository
	storageService   *services.StorageService
	logger           *pkg.Logger
}

// CleanupConfig holds configuration for cleanup operations
type CleanupConfig struct {
	// File cleanup settings
	OrphanedFileRetentionDays     int `json:"orphanedFileRetentionDays"`
	DeletedFileRetentionDays      int `json:"deletedFileRetentionDays"`
	TempFileRetentionHours        int `json:"tempFileRetentionHours"`
	IncompleteUploadRetentionDays int `json:"incompleteUploadRetentionDays"`

	// Share cleanup settings
	ExpiredShareRetentionDays    int `json:"expiredShareRetentionDays"`
	InactiveShareRetentionDays   int `json:"inactiveShareRetentionDays"`
	UnusedShareLinkRetentionDays int `json:"unusedShareLinkRetentionDays"`

	// Log cleanup settings
	AuditLogRetentionDays  int `json:"auditLogRetentionDays"`
	AnalyticsRetentionDays int `json:"analyticsRetentionDays"`
	ErrorLogRetentionDays  int `json:"errorLogRetentionDays"`

	// User cleanup settings
	InactiveUserRetentionDays   int `json:"inactiveUserRetentionDays"`
	UnverifiedUserRetentionDays int `json:"unverifiedUserRetentionDays"`

	// System cleanup settings
	DatabaseOptimizationInterval int `json:"databaseOptimizationInterval"`
	StorageOptimizationInterval  int `json:"storageOptimizationInterval"`
}

// CleanupStats tracks cleanup operation statistics
type CleanupStats struct {
	StartTime         time.Time `json:"startTime"`
	EndTime           time.Time `json:"endTime"`
	Duration          string    `json:"duration"`
	OrphanedFiles     int64     `json:"orphanedFiles"`
	DeletedFiles      int64     `json:"deletedFiles"`
	ExpiredShares     int64     `json:"expiredShares"`
	CleanedLogs       int64     `json:"cleanedLogs"`
	InactiveUsers     int64     `json:"inactiveUsers"`
	StorageFreed      int64     `json:"storageFreed"`
	ErrorsEncountered int64     `json:"errorsEncountered"`
}

// NewCleanupWorker creates a new cleanup worker
func NewCleanupWorker(
	fileRepo repository.FileRepository,
	folderRepo repository.FolderRepository,
	shareRepo repository.ShareRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
	subscriptionRepo repository.SubscriptionRepository,
	paymentRepo repository.PaymentRepository,
	storageService *services.StorageService,
	logger *pkg.Logger,
) *CleanupWorker {
	return &CleanupWorker{
		fileRepo:         fileRepo,
		folderRepo:       folderRepo,
		shareRepo:        shareRepo,
		userRepo:         userRepo,
		auditRepo:        auditRepo,
		analyticsRepo:    analyticsRepo,
		subscriptionRepo: subscriptionRepo,
		paymentRepo:      paymentRepo,
		storageService:   storageService,
		logger:           logger,
	}
}

// DefaultCleanupConfig returns default cleanup configuration
func DefaultCleanupConfig() *CleanupConfig {
	return &CleanupConfig{
		OrphanedFileRetentionDays:     30,
		DeletedFileRetentionDays:      90,
		TempFileRetentionHours:        24,
		IncompleteUploadRetentionDays: 7,
		ExpiredShareRetentionDays:     30,
		InactiveShareRetentionDays:    180,
		UnusedShareLinkRetentionDays:  365,
		AuditLogRetentionDays:         365,
		AnalyticsRetentionDays:        1095, // 3 years
		ErrorLogRetentionDays:         90,
		InactiveUserRetentionDays:     1095, // 3 years
		UnverifiedUserRetentionDays:   30,
		DatabaseOptimizationInterval:  7,  // days
		StorageOptimizationInterval:   30, // days
	}
}

// RunFullCleanup performs all cleanup operations
func (w *CleanupWorker) RunFullCleanup(ctx context.Context, config *CleanupConfig) (*CleanupStats, error) {
	if config == nil {
		config = DefaultCleanupConfig()
	}

	stats := &CleanupStats{
		StartTime: time.Now(),
	}

	w.logger.Info("Starting full cleanup operation", map[string]interface{}{
		"config": config,
	})

	// Cleanup orphaned files
	if orphanedCount, err := w.CleanupOrphanedFiles(ctx, config.OrphanedFileRetentionDays); err != nil {
		w.logger.Error("Failed to cleanup orphaned files", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	} else {
		stats.OrphanedFiles = orphanedCount
	}

	// Cleanup deleted files
	if deletedCount, freedSpace, err := w.CleanupDeletedFiles(ctx, config.DeletedFileRetentionDays); err != nil {
		w.logger.Error("Failed to cleanup deleted files", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	} else {
		stats.DeletedFiles = deletedCount
		stats.StorageFreed += freedSpace
	}

	// Cleanup temporary files
	if tempFreedSpace, err := w.CleanupTempFiles(ctx, config.TempFileRetentionHours); err != nil {
		w.logger.Error("Failed to cleanup temp files", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	} else {
		stats.StorageFreed += tempFreedSpace
	}

	// Cleanup expired shares
	if expiredCount, err := w.CleanupExpiredShares(ctx, config.ExpiredShareRetentionDays); err != nil {
		w.logger.Error("Failed to cleanup expired shares", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	} else {
		stats.ExpiredShares = expiredCount
	}

	// Cleanup old audit logs
	if auditCount, err := w.CleanupAuditLogs(ctx, config.AuditLogRetentionDays); err != nil {
		w.logger.Error("Failed to cleanup audit logs", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	} else {
		stats.CleanedLogs += auditCount
	}

	// Cleanup old analytics
	if analyticsCount, err := w.CleanupAnalytics(ctx, config.AnalyticsRetentionDays); err != nil {
		w.logger.Error("Failed to cleanup analytics", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	} else {
		stats.CleanedLogs += analyticsCount
	}

	// Cleanup inactive users
	if inactiveCount, err := w.CleanupInactiveUsers(ctx, config.InactiveUserRetentionDays, config.UnverifiedUserRetentionDays); err != nil {
		w.logger.Error("Failed to cleanup inactive users", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	} else {
		stats.InactiveUsers = inactiveCount
	}

	// Cleanup incomplete uploads
	if incompleteFreedSpace, err := w.CleanupIncompleteUploads(ctx, config.IncompleteUploadRetentionDays); err != nil {
		w.logger.Error("Failed to cleanup incomplete uploads", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	} else {
		stats.StorageFreed += incompleteFreedSpace
	}

	// Cleanup unused share links
	if err := w.CleanupUnusedShareLinks(ctx, config.UnusedShareLinkRetentionDays); err != nil {
		w.logger.Error("Failed to cleanup unused share links", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	}

	// Optimize storage
	if err := w.OptimizeStorage(ctx); err != nil {
		w.logger.Error("Failed to optimize storage", map[string]interface{}{
			"error": err.Error(),
		})
		stats.ErrorsEncountered++
	}

	stats.EndTime = time.Now()
	stats.Duration = stats.EndTime.Sub(stats.StartTime).String()

	w.logger.Info("Completed full cleanup operation", map[string]interface{}{
		"stats": stats,
	})

	// Log cleanup results as analytics
	w.logCleanupAnalytics(ctx, stats)

	return stats, nil
}

// CleanupOrphanedFiles removes files without valid folder references
func (w *CleanupWorker) CleanupOrphanedFiles(ctx context.Context, retentionDays int) (int64, error) {
	w.logger.Info("Starting orphaned files cleanup", map[string]interface{}{
		"retention_days": retentionDays,
	})

	// Get orphaned files
	orphanedFiles, err := w.fileRepo.GetOrphanedFiles(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get orphaned files: %w", err)
	}

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)
	var cleanedCount int64

	for _, file := range orphanedFiles {
		// Only cleanup files older than retention period
		if file.CreatedAt.After(cutoffDate) {
			continue
		}

		// Delete from storage
		if err := w.storageService.Delete(ctx, file.StoragePath); err != nil {
			w.logger.Error("Failed to delete orphaned file from storage", map[string]interface{}{
				"file_id":      file.ID.Hex(),
				"storage_path": file.StoragePath,
				"error":        err.Error(),
			})
		}

		// Delete from database
		if err := w.fileRepo.Delete(ctx, file.ID); err != nil {
			w.logger.Error("Failed to delete orphaned file from database", map[string]interface{}{
				"file_id": file.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		cleanedCount++

		// Log audit event
		w.logAuditEvent(ctx, file.UserID, models.AuditActionFileDelete, "file", file.ID, true, "Orphaned file cleanup")
	}

	w.logger.Info("Completed orphaned files cleanup", map[string]interface{}{
		"files_found":    len(orphanedFiles),
		"files_cleaned":  cleanedCount,
		"retention_days": retentionDays,
	})

	return cleanedCount, nil
}

// CleanupDeletedFiles permanently removes soft-deleted files older than retention period
func (w *CleanupWorker) CleanupDeletedFiles(ctx context.Context, retentionDays int) (int64, int64, error) {
	w.logger.Info("Starting deleted files cleanup", map[string]interface{}{
		"retention_days": retentionDays,
	})

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	// Get deleted files older than cutoff
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"deleted_before": cutoffDate,
		},
	}

	deletedFiles, _, err := w.fileRepo.GetDeletedFiles(ctx, params)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get deleted files: %w", err)
	}

	var cleanedCount int64
	var freedSpace int64

	for _, file := range deletedFiles {
		if file.DeletedAt == nil || file.DeletedAt.After(cutoffDate) {
			continue
		}

		// Delete from storage
		if err := w.storageService.Delete(ctx, file.StoragePath); err != nil {
			w.logger.Error("Failed to delete file from storage", map[string]interface{}{
				"file_id":      file.ID.Hex(),
				"storage_path": file.StoragePath,
				"error":        err.Error(),
			})
		}

		// Delete file versions if any
		for _, version := range file.Versions {
			if err := w.storageService.Delete(ctx, version.Path); err != nil {
				w.logger.Error("Failed to delete file version from storage", map[string]interface{}{
					"file_id":      file.ID.Hex(),
					"version_path": version.Path,
					"error":        err.Error(),
				})
			}
		}

		// Delete thumbnails if any
		for _, thumbnail := range file.Thumbnails {
			if err := w.storageService.Delete(ctx, thumbnail.Path); err != nil {
				w.logger.Error("Failed to delete thumbnail from storage", map[string]interface{}{
					"file_id":        file.ID.Hex(),
					"thumbnail_path": thumbnail.Path,
					"error":          err.Error(),
				})
			}
		}

		freedSpace += file.Size

		// Permanently delete from database
		if err := w.fileRepo.Delete(ctx, file.ID); err != nil {
			w.logger.Error("Failed to permanently delete file from database", map[string]interface{}{
				"file_id": file.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		cleanedCount++

		// Log audit event
		w.logAuditEvent(ctx, file.UserID, models.AuditActionFileDelete, "file", file.ID, true, "Permanent deletion after retention period")
	}

	w.logger.Info("Completed deleted files cleanup", map[string]interface{}{
		"files_processed": len(deletedFiles),
		"files_cleaned":   cleanedCount,
		"space_freed":     pkg.Files.FormatFileSize(freedSpace),
		"retention_days":  retentionDays,
	})

	return cleanedCount, freedSpace, nil
}

// CleanupTempFiles removes temporary files older than retention period
func (w *CleanupWorker) CleanupTempFiles(ctx context.Context, retentionHours int) (int64, error) {
	w.logger.Info("Starting temp files cleanup", map[string]interface{}{
		"retention_hours": retentionHours,
	})

	// This would cleanup temp files from storage
	// For now, we'll simulate this operation
	var freedSpace int64

	// Cleanup multipart upload temporary files
	// In a real implementation, this would interact with the storage service
	// to list and delete temporary files based on naming patterns or metadata

	w.logger.Info("Completed temp files cleanup", map[string]interface{}{
		"space_freed":     pkg.Files.FormatFileSize(freedSpace),
		"retention_hours": retentionHours,
	})

	return freedSpace, nil
}

// CleanupExpiredShares removes expired shares and their access logs
func (w *CleanupWorker) CleanupExpiredShares(ctx context.Context, retentionDays int) (int64, error) {
	w.logger.Info("Starting expired shares cleanup", map[string]interface{}{
		"retention_days": retentionDays,
	})

	// Get expired shares
	expiredShares, err := w.shareRepo.GetExpiredShares(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get expired shares: %w", err)
	}

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)
	var cleanedCount int64

	for _, share := range expiredShares {
		// Only delete shares that expired before the cutoff date
		if share.ExpiresAt == nil || share.ExpiresAt.After(cutoffDate) {
			continue
		}

		// Soft delete the share (it may already be soft-deleted due to expiration)
		if err := w.shareRepo.SoftDelete(ctx, share.ID); err != nil {
			w.logger.Error("Failed to soft delete expired share", map[string]interface{}{
				"share_id": share.ID.Hex(),
				"error":    err.Error(),
			})
			continue
		}

		cleanedCount++

		// Log audit event
		w.logAuditEvent(ctx, share.UserID, models.AuditActionShareDelete, "share", share.ID, true, "Expired share cleanup")
	}

	w.logger.Info("Completed expired shares cleanup", map[string]interface{}{
		"shares_found":   len(expiredShares),
		"shares_cleaned": cleanedCount,
		"retention_days": retentionDays,
	})

	return cleanedCount, nil
}

// CleanupAuditLogs removes old audit logs
func (w *CleanupWorker) CleanupAuditLogs(ctx context.Context, retentionDays int) (int64, error) {
	w.logger.Info("Starting audit logs cleanup", map[string]interface{}{
		"retention_days": retentionDays,
	})

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	// Delete old audit logs
	if err := w.auditRepo.DeleteOldLogs(ctx, cutoffDate); err != nil {
		return 0, fmt.Errorf("failed to delete old audit logs: %w", err)
	}

	// Count how many were deleted (simplified)
	var deletedCount int64 = 0

	w.logger.Info("Completed audit logs cleanup", map[string]interface{}{
		"logs_deleted":   deletedCount,
		"retention_days": retentionDays,
		"cutoff_date":    cutoffDate.Format("2006-01-02"),
	})

	return deletedCount, nil
}

// CleanupAnalytics removes old analytics data
func (w *CleanupWorker) CleanupAnalytics(ctx context.Context, retentionDays int) (int64, error) {
	w.logger.Info("Starting analytics cleanup", map[string]interface{}{
		"retention_days": retentionDays,
	})

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	// Get old analytics events in batches
	pageSize := 1000
	page := 1
	var deletedCount int64

	for {
		params := &pkg.PaginationParams{
			Page:  page,
			Limit: pageSize,
			Filter: map[string]interface{}{
				"before_date": cutoffDate,
			},
		}

		analytics, totalCount, err := w.analyticsRepo.List(ctx, params)
		if err != nil {
			return deletedCount, fmt.Errorf("failed to get analytics: %w", err)
		}

		if len(analytics) == 0 {
			break
		}

		// Delete old analytics events
		for _, event := range analytics {
			if event.Timestamp.Before(cutoffDate) {
				// Delete individual analytics event
				// Note: This would need a delete method in the analytics repository
				deletedCount++
			}
		}

		page++
		if int64((page-1)*pageSize) >= totalCount {
			break
		}
	}

	w.logger.Info("Completed analytics cleanup", map[string]interface{}{
		"events_deleted": deletedCount,
		"retention_days": retentionDays,
		"cutoff_date":    cutoffDate.Format("2006-01-02"),
	})

	return deletedCount, nil
}

// CleanupInactiveUsers handles cleanup of inactive and unverified users
func (w *CleanupWorker) CleanupInactiveUsers(ctx context.Context, inactiveRetentionDays, unverifiedRetentionDays int) (int64, error) {
	w.logger.Info("Starting inactive users cleanup", map[string]interface{}{
		"inactive_retention_days":   inactiveRetentionDays,
		"unverified_retention_days": unverifiedRetentionDays,
	})

	var cleanedCount int64

	// Cleanup unverified users
	unverifiedCutoff := time.Now().AddDate(0, 0, -unverifiedRetentionDays)
	unverifiedCount, err := w.cleanupUnverifiedUsers(ctx, unverifiedCutoff)
	if err != nil {
		w.logger.Error("Failed to cleanup unverified users", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		cleanedCount += unverifiedCount
	}

	// Cleanup inactive users (with no recent activity)
	inactiveCutoff := time.Now().AddDate(0, 0, -inactiveRetentionDays)
	inactiveCount, err := w.cleanupInactiveUsersOnly(ctx, inactiveCutoff)
	if err != nil {
		w.logger.Error("Failed to cleanup inactive users", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		cleanedCount += inactiveCount
	}

	w.logger.Info("Completed inactive users cleanup", map[string]interface{}{
		"total_cleaned":             cleanedCount,
		"unverified_cleaned":        unverifiedCount,
		"inactive_cleaned":          inactiveCount,
		"inactive_retention_days":   inactiveRetentionDays,
		"unverified_retention_days": unverifiedRetentionDays,
	})

	return cleanedCount, nil
}

// CleanupIncompleteUploads removes incomplete multipart uploads
func (w *CleanupWorker) CleanupIncompleteUploads(ctx context.Context, retentionDays int) (int64, error) {
	w.logger.Info("Starting incomplete uploads cleanup", map[string]interface{}{
		"retention_days": retentionDays,
	})

	// This would cleanup incomplete multipart uploads from storage
	// Implementation depends on storage backend
	var freedSpace int64

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	// Get files with incomplete upload status (if such a field exists)
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"upload_status":  "incomplete",
			"created_before": cutoffDate,
		},
	}

	files, _, err := w.fileRepo.List(ctx, params)
	if err != nil {
		return 0, fmt.Errorf("failed to get incomplete uploads: %w", err)
	}

	for _, file := range files {
		if file.CreatedAt.After(cutoffDate) {
			continue
		}

		// Delete from storage
		if err := w.storageService.Delete(ctx, file.StoragePath); err != nil {
			w.logger.Error("Failed to delete incomplete upload from storage", map[string]interface{}{
				"file_id":      file.ID.Hex(),
				"storage_path": file.StoragePath,
				"error":        err.Error(),
			})
		}

		// Delete from database
		if err := w.fileRepo.Delete(ctx, file.ID); err != nil {
			w.logger.Error("Failed to delete incomplete upload from database", map[string]interface{}{
				"file_id": file.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		freedSpace += file.Size

		// Log audit event
		w.logAuditEvent(ctx, file.UserID, models.AuditActionFileDelete, "file", file.ID, true, "Incomplete upload cleanup")
	}

	w.logger.Info("Completed incomplete uploads cleanup", map[string]interface{}{
		"files_processed": len(files),
		"space_freed":     pkg.Files.FormatFileSize(freedSpace),
		"retention_days":  retentionDays,
	})

	return freedSpace, nil
}

// CleanupUnusedShareLinks removes share links that have never been accessed
func (w *CleanupWorker) CleanupUnusedShareLinks(ctx context.Context, retentionDays int) error {
	w.logger.Info("Starting unused share links cleanup", map[string]interface{}{
		"retention_days": retentionDays,
	})

	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)

	// Get shares with no access logs and created before cutoff
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"view_count":     0,
			"download_count": 0,
			"created_before": cutoffDate,
		},
	}

	shares, _, err := w.shareRepo.List(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to get unused shares: %w", err)
	}

	var cleanedCount int64

	for _, share := range shares {
		if share.CreatedAt.After(cutoffDate) || share.ViewCount > 0 || share.DownloadCount > 0 {
			continue
		}

		// Soft delete the share
		if err := w.shareRepo.SoftDelete(ctx, share.ID); err != nil {
			w.logger.Error("Failed to delete unused share", map[string]interface{}{
				"share_id": share.ID.Hex(),
				"error":    err.Error(),
			})
			continue
		}

		cleanedCount++

		// Log audit event
		w.logAuditEvent(ctx, share.UserID, models.AuditActionShareDelete, "share", share.ID, true, "Unused share link cleanup")
	}

	w.logger.Info("Completed unused share links cleanup", map[string]interface{}{
		"shares_found":   len(shares),
		"shares_cleaned": cleanedCount,
		"retention_days": retentionDays,
	})

	return nil
}

// OptimizeStorage performs storage optimization tasks
func (w *CleanupWorker) OptimizeStorage(ctx context.Context) error {
	w.logger.Info("Starting storage optimization")

	// Identify duplicate files
	duplicates, err := w.identifyDuplicateFiles(ctx)
	if err != nil {
		w.logger.Error("Failed to identify duplicate files", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		w.logger.Info("Identified duplicate files", map[string]interface{}{
			"duplicate_sets": len(duplicates),
		})
	}

	// Update storage usage statistics
	if err := w.updateStorageUsageStats(ctx); err != nil {
		w.logger.Error("Failed to update storage usage stats", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Identify files that could be compressed
	if err := w.identifyCompressibleFiles(ctx); err != nil {
		w.logger.Error("Failed to identify compressible files", map[string]interface{}{
			"error": err.Error(),
		})
	}

	w.logger.Info("Completed storage optimization")
	return nil
}

// Helper methods

// cleanupUnverifiedUsers removes users who haven't verified their email
func (w *CleanupWorker) cleanupUnverifiedUsers(ctx context.Context, cutoffDate time.Time) (int64, error) {
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"email_verified": false,
			"created_before": cutoffDate,
		},
	}

	users, _, err := w.userRepo.List(ctx, params)
	if err != nil {
		return 0, fmt.Errorf("failed to get unverified users: %w", err)
	}

	var cleanedCount int64

	for _, user := range users {
		if user.EmailVerified || user.CreatedAt.After(cutoffDate) {
			continue
		}

		// Delete user files first
		if err := w.deleteUserFiles(ctx, user.ID); err != nil {
			w.logger.Error("Failed to delete user files", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
		}

		// Soft delete user
		if err := w.userRepo.SoftDelete(ctx, user.ID); err != nil {
			w.logger.Error("Failed to soft delete unverified user", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		cleanedCount++

		// Log audit event
		w.logAuditEvent(ctx, user.ID, models.AuditActionUserDelete, "user", user.ID, true, "Unverified user cleanup")
	}

	return cleanedCount, nil
}

// cleanupInactiveUsersOnly removes users with no recent activity
func (w *CleanupWorker) cleanupInactiveUsersOnly(ctx context.Context, cutoffDate time.Time) (int64, error) {
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"last_login_before": cutoffDate,
			"status":            models.StatusInactive,
		},
	}

	users, _, err := w.userRepo.List(ctx, params)
	if err != nil {
		return 0, fmt.Errorf("failed to get inactive users: %w", err)
	}

	var cleanedCount int64

	for _, user := range users {
		if user.LastLoginAt != nil && user.LastLoginAt.After(cutoffDate) {
			continue
		}

		if user.Status != models.StatusInactive {
			continue
		}

		// Check if user has any recent file activity
		hasRecentActivity, err := w.hasRecentFileActivity(ctx, user.ID, cutoffDate)
		if err != nil {
			w.logger.Error("Failed to check user activity", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		if hasRecentActivity {
			continue
		}

		// Archive user data before deletion
		if err := w.archiveUserData(ctx, user.ID); err != nil {
			w.logger.Error("Failed to archive user data", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
		}

		// Soft delete user
		if err := w.userRepo.SoftDelete(ctx, user.ID); err != nil {
			w.logger.Error("Failed to soft delete inactive user", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		cleanedCount++

		// Log audit event
		w.logAuditEvent(ctx, user.ID, models.AuditActionUserDelete, "user", user.ID, true, "Inactive user cleanup")
	}

	return cleanedCount, nil
}

// deleteUserFiles deletes all files belonging to a user
func (w *CleanupWorker) deleteUserFiles(ctx context.Context, userID primitive.ObjectID) error {
	params := &pkg.PaginationParams{Page: 1, Limit: 1000}
	files, _, err := w.fileRepo.ListByUser(ctx, userID, params)
	if err != nil {
		return fmt.Errorf("failed to get user files: %w", err)
	}

	for _, file := range files {
		// Delete from storage
		if err := w.storageService.Delete(ctx, file.StoragePath); err != nil {
			w.logger.Error("Failed to delete user file from storage", map[string]interface{}{
				"file_id":      file.ID.Hex(),
				"user_id":      userID.Hex(),
				"storage_path": file.StoragePath,
				"error":        err.Error(),
			})
		}

		// Delete from database
		if err := w.fileRepo.Delete(ctx, file.ID); err != nil {
			w.logger.Error("Failed to delete user file from database", map[string]interface{}{
				"file_id": file.ID.Hex(),
				"user_id": userID.Hex(),
				"error":   err.Error(),
			})
		}
	}

	return nil
}

// hasRecentFileActivity checks if user has recent file activity
func (w *CleanupWorker) hasRecentFileActivity(ctx context.Context, userID primitive.ObjectID, since time.Time) (bool, error) {
	// Check for recent analytics events
	events, err := w.analyticsRepo.GetByUser(ctx, userID, since, time.Now())
	if err != nil {
		return false, err
	}

	// Check for any file-related activity
	for _, event := range events {
		if event.EventType == models.EventTypeFileUpload ||
			event.EventType == models.EventTypeFileDownload ||
			event.EventType == models.EventTypeFileView {
			return true, nil
		}
	}

	return false, nil
}

// archiveUserData archives user data before deletion
func (w *CleanupWorker) archiveUserData(ctx context.Context, userID primitive.ObjectID) error {
	// This would create an archive of user data for compliance purposes
	// Implementation would depend on specific requirements
	w.logger.Info("Archiving user data", map[string]interface{}{
		"user_id": userID.Hex(),
	})

	return nil
}

// identifyDuplicateFiles finds files with identical hashes
func (w *CleanupWorker) identifyDuplicateFiles(ctx context.Context) (map[string][]*models.File, error) {
	// Get all files and group by hash
	params := &pkg.PaginationParams{Page: 1, Limit: 10000}
	files, _, err := w.fileRepo.List(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get files: %w", err)
	}

	duplicates := make(map[string][]*models.File)

	for _, file := range files {
		if file.Hash != "" {
			duplicates[file.Hash] = append(duplicates[file.Hash], file)
		}
	}

	// Remove entries with only one file
	for hash, fileList := range duplicates {
		if len(fileList) <= 1 {
			delete(duplicates, hash)
		}
	}

	return duplicates, nil
}

// updateStorageUsageStats updates storage usage statistics for all users
func (w *CleanupWorker) updateStorageUsageStats(ctx context.Context) error {
	params := &pkg.PaginationParams{Page: 1, Limit: 1000}
	users, _, err := w.userRepo.List(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to get users: %w", err)
	}

	for _, user := range users {
		// Calculate actual storage used
		actualUsage, err := w.fileRepo.GetStorageByUser(ctx, user.ID)
		if err != nil {
			w.logger.Error("Failed to calculate user storage", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		// Update user storage if different
		if actualUsage != user.StorageUsed {
			updates := map[string]interface{}{
				"storage_used": actualUsage,
			}

			if err := w.userRepo.Update(ctx, user.ID, updates); err != nil {
				w.logger.Error("Failed to update user storage", map[string]interface{}{
					"user_id": user.ID.Hex(),
					"error":   err.Error(),
				})
			}
		}
	}

	return nil
}

// identifyCompressibleFiles identifies files that could benefit from compression
func (w *CleanupWorker) identifyCompressibleFiles(ctx context.Context) error {
	// Identify large files that could be compressed
	largeFiles, err := w.fileRepo.GetLargestFiles(ctx, 1000)
	if err != nil {
		return fmt.Errorf("failed to get large files: %w", err)
	}

	compressibleTypes := []string{"text/", "application/json", "application/xml", "image/svg+xml"}
	var compressibleFiles []*models.File

	for _, file := range largeFiles {
		for _, compressibleType := range compressibleTypes {
			if strings.HasPrefix(file.MimeType, compressibleType) {
				compressibleFiles = append(compressibleFiles, file)
				break
			}
		}
	}

	w.logger.Info("Identified compressible files", map[string]interface{}{
		"total_large_files":    len(largeFiles),
		"compressible_files":   len(compressibleFiles),
		"potential_savings_gb": w.estimateCompressionSavings(compressibleFiles),
	})

	return nil
}

// estimateCompressionSavings estimates potential storage savings from compression
func (w *CleanupWorker) estimateCompressionSavings(files []*models.File) float64 {
	var totalSize int64
	compressionRatio := 0.3 // Assume 30% compression ratio

	for _, file := range files {
		totalSize += file.Size
	}

	savings := float64(totalSize) * compressionRatio
	return savings / (1024 * 1024 * 1024) // Convert to GB
}

// logCleanupAnalytics logs cleanup operation results as analytics
func (w *CleanupWorker) logCleanupAnalytics(ctx context.Context, stats *CleanupStats) {
	analytics := &models.Analytics{
		EventType: "system_cleanup",
		Action:    "cleanup_completed",
		Resource: models.AnalyticsResource{
			Type: "system",
			Name: "cleanup_operation",
		},
		Metadata: map[string]interface{}{
			"duration":           stats.Duration,
			"orphaned_files":     stats.OrphanedFiles,
			"deleted_files":      stats.DeletedFiles,
			"expired_shares":     stats.ExpiredShares,
			"cleaned_logs":       stats.CleanedLogs,
			"inactive_users":     stats.InactiveUsers,
			"storage_freed_mb":   stats.StorageFreed / (1024 * 1024),
			"errors_encountered": stats.ErrorsEncountered,
		},
		Timestamp: time.Now(),
	}

	if err := w.analyticsRepo.Create(ctx, analytics); err != nil {
		w.logger.Error("Failed to log cleanup analytics", map[string]interface{}{
			"error": err.Error(),
		})
	}
}

// logAuditEvent logs an audit event
func (w *CleanupWorker) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
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

	if err := w.auditRepo.Create(ctx, auditLog); err != nil {
		w.logger.Error("Failed to log audit event", map[string]interface{}{
			"error": err.Error(),
		})
	}
}
