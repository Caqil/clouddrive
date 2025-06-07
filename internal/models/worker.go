// internal/models/worker.go
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Job struct {
	ID          primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	Type        JobType                `bson:"type" json:"type"`
	Queue       string                 `bson:"queue" json:"queue"`
	Priority    int                    `bson:"priority" json:"priority"`
	Status      JobStatus              `bson:"status" json:"status"`
	Payload     map[string]interface{} `bson:"payload" json:"payload"`
	Result      map[string]interface{} `bson:"result,omitempty" json:"result,omitempty"`
	Error       string                 `bson:"error,omitempty" json:"error,omitempty"`
	Attempts    int                    `bson:"attempts" json:"attempts"`
	MaxAttempts int                    `bson:"max_attempts" json:"maxAttempts"`
	RetryDelay  time.Duration          `bson:"retry_delay" json:"retryDelay"`
	RunAt       time.Time              `bson:"run_at" json:"runAt"`
	StartedAt   *time.Time             `bson:"started_at,omitempty" json:"startedAt,omitempty"`
	CompletedAt *time.Time             `bson:"completed_at,omitempty" json:"completedAt,omitempty"`
	WorkerID    string                 `bson:"worker_id,omitempty" json:"workerId,omitempty"`
	Timeout     time.Duration          `bson:"timeout" json:"timeout"`
	CreatedAt   time.Time              `bson:"created_at" json:"createdAt"`
	UpdatedAt   time.Time              `bson:"updated_at" json:"updatedAt"`
}

type JobType string

const (
	// Analytics jobs
	JobTypeAnalyticsProcessing   JobType = "analytics_processing"
	JobTypeAnalyticsSummary      JobType = "analytics_summary"
	JobTypeAnalyticsReport       JobType = "analytics_report"
	JobTypeUserActivityAnalytics JobType = "user_activity_analytics"
	JobTypeFileUsageAnalytics    JobType = "file_usage_analytics"
	JobTypeStorageAnalytics      JobType = "storage_analytics"
	JobTypeRevenueAnalytics      JobType = "revenue_analytics"

	// Cleanup jobs
	JobTypeCleanupTempFiles       JobType = "cleanup_temp_files"
	JobTypeCleanupOrphanedFiles   JobType = "cleanup_orphaned_files"
	JobTypeCleanupExpiredShares   JobType = "cleanup_expired_shares"
	JobTypeCleanupOldLogs         JobType = "cleanup_old_logs"
	JobTypeCleanupDeletedFiles    JobType = "cleanup_deleted_files"
	JobTypeCleanupExpiredSessions JobType = "cleanup_expired_sessions"
	JobTypeCleanupAnalyticsData   JobType = "cleanup_analytics_data"
	JobTypeDatabaseOptimization   JobType = "database_optimization"

	// Email jobs
	JobTypeEmailSend              JobType = "email_send"
	JobTypeEmailBulkSend          JobType = "email_bulk_send"
	JobTypeEmailWelcome           JobType = "email_welcome"
	JobTypeEmailVerification      JobType = "email_verification"
	JobTypeEmailPasswordReset     JobType = "email_password_reset"
	JobTypeEmailShareNotification JobType = "email_share_notification"
	JobTypeEmailStorageAlert      JobType = "email_storage_alert"
	JobTypeEmailPaymentReminder   JobType = "email_payment_reminder"
	JobTypeEmailDigest            JobType = "email_digest"

	// Thumbnail jobs
	JobTypeThumbnailGenerate JobType = "thumbnail_generate"
	JobTypeThumbnailBatch    JobType = "thumbnail_batch"
	JobTypeThumbnailCleanup  JobType = "thumbnail_cleanup"
	JobTypeImageOptimization JobType = "image_optimization"
	JobTypeVideoPreview      JobType = "video_preview"
	JobTypeDocumentPreview   JobType = "document_preview"

	// File processing jobs
	JobTypeFileProcessing     JobType = "file_processing"
	JobTypeVirusScan          JobType = "virus_scan"
	JobTypeFileCompression    JobType = "file_compression"
	JobTypeFileEncryption     JobType = "file_encryption"
	JobTypeMetadataExtraction JobType = "metadata_extraction"

	// Notification jobs
	JobTypeNotificationSend JobType = "notification_send"
	JobTypePushNotification JobType = "push_notification"
	JobTypeWebhookDelivery  JobType = "webhook_delivery"

	// Backup jobs
	JobTypeBackupDatabase JobType = "backup_database"
	JobTypeBackupFiles    JobType = "backup_files"
	JobTypeBackupRestore  JobType = "backup_restore"

	// System jobs
	JobTypeSystemMaintenance JobType = "system_maintenance"
	JobTypeHealthCheck       JobType = "health_check"
	JobTypeMetricsCollection JobType = "metrics_collection"
)

type JobStatus string

const (
	JobStatusPending    JobStatus = "pending"
	JobStatusProcessing JobStatus = "processing"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
	JobStatusRetrying   JobStatus = "retrying"
	JobStatusCanceled   JobStatus = "canceled"
	JobStatusExpired    JobStatus = "expired"
)

type JobQueue struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description" json:"description"`
	Priority    int                `bson:"priority" json:"priority"`
	MaxWorkers  int                `bson:"max_workers" json:"maxWorkers"`
	IsActive    bool               `bson:"is_active" json:"isActive"`
	JobTypes    []JobType          `bson:"job_types" json:"jobTypes"`
	Settings    QueueSettings      `bson:"settings" json:"settings"`
	Stats       QueueStats         `bson:"stats" json:"stats"`
	CreatedAt   time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updatedAt"`
}

type QueueSettings struct {
	MaxJobsPerHour      int           `bson:"max_jobs_per_hour" json:"maxJobsPerHour"`
	MaxRetries          int           `bson:"max_retries" json:"maxRetries"`
	DefaultTimeout      time.Duration `bson:"default_timeout" json:"defaultTimeout"`
	RetryBackoff        string        `bson:"retry_backoff" json:"retryBackoff"`
	DeadLetterQueue     string        `bson:"dead_letter_queue" json:"deadLetterQueue"`
	EnablePriority      bool          `bson:"enable_priority" json:"enablePriority"`
	EnableDeduplication bool          `bson:"enable_deduplication" json:"enableDeduplication"`
}

type QueueStats struct {
	PendingJobs    int64     `bson:"pending_jobs" json:"pendingJobs"`
	ProcessingJobs int64     `bson:"processing_jobs" json:"processingJobs"`
	CompletedJobs  int64     `bson:"completed_jobs" json:"completedJobs"`
	FailedJobs     int64     `bson:"failed_jobs" json:"failedJobs"`
	TotalJobs      int64     `bson:"total_jobs" json:"totalJobs"`
	AverageRuntime float64   `bson:"average_runtime" json:"averageRuntime"`
	LastProcessed  time.Time `bson:"last_processed" json:"lastProcessed"`
}

type Worker struct {
	ID            primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Name          string              `bson:"name" json:"name"`
	Type          WorkerType          `bson:"type" json:"type"`
	Status        WorkerStatus        `bson:"status" json:"status"`
	Hostname      string              `bson:"hostname" json:"hostname"`
	PID           int                 `bson:"pid" json:"pid"`
	Version       string              `bson:"version" json:"version"`
	Queues        []string            `bson:"queues" json:"queues"`
	CurrentJob    *primitive.ObjectID `bson:"current_job,omitempty" json:"currentJob,omitempty"`
	LastHeartbeat time.Time           `bson:"last_heartbeat" json:"lastHeartbeat"`
	Stats         WorkerStats         `bson:"stats" json:"stats"`
	Config        WorkerConfig        `bson:"config" json:"config"`
	CreatedAt     time.Time           `bson:"created_at" json:"createdAt"`
	UpdatedAt     time.Time           `bson:"updated_at" json:"updatedAt"`
}

type WorkerType string

const (
	WorkerTypeGeneral   WorkerType = "general"
	WorkerTypeAnalytics WorkerType = "analytics"
	WorkerTypeCleanup   WorkerType = "cleanup"
	WorkerTypeEmail     WorkerType = "email"
	WorkerTypeThumbnail WorkerType = "thumbnail"
	WorkerTypeFile      WorkerType = "file"
	WorkerTypeBackup    WorkerType = "backup"
)

type WorkerStatus string

const (
	WorkerStatusIdle     WorkerStatus = "idle"
	WorkerStatusBusy     WorkerStatus = "busy"
	WorkerStatusStopping WorkerStatus = "stopping"
	WorkerStatusStopped  WorkerStatus = "stopped"
	WorkerStatusError    WorkerStatus = "error"
)

type WorkerStats struct {
	JobsProcessed  int64      `bson:"jobs_processed" json:"jobsProcessed"`
	JobsSucceeded  int64      `bson:"jobs_succeeded" json:"jobsSucceeded"`
	JobsFailed     int64      `bson:"jobs_failed" json:"jobsFailed"`
	AverageRuntime float64    `bson:"average_runtime" json:"averageRuntime"`
	TotalRuntime   float64    `bson:"total_runtime" json:"totalRuntime"`
	MemoryUsage    int64      `bson:"memory_usage" json:"memoryUsage"`
	CPUUsage       float64    `bson:"cpu_usage" json:"cpuUsage"`
	LastJobAt      *time.Time `bson:"last_job_at,omitempty" json:"lastJobAt,omitempty"`
	UptimeSeconds  int64      `bson:"uptime_seconds" json:"uptimeSeconds"`
}

type WorkerConfig struct {
	MaxConcurrentJobs int           `bson:"max_concurrent_jobs" json:"maxConcurrentJobs"`
	HeartbeatInterval time.Duration `bson:"heartbeat_interval" json:"heartbeatInterval"`
	ShutdownTimeout   time.Duration `bson:"shutdown_timeout" json:"shutdownTimeout"`
	MaxJobRuntime     time.Duration `bson:"max_job_runtime" json:"maxJobRuntime"`
	PollInterval      time.Duration `bson:"poll_interval" json:"pollInterval"`
	EnableMetrics     bool          `bson:"enable_metrics" json:"enableMetrics"`
}

type CronJob struct {
	ID          primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	Name        string                 `bson:"name" json:"name"`
	Description string                 `bson:"description" json:"description"`
	Schedule    string                 `bson:"schedule" json:"schedule"` // Cron expression
	JobType     JobType                `bson:"job_type" json:"jobType"`
	Queue       string                 `bson:"queue" json:"queue"`
	Payload     map[string]interface{} `bson:"payload" json:"payload"`
	IsActive    bool                   `bson:"is_active" json:"isActive"`
	Timezone    string                 `bson:"timezone" json:"timezone"`
	NextRun     time.Time              `bson:"next_run" json:"nextRun"`
	LastRun     *time.Time             `bson:"last_run,omitempty" json:"lastRun,omitempty"`
	LastJobID   *primitive.ObjectID    `bson:"last_job_id,omitempty" json:"lastJobId,omitempty"`
	RunCount    int64                  `bson:"run_count" json:"runCount"`
	FailCount   int64                  `bson:"fail_count" json:"failCount"`
	CreatedAt   time.Time              `bson:"created_at" json:"createdAt"`
	UpdatedAt   time.Time              `bson:"updated_at" json:"updatedAt"`
}

type JobTemplate struct {
	ID             primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	Name           string                 `bson:"name" json:"name"`
	Description    string                 `bson:"description" json:"description"`
	JobType        JobType                `bson:"job_type" json:"jobType"`
	Queue          string                 `bson:"queue" json:"queue"`
	Priority       int                    `bson:"priority" json:"priority"`
	MaxAttempts    int                    `bson:"max_attempts" json:"maxAttempts"`
	Timeout        time.Duration          `bson:"timeout" json:"timeout"`
	RetryDelay     time.Duration          `bson:"retry_delay" json:"retryDelay"`
	DefaultPayload map[string]interface{} `bson:"default_payload" json:"defaultPayload"`
	IsActive       bool                   `bson:"is_active" json:"isActive"`
	CreatedAt      time.Time              `bson:"created_at" json:"createdAt"`
	UpdatedAt      time.Time              `bson:"updated_at" json:"updatedAt"`
}
