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

// EmailWorker handles email processing tasks
type EmailWorker struct {
	userRepo         repository.UserRepository
	subscriptionRepo repository.SubscriptionRepository
	paymentRepo      repository.PaymentRepository
	auditRepo        repository.AuditLogRepository
	analyticsRepo    repository.AnalyticsRepository
	emailService     services.EmailService
	logger           *pkg.Logger
	emailQueue       *EmailQueue
}

// EmailQueue represents an email queue for batch processing
type EmailQueue struct {
	items   []EmailQueueItem
	maxSize int
}

// EmailQueueItem represents an item in the email queue
type EmailQueueItem struct {
	ID          primitive.ObjectID     `json:"id"`
	Type        EmailType              `json:"type"`
	Priority    EmailPriority          `json:"priority"`
	Recipient   string                 `json:"recipient"`
	Subject     string                 `json:"subject"`
	Body        string                 `json:"body"`
	TemplateID  string                 `json:"templateId,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	ScheduledAt time.Time              `json:"scheduledAt"`
	CreatedAt   time.Time              `json:"createdAt"`
	Attempts    int                    `json:"attempts"`
	MaxAttempts int                    `json:"maxAttempts"`
	Status      EmailStatus            `json:"status"`
	Error       string                 `json:"error,omitempty"`
	UserID      *primitive.ObjectID    `json:"userId,omitempty"`
}

// EmailType represents different types of emails
type EmailType string

const (
	EmailTypeWelcome             EmailType = "welcome"
	EmailTypeVerification        EmailType = "verification"
	EmailTypePasswordReset       EmailType = "password_reset"
	EmailTypeNotification        EmailType = "notification"
	EmailTypeAlert               EmailType = "alert"
	EmailTypeMarketing           EmailType = "marketing"
	EmailTypeNewsletter          EmailType = "newsletter"
	EmailTypeInvoice             EmailType = "invoice"
	EmailTypeReceipt             EmailType = "receipt"
	EmailTypeSubscriptionExpiry  EmailType = "subscription_expiry"
	EmailTypeShareNotification   EmailType = "share_notification"
	EmailTypeActivitySummary     EmailType = "activity_summary"
	EmailTypeSecurityAlert       EmailType = "security_alert"
	EmailTypeStorageAlert        EmailType = "storage_alert"
	EmailTypeMaintenanceNotice   EmailType = "maintenance_notice"
	EmailTypeFeatureAnnouncement EmailType = "feature_announcement"
)

// EmailPriority represents email priority levels
type EmailPriority int

const (
	EmailPriorityLow EmailPriority = iota
	EmailPriorityNormal
	EmailPriorityHigh
	EmailPriorityCritical
)

// EmailStatus represents email delivery status
type EmailStatus string

const (
	EmailStatusPending   EmailStatus = "pending"
	EmailStatusSending   EmailStatus = "sending"
	EmailStatusSent      EmailStatus = "sent"
	EmailStatusFailed    EmailStatus = "failed"
	EmailStatusRetrying  EmailStatus = "retrying"
	EmailStatusCanceled  EmailStatus = "canceled"
	EmailStatusScheduled EmailStatus = "scheduled"
)

// EmailTemplate represents an email template
type EmailTemplate struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Subject   string                 `json:"subject"`
	BodyHTML  string                 `json:"bodyHtml"`
	BodyText  string                 `json:"bodyText"`
	Variables []string               `json:"variables"`
	Type      EmailType              `json:"type"`
	Active    bool                   `json:"active"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
}

// EmailCampaign represents an email campaign
type EmailCampaign struct {
	ID          primitive.ObjectID `json:"id"`
	Name        string             `json:"name"`
	Subject     string             `json:"subject"`
	TemplateID  string             `json:"templateId"`
	Recipients  []string           `json:"recipients"`
	SegmentID   string             `json:"segmentId,omitempty"`
	ScheduledAt *time.Time         `json:"scheduledAt,omitempty"`
	Status      CampaignStatus     `json:"status"`
	Stats       CampaignStats      `json:"stats"`
	CreatedAt   time.Time          `json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt"`
}

// CampaignStatus represents campaign status
type CampaignStatus string

const (
	CampaignStatusDraft     CampaignStatus = "draft"
	CampaignStatusScheduled CampaignStatus = "scheduled"
	CampaignStatusSending   CampaignStatus = "sending"
	CampaignStatusSent      CampaignStatus = "sent"
	CampaignStatusPaused    CampaignStatus = "paused"
	CampaignStatusCanceled  CampaignStatus = "canceled"
	CampaignStatusCompleted CampaignStatus = "completed"
)

// CampaignStats represents campaign statistics
type CampaignStats struct {
	TotalRecipients int64      `json:"totalRecipients"`
	Sent            int64      `json:"sent"`
	Delivered       int64      `json:"delivered"`
	Failed          int64      `json:"failed"`
	Opened          int64      `json:"opened"`
	Clicked         int64      `json:"clicked"`
	Unsubscribed    int64      `json:"unsubscribed"`
	Bounced         int64      `json:"bounced"`
	StartedAt       time.Time  `json:"startedAt"`
	CompletedAt     *time.Time `json:"completedAt,omitempty"`
}

// NewEmailWorker creates a new email worker
func NewEmailWorker(
	userRepo repository.UserRepository,
	subscriptionRepo repository.SubscriptionRepository,
	paymentRepo repository.PaymentRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
	emailService services.EmailService,
	logger *pkg.Logger,
) *EmailWorker {
	return &EmailWorker{
		userRepo:         userRepo,
		subscriptionRepo: subscriptionRepo,
		paymentRepo:      paymentRepo,
		auditRepo:        auditRepo,
		analyticsRepo:    analyticsRepo,
		emailService:     emailService,
		logger:           logger,
		emailQueue:       NewEmailQueue(10000), // Max 10k items in queue
	}
}

// NewEmailQueue creates a new email queue
func NewEmailQueue(maxSize int) *EmailQueue {
	return &EmailQueue{
		items:   make([]EmailQueueItem, 0),
		maxSize: maxSize,
	}
}

// ProcessEmailQueue processes pending emails in the queue
func (w *EmailWorker) ProcessEmailQueue(ctx context.Context) error {
	w.logger.Info("Starting email queue processing", map[string]interface{}{
		"queue_size": len(w.emailQueue.items),
	})

	var processed, failed int64

	// Process emails by priority
	for priority := EmailPriorityCritical; priority >= EmailPriorityLow; priority-- {
		items := w.getEmailsByPriority(priority)

		for _, item := range items {
			if err := w.processEmailItem(ctx, &item); err != nil {
				w.logger.Error("Failed to process email item", map[string]interface{}{
					"email_id":  item.ID.Hex(),
					"recipient": item.Recipient,
					"type":      string(item.Type),
					"error":     err.Error(),
				})
				failed++
			} else {
				processed++
			}

			// Remove processed item from queue
			w.removeFromQueue(item.ID)
		}
	}

	w.logger.Info("Completed email queue processing", map[string]interface{}{
		"processed": processed,
		"failed":    failed,
	})

	return nil
}

// SendWelcomeEmails sends welcome emails to new users
func (w *EmailWorker) SendWelcomeEmails(ctx context.Context) error {
	w.logger.Info("Processing welcome emails")

	// Get users who registered in the last 24 hours and haven't received welcome email
	yesterday := time.Now().AddDate(0, 0, -1)

	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"created_after":      yesterday,
			"email_verified":     true,
			"welcome_email_sent": false,
		},
	}

	users, _, err := w.userRepo.List(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to get new users: %w", err)
	}

	var sent int64

	for _, user := range users {
		// Check if welcome email already sent by checking analytics
		if w.hasWelcomeEmailBeenSent(ctx, user.ID) {
			continue
		}

		emailItem := EmailQueueItem{
			ID:         primitive.NewObjectID(),
			Type:       EmailTypeWelcome,
			Priority:   EmailPriorityNormal,
			Recipient:  user.Email,
			Subject:    "Welcome to CloudDrive!",
			TemplateID: "welcome",
			Data: map[string]interface{}{
				"FirstName": user.FirstName,
				"LastName":  user.LastName,
				"Email":     user.Email,
			},
			ScheduledAt: time.Now(),
			CreatedAt:   time.Now(),
			MaxAttempts: 3,
			Status:      EmailStatusPending,
			UserID:      &user.ID,
		}

		if err := w.addToQueue(emailItem); err != nil {
			w.logger.Error("Failed to add welcome email to queue", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		sent++
	}

	w.logger.Info("Queued welcome emails", map[string]interface{}{
		"users_found": len(users),
		"emails_sent": sent,
	})

	return nil
}

// SendSubscriptionExpiryNotifications sends notifications for expiring subscriptions
func (w *EmailWorker) SendSubscriptionExpiryNotifications(ctx context.Context) error {
	w.logger.Info("Processing subscription expiry notifications")

	// Get subscriptions expiring in 7, 3, and 1 days
	expiryPeriods := []int{7, 3, 1}
	var totalSent int64

	for _, days := range expiryPeriods {
		subscriptions, err := w.subscriptionRepo.GetExpiringSubscriptions(ctx, days)
		if err != nil {
			w.logger.Error("Failed to get expiring subscriptions", map[string]interface{}{
				"days":  days,
				"error": err.Error(),
			})
			continue
		}

		var sent int64

		for _, subscription := range subscriptions {
			// Check if notification already sent for this period
			if w.hasExpiryNotificationBeenSent(ctx, subscription.ID, days) {
				continue
			}

			user, err := w.userRepo.GetByID(ctx, subscription.UserID)
			if err != nil {
				w.logger.Error("Failed to get user for expiry notification", map[string]interface{}{
					"user_id":         subscription.UserID.Hex(),
					"subscription_id": subscription.ID.Hex(),
					"error":           err.Error(),
				})
				continue
			}

			plan, err := w.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
			if err != nil {
				w.logger.Error("Failed to get plan for expiry notification", map[string]interface{}{
					"plan_id": subscription.PlanID.Hex(),
					"error":   err.Error(),
				})
				continue
			}

			priority := EmailPriorityNormal
			if days == 1 {
				priority = EmailPriorityHigh
			}

			emailItem := EmailQueueItem{
				ID:         primitive.NewObjectID(),
				Type:       EmailTypeSubscriptionExpiry,
				Priority:   priority,
				Recipient:  user.Email,
				Subject:    fmt.Sprintf("Your %s subscription expires in %d day(s)", plan.Name, days),
				TemplateID: "subscription_expiry",
				Data: map[string]interface{}{
					"FirstName":     user.FirstName,
					"LastName":      user.LastName,
					"PlanName":      plan.Name,
					"ExpiryDate":    subscription.CurrentPeriodEnd.Format("January 2, 2006"),
					"DaysRemaining": days,
					"RenewalURL":    fmt.Sprintf("/subscription/renew?id=%s", subscription.ID.Hex()),
				},
				ScheduledAt: time.Now(),
				CreatedAt:   time.Now(),
				MaxAttempts: 3,
				Status:      EmailStatusPending,
				UserID:      &user.ID,
			}

			if err := w.addToQueue(emailItem); err != nil {
				w.logger.Error("Failed to add expiry notification to queue", map[string]interface{}{
					"subscription_id": subscription.ID.Hex(),
					"error":           err.Error(),
				})
				continue
			}

			sent++
		}

		w.logger.Info("Queued subscription expiry notifications", map[string]interface{}{
			"days":          days,
			"subscriptions": len(subscriptions),
			"notifications": sent,
		})

		totalSent += sent
	}

	w.logger.Info("Completed subscription expiry notifications", map[string]interface{}{
		"total_sent": totalSent,
	})

	return nil
}

// SendStorageAlerts sends storage usage alerts
func (w *EmailWorker) SendStorageAlerts(ctx context.Context) error {
	w.logger.Info("Processing storage alerts")

	// Get users approaching storage limits
	params := &pkg.PaginationParams{Page: 1, Limit: 1000}
	users, _, err := w.userRepo.List(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to get users: %w", err)
	}

	var sent int64

	for _, user := range users {
		if user.StorageLimit == 0 {
			continue
		}

		usagePercentage := float64(user.StorageUsed) / float64(user.StorageLimit) * 100

		// Send alerts at 80%, 90%, and 95%
		var alertThreshold int
		var shouldSendAlert bool

		switch {
		case usagePercentage >= 95:
			alertThreshold = 95
			shouldSendAlert = !w.hasStorageAlertBeenSent(ctx, user.ID, alertThreshold)
		case usagePercentage >= 90:
			alertThreshold = 90
			shouldSendAlert = !w.hasStorageAlertBeenSent(ctx, user.ID, alertThreshold)
		case usagePercentage >= 80:
			alertThreshold = 80
			shouldSendAlert = !w.hasStorageAlertBeenSent(ctx, user.ID, alertThreshold)
		}

		if !shouldSendAlert {
			continue
		}

		priority := EmailPriorityNormal
		if alertThreshold >= 95 {
			priority = EmailPriorityHigh
		}

		emailItem := EmailQueueItem{
			ID:         primitive.NewObjectID(),
			Type:       EmailTypeStorageAlert,
			Priority:   priority,
			Recipient:  user.Email,
			Subject:    fmt.Sprintf("Storage Alert: %d%% of your storage is used", alertThreshold),
			TemplateID: "storage_alert",
			Data: map[string]interface{}{
				"FirstName":        user.FirstName,
				"LastName":         user.LastName,
				"UsagePercentage":  int(usagePercentage),
				"StorageUsed":      pkg.Files.FormatFileSize(user.StorageUsed),
				"StorageLimit":     pkg.Files.FormatFileSize(user.StorageLimit),
				"RemainingStorage": pkg.Files.FormatFileSize(user.StorageLimit - user.StorageUsed),
				"UpgradeURL":       "/subscription/upgrade",
			},
			ScheduledAt: time.Now(),
			CreatedAt:   time.Now(),
			MaxAttempts: 3,
			Status:      EmailStatusPending,
			UserID:      &user.ID,
		}

		if err := w.addToQueue(emailItem); err != nil {
			w.logger.Error("Failed to add storage alert to queue", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		sent++
	}

	w.logger.Info("Queued storage alerts", map[string]interface{}{
		"alerts_sent": sent,
	})

	return nil
}

// SendActivitySummaries sends weekly activity summaries
func (w *EmailWorker) SendActivitySummaries(ctx context.Context) error {
	w.logger.Info("Processing weekly activity summaries")

	// Send summaries on Mondays for the previous week
	if time.Now().Weekday() != time.Monday {
		w.logger.Info("Skipping activity summaries - not Monday")
		return nil
	}

	weekStart := time.Now().AddDate(0, 0, -7)
	weekEnd := time.Now()

	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"email_notifications": true,
			"status":              models.StatusActive,
		},
	}

	users, _, err := w.userRepo.List(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to get users: %w", err)
	}

	var sent int64

	for _, user := range users {
		// Check if user has had any activity this week
		userAnalytics, err := w.analyticsRepo.GetUserAnalyticsByPeriod(ctx, user.ID, weekStart, weekEnd)
		if err != nil {
			w.logger.Error("Failed to get user analytics", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		if len(userAnalytics) == 0 {
			continue // No activity, skip summary
		}

		// Aggregate weekly stats
		var totalUploads, totalDownloads, totalLogins int64
		for _, analytics := range userAnalytics {
			totalUploads += analytics.FilesUploaded
			totalDownloads += analytics.FilesDownloaded
			totalLogins += analytics.LoginCount
		}

		// Skip if no meaningful activity
		if totalUploads == 0 && totalDownloads == 0 && totalLogins == 0 {
			continue
		}

		emailItem := EmailQueueItem{
			ID:         primitive.NewObjectID(),
			Type:       EmailTypeActivitySummary,
			Priority:   EmailPriorityLow,
			Recipient:  user.Email,
			Subject:    "Your Weekly CloudDrive Activity Summary",
			TemplateID: "activity_summary",
			Data: map[string]interface{}{
				"FirstName":      user.FirstName,
				"LastName":       user.LastName,
				"WeekStart":      weekStart.Format("January 2, 2006"),
				"WeekEnd":        weekEnd.Format("January 2, 2006"),
				"TotalUploads":   totalUploads,
				"TotalDownloads": totalDownloads,
				"TotalLogins":    totalLogins,
				"StorageUsed":    pkg.Files.FormatFileSize(user.StorageUsed),
				"StorageLimit":   pkg.Files.FormatFileSize(user.StorageLimit),
			},
			ScheduledAt: time.Now(),
			CreatedAt:   time.Now(),
			MaxAttempts: 3,
			Status:      EmailStatusPending,
			UserID:      &user.ID,
		}

		if err := w.addToQueue(emailItem); err != nil {
			w.logger.Error("Failed to add activity summary to queue", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		sent++
	}

	w.logger.Info("Queued activity summaries", map[string]interface{}{
		"summaries_sent": sent,
	})

	return nil
}

// SendSecurityAlerts sends security-related notifications
func (w *EmailWorker) SendSecurityAlerts(ctx context.Context) error {
	w.logger.Info("Processing security alerts")

	// Get security-related audit logs from the last hour
	oneHourAgo := time.Now().Add(-1 * time.Hour)

	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"severity":        models.AuditSeverityHigh,
			"timestamp_after": oneHourAgo,
		},
	}

	auditLogs, _, err := w.auditRepo.List(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to get security audit logs: %w", err)
	}

	// Group by user ID
	userAlerts := make(map[primitive.ObjectID][]*models.AuditLog)
	for _, log := range auditLogs {
		if log.UserID != nil {
			userAlerts[*log.UserID] = append(userAlerts[*log.UserID], log)
		}
	}

	var sent int64

	for userID, alerts := range userAlerts {
		user, err := w.userRepo.GetByID(ctx, userID)
		if err != nil {
			w.logger.Error("Failed to get user for security alert", map[string]interface{}{
				"user_id": userID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		// Create summary of alerts
		alertSummary := w.createSecurityAlertSummary(alerts)

		emailItem := EmailQueueItem{
			ID:         primitive.NewObjectID(),
			Type:       EmailTypeSecurityAlert,
			Priority:   EmailPriorityCritical,
			Recipient:  user.Email,
			Subject:    "Security Alert - Unusual Activity Detected",
			TemplateID: "security_alert",
			Data: map[string]interface{}{
				"FirstName":    user.FirstName,
				"LastName":     user.LastName,
				"AlertCount":   len(alerts),
				"AlertSummary": alertSummary,
				"Timestamp":    time.Now().Format("January 2, 2006 at 3:04 PM"),
				"SecurityURL":  "/security/activity",
			},
			ScheduledAt: time.Now(),
			CreatedAt:   time.Now(),
			MaxAttempts: 5, // Higher attempts for security alerts
			Status:      EmailStatusPending,
			UserID:      &userID,
		}

		if err := w.addToQueue(emailItem); err != nil {
			w.logger.Error("Failed to add security alert to queue", map[string]interface{}{
				"user_id": userID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		sent++
	}

	w.logger.Info("Queued security alerts", map[string]interface{}{
		"alerts_sent": sent,
	})

	return nil
}

// SendMaintenanceNotifications sends maintenance notifications
func (w *EmailWorker) SendMaintenanceNotifications(ctx context.Context, maintenanceStart time.Time, duration time.Duration, message string) error {
	w.logger.Info("Sending maintenance notifications", map[string]interface{}{
		"maintenance_start": maintenanceStart.Format("2006-01-02 15:04:05"),
		"duration":          duration.String(),
	})

	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 10000, // Send to all active users
		Filter: map[string]interface{}{
			"status": models.StatusActive,
		},
	}

	users, _, err := w.userRepo.List(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to get users: %w", err)
	}

	var sent int64

	for _, user := range users {
		emailItem := EmailQueueItem{
			ID:         primitive.NewObjectID(),
			Type:       EmailTypeMaintenanceNotice,
			Priority:   EmailPriorityHigh,
			Recipient:  user.Email,
			Subject:    "Scheduled Maintenance Notification - CloudDrive",
			TemplateID: "maintenance_notice",
			Data: map[string]interface{}{
				"FirstName":        user.FirstName,
				"LastName":         user.LastName,
				"MaintenanceStart": maintenanceStart.Format("January 2, 2006 at 3:04 PM MST"),
				"MaintenanceEnd":   maintenanceStart.Add(duration).Format("January 2, 2006 at 3:04 PM MST"),
				"Duration":         w.formatDuration(duration),
				"Message":          message,
				"StatusURL":        "/status",
			},
			ScheduledAt: time.Now(),
			CreatedAt:   time.Now(),
			MaxAttempts: 3,
			Status:      EmailStatusPending,
			UserID:      &user.ID,
		}

		if err := w.addToQueue(emailItem); err != nil {
			w.logger.Error("Failed to add maintenance notification to queue", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"error":   err.Error(),
			})
			continue
		}

		sent++
	}

	w.logger.Info("Queued maintenance notifications", map[string]interface{}{
		"notifications_sent": sent,
	})

	return nil
}

// ProcessEmailCampaign processes an email campaign
func (w *EmailWorker) ProcessEmailCampaign(ctx context.Context, campaignID primitive.ObjectID) error {
	w.logger.Info("Processing email campaign", map[string]interface{}{
		"campaign_id": campaignID.Hex(),
	})

	// This would load campaign from database
	// For now, we'll simulate a campaign
	campaign := &EmailCampaign{
		ID:         campaignID,
		Name:       "Feature Announcement",
		Subject:    "Exciting New Features in CloudDrive",
		TemplateID: "feature_announcement",
		Status:     CampaignStatusSending,
		Stats: CampaignStats{
			StartedAt: time.Now(),
		},
	}

	// Get campaign recipients
	recipients, err := w.getCampaignRecipients(ctx, campaign)
	if err != nil {
		return fmt.Errorf("failed to get campaign recipients: %w", err)
	}

	campaign.Stats.TotalRecipients = int64(len(recipients))

	var sent, failed int64

	for _, recipient := range recipients {
		emailItem := EmailQueueItem{
			ID:         primitive.NewObjectID(),
			Type:       EmailTypeMarketing,
			Priority:   EmailPriorityLow,
			Recipient:  recipient.Email,
			Subject:    campaign.Subject,
			TemplateID: campaign.TemplateID,
			Data: map[string]interface{}{
				"FirstName":  recipient.FirstName,
				"LastName":   recipient.LastName,
				"Email":      recipient.Email,
				"CampaignID": campaign.ID.Hex(),
			},
			ScheduledAt: time.Now(),
			CreatedAt:   time.Now(),
			MaxAttempts: 3,
			Status:      EmailStatusPending,
			UserID:      &recipient.ID,
		}

		if err := w.addToQueue(emailItem); err != nil {
			w.logger.Error("Failed to add campaign email to queue", map[string]interface{}{
				"recipient": recipient.Email,
				"error":     err.Error(),
			})
			failed++
			continue
		}

		sent++
	}

	campaign.Stats.Sent = sent
	campaign.Stats.Failed = failed

	if failed == 0 {
		campaign.Status = CampaignStatusCompleted
		completedAt := time.Now()
		campaign.Stats.CompletedAt = &completedAt
	}

	w.logger.Info("Processed email campaign", map[string]interface{}{
		"campaign_id": campaignID.Hex(),
		"sent":        sent,
		"failed":      failed,
	})

	return nil
}

// Helper methods

// processEmailItem processes a single email item
func (w *EmailWorker) processEmailItem(ctx context.Context, item *EmailQueueItem) error {
	// Check if item is scheduled for future
	if item.ScheduledAt.After(time.Now()) {
		return nil // Skip, not yet time
	}

	// Check max attempts
	if item.Attempts >= item.MaxAttempts {
		item.Status = EmailStatusFailed
		return fmt.Errorf("max attempts exceeded")
	}

	item.Status = EmailStatusSending
	item.Attempts++

	// Render email template if using template
	var body string
	var err error

	if item.TemplateID != "" {
		body, err = w.renderEmailTemplate(item.TemplateID, item.Data)
		if err != nil {
			item.Status = EmailStatusFailed
			item.Error = err.Error()
			return fmt.Errorf("failed to render template: %w", err)
		}
	} else {
		body = item.Body
	}

	// Send email based on type
	switch item.Type {
	case EmailTypeWelcome:
		err = w.emailService.SendWelcomeEmail(ctx, item.Recipient, item.Data["FirstName"].(string))
	case EmailTypeVerification:
		err = w.emailService.SendVerificationEmail(ctx, item.Recipient, item.Data["FirstName"].(string), item.Data["Token"].(string))
	case EmailTypePasswordReset:
		err = w.emailService.SendPasswordResetEmail(ctx, item.Recipient, item.Data["FirstName"].(string), item.Data["Token"].(string))
	case EmailTypeInvoice:
		err = w.emailService.SendInvoiceEmail(ctx, item.Recipient, item.Data["InvoiceData"].(string))
	default:
		err = w.emailService.SendNotificationEmail(ctx, item.Recipient, item.Subject, body)
	}

	if err != nil {
		item.Status = EmailStatusFailed
		item.Error = err.Error()

		// Check if should retry
		if item.Attempts < item.MaxAttempts {
			item.Status = EmailStatusRetrying
			// Add exponential backoff
			item.ScheduledAt = time.Now().Add(time.Duration(item.Attempts*item.Attempts) * time.Minute)
		}

		return fmt.Errorf("failed to send email: %w", err)
	}

	item.Status = EmailStatusSent
	item.Error = ""

	// Track email analytics
	w.trackEmailAnalytics(ctx, item)

	// Log audit event
	if item.UserID != nil {
		w.logAuditEvent(ctx, *item.UserID, "email_sent", "email", item.ID, true, string(item.Type))
	}

	return nil
}

// getEmailsByPriority returns emails of a specific priority
func (w *EmailWorker) getEmailsByPriority(priority EmailPriority) []EmailQueueItem {
	var items []EmailQueueItem
	for _, item := range w.emailQueue.items {
		if item.Priority == priority && (item.Status == EmailStatusPending || item.Status == EmailStatusRetrying) {
			items = append(items, item)
		}
	}
	return items
}

// addToQueue adds an email item to the queue
func (w *EmailWorker) addToQueue(item EmailQueueItem) error {
	if len(w.emailQueue.items) >= w.emailQueue.maxSize {
		return fmt.Errorf("email queue is full")
	}

	w.emailQueue.items = append(w.emailQueue.items, item)
	return nil
}

// removeFromQueue removes an item from the queue
func (w *EmailWorker) removeFromQueue(itemID primitive.ObjectID) {
	for i, item := range w.emailQueue.items {
		if item.ID == itemID {
			w.emailQueue.items = append(w.emailQueue.items[:i], w.emailQueue.items[i+1:]...)
			break
		}
	}
}

// renderEmailTemplate renders an email template with data
func (w *EmailWorker) renderEmailTemplate(templateID string, data map[string]interface{}) (string, error) {
	// Get template
	template, err := w.getEmailTemplate(templateID)
	if err != nil {
		return "", fmt.Errorf("failed to get template: %w", err)
	}

	// Simple template variable replacement
	body := template.BodyHTML
	for key, value := range data {
		placeholder := fmt.Sprintf("{{.%s}}", key)
		body = strings.ReplaceAll(body, placeholder, fmt.Sprintf("%v", value))
	}

	return body, nil
}

// getEmailTemplate gets an email template by ID
func (w *EmailWorker) getEmailTemplate(templateID string) (*EmailTemplate, error) {
	// In a real implementation, this would fetch from database
	// For now, return a default template
	templates := map[string]*EmailTemplate{
		"welcome": {
			ID:       "welcome",
			Name:     "Welcome Email",
			Subject:  "Welcome to CloudDrive!",
			BodyHTML: `<h1>Welcome {{.FirstName}}!</h1><p>Thank you for joining CloudDrive.</p>`,
			Type:     EmailTypeWelcome,
			Active:   true,
		},
		"subscription_expiry": {
			ID:       "subscription_expiry",
			Name:     "Subscription Expiry",
			Subject:  "Your subscription expires soon",
			BodyHTML: `<h1>Hi {{.FirstName}},</h1><p>Your {{.PlanName}} subscription expires on {{.ExpiryDate}}.</p>`,
			Type:     EmailTypeSubscriptionExpiry,
			Active:   true,
		},
		"storage_alert": {
			ID:       "storage_alert",
			Name:     "Storage Alert",
			Subject:  "Storage usage alert",
			BodyHTML: `<h1>Hi {{.FirstName}},</h1><p>You have used {{.UsagePercentage}}% of your storage.</p>`,
			Type:     EmailTypeStorageAlert,
			Active:   true,
		},
		"activity_summary": {
			ID:       "activity_summary",
			Name:     "Weekly Activity Summary",
			Subject:  "Your weekly CloudDrive activity",
			BodyHTML: `<h1>Hi {{.FirstName}},</h1><p>Here's your activity from {{.WeekStart}} to {{.WeekEnd}}.</p>`,
			Type:     EmailTypeActivitySummary,
			Active:   true,
		},
		"security_alert": {
			ID:       "security_alert",
			Name:     "Security Alert",
			Subject:  "Security alert for your account",
			BodyHTML: `<h1>Hi {{.FirstName}},</h1><p>We detected unusual activity on your account.</p>`,
			Type:     EmailTypeSecurityAlert,
			Active:   true,
		},
		"maintenance_notice": {
			ID:       "maintenance_notice",
			Name:     "Maintenance Notice",
			Subject:  "Scheduled maintenance notification",
			BodyHTML: `<h1>Hi {{.FirstName}},</h1><p>CloudDrive will undergo maintenance from {{.MaintenanceStart}} to {{.MaintenanceEnd}}.</p>`,
			Type:     EmailTypeMaintenanceNotice,
			Active:   true,
		},
		"feature_announcement": {
			ID:       "feature_announcement",
			Name:     "Feature Announcement",
			Subject:  "New features available",
			BodyHTML: `<h1>Hi {{.FirstName}},</h1><p>We've added exciting new features to CloudDrive!</p>`,
			Type:     EmailTypeFeatureAnnouncement,
			Active:   true,
		},
	}

	template, exists := templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	return template, nil
}

// getCampaignRecipients gets recipients for an email campaign
func (w *EmailWorker) getCampaignRecipients(ctx context.Context, campaign *EmailCampaign) ([]*models.User, error) {
	// Get active users who opted in for marketing emails
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 10000,
		Filter: map[string]interface{}{
			"status":           models.StatusActive,
			"marketing_emails": true,
			"email_verified":   true,
		},
	}

	users, _, err := w.userRepo.List(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get campaign recipients: %w", err)
	}

	return users, nil
}

// Check methods for avoiding duplicate emails

// hasWelcomeEmailBeenSent checks if welcome email was already sent
func (w *EmailWorker) hasWelcomeEmailBeenSent(ctx context.Context, userID primitive.ObjectID) bool {
	// Check analytics for welcome email event
	yesterday := time.Now().AddDate(0, 0, -1)
	events, err := w.analyticsRepo.GetByUser(ctx, userID, yesterday, time.Now())
	if err != nil {
		return false
	}

	for _, event := range events {
		if event.EventType == "email_sent" && event.Action == string(EmailTypeWelcome) {
			return true
		}
	}

	return false
}

// hasExpiryNotificationBeenSent checks if expiry notification was sent
func (w *EmailWorker) hasExpiryNotificationBeenSent(ctx context.Context, subscriptionID primitive.ObjectID, days int) bool {
	// Check analytics for expiry notification
	yesterday := time.Now().AddDate(0, 0, -1)

	// This would check if notification was sent in the last 24 hours
	// Implementation would depend on how you track sent emails
	return false
}

// hasStorageAlertBeenSent checks if storage alert was sent
func (w *EmailWorker) hasStorageAlertBeenSent(ctx context.Context, userID primitive.ObjectID, threshold int) bool {
	// Check analytics for storage alert
	yesterday := time.Now().AddDate(0, 0, -1)
	events, err := w.analyticsRepo.GetByUser(ctx, userID, yesterday, time.Now())
	if err != nil {
		return false
	}

	for _, event := range events {
		if event.EventType == "email_sent" && event.Action == string(EmailTypeStorageAlert) {
			if thresholdData, exists := event.Metadata["threshold"]; exists {
				if thresholdData == threshold {
					return true
				}
			}
		}
	}

	return false
}

// createSecurityAlertSummary creates a summary of security alerts
func (w *EmailWorker) createSecurityAlertSummary(alerts []*models.AuditLog) string {
	alertTypes := make(map[string]int)

	for _, alert := range alerts {
		alertTypes[string(alert.Action)]++
	}

	var summary []string
	for action, count := range alertTypes {
		if count == 1 {
			summary = append(summary, fmt.Sprintf("1 %s event", action))
		} else {
			summary = append(summary, fmt.Sprintf("%d %s events", count, action))
		}
	}

	return strings.Join(summary, ", ")
}

// formatDuration formats duration for human reading
func (w *EmailWorker) formatDuration(duration time.Duration) string {
	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60

	if hours > 0 {
		if minutes > 0 {
			return fmt.Sprintf("%d hours and %d minutes", hours, minutes)
		}
		return fmt.Sprintf("%d hours", hours)
	}
	return fmt.Sprintf("%d minutes", minutes)
}

// trackEmailAnalytics tracks email sending analytics
func (w *EmailWorker) trackEmailAnalytics(ctx context.Context, item *EmailQueueItem) {
	analytics := &models.Analytics{
		UserID:    item.UserID,
		EventType: "email_sent",
		Action:    string(item.Type),
		Resource: models.AnalyticsResource{
			Type: "email",
			ID:   item.ID,
			Name: item.Subject,
		},
		Metadata: map[string]interface{}{
			"recipient":   item.Recipient,
			"type":        string(item.Type),
			"priority":    int(item.Priority),
			"attempts":    item.Attempts,
			"template_id": item.TemplateID,
		},
		Timestamp: time.Now(),
	}

	if err := w.analyticsRepo.Create(ctx, analytics); err != nil {
		w.logger.Error("Failed to track email analytics", map[string]interface{}{
			"email_id": item.ID.Hex(),
			"error":    err.Error(),
		})
	}
}

// logAuditEvent logs an audit event
func (w *EmailWorker) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action string, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
	auditLog := &models.AuditLog{
		UserID:    &userID,
		Action:    models.AuditAction(action),
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

// GetQueueStatus returns the current status of the email queue
func (w *EmailWorker) GetQueueStatus() map[string]interface{} {
	statusCounts := make(map[EmailStatus]int)
	priorityCounts := make(map[EmailPriority]int)
	typeCounts := make(map[EmailType]int)

	for _, item := range w.emailQueue.items {
		statusCounts[item.Status]++
		priorityCounts[item.Priority]++
		typeCounts[item.Type]++
	}

	return map[string]interface{}{
		"total_items":     len(w.emailQueue.items),
		"max_size":        w.emailQueue.maxSize,
		"status_counts":   statusCounts,
		"priority_counts": priorityCounts,
		"type_counts":     typeCounts,
	}
}
