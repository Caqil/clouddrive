package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AnalyticsWorker handles analytics processing tasks
type AnalyticsWorker struct {
	analyticsRepo repository.AnalyticsRepository
	userRepo      repository.UserRepository
	fileRepo      repository.FileRepository
	paymentRepo   repository.PaymentRepository
	shareRepo     repository.ShareRepository
	auditRepo     repository.AuditLogRepository
	logger        *pkg.Logger
}

// NewAnalyticsWorker creates a new analytics worker
func NewAnalyticsWorker(
	analyticsRepo repository.AnalyticsRepository,
	userRepo repository.UserRepository,
	fileRepo repository.FileRepository,
	paymentRepo repository.PaymentRepository,
	shareRepo repository.ShareRepository,
	auditRepo repository.AuditLogRepository,
	logger *pkg.Logger,
) *AnalyticsWorker {
	return &AnalyticsWorker{
		analyticsRepo: analyticsRepo,
		userRepo:      userRepo,
		fileRepo:      fileRepo,
		paymentRepo:   paymentRepo,
		shareRepo:     shareRepo,
		auditRepo:     auditRepo,
		logger:        logger,
	}
}

// ProcessDailySummary generates daily analytics summary
func (w *AnalyticsWorker) ProcessDailySummary(ctx context.Context, date time.Time) error {
	w.logger.Info("Starting daily analytics summary processing", map[string]interface{}{
		"date": date.Format("2006-01-02"),
	})

	startOfDay := pkg.Times.StartOfDay(date)
	endOfDay := pkg.Times.EndOfDay(date)

	// Get all analytics events for the day
	eventParams := &pkg.PaginationParams{Page: 1, Limit: 10000, Sort: "timestamp", Order: "asc"}
	events, _, err := w.analyticsRepo.List(ctx, eventParams)
	if err != nil {
		w.logger.Error("Failed to get analytics events", map[string]interface{}{
			"error": err.Error(),
			"date":  date.Format("2006-01-02"),
		})
		return fmt.Errorf("failed to get analytics events: %w", err)
	}

	// Filter events for the specific day
	var dayEvents []*models.Analytics
	for _, event := range events {
		if event.Timestamp.After(startOfDay) && event.Timestamp.Before(endOfDay) {
			dayEvents = append(dayEvents, event)
		}
	}

	// Process events and calculate metrics
	metrics := w.calculateDailyMetrics(ctx, dayEvents, startOfDay, endOfDay)

	// Check if summary already exists
	existingSummary, err := w.analyticsRepo.GetSummaryByDate(ctx, date)
	if err == nil {
		// Update existing summary
		updates := map[string]interface{}{
			"total_users":       metrics.TotalUsers,
			"active_users":      metrics.ActiveUsers,
			"new_users":         metrics.NewUsers,
			"total_files":       metrics.TotalFiles,
			"files_uploaded":    metrics.FilesUploaded,
			"files_downloaded":  metrics.FilesDownloaded,
			"storage_used":      metrics.StorageUsed,
			"bandwidth_used":    metrics.BandwidthUsed,
			"total_revenue":     metrics.TotalRevenue,
			"new_subscriptions": metrics.NewSubscriptions,
			"churn":             metrics.Churn,
			"page_views":        metrics.PageViews,
			"unique_visitors":   metrics.UniqueVisitors,
			"api_calls":         metrics.ApiCalls,
			"errors":            metrics.Errors,
			"shares_created":    metrics.SharesCreated,
			"shares_accessed":   metrics.SharesAccessed,
		}

		if err := w.analyticsRepo.UpdateSummary(ctx, date, updates); err != nil {
			return fmt.Errorf("failed to update analytics summary: %w", err)
		}

		w.logger.Info("Updated existing daily analytics summary", map[string]interface{}{
			"date":         date.Format("2006-01-02"),
			"active_users": metrics.ActiveUsers,
			"new_users":    metrics.NewUsers,
		})
	} else {
		// Create new summary
		summary := &models.AnalyticsSummary{
			Date:             startOfDay,
			TotalUsers:       metrics.TotalUsers,
			ActiveUsers:      metrics.ActiveUsers,
			NewUsers:         metrics.NewUsers,
			TotalFiles:       metrics.TotalFiles,
			FilesUploaded:    metrics.FilesUploaded,
			FilesDownloaded:  metrics.FilesDownloaded,
			StorageUsed:      metrics.StorageUsed,
			BandwidthUsed:    metrics.BandwidthUsed,
			TotalRevenue:     metrics.TotalRevenue,
			NewSubscriptions: metrics.NewSubscriptions,
			Churn:            metrics.Churn,
			PageViews:        metrics.PageViews,
			UniqueVisitors:   metrics.UniqueVisitors,
			ApiCalls:         metrics.ApiCalls,
			Errors:           metrics.Errors,
			SharesCreated:    metrics.SharesCreated,
			SharesAccessed:   metrics.SharesAccessed,
		}

		if err := w.analyticsRepo.CreateSummary(ctx, summary); err != nil {
			return fmt.Errorf("failed to create analytics summary: %w", err)
		}

		w.logger.Info("Created new daily analytics summary", map[string]interface{}{
			"date":         date.Format("2006-01-02"),
			"active_users": metrics.ActiveUsers,
			"new_users":    metrics.NewUsers,
		})
	}

	return nil
}

// ProcessUserAnalytics generates user-specific analytics
func (w *AnalyticsWorker) ProcessUserAnalytics(ctx context.Context, date time.Time) error {
	w.logger.Info("Starting user analytics processing", map[string]interface{}{
		"date": date.Format("2006-01-02"),
	})

	startOfDay := pkg.Times.StartOfDay(date)
	endOfDay := pkg.Times.EndOfDay(date)

	// Get all users in batches
	pageSize := 100
	page := 1

	for {
		userParams := &pkg.PaginationParams{Page: page, Limit: pageSize}
		users, totalUsers, err := w.userRepo.List(ctx, userParams)
		if err != nil {
			return fmt.Errorf("failed to get users: %w", err)
		}

		if len(users) == 0 {
			break
		}

		// Process each user
		for _, user := range users {
			if err := w.processIndividualUserAnalytics(ctx, user.ID, startOfDay, endOfDay); err != nil {
				w.logger.Error("Failed to process user analytics", map[string]interface{}{
					"user_id": user.ID.Hex(),
					"error":   err.Error(),
				})
				continue
			}
		}

		w.logger.Info("Processed user analytics batch", map[string]interface{}{
			"page":        page,
			"users_count": len(users),
			"total_users": totalUsers,
		})

		page++
		if int64((page-1)*pageSize) >= totalUsers {
			break
		}
	}

	return nil
}

// ProcessWeeklySummary generates weekly analytics summary
func (w *AnalyticsWorker) ProcessWeeklySummary(ctx context.Context, weekStart time.Time) error {
	w.logger.Info("Starting weekly analytics summary processing", map[string]interface{}{
		"week_start": weekStart.Format("2006-01-02"),
	})

	weekEnd := weekStart.AddDate(0, 0, 7)

	// Get daily summaries for the week
	summaries, err := w.analyticsRepo.GetSummariesByPeriod(ctx, weekStart, weekEnd)
	if err != nil {
		return fmt.Errorf("failed to get weekly summaries: %w", err)
	}

	if len(summaries) == 0 {
		w.logger.Warn("No daily summaries found for week", map[string]interface{}{
			"week_start": weekStart.Format("2006-01-02"),
		})
		return nil
	}

	// Aggregate weekly metrics
	var weeklyMetrics models.AnalyticsSummary
	weeklyMetrics.Date = weekStart

	for _, summary := range summaries {
		weeklyMetrics.NewUsers += summary.NewUsers
		weeklyMetrics.FilesUploaded += summary.FilesUploaded
		weeklyMetrics.FilesDownloaded += summary.FilesDownloaded
		weeklyMetrics.BandwidthUsed += summary.BandwidthUsed
		weeklyMetrics.TotalRevenue += summary.TotalRevenue
		weeklyMetrics.NewSubscriptions += summary.NewSubscriptions
		weeklyMetrics.PageViews += summary.PageViews
		weeklyMetrics.ApiCalls += summary.ApiCalls
		weeklyMetrics.Errors += summary.Errors
		weeklyMetrics.SharesCreated += summary.SharesCreated
		weeklyMetrics.SharesAccessed += summary.SharesAccessed

		// Use latest values for current state metrics
		if summary.Date.After(weeklyMetrics.Date) || weeklyMetrics.TotalUsers == 0 {
			weeklyMetrics.TotalUsers = summary.TotalUsers
			weeklyMetrics.TotalFiles = summary.TotalFiles
			weeklyMetrics.StorageUsed = summary.StorageUsed
		}
	}

	// Calculate average active users and unique visitors
	weeklyMetrics.ActiveUsers = w.calculateAverageActiveUsers(summaries)
	weeklyMetrics.UniqueVisitors = w.calculateAverageUniqueVisitors(summaries)

	// Calculate churn rate for the week
	weeklyMetrics.Churn = w.calculateWeeklyChurn(ctx, weekStart, weekEnd)

	// Store weekly summary with special identifier
	weeklyMetrics.ID = primitive.NewObjectID()
	weeklyMetrics.CreatedAt = time.Now()
	weeklyMetrics.UpdatedAt = time.Now()

	// Add weekly identifier to distinguish from daily summaries
	if err := w.analyticsRepo.CreateSummary(ctx, &weeklyMetrics); err != nil {
		return fmt.Errorf("failed to create weekly summary: %w", err)
	}

	w.logger.Info("Created weekly analytics summary", map[string]interface{}{
		"week_start": weekStart.Format("2006-01-02"),
		"new_users":  weeklyMetrics.NewUsers,
		"revenue":    weeklyMetrics.TotalRevenue,
	})

	return nil
}

// ProcessTopUsers identifies and ranks top users by various metrics
func (w *AnalyticsWorker) ProcessTopUsers(ctx context.Context, date time.Time) error {
	w.logger.Info("Processing top users analytics", map[string]interface{}{
		"date": date.Format("2006-01-02"),
	})

	// Define metrics to track
	metrics := []string{"files_uploaded", "files_downloaded", "storage_used", "shares_created", "login_count"}
	limit := 100

	for _, metric := range metrics {
		topUsers, err := w.analyticsRepo.GetTopUsers(ctx, metric, limit, date.AddDate(0, 0, -30), date)
		if err != nil {
			w.logger.Error("Failed to get top users", map[string]interface{}{
				"metric": metric,
				"error":  err.Error(),
			})
			continue
		}

		// Process and store top user rankings
		for rank, userAnalytics := range topUsers {
			if err := w.storeUserRanking(ctx, userAnalytics.UserID, metric, rank+1, date); err != nil {
				w.logger.Error("Failed to store user ranking", map[string]interface{}{
					"user_id": userAnalytics.UserID.Hex(),
					"metric":  metric,
					"rank":    rank + 1,
					"error":   err.Error(),
				})
			}
		}

		w.logger.Info("Processed top users for metric", map[string]interface{}{
			"metric":      metric,
			"users_count": len(topUsers),
		})
	}

	return nil
}

// ProcessGeoAnalytics analyzes geographic distribution of users and activity
func (w *AnalyticsWorker) ProcessGeoAnalytics(ctx context.Context, date time.Time) error {
	w.logger.Info("Processing geographic analytics", map[string]interface{}{
		"date": date.Format("2006-01-02"),
	})

	startOfDay := pkg.Times.StartOfDay(date)
	endOfDay := pkg.Times.EndOfDay(date)

	// Get analytics events with geographic data
	eventParams := &pkg.PaginationParams{Page: 1, Limit: 10000}
	events, _, err := w.analyticsRepo.List(ctx, eventParams)
	if err != nil {
		return fmt.Errorf("failed to get analytics events: %w", err)
	}

	// Aggregate by country and city
	countryStats := make(map[string]*GeoStats)
	cityStats := make(map[string]*GeoStats)

	for _, event := range events {
		if event.Timestamp.Before(startOfDay) || event.Timestamp.After(endOfDay) {
			continue
		}

		// Process country stats
		if event.Country != "" {
			if _, exists := countryStats[event.Country]; !exists {
				countryStats[event.Country] = &GeoStats{
					Location: event.Country,
					Type:     "country",
				}
			}
			countryStats[event.Country].EventCount++
			countryStats[event.Country].UniqueUsers[event.UserID.Hex()] = true

			if event.EventType == models.EventTypeFileUpload {
				countryStats[event.Country].Uploads++
			} else if event.EventType == models.EventTypeFileDownload {
				countryStats[event.Country].Downloads++
			}
		}

		// Process city stats
		if event.City != "" {
			cityKey := fmt.Sprintf("%s, %s", event.City, event.Country)
			if _, exists := cityStats[cityKey]; !exists {
				cityStats[cityKey] = &GeoStats{
					Location: cityKey,
					Type:     "city",
				}
			}
			cityStats[cityKey].EventCount++
			cityStats[cityKey].UniqueUsers[event.UserID.Hex()] = true

			if event.EventType == models.EventTypeFileUpload {
				cityStats[cityKey].Uploads++
			} else if event.EventType == models.EventTypeFileDownload {
				cityStats[cityKey].Downloads++
			}
		}
	}

	// Store geographic analytics
	if err := w.storeGeoAnalytics(ctx, countryStats, cityStats, date); err != nil {
		return fmt.Errorf("failed to store geo analytics: %w", err)
	}

	w.logger.Info("Processed geographic analytics", map[string]interface{}{
		"countries": len(countryStats),
		"cities":    len(cityStats),
	})

	return nil
}

// Helper methods

// calculateDailyMetrics calculates various metrics from daily events
func (w *AnalyticsWorker) calculateDailyMetrics(ctx context.Context, events []*models.Analytics, startOfDay, endOfDay time.Time) *DailyMetrics {
	metrics := &DailyMetrics{}

	// Count events by type
	eventCounts := make(map[models.AnalyticsEventType]int64)
	uniqueUsers := make(map[string]bool)

	for _, event := range events {
		eventCounts[event.EventType]++

		if event.UserID != nil {
			uniqueUsers[event.UserID.Hex()] = true
		}

		switch event.EventType {
		case models.EventTypeUserRegister:
			metrics.NewUsers++
		case models.EventTypeFileUpload:
			metrics.FilesUploaded++
			if event.Resource.Size != nil {
				metrics.BandwidthUsed += *event.Resource.Size
			}
		case models.EventTypeFileDownload:
			metrics.FilesDownloaded++
			if event.Resource.Size != nil {
				metrics.BandwidthUsed += *event.Resource.Size
			}
		case models.EventTypeFileShare:
			metrics.SharesCreated++
		case models.EventTypeShareAccess:
			metrics.SharesAccessed++
		case models.EventTypePageView:
			metrics.PageViews++
		case models.EventTypeAPICall:
			metrics.ApiCalls++
		case models.EventTypeError:
			metrics.Errors++
		}
	}

	metrics.ActiveUsers = int64(len(uniqueUsers))
	metrics.UniqueVisitors = int64(len(uniqueUsers))

	// Get current totals
	userParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalUsers, _ := w.userRepo.List(ctx, userParams)
	metrics.TotalUsers = totalUsers

	fileParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalFiles, _ := w.fileRepo.List(ctx, fileParams)
	metrics.TotalFiles = totalFiles

	totalStorage, _ := w.fileRepo.GetTotalStorageUsed(ctx)
	metrics.StorageUsed = totalStorage

	// Get revenue for the day
	revenue, _ := w.paymentRepo.GetRevenueByPeriod(ctx, startOfDay, endOfDay)
	metrics.TotalRevenue = revenue

	// Calculate new subscriptions (simplified)
	metrics.NewSubscriptions = eventCounts[models.EventTypeSubscription]

	// Calculate churn (simplified)
	metrics.Churn = w.calculateDailyChurn(ctx, startOfDay, endOfDay)

	return metrics
}

// processIndividualUserAnalytics processes analytics for a single user
func (w *AnalyticsWorker) processIndividualUserAnalytics(ctx context.Context, userID primitive.ObjectID, startOfDay, endOfDay time.Time) error {
	// Get user events for the day
	events, err := w.analyticsRepo.GetByUser(ctx, userID, startOfDay, endOfDay)
	if err != nil {
		return fmt.Errorf("failed to get user events: %w", err)
	}

	// Calculate user metrics
	userMetrics := &models.UserAnalytics{
		UserID: userID,
		Date:   startOfDay,
	}

	sessionStart := time.Time{}
	var sessionDuration time.Duration

	for _, event := range events {
		switch event.EventType {
		case models.EventTypeFileUpload:
			userMetrics.FilesUploaded++
		case models.EventTypeFileDownload:
			userMetrics.FilesDownloaded++
		case models.EventTypeUserLogin:
			userMetrics.LoginCount++
			if sessionStart.IsZero() {
				sessionStart = event.Timestamp
			}
		case models.EventTypeUserLogout:
			if !sessionStart.IsZero() {
				sessionDuration += event.Timestamp.Sub(sessionStart)
				sessionStart = time.Time{}
			}
		case models.EventTypeFileShare:
			userMetrics.SharesCreated++
		case models.EventTypeShareAccess:
			userMetrics.SharesAccessed++
		case models.EventTypePageView:
			userMetrics.PageViews++
		case models.EventTypeAPICall:
			userMetrics.ApiCalls++
		}
	}

	// If user is still logged in, calculate partial session
	if !sessionStart.IsZero() {
		sessionDuration += endOfDay.Sub(sessionStart)
	}

	userMetrics.SessionDuration = int64(sessionDuration.Seconds())

	// Get current storage used by user
	storageUsed, _ := w.fileRepo.GetStorageByUser(ctx, userID)
	userMetrics.StorageUsed = storageUsed

	// Check if user analytics already exists for this date
	if existingAnalytics, err := w.analyticsRepo.GetUserAnalyticsByDate(ctx, userID, startOfDay); err == nil {
		// Update existing
		updates := map[string]interface{}{
			"files_uploaded":   userMetrics.FilesUploaded,
			"files_downloaded": userMetrics.FilesDownloaded,
			"storage_used":     userMetrics.StorageUsed,
			"login_count":      userMetrics.LoginCount,
			"session_duration": userMetrics.SessionDuration,
			"page_views":       userMetrics.PageViews,
			"api_calls":        userMetrics.ApiCalls,
			"shares_created":   userMetrics.SharesCreated,
			"shares_accessed":  userMetrics.SharesAccessed,
		}
		return w.analyticsRepo.UpdateUserAnalytics(ctx, userID, startOfDay, updates)
	} else {
		// Create new
		return w.analyticsRepo.CreateUserAnalytics(ctx, userMetrics)
	}
}

// calculateAverageActiveUsers calculates average active users from daily summaries
func (w *AnalyticsWorker) calculateAverageActiveUsers(summaries []*models.AnalyticsSummary) int64 {
	if len(summaries) == 0 {
		return 0
	}

	var total int64
	for _, summary := range summaries {
		total += summary.ActiveUsers
	}

	return total / int64(len(summaries))
}

// calculateAverageUniqueVisitors calculates average unique visitors
func (w *AnalyticsWorker) calculateAverageUniqueVisitors(summaries []*models.AnalyticsSummary) int64 {
	if len(summaries) == 0 {
		return 0
	}

	var total int64
	for _, summary := range summaries {
		total += summary.UniqueVisitors
	}

	return total / int64(len(summaries))
}

// calculateDailyChurn calculates daily churn rate
func (w *AnalyticsWorker) calculateDailyChurn(ctx context.Context, startOfDay, endOfDay time.Time) float64 {
	// Get cancellation events for the day
	eventParams := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"event_type": models.EventTypeSubscription,
			"action":     "cancel",
		},
	}

	events, _, err := w.analyticsRepo.List(ctx, eventParams)
	if err != nil {
		return 0
	}

	var cancellations int64
	for _, event := range events {
		if event.Timestamp.After(startOfDay) && event.Timestamp.Before(endOfDay) {
			cancellations++
		}
	}

	// Get total active subscriptions (simplified)
	userParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalUsers, _ := w.userRepo.List(ctx, userParams)

	if totalUsers == 0 {
		return 0
	}

	return float64(cancellations) / float64(totalUsers) * 100
}

// calculateWeeklyChurn calculates weekly churn rate
func (w *AnalyticsWorker) calculateWeeklyChurn(ctx context.Context, weekStart, weekEnd time.Time) float64 {
	// Similar to daily churn but for a week period
	eventParams := &pkg.PaginationParams{
		Page:  1,
		Limit: 1000,
		Filter: map[string]interface{}{
			"event_type": models.EventTypeSubscription,
			"action":     "cancel",
		},
	}

	events, _, err := w.analyticsRepo.List(ctx, eventParams)
	if err != nil {
		return 0
	}

	var cancellations int64
	for _, event := range events {
		if event.Timestamp.After(weekStart) && event.Timestamp.Before(weekEnd) {
			cancellations++
		}
	}

	userParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalUsers, _ := w.userRepo.List(ctx, userParams)

	if totalUsers == 0 {
		return 0
	}

	return float64(cancellations) / float64(totalUsers) * 100
}

// storeUserRanking stores user ranking data
func (w *AnalyticsWorker) storeUserRanking(ctx context.Context, userID primitive.ObjectID, metric string, rank int, date time.Time) error {
	// Create analytics event for ranking
	ranking := &models.Analytics{
		UserID:    &userID,
		EventType: "user_ranking",
		Action:    "rank_update",
		Resource: models.AnalyticsResource{
			Type: "ranking",
			ID:   userID,
			Name: metric,
		},
		Metadata: map[string]interface{}{
			"metric": metric,
			"rank":   rank,
			"date":   date.Format("2006-01-02"),
		},
		Timestamp: time.Now(),
	}

	return w.analyticsRepo.Create(ctx, ranking)
}

// storeGeoAnalytics stores geographic analytics data
func (w *AnalyticsWorker) storeGeoAnalytics(ctx context.Context, countryStats, cityStats map[string]*GeoStats, date time.Time) error {
	// Store country-level analytics
	for country, stats := range countryStats {
		geoAnalytics := &models.Analytics{
			EventType: "geo_analytics",
			Action:    "country_stats",
			Resource: models.AnalyticsResource{
				Type: "geography",
				Name: country,
			},
			Metadata: map[string]interface{}{
				"location":     country,
				"type":         "country",
				"event_count":  stats.EventCount,
				"unique_users": len(stats.UniqueUsers),
				"uploads":      stats.Uploads,
				"downloads":    stats.Downloads,
				"date":         date.Format("2006-01-02"),
			},
			Country:   country,
			Timestamp: time.Now(),
		}

		if err := w.analyticsRepo.Create(ctx, geoAnalytics); err != nil {
			w.logger.Error("Failed to store country analytics", map[string]interface{}{
				"country": country,
				"error":   err.Error(),
			})
		}
	}

	// Store city-level analytics
	for city, stats := range cityStats {
		geoAnalytics := &models.Analytics{
			EventType: "geo_analytics",
			Action:    "city_stats",
			Resource: models.AnalyticsResource{
				Type: "geography",
				Name: city,
			},
			Metadata: map[string]interface{}{
				"location":     city,
				"type":         "city",
				"event_count":  stats.EventCount,
				"unique_users": len(stats.UniqueUsers),
				"uploads":      stats.Uploads,
				"downloads":    stats.Downloads,
				"date":         date.Format("2006-01-02"),
			},
			City:      city,
			Timestamp: time.Now(),
		}

		if err := w.analyticsRepo.Create(ctx, geoAnalytics); err != nil {
			w.logger.Error("Failed to store city analytics", map[string]interface{}{
				"city":  city,
				"error": err.Error(),
			})
		}
	}

	return nil
}

// Supporting types

// DailyMetrics represents calculated daily metrics
type DailyMetrics struct {
	TotalUsers       int64   `json:"totalUsers"`
	ActiveUsers      int64   `json:"activeUsers"`
	NewUsers         int64   `json:"newUsers"`
	TotalFiles       int64   `json:"totalFiles"`
	FilesUploaded    int64   `json:"filesUploaded"`
	FilesDownloaded  int64   `json:"filesDownloaded"`
	StorageUsed      int64   `json:"storageUsed"`
	BandwidthUsed    int64   `json:"bandwidthUsed"`
	TotalRevenue     int64   `json:"totalRevenue"`
	NewSubscriptions int64   `json:"newSubscriptions"`
	Churn            float64 `json:"churn"`
	PageViews        int64   `json:"pageViews"`
	UniqueVisitors   int64   `json:"uniqueVisitors"`
	ApiCalls         int64   `json:"apiCalls"`
	Errors           int64   `json:"errors"`
	SharesCreated    int64   `json:"sharesCreated"`
	SharesAccessed   int64   `json:"sharesAccessed"`
}

// GeoStats represents geographic statistics
type GeoStats struct {
	Location    string          `json:"location"`
	Type        string          `json:"type"`
	EventCount  int64           `json:"eventCount"`
	UniqueUsers map[string]bool `json:"-"`
	Uploads     int64           `json:"uploads"`
	Downloads   int64           `json:"downloads"`
}

// Initialize GeoStats with empty map
func NewGeoStats(location, geoType string) *GeoStats {
	return &GeoStats{
		Location:    location,
		Type:        geoType,
		UniqueUsers: make(map[string]bool),
	}
}
