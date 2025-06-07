package services

import (
	"context"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AnalyticsService handles analytics operations
type AnalyticsService struct {
	analyticsRepo repository.AnalyticsRepository
	userRepo      repository.UserRepository
	fileRepo      repository.FileRepository
	paymentRepo   repository.PaymentRepository
}

// NewAnalyticsService creates a new analytics service
func NewAnalyticsService(
	analyticsRepo repository.AnalyticsRepository,
	userRepo repository.UserRepository,
	fileRepo repository.FileRepository,
	paymentRepo repository.PaymentRepository,
) *AnalyticsService {
	return &AnalyticsService{
		analyticsRepo: analyticsRepo,
		userRepo:      userRepo,
		fileRepo:      fileRepo,
		paymentRepo:   paymentRepo,
	}
}

// DashboardStats represents dashboard statistics
type DashboardStats struct {
	TotalUsers     int64              `json:"totalUsers"`
	ActiveUsers    int64              `json:"activeUsers"`
	TotalFiles     int64              `json:"totalFiles"`
	TotalStorage   int64              `json:"totalStorage"`
	TotalRevenue   int64              `json:"totalRevenue"`
	GrowthRate     float64            `json:"growthRate"`
	StorageUsage   float64            `json:"storageUsage"`
	RecentActivity []models.Analytics `json:"recentActivity"`
}

// UserAnalyticsData represents user analytics data
type UserAnalyticsData struct {
	FilesUploaded   int64   `json:"filesUploaded"`
	FilesDownloaded int64   `json:"filesDownloaded"`
	StorageUsed     int64   `json:"storageUsed"`
	SharesCreated   int64   `json:"sharesCreated"`
	LoginCount      int64   `json:"loginCount"`
	ActivityScore   float64 `json:"activityScore"`
}

// PeriodStats represents statistics for a period
type PeriodStats struct {
	Period  string `json:"period"`
	Users   int64  `json:"users"`
	Files   int64  `json:"files"`
	Storage int64  `json:"storage"`
	Revenue int64  `json:"revenue"`
}

// TrackEvent tracks an analytics event
func (s *AnalyticsService) TrackEvent(ctx context.Context, userID *primitive.ObjectID, eventType models.AnalyticsEventType, action string, resource models.AnalyticsResource, metadata map[string]interface{}, ip, userAgent string) error {
	analytics := &models.Analytics{
		UserID:    userID,
		EventType: eventType,
		Action:    action,
		Resource:  resource,
		Metadata:  metadata,
		IP:        ip,
		UserAgent: userAgent,
		Timestamp: time.Now(),
	}

	return s.analyticsRepo.Create(ctx, analytics)
}

// GetDashboardStats retrieves dashboard statistics
func (s *AnalyticsService) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	now := time.Now()
	lastWeek := now.AddDate(0, 0, -7)
	lastMonth := now.AddDate(0, -1, 0)

	// Get total users
	userParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalUsers, err := s.userRepo.List(ctx, userParams)
	if err != nil {
		return nil, err
	}

	// Get active users (logged in within last 7 days)
	activeUsers, err := s.userRepo.GetActiveUsers(ctx, lastWeek)
	if err != nil {
		return nil, err
	}

	// Get total files
	fileParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalFiles, err := s.fileRepo.List(ctx, fileParams)
	if err != nil {
		return nil, err
	}

	// Get total storage used
	totalStorage, err := s.fileRepo.GetTotalStorageUsed(ctx)
	if err != nil {
		return nil, err
	}

	// Get total revenue for last month
	totalRevenue, err := s.paymentRepo.GetRevenueByPeriod(ctx, lastMonth, now)
	if err != nil {
		return nil, err
	}

	// Calculate growth rate (simplified)
	previousMonth := lastMonth.AddDate(0, -1, 0)
	prevRevenue, _ := s.paymentRepo.GetRevenueByPeriod(ctx, previousMonth, lastMonth)
	growthRate := float64(0)
	if prevRevenue > 0 {
		growthRate = float64(totalRevenue-prevRevenue) / float64(prevRevenue) * 100
	}

	// Get recent activity
	recentParams := &pkg.PaginationParams{Page: 1, Limit: 10, Sort: "timestamp", Order: "desc"}
	recentActivity, _, err := s.analyticsRepo.List(ctx, recentParams)
	if err != nil {
		return nil, err
	}

	return &DashboardStats{
		TotalUsers:     totalUsers,
		ActiveUsers:    activeUsers,
		TotalFiles:     totalFiles,
		TotalStorage:   totalStorage,
		TotalRevenue:   totalRevenue,
		GrowthRate:     growthRate,
		StorageUsage:   float64(totalStorage) / (1024 * 1024 * 1024), // GB
		RecentActivity: recentActivity,
	}, nil
}

// GetUserAnalytics retrieves analytics for a specific user
func (s *AnalyticsService) GetUserAnalytics(ctx context.Context, userID primitive.ObjectID, start, end time.Time) (*UserAnalyticsData, error) {
	// Get user analytics data
	userAnalytics, err := s.analyticsRepo.GetUserAnalyticsByPeriod(ctx, userID, start, end)
	if err != nil {
		return nil, err
	}

	// Aggregate data
	var data UserAnalyticsData
	for _, ua := range userAnalytics {
		data.FilesUploaded += ua.FilesUploaded
		data.FilesDownloaded += ua.FilesDownloaded
		data.StorageUsed += ua.StorageUsed
		data.SharesCreated += ua.SharesCreated
		data.LoginCount += ua.LoginCount
	}

	// Calculate activity score (simplified algorithm)
	data.ActivityScore = float64(data.FilesUploaded+data.FilesDownloaded+data.SharesCreated+data.LoginCount) / 10

	return &data, nil
}

// GetAnalyticsByPeriod retrieves analytics data for a period
func (s *AnalyticsService) GetAnalyticsByPeriod(ctx context.Context, start, end time.Time, granularity string) ([]*PeriodStats, error) {
	summaries, err := s.analyticsRepo.GetSummariesByPeriod(ctx, start, end)
	if err != nil {
		return nil, err
	}

	var stats []*PeriodStats
	for _, summary := range summaries {
		period := summary.Date.Format("2006-01-02")
		if granularity == "month" {
			period = summary.Date.Format("2006-01")
		} else if granularity == "year" {
			period = summary.Date.Format("2006")
		}

		stats = append(stats, &PeriodStats{
			Period:  period,
			Users:   summary.NewUsers,
			Files:   summary.FilesUploaded,
			Storage: summary.StorageUsed,
			Revenue: summary.TotalRevenue,
		})
	}

	return stats, nil
}

// GetTopUsers retrieves top users by metric
func (s *AnalyticsService) GetTopUsers(ctx context.Context, metric string, limit int, start, end time.Time) ([]*models.UserAnalytics, error) {
	return s.analyticsRepo.GetTopUsers(ctx, metric, limit, start, end)
}

// GetEventCounts retrieves event counts for a period
func (s *AnalyticsService) GetEventCounts(ctx context.Context, start, end time.Time) (map[string]int64, error) {
	return s.analyticsRepo.GetEventCounts(ctx, start, end)
}

// GenerateDailySummary generates daily analytics summary
func (s *AnalyticsService) GenerateDailySummary(ctx context.Context, date time.Time) error {
	startOfDay := pkg.Times.StartOfDay(date)
	endOfDay := pkg.Times.EndOfDay(date)

	// Get analytics events for the day
	events, err := s.analyticsRepo.GetByEventType(ctx, "", startOfDay, endOfDay)
	if err != nil {
		return err
	}

	// Count events by type
	eventCounts := make(map[models.AnalyticsEventType]int64)
	uniqueUsers := make(map[primitive.ObjectID]bool)
	var newUsers, filesUploaded, filesDownloaded, storageUsed int64

	for _, event := range events {
		eventCounts[event.EventType]++

		if event.UserID != nil {
			uniqueUsers[*event.UserID] = true
		}

		switch event.EventType {
		case models.EventTypeUserRegister:
			newUsers++
		case models.EventTypeFileUpload:
			filesUploaded++
			if event.Resource.Size != nil {
				storageUsed += *event.Resource.Size
			}
		case models.EventTypeFileDownload:
			filesDownloaded++
		}
	}

	// Get revenue for the day
	revenue, err := s.paymentRepo.GetRevenueByPeriod(ctx, startOfDay, endOfDay)
	if err != nil {
		return err
	}

	// Get total counts
	userParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalUsers, _ := s.userRepo.List(ctx, userParams)

	fileParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalFiles, _ := s.fileRepo.List(ctx, fileParams)

	totalStorage, _ := s.fileRepo.GetTotalStorageUsed(ctx)

	// Create summary
	summary := &models.AnalyticsSummary{
		Date:            startOfDay,
		TotalUsers:      totalUsers,
		ActiveUsers:     int64(len(uniqueUsers)),
		NewUsers:        newUsers,
		TotalFiles:      totalFiles,
		FilesUploaded:   filesUploaded,
		FilesDownloaded: filesDownloaded,
		StorageUsed:     totalStorage,
		TotalRevenue:    revenue,
		PageViews:       eventCounts[models.EventTypePageView],
		UniqueVisitors:  int64(len(uniqueUsers)),
		SharesCreated:   eventCounts[models.EventTypeFileShare],
		SharesAccessed:  eventCounts[models.EventTypeShareAccess],
	}

	// Save or update summary
	if existing, err := s.analyticsRepo.GetSummaryByDate(ctx, date); err == nil {
		// Update existing summary
		updates := map[string]interface{}{
			"active_users":     summary.ActiveUsers,
			"new_users":        summary.NewUsers,
			"files_uploaded":   summary.FilesUploaded,
			"files_downloaded": summary.FilesDownloaded,
			"storage_used":     summary.StorageUsed,
			"total_revenue":    summary.TotalRevenue,
			"page_views":       summary.PageViews,
			"unique_visitors":  summary.UniqueVisitors,
			"shares_created":   summary.SharesCreated,
			"shares_accessed":  summary.SharesAccessed,
		}
		return s.analyticsRepo.UpdateSummary(ctx, date, updates)
	} else {
		// Create new summary
		return s.analyticsRepo.CreateSummary(ctx, summary)
	}
}

// ProcessAnalytics processes analytics in background
func (s *AnalyticsService) ProcessAnalytics(ctx context.Context) error {
	// Generate yesterday's summary
	yesterday := time.Now().AddDate(0, 0, -1)
	if err := s.GenerateDailySummary(ctx, yesterday); err != nil {
		return err
	}

	// Generate user analytics for yesterday
	return s.generateUserAnalytics(ctx, yesterday)
}

// generateUserAnalytics generates user analytics for a specific date
func (s *AnalyticsService) generateUserAnalytics(ctx context.Context, date time.Time) error {
	startOfDay := pkg.Times.StartOfDay(date)
	endOfDay := pkg.Times.EndOfDay(date)

	// Get all users
	userParams := &pkg.PaginationParams{Page: 1, Limit: 1000}
	users, _, err := s.userRepo.List(ctx, userParams)
	if err != nil {
		return err
	}

	for _, user := range users {
		// Get user events for the day
		events, err := s.analyticsRepo.GetByUser(ctx, user.ID, startOfDay, endOfDay)
		if err != nil {
			continue
		}

		// Count events
		var filesUploaded, filesDownloaded, storageUsed, loginCount, sharesCreated int64
		sessionDuration := int64(0)

		for _, event := range events {
			switch event.EventType {
			case models.EventTypeFileUpload:
				filesUploaded++
				if event.Resource.Size != nil {
					storageUsed += *event.Resource.Size
				}
			case models.EventTypeFileDownload:
				filesDownloaded++
			case models.EventTypeUserLogin:
				loginCount++
			case models.EventTypeFileShare:
				sharesCreated++
			}
		}

		// Get current user storage
		currentStorage, _ := s.fileRepo.GetStorageByUser(ctx, user.ID)

		// Create or update user analytics
		userAnalytics := &models.UserAnalytics{
			UserID:          user.ID,
			Date:            startOfDay,
			FilesUploaded:   filesUploaded,
			FilesDownloaded: filesDownloaded,
			StorageUsed:     currentStorage,
			LoginCount:      loginCount,
			SessionDuration: sessionDuration,
			PageViews:       int64(len(events)),
			SharesCreated:   sharesCreated,
		}

		// Check if user analytics already exists for this date
		if existing, err := s.analyticsRepo.GetUserAnalyticsByDate(ctx, user.ID, date); err == nil {
			// Update existing
			updates := map[string]interface{}{
				"files_uploaded":   userAnalytics.FilesUploaded,
				"files_downloaded": userAnalytics.FilesDownloaded,
				"storage_used":     userAnalytics.StorageUsed,
				"login_count":      userAnalytics.LoginCount,
				"session_duration": userAnalytics.SessionDuration,
				"page_views":       userAnalytics.PageViews,
				"shares_created":   userAnalytics.SharesCreated,
			}
			s.analyticsRepo.UpdateUserAnalytics(ctx, user.ID, date, updates)
		} else {
			// Create new
			s.analyticsRepo.CreateUserAnalytics(ctx, userAnalytics)
		}
	}

	return nil
}
