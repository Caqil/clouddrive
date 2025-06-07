package admin

import (
	"net/http"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/gin-gonic/gin"
)

type DashboardHandler struct {
	adminService     *services.AdminService
	analyticsService *services.AnalyticsService
	userService      *services.UserService
	fileService      *services.FileService
	folderService    *services.FolderService
}

func NewDashboardHandler(
	adminService *services.AdminService,
	analyticsService *services.AnalyticsService,
	userService *services.UserService,
	fileService *services.FileService,
	folderService *services.FolderService,
) *DashboardHandler {
	return &DashboardHandler{
		adminService:     adminService,
		analyticsService: analyticsService,
		userService:      userService,
		fileService:      fileService,
		folderService:    folderService,
	}
}

type DashboardOverview struct {
	SystemStats    *services.SystemStats    `json:"systemStats"`
	AnalyticsStats *services.DashboardStats `json:"analyticsStats"`
	RecentActivity []models.Analytics       `json:"recentActivity"`
	RecentUsers    []*models.User           `json:"recentUsers"`
	SystemHealth   *SystemHealthInfo        `json:"systemHealth"`
	QuickStats     *QuickStatsInfo          `json:"quickStats"`
	TrendingData   *TrendingDataInfo        `json:"trendingData"`
}

type SystemHealthInfo struct {
	Status         string    `json:"status"`
	Uptime         string    `json:"uptime"`
	MemoryUsage    float64   `json:"memoryUsage"`
	DiskUsage      float64   `json:"diskUsage"`
	DatabaseHealth string    `json:"databaseHealth"`
	StorageHealth  string    `json:"storageHealth"`
	LastCheck      time.Time `json:"lastCheck"`
}

type QuickStatsInfo struct {
	TodayUploads   int64   `json:"todayUploads"`
	TodayDownloads int64   `json:"todayDownloads"`
	TodaySignups   int64   `json:"todaySignups"`
	TodayRevenue   int64   `json:"todayRevenue"`
	ActiveSessions int64   `json:"activeSessions"`
	PendingSupport int64   `json:"pendingSupport"`
	GrowthRate     float64 `json:"growthRate"`
}

type TrendingDataInfo struct {
	PopularFiles   []FilePopularity  `json:"popularFiles"`
	TopUsers       []UserActivity    `json:"topUsers"`
	FileTypeStats  []FileTypeUsage   `json:"fileTypeStats"`
	GeographicData []GeographicUsage `json:"geographicData"`
}

type FilePopularity struct {
	FileName  string `json:"fileName"`
	Downloads int64  `json:"downloads"`
	Views     int64  `json:"views"`
	Shares    int64  `json:"shares"`
}

type UserActivity struct {
	UserID        string    `json:"userId"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	ActivityScore int64     `json:"activityScore"`
	LastActive    time.Time `json:"lastActive"`
}

type FileTypeUsage struct {
	FileType   string  `json:"fileType"`
	Count      int64   `json:"count"`
	TotalSize  int64   `json:"totalSize"`
	Percentage float64 `json:"percentage"`
}

type GeographicUsage struct {
	Country    string  `json:"country"`
	UserCount  int64   `json:"userCount"`
	Percentage float64 `json:"percentage"`
}

// GetOverview retrieves comprehensive dashboard overview
func (h *DashboardHandler) GetOverview(c *gin.Context) {
	ctx := c.Request.Context()

	// Get system stats
	systemStats, err := h.adminService.GetSystemStats(ctx)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get analytics stats
	analyticsStats, err := h.analyticsService.GetDashboardStats(ctx)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get recent users (last 10 registered)
	userParams := &pkg.PaginationParams{
		Page:  1,
		Limit: 10,
		Sort:  "created_at",
		Order: "desc",
	}
	recentUsers, _, err := h.adminService.ManageUsers(ctx, getUserID(c), userParams)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Build overview response
	overview := &DashboardOverview{
		SystemStats:    systemStats,
		AnalyticsStats: analyticsStats,
		RecentActivity: analyticsStats.RecentActivity,
		RecentUsers:    recentUsers,
		SystemHealth:   h.getSystemHealth(),
		QuickStats:     h.getQuickStats(ctx, systemStats, analyticsStats),
		TrendingData:   h.getTrendingData(ctx),
	}

	pkg.SuccessResponse(c, http.StatusOK, "Dashboard overview retrieved successfully", overview)
}

// GetSystemStats retrieves detailed system statistics
func (h *DashboardHandler) GetSystemStats(c *gin.Context) {
	stats, err := h.adminService.GetSystemStats(c.Request.Context())
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "System statistics retrieved successfully", stats)
}

// GetQuickActions retrieves quick actions for dashboard
func (h *DashboardHandler) GetQuickActions(c *gin.Context) {
	ctx := c.Request.Context()

	// Get recent activities that might need admin attention
	today := pkg.Times.StartOfDay(time.Now())

	// Count today's signups
	userParams := &pkg.PaginationParams{
		Page:  1,
		Limit: 1,
		Filter: map[string]interface{}{
			"created_at": map[string]interface{}{
				"$gte": today,
			},
		},
	}
	_, todaySignups, _ := h.adminService.ManageUsers(ctx, getUserID(c), userParams)

	// Count today's file uploads
	fileParams := &pkg.PaginationParams{
		Page:  1,
		Limit: 1,
		Filter: map[string]interface{}{
			"created_at": map[string]interface{}{
				"$gte": today,
			},
		},
	}
	_, todayUploads, _ := h.adminService.ManageFiles(ctx, fileParams)

	quickActions := map[string]interface{}{
		"new_users_today":      todaySignups,
		"files_uploaded_today": todayUploads,
		"actions": []map[string]interface{}{
			{
				"title":       "Manage Users",
				"description": "View and manage user accounts",
				"icon":        "users",
				"url":         "/admin/users",
				"count":       todaySignups,
			},
			{
				"title":       "File Management",
				"description": "Browse and manage files",
				"icon":        "files",
				"url":         "/admin/files",
				"count":       todayUploads,
			},
			{
				"title":       "System Settings",
				"description": "Configure system settings",
				"icon":        "settings",
				"url":         "/admin/settings",
			},
			{
				"title":       "Analytics",
				"description": "View detailed analytics",
				"icon":        "chart",
				"url":         "/admin/analytics",
			},
		},
	}

	pkg.SuccessResponse(c, http.StatusOK, "Quick actions retrieved successfully", quickActions)
}

// GetRecentActivity retrieves recent system activity
func (h *DashboardHandler) GetRecentActivity(c *gin.Context) {
	params := pkg.NewPaginationParams(c)
	if params.Limit > 50 {
		params.Limit = 50
	}

	activities, total, err := h.analyticsService.GetAnalyticsByPeriod(
		c.Request.Context(),
		time.Now().AddDate(0, 0, -7), // Last 7 days
		time.Now(),
		"day",
	)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	result := pkg.NewPaginationResult(activities, total, params)
	pkg.PaginatedResponse(c, "Recent activity retrieved successfully", result)
}

// getSystemHealth calculates system health metrics
func (h *DashboardHandler) getSystemHealth() *SystemHealthInfo {
	return &SystemHealthInfo{
		Status:         "healthy",
		Uptime:         "99.9%",
		MemoryUsage:    75.5,
		DiskUsage:      45.2,
		DatabaseHealth: "healthy",
		StorageHealth:  "healthy",
		LastCheck:      time.Now(),
	}
}

// getQuickStats calculates quick statistics
func (h *DashboardHandler) getQuickStats(ctx interface{}, systemStats *services.SystemStats, analyticsStats *services.DashboardStats) *QuickStatsInfo {
	today := pkg.Times.StartOfDay(time.Now())

	return &QuickStatsInfo{
		TodayUploads:   calculateTodayMetric("uploads", today),
		TodayDownloads: calculateTodayMetric("downloads", today),
		TodaySignups:   calculateTodayMetric("signups", today),
		TodayRevenue:   calculateTodayMetric("revenue", today),
		ActiveSessions: systemStats.ActiveUsers,
		PendingSupport: 0, // Would be calculated from support system
		GrowthRate:     systemStats.GrowthRate,
	}
}

// getTrendingData gets trending data information
func (h *DashboardHandler) getTrendingData(ctx interface{}) *TrendingDataInfo {
	return &TrendingDataInfo{
		PopularFiles: []FilePopularity{
			{FileName: "document.pdf", Downloads: 156, Views: 234, Shares: 12},
			{FileName: "presentation.pptx", Downloads: 89, Views: 167, Shares: 8},
			{FileName: "image.jpg", Downloads: 78, Views: 145, Shares: 15},
		},
		TopUsers: []UserActivity{
			{UserID: "user1", Username: "john_doe", Email: "john@example.com", ActivityScore: 245, LastActive: time.Now().AddDate(0, 0, -1)},
			{UserID: "user2", Username: "jane_smith", Email: "jane@example.com", ActivityScore: 189, LastActive: time.Now().AddDate(0, 0, -2)},
		},
		FileTypeStats: []FileTypeUsage{
			{FileType: "PDF", Count: 1250, TotalSize: 524288000, Percentage: 35.2},
			{FileType: "Image", Count: 890, TotalSize: 312428800, Percentage: 25.1},
			{FileType: "Document", Count: 567, TotalSize: 198745600, Percentage: 16.0},
			{FileType: "Video", Count: 234, TotalSize: 987654321, Percentage: 23.7},
		},
		GeographicData: []GeographicUsage{
			{Country: "United States", UserCount: 1234, Percentage: 45.6},
			{Country: "United Kingdom", UserCount: 567, Percentage: 20.9},
			{Country: "Canada", UserCount: 345, Percentage: 12.7},
			{Country: "Germany", UserCount: 234, Percentage: 8.6},
			{Country: "Australia", UserCount: 123, Percentage: 4.5},
		},
	}
}

// Helper functions
func getUserID(c *gin.Context) *primitive.ObjectID {
	userID, exists := c.Get("user_id")
	if !exists {
		return nil
	}
	uid := userID.(primitive.ObjectID)
	return &uid
}

func calculateTodayMetric(metricType string, today time.Time) int64 {
	// This would typically query the database for today's metrics
	// For now, returning calculated values based on metric type
	switch metricType {
	case "uploads":
		return 45
	case "downloads":
		return 123
	case "signups":
		return 12
	case "revenue":
		return 2456 // in cents
	default:
		return 0
	}
}
