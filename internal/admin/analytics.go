package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AnalyticsHandler struct {
	analyticsService *services.AnalyticsService
	adminService     *services.AdminService
}

func NewAnalyticsHandler(analyticsService *services.AnalyticsService, adminService *services.AdminService) *AnalyticsHandler {
	return &AnalyticsHandler{
		analyticsService: analyticsService,
		adminService:     adminService,
	}
}

// GetDashboardStats retrieves dashboard statistics
func (h *AnalyticsHandler) GetDashboardStats(c *gin.Context) {
	stats, err := h.analyticsService.GetDashboardStats(c.Request.Context())
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Dashboard statistics retrieved successfully", stats)
}

// GetAnalyticsByPeriod retrieves analytics data for a specific period
func (h *AnalyticsHandler) GetAnalyticsByPeriod(c *gin.Context) {
	// Parse query parameters
	startStr := c.Query("start")
	endStr := c.Query("end")
	granularity := c.DefaultQuery("granularity", "day")

	if startStr == "" || endStr == "" {
		pkg.BadRequestResponse(c, "Start and end dates are required")
		return
	}

	start, err := time.Parse("2006-01-02", startStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid start date format. Use YYYY-MM-DD")
		return
	}

	end, err := time.Parse("2006-01-02", endStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid end date format. Use YYYY-MM-DD")
		return
	}

	// Validate granularity
	if granularity != "day" && granularity != "week" && granularity != "month" && granularity != "year" {
		pkg.BadRequestResponse(c, "Invalid granularity. Use: day, week, month, or year")
		return
	}

	analytics, err := h.analyticsService.GetAnalyticsByPeriod(c.Request.Context(), start, end, granularity)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Analytics data retrieved successfully", analytics)
}

// GetUserAnalytics retrieves analytics for a specific user
func (h *AnalyticsHandler) GetUserAnalytics(c *gin.Context) {
	userIDStr := c.Param("userId")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	// Parse date range
	startStr := c.DefaultQuery("start", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endStr := c.DefaultQuery("end", time.Now().Format("2006-01-02"))

	start, err := time.Parse("2006-01-02", startStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid start date format")
		return
	}

	end, err := time.Parse("2006-01-02", endStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid end date format")
		return
	}

	analytics, err := h.analyticsService.GetUserAnalytics(c.Request.Context(), userID, start, end)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "User analytics retrieved successfully", analytics)
}

// GetTopUsers retrieves top users by specific metric
func (h *AnalyticsHandler) GetTopUsers(c *gin.Context) {
	metric := c.DefaultQuery("metric", "files_uploaded")
	limitStr := c.DefaultQuery("limit", "10")
	startStr := c.DefaultQuery("start", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endStr := c.DefaultQuery("end", time.Now().Format("2006-01-02"))

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 10
	}

	start, err := time.Parse("2006-01-02", startStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid start date format")
		return
	}

	end, err := time.Parse("2006-01-02", endStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid end date format")
		return
	}

	// Validate metric
	validMetrics := []string{"files_uploaded", "files_downloaded", "storage_used", "shares_created", "login_count"}
	isValid := false
	for _, vm := range validMetrics {
		if metric == vm {
			isValid = true
			break
		}
	}
	if !isValid {
		pkg.BadRequestResponse(c, "Invalid metric. Valid options: files_uploaded, files_downloaded, storage_used, shares_created, login_count")
		return
	}

	topUsers, err := h.analyticsService.GetTopUsers(c.Request.Context(), metric, limit, start, end)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Top users retrieved successfully", topUsers)
}

// GetEventCounts retrieves event counts for a period
func (h *AnalyticsHandler) GetEventCounts(c *gin.Context) {
	startStr := c.DefaultQuery("start", time.Now().AddDate(0, 0, -7).Format("2006-01-02"))
	endStr := c.DefaultQuery("end", time.Now().Format("2006-01-02"))

	start, err := time.Parse("2006-01-02", startStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid start date format")
		return
	}

	end, err := time.Parse("2006-01-02", endStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid end date format")
		return
	}

	eventCounts, err := h.analyticsService.GetEventCounts(c.Request.Context(), start, end)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Event counts retrieved successfully", eventCounts)
}

// TrackEvent manually track an analytics event (for admin testing)
func (h *AnalyticsHandler) TrackEvent(c *gin.Context) {
	var req struct {
		UserID     *string                   `json:"userId"`
		EventType  models.AnalyticsEventType `json:"eventType" validate:"required"`
		Action     string                    `json:"action" validate:"required"`
		ResourceID *string                   `json:"resourceId"`
		Metadata   map[string]interface{}    `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	var userID *primitive.ObjectID
	if req.UserID != nil {
		uid, err := primitive.ObjectIDFromHex(*req.UserID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid user ID")
			return
		}
		userID = &uid
	}

	var resourceID primitive.ObjectID
	if req.ResourceID != nil {
		rid, err := primitive.ObjectIDFromHex(*req.ResourceID)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid resource ID")
			return
		}
		resourceID = rid
	}

	resource := models.AnalyticsResource{
		Type: "admin",
		ID:   resourceID,
		Name: "Manual Event",
	}

	err := h.analyticsService.TrackEvent(
		c.Request.Context(),
		userID,
		req.EventType,
		req.Action,
		resource,
		req.Metadata,
		c.ClientIP(),
		c.GetHeader("User-Agent"),
	)

	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusCreated, "Event tracked successfully", nil)
}

// ProcessAnalytics manually trigger analytics processing
func (h *AnalyticsHandler) ProcessAnalytics(c *gin.Context) {
	err := h.analyticsService.ProcessAnalytics(c.Request.Context())
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Analytics processing completed successfully", nil)
}

// GenerateDailySummary manually generate daily summary for specific date
func (h *AnalyticsHandler) GenerateDailySummary(c *gin.Context) {
	dateStr := c.Query("date")
	if dateStr == "" {
		dateStr = time.Now().AddDate(0, 0, -1).Format("2006-01-02") // Yesterday by default
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid date format. Use YYYY-MM-DD")
		return
	}

	err = h.analyticsService.GenerateDailySummary(c.Request.Context(), date)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Daily summary generated successfully", map[string]interface{}{
		"date": date.Format("2006-01-02"),
	})
}
