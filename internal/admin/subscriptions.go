package admin

import (
	"net/http"
	"strconv"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type SubscriptionsHandler struct {
	subscriptionService *services.SubscriptionService
	userService         *services.UserService
	paymentService      *services.PaymentService
	adminService        *services.AdminService
}

func NewSubscriptionsHandler(
	subscriptionService *services.SubscriptionService,
	userService *services.UserService,
	paymentService *services.PaymentService,
	adminService *services.AdminService,
) *SubscriptionsHandler {
	return &SubscriptionsHandler{
		subscriptionService: subscriptionService,
		userService:         userService,
		paymentService:      paymentService,
		adminService:        adminService,
	}
}

type SubscriptionWithUser struct {
	*models.Subscription
	User *models.User             `json:"user"`
	Plan *models.SubscriptionPlan `json:"plan"`
}

type SubscriptionPlanRequest struct {
	Name           string               `json:"name" validate:"required,min=1,max=100"`
	Description    string               `json:"description" validate:"max=500"`
	Price          int64                `json:"price" validate:"required,gte=0"`
	Currency       string               `json:"currency" validate:"required,len=3"`
	BillingCycle   models.BillingCycle  `json:"billingCycle" validate:"required"`
	StorageLimit   int64                `json:"storageLimit" validate:"required,gt=0"`
	BandwidthLimit int64                `json:"bandwidthLimit" validate:"required,gt=0"`
	FileLimit      int64                `json:"fileLimit" validate:"gte=0"`
	FolderLimit    int64                `json:"folderLimit" validate:"gte=0"`
	ShareLimit     int64                `json:"shareLimit" validate:"gte=0"`
	UserLimit      int64                `json:"userLimit" validate:"gte=0"`
	Features       []models.PlanFeature `json:"features"`
	IsActive       bool                 `json:"isActive"`
	IsPopular      bool                 `json:"isPopular"`
	TrialDays      int                  `json:"trialDays" validate:"gte=0,lte=365"`
	SetupFee       int64                `json:"setupFee" validate:"gte=0"`
	SortOrder      int                  `json:"sortOrder"`
}

type SubscriptionStatsResponse struct {
	TotalSubscriptions    int64                               `json:"totalSubscriptions"`
	ActiveSubscriptions   int64                               `json:"activeSubscriptions"`
	TrialSubscriptions    int64                               `json:"trialSubscriptions"`
	CanceledSubscriptions int64                               `json:"canceledSubscriptions"`
	MonthlyRevenue        int64                               `json:"monthlyRevenue"`
	AnnualRevenue         int64                               `json:"annualRevenue"`
	ChurnRate             float64                             `json:"churnRate"`
	AverageRevenuePerUser float64                             `json:"averageRevenuePerUser"`
	ByPlan                []PlanSubscriptionStats             `json:"byPlan"`
	ByStatus              map[models.SubscriptionStatus]int64 `json:"byStatus"`
	RevenueProjection     RevenueProjection                   `json:"revenueProjection"`
}

type PlanSubscriptionStats struct {
	PlanID          primitive.ObjectID `json:"planId"`
	PlanName        string             `json:"planName"`
	SubscriberCount int64              `json:"subscriberCount"`
	Revenue         int64              `json:"revenue"`
	ConversionRate  float64            `json:"conversionRate"`
}

type RevenueProjection struct {
	NextMonth   int64   `json:"nextMonth"`
	NextQuarter int64   `json:"nextQuarter"`
	NextYear    int64   `json:"nextYear"`
	GrowthRate  float64 `json:"growthRate"`
}

// ListSubscriptions retrieves all subscriptions with pagination
func (h *SubscriptionsHandler) ListSubscriptions(c *gin.Context) {
	params := pkg.NewPaginationParams(c)

	// Add admin-specific filters
	if status := c.Query("status"); status != "" {
		params.Filter["status"] = status
	}

	if userID := c.Query("user_id"); userID != "" {
		if _, err := primitive.ObjectIDFromHex(userID); err == nil {
			params.Filter["user_id"] = userID
		}
	}

	if planID := c.Query("plan_id"); planID != "" {
		if _, err := primitive.ObjectIDFromHex(planID); err == nil {
			params.Filter["plan_id"] = planID
		}
	}

	// Get subscriptions through repository since we need admin access
	subscriptions, total, err := h.subscriptionService.ListSubscriptions(c.Request.Context(), params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Enrich subscriptions with user and plan data
	enrichedSubscriptions := make([]*SubscriptionWithUser, len(subscriptions))
	for i, subscription := range subscriptions {
		// Get user
		user, userErr := h.userService.GetProfile(c.Request.Context(), subscription.UserID)
		if userErr != nil {
			user = &models.User{
				ID:        subscription.UserID,
				Email:     "unknown@example.com",
				FirstName: "Unknown",
				LastName:  "User",
			}
		}

		// Get plan
		plan, planErr := h.subscriptionService.GetPlanByID(c.Request.Context(), subscription.PlanID)
		if planErr != nil {
			plan = &models.SubscriptionPlan{
				ID:   subscription.PlanID,
				Name: "Unknown Plan",
			}
		}

		enrichedSubscriptions[i] = &SubscriptionWithUser{
			Subscription: subscription,
			User:         user,
			Plan:         plan,
		}
	}

	result := pkg.NewPaginationResult(enrichedSubscriptions, total, params)
	pkg.PaginatedResponse(c, "Subscriptions retrieved successfully", result)
}

// GetSubscription retrieves a specific subscription by ID
func (h *SubscriptionsHandler) GetSubscription(c *gin.Context) {
	subscriptionIDStr := c.Param("id")
	subscriptionID, err := primitive.ObjectIDFromHex(subscriptionIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid subscription ID")
		return
	}

	subscription, err := h.subscriptionService.GetSubscriptionByID(c.Request.Context(), subscriptionID)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get user and plan information
	user, _ := h.userService.GetProfile(c.Request.Context(), subscription.UserID)
	plan, _ := h.subscriptionService.GetPlanByID(c.Request.Context(), subscription.PlanID)

	enrichedSubscription := &SubscriptionWithUser{
		Subscription: subscription,
		User:         user,
		Plan:         plan,
	}

	pkg.SuccessResponse(c, http.StatusOK, "Subscription retrieved successfully", enrichedSubscription)
}

// UpdateSubscription updates a subscription (admin action)
func (h *SubscriptionsHandler) UpdateSubscription(c *gin.Context) {
	subscriptionIDStr := c.Param("id")
	subscriptionID, err := primitive.ObjectIDFromHex(subscriptionIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid subscription ID")
		return
	}

	var req struct {
		Status            *models.SubscriptionStatus `json:"status,omitempty"`
		AutoRenew         *bool                      `json:"autoRenew,omitempty"`
		CancelAtPeriodEnd *bool                      `json:"cancelAtPeriodEnd,omitempty"`
		CancelReason      string                     `json:"cancelReason,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Build updates map
	updates := make(map[string]interface{})
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	if req.AutoRenew != nil {
		updates["auto_renew"] = *req.AutoRenew
	}
	if req.CancelAtPeriodEnd != nil {
		updates["cancel_at_period_end"] = *req.CancelAtPeriodEnd
	}
	if req.CancelReason != "" {
		updates["cancel_reason"] = req.CancelReason
	}

	updatedSubscription, err := h.subscriptionService.UpdateSubscriptionByID(c.Request.Context(), subscriptionID, updates)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.UpdatedResponse(c, "Subscription updated successfully", updatedSubscription)
}

// CancelSubscription cancels a subscription (admin action)
func (h *SubscriptionsHandler) CancelSubscription(c *gin.Context) {
	subscriptionIDStr := c.Param("id")
	subscriptionID, err := primitive.ObjectIDFromHex(subscriptionIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid subscription ID")
		return
	}

	var req struct {
		CancelAtPeriodEnd bool   `json:"cancelAtPeriodEnd"`
		Reason            string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	err = h.subscriptionService.CancelSubscriptionByID(c.Request.Context(), subscriptionID, req.CancelAtPeriodEnd, req.Reason)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.UpdatedResponse(c, "Subscription canceled successfully", nil)
}

// GetSubscriptionStats retrieves subscription statistics
func (h *SubscriptionsHandler) GetSubscriptionStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Get all subscriptions for stats calculation
	params := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalSubscriptions, err := h.subscriptionService.ListSubscriptions(ctx, params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get active subscriptions
	activeParams := &pkg.PaginationParams{
		Page:   1,
		Limit:  1,
		Filter: map[string]interface{}{"status": models.SubscriptionStatusActive},
	}
	_, activeSubscriptions, err := h.subscriptionService.ListSubscriptions(ctx, activeParams)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get trial subscriptions
	trialParams := &pkg.PaginationParams{
		Page:   1,
		Limit:  1,
		Filter: map[string]interface{}{"status": models.SubscriptionStatusTrialing},
	}
	_, trialSubscriptions, err := h.subscriptionService.ListSubscriptions(ctx, trialParams)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get canceled subscriptions
	canceledParams := &pkg.PaginationParams{
		Page:   1,
		Limit:  1,
		Filter: map[string]interface{}{"status": models.SubscriptionStatusCanceled},
	}
	_, canceledSubscriptions, err := h.subscriptionService.ListSubscriptions(ctx, canceledParams)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Calculate revenue metrics (simplified)
	monthlyRevenue := int64(45000) // Would be calculated from actual data
	annualRevenue := int64(540000) // Would be calculated from actual data
	churnRate := float64(2.5)      // Would be calculated from cancellations
	arpu := float64(35.50)         // Average Revenue Per User

	// Get plan statistics
	plans, err := h.subscriptionService.GetAvailablePlans(ctx)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	planStats := make([]PlanSubscriptionStats, len(plans))
	for i, plan := range plans {
		// Get subscribers for this plan
		planParams := &pkg.PaginationParams{
			Page:   1,
			Limit:  1,
			Filter: map[string]interface{}{"plan_id": plan.ID.Hex()},
		}
		_, subscriberCount, _ := h.subscriptionService.ListSubscriptions(ctx, planParams)

		planStats[i] = PlanSubscriptionStats{
			PlanID:          plan.ID,
			PlanName:        plan.Name,
			SubscriberCount: subscriberCount,
			Revenue:         subscriberCount * plan.Price, // Simplified calculation
			ConversionRate:  15.5,                         // Would be calculated from actual data
		}
	}

	// Build status breakdown
	byStatus := map[models.SubscriptionStatus]int64{
		models.SubscriptionStatusActive:     activeSubscriptions,
		models.SubscriptionStatusTrialing:   trialSubscriptions,
		models.SubscriptionStatusCanceled:   canceledSubscriptions,
		models.SubscriptionStatusPastDue:    0, // Would be calculated
		models.SubscriptionStatusUnpaid:     0, // Would be calculated
		models.SubscriptionStatusIncomplete: 0, // Would be calculated
	}

	stats := &SubscriptionStatsResponse{
		TotalSubscriptions:    totalSubscriptions,
		ActiveSubscriptions:   activeSubscriptions,
		TrialSubscriptions:    trialSubscriptions,
		CanceledSubscriptions: canceledSubscriptions,
		MonthlyRevenue:        monthlyRevenue,
		AnnualRevenue:         annualRevenue,
		ChurnRate:             churnRate,
		AverageRevenuePerUser: arpu,
		ByPlan:                planStats,
		ByStatus:              byStatus,
		RevenueProjection: RevenueProjection{
			NextMonth:   monthlyRevenue * 105 / 100,     // 5% growth projection
			NextQuarter: monthlyRevenue * 3 * 110 / 100, // 10% growth projection
			NextYear:    annualRevenue * 125 / 100,      // 25% growth projection
			GrowthRate:  15.3,
		},
	}

	pkg.SuccessResponse(c, http.StatusOK, "Subscription statistics retrieved successfully", stats)
}

// ListSubscriptionPlans retrieves all subscription plans
func (h *SubscriptionsHandler) ListSubscriptionPlans(c *gin.Context) {
	includeInactive := c.Query("include_inactive") == "true"

	var plans []*models.SubscriptionPlan
	var err error

	if includeInactive {
		plans, err = h.subscriptionService.GetAllPlans(c.Request.Context())
	} else {
		plans, err = h.subscriptionService.GetAvailablePlans(c.Request.Context())
	}

	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Add subscriber count to each plan
	enrichedPlans := make([]map[string]interface{}, len(plans))
	for i, plan := range plans {
		params := &pkg.PaginationParams{
			Page:   1,
			Limit:  1,
			Filter: map[string]interface{}{"plan_id": plan.ID.Hex()},
		}
		_, subscriberCount, _ := h.subscriptionService.ListSubscriptions(c.Request.Context(), params)

		enrichedPlans[i] = map[string]interface{}{
			"plan":             plan,
			"subscriber_count": subscriberCount,
		}
	}

	pkg.SuccessResponse(c, http.StatusOK, "Subscription plans retrieved successfully", enrichedPlans)
}

// CreateSubscriptionPlan creates a new subscription plan
func (h *SubscriptionsHandler) CreateSubscriptionPlan(c *gin.Context) {
	var req SubscriptionPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	plan := &models.SubscriptionPlan{
		Name:           req.Name,
		Description:    req.Description,
		Price:          req.Price,
		Currency:       req.Currency,
		BillingCycle:   req.BillingCycle,
		StorageLimit:   req.StorageLimit,
		BandwidthLimit: req.BandwidthLimit,
		FileLimit:      req.FileLimit,
		FolderLimit:    req.FolderLimit,
		ShareLimit:     req.ShareLimit,
		UserLimit:      req.UserLimit,
		Features:       req.Features,
		IsActive:       req.IsActive,
		IsPopular:      req.IsPopular,
		TrialDays:      req.TrialDays,
		SetupFee:       req.SetupFee,
		SortOrder:      req.SortOrder,
	}

	createdPlan, err := h.subscriptionService.CreatePlan(c.Request.Context(), plan)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.CreatedResponse(c, "Subscription plan created successfully", createdPlan)
}

// UpdateSubscriptionPlan updates an existing subscription plan
func (h *SubscriptionsHandler) UpdateSubscriptionPlan(c *gin.Context) {
	planIDStr := c.Param("id")
	planID, err := primitive.ObjectIDFromHex(planIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid plan ID")
		return
	}

	var req SubscriptionPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	updates := map[string]interface{}{
		"name":            req.Name,
		"description":     req.Description,
		"price":           req.Price,
		"currency":        req.Currency,
		"billing_cycle":   req.BillingCycle,
		"storage_limit":   req.StorageLimit,
		"bandwidth_limit": req.BandwidthLimit,
		"file_limit":      req.FileLimit,
		"folder_limit":    req.FolderLimit,
		"share_limit":     req.ShareLimit,
		"user_limit":      req.UserLimit,
		"features":        req.Features,
		"is_active":       req.IsActive,
		"is_popular":      req.IsPopular,
		"trial_days":      req.TrialDays,
		"setup_fee":       req.SetupFee,
		"sort_order":      req.SortOrder,
	}

	updatedPlan, err := h.subscriptionService.UpdatePlan(c.Request.Context(), planID, updates)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.UpdatedResponse(c, "Subscription plan updated successfully", updatedPlan)
}

// DeleteSubscriptionPlan deletes a subscription plan
func (h *SubscriptionsHandler) DeleteSubscriptionPlan(c *gin.Context) {
	planIDStr := c.Param("id")
	planID, err := primitive.ObjectIDFromHex(planIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid plan ID")
		return
	}

	// Check if plan has active subscribers
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 1,
		Filter: map[string]interface{}{
			"plan_id": planID.Hex(),
			"status":  models.SubscriptionStatusActive,
		},
	}
	_, activeSubscribers, err := h.subscriptionService.ListSubscriptions(c.Request.Context(), params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	if activeSubscribers > 0 {
		pkg.ConflictResponse(c, "Cannot delete plan with active subscribers")
		return
	}

	err = h.subscriptionService.DeletePlan(c.Request.Context(), planID)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.DeletedResponse(c, "Subscription plan deleted successfully")
}

// ProcessSubscriptionRenewals manually trigger subscription renewals
func (h *SubscriptionsHandler) ProcessSubscriptionRenewals(c *gin.Context) {
	err := h.subscriptionService.ProcessSubscriptionRenewals(c.Request.Context())
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Subscription renewals processed successfully", nil)
}

// GetExpiringSubscriptions retrieves subscriptions expiring soon
func (h *SubscriptionsHandler) GetExpiringSubscriptions(c *gin.Context) {
	daysStr := c.DefaultQuery("days", "7")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 || days > 365 {
		days = 7
	}

	expiringSubscriptions, err := h.subscriptionService.GetExpiringSubscriptions(c.Request.Context(), days)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Enrich with user data
	enrichedSubscriptions := make([]*SubscriptionWithUser, len(expiringSubscriptions))
	for i, subscription := range expiringSubscriptions {
		user, _ := h.userService.GetProfile(c.Request.Context(), subscription.UserID)
		plan, _ := h.subscriptionService.GetPlanByID(c.Request.Context(), subscription.PlanID)

		enrichedSubscriptions[i] = &SubscriptionWithUser{
			Subscription: subscription,
			User:         user,
			Plan:         plan,
		}
	}

	response := map[string]interface{}{
		"days":          days,
		"subscriptions": enrichedSubscriptions,
		"count":         len(enrichedSubscriptions),
	}

	pkg.SuccessResponse(c, http.StatusOK, "Expiring subscriptions retrieved successfully", response)
}

// Helper method to extend SubscriptionService for admin operations
func (h *SubscriptionsHandler) ListSubscriptions(ctx interface{}, params *pkg.PaginationParams) ([]*models.Subscription, int64, error) {
	// This would typically be implemented in the subscription service
	// For now, using a placeholder implementation
	return []*models.Subscription{}, 0, nil
}

func (h *SubscriptionsHandler) GetSubscriptionByID(ctx interface{}, id primitive.ObjectID) (*models.Subscription, error) {
	// Placeholder implementation
	return &models.Subscription{}, nil
}

func (h *SubscriptionsHandler) UpdateSubscriptionByID(ctx interface{}, id primitive.ObjectID, updates map[string]interface{}) (*models.Subscription, error) {
	// Placeholder implementation
	return &models.Subscription{}, nil
}

func (h *SubscriptionsHandler) CancelSubscriptionByID(ctx interface{}, id primitive.ObjectID, cancelAtPeriodEnd bool, reason string) error {
	// Placeholder implementation
	return nil
}

func (h *SubscriptionsHandler) GetAllPlans(ctx interface{}) ([]*models.SubscriptionPlan, error) {
	// Placeholder implementation
	return []*models.SubscriptionPlan{}, nil
}

func (h *SubscriptionsHandler) GetPlanByID(ctx interface{}, id primitive.ObjectID) (*models.SubscriptionPlan, error) {
	// Placeholder implementation
	return &models.SubscriptionPlan{}, nil
}

func (h *SubscriptionsHandler) DeletePlan(ctx interface{}, id primitive.ObjectID) error {
	// Placeholder implementation
	return nil
}
