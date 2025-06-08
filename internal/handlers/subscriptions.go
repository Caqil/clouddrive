package handlers

import (
	"net/http"
	"strconv"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// SubscriptionHandler handles subscription management operations
type SubscriptionHandler struct {
	subscriptionService *services.SubscriptionService
	logger              *pkg.Logger
}

// NewSubscriptionHandler creates a new subscription handler
func NewSubscriptionHandler(
	subscriptionService *services.SubscriptionService,
	logger *pkg.Logger,
) *SubscriptionHandler {
	return &SubscriptionHandler{
		subscriptionService: subscriptionService,
		logger:              logger,
	}
}

// ============================================================================
// REQUEST/RESPONSE STRUCTURES
// ============================================================================

// CreateSubscriptionRequest represents subscription creation request
type CreateSubscriptionRequest struct {
	PlanID         string                 `json:"planId" binding:"required"`
	PaymentMethod  string                 `json:"paymentMethod" binding:"required,oneof=stripe paypal"`
	BillingCycle   models.BillingCycle    `json:"billingCycle" binding:"required"`
	PaymentTokenID string                 `json:"paymentTokenId,omitempty"`
	CouponCode     string                 `json:"couponCode,omitempty"`
	BillingAddress *models.BillingAddress `json:"billingAddress,omitempty"`
}

// UpgradeDowngradeRequest represents plan change request
type UpgradeDowngradeRequest struct {
	NewPlanID         string `json:"newPlanId" binding:"required"`
	EffectiveAt       string `json:"effectiveAt,omitempty"`       // "immediate" or "end_of_period"
	ProrationBehavior string `json:"prorationBehavior,omitempty"` // "create_prorations" or "none"
}

// CancelSubscriptionRequest represents cancellation request
type CancelSubscriptionRequest struct {
	Reason      string `json:"reason,omitempty"`
	CancelAtEnd bool   `json:"cancelAtEnd"` // true: cancel at period end, false: immediate
	Feedback    string `json:"feedback,omitempty"`
}

// ReactivateSubscriptionRequest represents reactivation request
type ReactivateSubscriptionRequest struct {
	PaymentMethod  string `json:"paymentMethod,omitempty"`
	PaymentTokenID string `json:"paymentTokenId,omitempty"`
}

// CreatePlanRequest represents plan creation request (admin only)
type CreatePlanRequest struct {
	Name           string               `json:"name" binding:"required,min=1,max=100"`
	Description    string               `json:"description" binding:"max=500"`
	Price          int64                `json:"price" binding:"min=0"` // Price in cents
	Currency       string               `json:"currency" binding:"required,len=3"`
	BillingCycle   models.BillingCycle  `json:"billingCycle" binding:"required"`
	StorageLimit   int64                `json:"storageLimit" binding:"min=1"`   // In bytes
	BandwidthLimit int64                `json:"bandwidthLimit" binding:"min=1"` // In bytes per month
	FileLimit      int64                `json:"fileLimit" binding:"min=1"`
	FolderLimit    int64                `json:"folderLimit" binding:"min=1"`
	ShareLimit     int64                `json:"shareLimit" binding:"min=1"`
	UserLimit      int64                `json:"userLimit" binding:"min=1"`
	Features       []models.PlanFeature `json:"features"`
	IsActive       bool                 `json:"isActive"`
	IsPopular      bool                 `json:"isPopular"`
	TrialDays      int                  `json:"trialDays" binding:"min=0,max=365"`
	SetupFee       int64                `json:"setupFee" binding:"min=0"`
	SortOrder      int                  `json:"sortOrder" binding:"min=0"`
}

// UpdatePlanRequest represents plan update request (admin only)
type UpdatePlanRequest struct {
	Name           *string               `json:"name,omitempty" binding:"omitempty,min=1,max=100"`
	Description    *string               `json:"description,omitempty" binding:"omitempty,max=500"`
	Price          *int64                `json:"price,omitempty" binding:"omitempty,min=0"`
	StorageLimit   *int64                `json:"storageLimit,omitempty" binding:"omitempty,min=1"`
	BandwidthLimit *int64                `json:"bandwidthLimit,omitempty" binding:"omitempty,min=1"`
	FileLimit      *int64                `json:"fileLimit,omitempty" binding:"omitempty,min=1"`
	FolderLimit    *int64                `json:"folderLimit,omitempty" binding:"omitempty,min=1"`
	ShareLimit     *int64                `json:"shareLimit,omitempty" binding:"omitempty,min=1"`
	UserLimit      *int64                `json:"userLimit,omitempty" binding:"omitempty,min=1"`
	Features       *[]models.PlanFeature `json:"features,omitempty"`
	IsActive       *bool                 `json:"isActive,omitempty"`
	IsPopular      *bool                 `json:"isPopular,omitempty"`
	TrialDays      *int                  `json:"trialDays,omitempty" binding:"omitempty,min=0,max=365"`
	SetupFee       *int64                `json:"setupFee,omitempty" binding:"omitempty,min=0"`
	SortOrder      *int                  `json:"sortOrder,omitempty" binding:"omitempty,min=0"`
}

// ============================================================================
// PUBLIC ENDPOINTS - Available to all authenticated users
// ============================================================================

// GetAvailablePlans returns all available subscription plans
func (h *SubscriptionHandler) GetAvailablePlans(c *gin.Context) {
	plans, err := h.subscriptionService.GetAvailablePlans(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to get available plans", map[string]interface{}{
			"error": err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve subscription plans")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Subscription plans retrieved successfully", plans)
}

// GetPlan returns specific plan details
func (h *SubscriptionHandler) GetPlan(c *gin.Context) {
	planIDStr := c.Param("id")
	planID, err := primitive.ObjectIDFromHex(planIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid plan ID")
		return
	}

	plan, err := h.subscriptionService.GetPlanByID(c.Request.Context(), planID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve plan")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Plan retrieved successfully", plan)
}

// CreateSubscription creates a new subscription for the authenticated user
func (h *SubscriptionHandler) CreateSubscription(c *gin.Context) {
	var req CreateSubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Convert plan ID string to ObjectID
	planID, err := primitive.ObjectIDFromHex(req.PlanID)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid plan ID")
		return
	}

	// Create service request
	serviceReq := &services.CreateSubscriptionRequest{
		PlanID:         planID,
		PaymentMethod:  req.PaymentMethod,
		BillingCycle:   req.BillingCycle,
		PaymentTokenID: req.PaymentTokenID,
		CouponCode:     req.CouponCode,
		BillingAddress: req.BillingAddress,
	}

	subscription, err := h.subscriptionService.CreateSubscription(c.Request.Context(), userObjID, serviceReq)
	if err != nil {
		h.logger.Error("Failed to create subscription", map[string]interface{}{
			"user_id": userObjID.Hex(),
			"plan_id": req.PlanID,
			"error":   err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to create subscription")
		return
	}

	h.logger.Info("Subscription created successfully", map[string]interface{}{
		"user_id":         userObjID.Hex(),
		"subscription_id": subscription.Subscription.ID.Hex(),
		"plan_id":         req.PlanID,
	})

	pkg.CreatedResponse(c, "Subscription created successfully", subscription)
}

// GetMySubscription returns the current user's subscription
func (h *SubscriptionHandler) GetMySubscription(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	subscription, err := h.subscriptionService.GetUserSubscription(c.Request.Context(), userObjID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			if appErr.Code == "SUBSCRIPTION_NOT_FOUND" {
				pkg.SuccessResponse(c, http.StatusOK, "No active subscription found", nil)
				return
			}
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve subscription")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Subscription retrieved successfully", subscription)
}

// UpgradeDowngradeSubscription changes the user's subscription plan
func (h *SubscriptionHandler) UpgradeDowngradeSubscription(c *gin.Context) {
	var req UpgradeDowngradeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Convert new plan ID string to ObjectID
	newPlanID, err := primitive.ObjectIDFromHex(req.NewPlanID)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid new plan ID")
		return
	}

	// Create service request
	serviceReq := &services.UpgradeDowngradeRequest{
		NewPlanID:         newPlanID,
		EffectiveAt:       req.EffectiveAt,
		ProrationBehavior: req.ProrationBehavior,
	}

	subscription, err := h.subscriptionService.UpgradeDowngradeSubscription(c.Request.Context(), userObjID, serviceReq)
	if err != nil {
		h.logger.Error("Failed to upgrade/downgrade subscription", map[string]interface{}{
			"user_id":     userObjID.Hex(),
			"new_plan_id": req.NewPlanID,
			"error":       err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to change subscription plan")
		return
	}

	h.logger.Info("Subscription plan changed successfully", map[string]interface{}{
		"user_id":         userObjID.Hex(),
		"new_plan_id":     req.NewPlanID,
		"subscription_id": subscription.Subscription.ID.Hex(),
	})

	pkg.SuccessResponse(c, http.StatusOK, "Subscription plan changed successfully", subscription)
}

// CancelSubscription cancels the user's subscription
func (h *SubscriptionHandler) CancelSubscription(c *gin.Context) {
	var req CancelSubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Create service request
	serviceReq := &services.CancelSubscriptionRequest{
		Reason:      req.Reason,
		CancelAtEnd: req.CancelAtEnd,
		Feedback:    req.Feedback,
	}

	subscription, err := h.subscriptionService.CancelSubscription(c.Request.Context(), userObjID, serviceReq)
	if err != nil {
		h.logger.Error("Failed to cancel subscription", map[string]interface{}{
			"user_id": userObjID.Hex(),
			"error":   err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to cancel subscription")
		return
	}

	h.logger.Info("Subscription canceled successfully", map[string]interface{}{
		"user_id":         userObjID.Hex(),
		"subscription_id": subscription.Subscription.ID.Hex(),
		"cancel_at_end":   req.CancelAtEnd,
	})

	pkg.SuccessResponse(c, http.StatusOK, "Subscription canceled successfully", subscription)
}

// ReactivateSubscription reactivates a canceled subscription
func (h *SubscriptionHandler) ReactivateSubscription(c *gin.Context) {
	var req ReactivateSubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Create service request
	serviceReq := &services.ReactivateSubscriptionRequest{
		PaymentMethod:  req.PaymentMethod,
		PaymentTokenID: req.PaymentTokenID,
	}

	subscription, err := h.subscriptionService.ReactivateSubscription(c.Request.Context(), userObjID, serviceReq)
	if err != nil {
		h.logger.Error("Failed to reactivate subscription", map[string]interface{}{
			"user_id": userObjID.Hex(),
			"error":   err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to reactivate subscription")
		return
	}

	h.logger.Info("Subscription reactivated successfully", map[string]interface{}{
		"user_id":         userObjID.Hex(),
		"subscription_id": subscription.Subscription.ID.Hex(),
	})

	pkg.SuccessResponse(c, http.StatusOK, "Subscription reactivated successfully", subscription)
}

// GetSubscriptionInvoices returns invoices for the user's subscription
func (h *SubscriptionHandler) GetSubscriptionInvoices(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	// Get pagination parameters
	params := pkg.NewPaginationParams(c)

	invoices, total, err := h.subscriptionService.GetUserInvoices(c.Request.Context(), userObjID, params)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve invoices")
		return
	}

	result := pkg.NewPaginationResult(invoices, total, params)
	pkg.PaginatedResponse(c, "Invoices retrieved successfully", result)
}

// GetSubscriptionUsage returns usage statistics for the user's subscription
func (h *SubscriptionHandler) GetSubscriptionUsage(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		pkg.UnauthorizedResponse(c, "Authentication required")
		return
	}

	userObjID := userID.(primitive.ObjectID)

	usage, err := h.subscriptionService.GetUsageStatistics(c.Request.Context(), userObjID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve usage statistics")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Usage statistics retrieved successfully", usage)
}

// ============================================================================
// ADMIN ENDPOINTS - Require admin role
// ============================================================================

// ListAllSubscriptions returns all subscriptions (admin only)
func (h *SubscriptionHandler) ListAllSubscriptions(c *gin.Context) {
	// Get pagination parameters
	params := pkg.NewPaginationParams(c)

	// Add filters if provided
	status := c.Query("status")
	userIDStr := c.Query("userId")

	var userID *primitive.ObjectID
	if userIDStr != "" {
		id, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			pkg.BadRequestResponse(c, "Invalid user ID")
			return
		}
		userID = &id
	}

	subscriptions, total, err := h.subscriptionService.ListSubscriptions(c.Request.Context(), params, status, userID)
	if err != nil {
		h.logger.Error("Failed to list subscriptions", map[string]interface{}{
			"error": err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve subscriptions")
		return
	}

	result := pkg.NewPaginationResult(subscriptions, total, params)
	pkg.PaginatedResponse(c, "Subscriptions retrieved successfully", result)
}

// GetSubscription returns specific subscription details (admin only)
func (h *SubscriptionHandler) GetSubscription(c *gin.Context) {
	subscriptionIDStr := c.Param("id")
	subscriptionID, err := primitive.ObjectIDFromHex(subscriptionIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid subscription ID")
		return
	}

	subscription, err := h.subscriptionService.GetSubscriptionByID(c.Request.Context(), subscriptionID)
	if err != nil {
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve subscription")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Subscription retrieved successfully", subscription)
}

// CreatePlan creates a new subscription plan (admin only)
func (h *SubscriptionHandler) CreatePlan(c *gin.Context) {
	var req CreatePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	// Create plan model
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
		h.logger.Error("Failed to create plan", map[string]interface{}{
			"name":  req.Name,
			"error": err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to create plan")
		return
	}

	h.logger.Info("Plan created successfully", map[string]interface{}{
		"plan_id": createdPlan.ID.Hex(),
		"name":    req.Name,
	})

	pkg.CreatedResponse(c, "Plan created successfully", createdPlan)
}

// UpdatePlan updates a subscription plan (admin only)
func (h *SubscriptionHandler) UpdatePlan(c *gin.Context) {
	planIDStr := c.Param("id")
	planID, err := primitive.ObjectIDFromHex(planIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid plan ID")
		return
	}

	var req UpdatePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	// Build updates map
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Price != nil {
		updates["price"] = *req.Price
	}
	if req.StorageLimit != nil {
		updates["storage_limit"] = *req.StorageLimit
	}
	if req.BandwidthLimit != nil {
		updates["bandwidth_limit"] = *req.BandwidthLimit
	}
	if req.FileLimit != nil {
		updates["file_limit"] = *req.FileLimit
	}
	if req.FolderLimit != nil {
		updates["folder_limit"] = *req.FolderLimit
	}
	if req.ShareLimit != nil {
		updates["share_limit"] = *req.ShareLimit
	}
	if req.UserLimit != nil {
		updates["user_limit"] = *req.UserLimit
	}
	if req.Features != nil {
		updates["features"] = *req.Features
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}
	if req.IsPopular != nil {
		updates["is_popular"] = *req.IsPopular
	}
	if req.TrialDays != nil {
		updates["trial_days"] = *req.TrialDays
	}
	if req.SetupFee != nil {
		updates["setup_fee"] = *req.SetupFee
	}
	if req.SortOrder != nil {
		updates["sort_order"] = *req.SortOrder
	}

	if len(updates) == 0 {
		pkg.BadRequestResponse(c, "No updates provided")
		return
	}

	updatedPlan, err := h.subscriptionService.UpdatePlan(c.Request.Context(), planID, updates)
	if err != nil {
		h.logger.Error("Failed to update plan", map[string]interface{}{
			"plan_id": planIDStr,
			"error":   err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to update plan")
		return
	}

	h.logger.Info("Plan updated successfully", map[string]interface{}{
		"plan_id": planIDStr,
		"updates": len(updates),
	})

	pkg.UpdatedResponse(c, "Plan updated successfully", updatedPlan)
}

// DeletePlan deletes a subscription plan (admin only)
func (h *SubscriptionHandler) DeletePlan(c *gin.Context) {
	planIDStr := c.Param("id")
	planID, err := primitive.ObjectIDFromHex(planIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid plan ID")
		return
	}

	err = h.subscriptionService.DeletePlan(c.Request.Context(), planID)
	if err != nil {
		h.logger.Error("Failed to delete plan", map[string]interface{}{
			"plan_id": planIDStr,
			"error":   err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to delete plan")
		return
	}

	h.logger.Info("Plan deleted successfully", map[string]interface{}{
		"plan_id": planIDStr,
	})

	pkg.DeletedResponse(c, "Plan deleted successfully")
}

// GetSubscriptionStats returns subscription statistics (admin only)
func (h *SubscriptionHandler) GetSubscriptionStats(c *gin.Context) {
	stats, err := h.subscriptionService.GetSubscriptionStats(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to get subscription statistics", map[string]interface{}{
			"error": err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve subscription statistics")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Subscription statistics retrieved successfully", stats)
}

// GetRevenueStats returns revenue statistics (admin only)
func (h *SubscriptionHandler) GetRevenueStats(c *gin.Context) {
	// Parse query parameters for date range
	periodStr := c.DefaultQuery("period", "month") // day, week, month, year
	limitStr := c.DefaultQuery("limit", "12")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		pkg.BadRequestResponse(c, "Invalid limit parameter")
		return
	}

	stats, err := h.subscriptionService.GetRevenueStats(c.Request.Context(), periodStr, limit)
	if err != nil {
		h.logger.Error("Failed to get revenue statistics", map[string]interface{}{
			"period": periodStr,
			"limit":  limit,
			"error":  err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to retrieve revenue statistics")
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Revenue statistics retrieved successfully", stats)
}

// ManageUserSubscription allows admin to manage user subscriptions
func (h *SubscriptionHandler) ManageUserSubscription(c *gin.Context) {
	userIDStr := c.Param("userId")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	action := c.Param("action") // cancel, reactivate, suspend

	type AdminActionRequest struct {
		Reason   string                 `json:"reason,omitempty"`
		Metadata map[string]interface{} `json:"metadata,omitempty"`
	}

	var req AdminActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request data: "+err.Error())
		return
	}

	var subscription *services.SubscriptionResponse
	switch action {
	case "cancel":
		cancelReq := &services.CancelSubscriptionRequest{
			Reason:      req.Reason,
			CancelAtEnd: false, // Admin cancellation is immediate
		}
		subscription, err = h.subscriptionService.CancelSubscription(c.Request.Context(), userID, cancelReq)
	case "reactivate":
		reactivateReq := &services.ReactivateSubscriptionRequest{}
		subscription, err = h.subscriptionService.ReactivateSubscription(c.Request.Context(), userID, reactivateReq)
	case "suspend":
		err = h.subscriptionService.SuspendSubscription(c.Request.Context(), userID, req.Reason)
		if err == nil {
			subscription, err = h.subscriptionService.GetUserSubscription(c.Request.Context(), userID)
		}
	default:
		pkg.BadRequestResponse(c, "Invalid action. Supported actions: cancel, reactivate, suspend")
		return
	}

	if err != nil {
		h.logger.Error("Failed to manage user subscription", map[string]interface{}{
			"user_id": userIDStr,
			"action":  action,
			"error":   err.Error(),
		})
		if appErr, ok := pkg.IsAppError(err); ok {
			pkg.ErrorResponseFromAppError(c, appErr)
			return
		}
		pkg.InternalServerErrorResponse(c, "Failed to manage subscription")
		return
	}

	h.logger.Info("User subscription managed successfully", map[string]interface{}{
		"user_id": userIDStr,
		"action":  action,
	})

	pkg.SuccessResponse(c, http.StatusOK, "Subscription "+action+" successful", subscription)
}

// ============================================================================
// HELPER METHODS
// ============================================================================

// getUserIDFromContext extracts user ID from gin context
func (h *SubscriptionHandler) getUserIDFromContext(c *gin.Context) (primitive.ObjectID, error) {
	userID, exists := c.Get("user_id")
	if !exists {
		return primitive.NilObjectID, pkg.ErrUserNotFound
	}

	if objID, ok := userID.(primitive.ObjectID); ok {
		return objID, nil
	}

	return primitive.NilObjectID, pkg.ErrUserNotFound
}

// validateObjectID converts string to ObjectID with validation
func (h *SubscriptionHandler) validateObjectID(idStr, fieldName string) (primitive.ObjectID, error) {
	if idStr == "" {
		return primitive.NilObjectID, pkg.ErrInvalidInput.WithDetails(map[string]interface{}{
			"message": fieldName + " is required",
		})
	}

	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		return primitive.NilObjectID, pkg.ErrInvalidInput.WithDetails(map[string]interface{}{
			"message": "Invalid " + fieldName,
		})
	}

	return id, nil
}
