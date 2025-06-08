package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// SubscriptionService handles subscription operations
type SubscriptionService struct {
	subscriptionRepo repository.SubscriptionRepository
	userRepo         repository.UserRepository
	paymentRepo      repository.PaymentRepository
	auditRepo        repository.AuditLogRepository
	analyticsRepo    repository.AnalyticsRepository
	paymentService   *PaymentService
	emailService     EmailService
	logger           *pkg.Logger
}

// NewSubscriptionService creates a new subscription service
func NewSubscriptionService(
	subscriptionRepo repository.SubscriptionRepository,
	userRepo repository.UserRepository,
	paymentRepo repository.PaymentRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
	paymentService *PaymentService,
	emailService EmailService,
	logger *pkg.Logger,
) *SubscriptionService {
	return &SubscriptionService{
		subscriptionRepo: subscriptionRepo,
		userRepo:         userRepo,
		paymentRepo:      paymentRepo,
		auditRepo:        auditRepo,
		analyticsRepo:    analyticsRepo,
		paymentService:   paymentService,
		emailService:     emailService,
		logger:           logger,
	}
}

// ============================================================================
// REQUEST/RESPONSE STRUCTURES
// ============================================================================

// CreateSubscriptionRequest represents subscription creation request
type CreateSubscriptionRequest struct {
	PlanID         primitive.ObjectID     `json:"planId" validate:"required"`
	PaymentMethod  string                 `json:"paymentMethod" validate:"required,oneof=stripe paypal"`
	BillingCycle   models.BillingCycle    `json:"billingCycle" validate:"required"`
	PaymentTokenID string                 `json:"paymentTokenId,omitempty"`
	CouponCode     string                 `json:"couponCode,omitempty"`
	BillingAddress *models.BillingAddress `json:"billingAddress,omitempty"`
}

// UpgradeDowngradeRequest represents plan change request
type UpgradeDowngradeRequest struct {
	NewPlanID         primitive.ObjectID `json:"newPlanId" validate:"required"`
	EffectiveAt       string             `json:"effectiveAt,omitempty"`       // "immediate" or "end_of_period"
	ProrationBehavior string             `json:"prorationBehavior,omitempty"` // "create_prorations" or "none"
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

// SubscriptionResponse represents subscription response
type SubscriptionResponse struct {
	*models.Subscription
	Plan  *models.SubscriptionPlan `json:"plan"`
	Usage *SubscriptionUsage       `json:"usage,omitempty"`
}

// SubscriptionUsage represents current usage statistics
type SubscriptionUsage struct {
	StorageUsed      int64   `json:"storageUsed"`
	StorageLimit     int64   `json:"storageLimit"`
	StoragePercent   float64 `json:"storagePercent"`
	BandwidthUsed    int64   `json:"bandwidthUsed"`
	BandwidthLimit   int64   `json:"bandwidthLimit"`
	BandwidthPercent float64 `json:"bandwidthPercent"`
	FilesUsed        int64   `json:"filesUsed"`
	FileLimit        int64   `json:"fileLimit"`
	FilesPercent     float64 `json:"filesPercent"`
	SharesUsed       int64   `json:"sharesUsed"`
	ShareLimit       int64   `json:"shareLimit"`
	SharesPercent    float64 `json:"sharesPercent"`
}

// ============================================================================
// CORE SUBSCRIPTION METHODS
// ============================================================================

// CreateSubscription creates a new subscription for a user
func (s *SubscriptionService) CreateSubscription(ctx context.Context, userID primitive.ObjectID, req *CreateSubscriptionRequest) (*SubscriptionResponse, error) {
	// Validate request
	if err := pkg.ValidateStruct(req); err != nil {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Check if user already has an active subscription
	existingSubscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err == nil && existingSubscription.Status == models.SubscriptionStatusActive {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "User already has an active subscription",
		})
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get plan
	plan, err := s.subscriptionRepo.GetPlanByID(ctx, req.PlanID)
	if err != nil {
		return nil, err
	}

	if !plan.IsActive {
		return nil, pkg.ErrInvalidPlan.WithDetails(map[string]interface{}{
			"message": "Selected plan is not available",
		})
	}

	// Calculate amounts
	now := time.Now()
	var periodEnd time.Time
	switch req.BillingCycle {
	case models.BillingCycleMonthly:
		periodEnd = now.AddDate(0, 1, 0)
	case models.BillingCycleYearly:
		periodEnd = now.AddDate(1, 0, 0)
	case models.BillingCycleWeekly:
		periodEnd = now.AddDate(0, 0, 7)
	default:
		return nil, pkg.ErrInvalidInput
	}

	// Apply coupon if provided
	finalAmount := plan.Price
	discountAmount := int64(0)
	if req.CouponCode != "" {
		discount, err := s.applyCoupon(ctx, req.CouponCode, plan.Price)
		if err == nil {
			discountAmount = discount
			finalAmount = plan.Price - discount
		}
	}

	// Add setup fee if applicable
	if plan.SetupFee > 0 {
		finalAmount += plan.SetupFee
	}

	// Create subscription
	subscription := &models.Subscription{
		UserID:             userID,
		PlanID:             req.PlanID,
		Status:             models.SubscriptionStatusActive,
		CurrentPeriodStart: now,
		CurrentPeriodEnd:   periodEnd,
		AutoRenew:          true,
		BillingCycle:       req.BillingCycle,
		Currency:           plan.Currency,
		Amount:             finalAmount,
		DiscountAmount:     discountAmount,
		Metadata:           make(map[string]interface{}),
	}

	// Handle trial period if plan has trial
	if plan.TrialDays > 0 {
		trialStart := now
		trialEnd := now.AddDate(0, 0, plan.TrialDays)
		subscription.Status = models.SubscriptionStatusTrialing
		subscription.TrialStart = &trialStart
		subscription.TrialEnd = &trialEnd
		subscription.CurrentPeriodEnd = trialEnd
	}

	// Store coupon code if used
	if req.CouponCode != "" {
		subscription.Metadata["coupon_code"] = req.CouponCode
	}

	// Store billing address if provided
	if req.BillingAddress != nil {
		subscription.Metadata["billing_address"] = *req.BillingAddress
	}

	// Create subscription with payment provider (only if not in trial)
	if subscription.Status != models.SubscriptionStatusTrialing {
		switch req.PaymentMethod {
		case "stripe":
			if err := s.createStripeSubscription(ctx, subscription, plan, user, req); err != nil {
				return nil, err
			}
		case "paypal":
			if err := s.createPayPalSubscription(ctx, subscription, plan, user, req); err != nil {
				return nil, err
			}
		default:
			return nil, pkg.ErrInvalidPaymentMethod
		}
	}

	// Save subscription
	if err := s.subscriptionRepo.Create(ctx, subscription); err != nil {
		// Rollback payment provider subscription if database save fails
		if subscription.Status != models.SubscriptionStatusTrialing {
			s.rollbackPaymentProviderSubscription(ctx, subscription, req.PaymentMethod)
		}
		return nil, err
	}

	// Update user storage limit and subscription info
	userUpdates := map[string]interface{}{
		"storage_limit": plan.StorageLimit,
		"subscription": models.UserSubscription{
			PlanID:    plan.ID,
			Status:    string(subscription.Status),
			ExpiresAt: subscription.CurrentPeriodEnd,
		},
	}
	if err := s.userRepo.Update(ctx, userID, userUpdates); err != nil {
		// Log error but don't fail the subscription
		s.logError(ctx, userID, "Failed to update user subscription info", err)
	}

	// Send confirmation email
	s.sendSubscriptionConfirmationEmail(ctx, user, subscription, plan)

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionCreate, "subscription", subscription.ID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeSubscription, "create", subscription.ID, plan.Name)

	// Get usage statistics
	usage, _ := s.getSubscriptionUsage(ctx, userID, plan)

	return &SubscriptionResponse{
		Subscription: subscription,
		Plan:         plan,
		Usage:        usage,
	}, nil
}

// GetUserSubscription retrieves user's current subscription
func (s *SubscriptionService) GetUserSubscription(ctx context.Context, userID primitive.ObjectID) (*SubscriptionResponse, error) {
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		if err.Error() == "subscription not found" {
			return nil, pkg.ErrSubscriptionNotFound
		}
		return nil, err
	}

	// Get plan details
	plan, err := s.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
	if err != nil {
		return nil, err
	}

	// Get usage statistics
	usage, _ := s.getSubscriptionUsage(ctx, userID, plan)

	return &SubscriptionResponse{
		Subscription: subscription,
		Plan:         plan,
		Usage:        usage,
	}, nil
}

// GetSubscriptionByID retrieves subscription by ID (admin only)
func (s *SubscriptionService) GetSubscriptionByID(ctx context.Context, subscriptionID primitive.ObjectID) (*SubscriptionResponse, error) {
	subscription, err := s.subscriptionRepo.GetByID(ctx, subscriptionID)
	if err != nil {
		return nil, err
	}

	// Get plan details
	plan, err := s.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
	if err != nil {
		return nil, err
	}

	// Get usage statistics
	usage, _ := s.getSubscriptionUsage(ctx, subscription.UserID, plan)

	return &SubscriptionResponse{
		Subscription: subscription,
		Plan:         plan,
		Usage:        usage,
	}, nil
}

// UpgradeDowngradeSubscription changes the subscription plan
func (s *SubscriptionService) UpgradeDowngradeSubscription(ctx context.Context, userID primitive.ObjectID, req *UpgradeDowngradeRequest) (*SubscriptionResponse, error) {
	// Validate request
	if err := pkg.ValidateStruct(req); err != nil {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Get current subscription
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if subscription.Status != models.SubscriptionStatusActive {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Can only upgrade/downgrade active subscriptions",
		})
	}

	// Get current and new plans
	currentPlan, err := s.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
	if err != nil {
		return nil, err
	}

	newPlan, err := s.subscriptionRepo.GetPlanByID(ctx, req.NewPlanID)
	if err != nil {
		return nil, err
	}

	if !newPlan.IsActive {
		return nil, pkg.ErrInvalidPlan.WithDetails(map[string]interface{}{
			"message": "Target plan is not available",
		})
	}

	// Check if it's actually a change
	if subscription.PlanID == req.NewPlanID {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "User is already on the selected plan",
		})
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Handle effective timing
	if req.EffectiveAt == "end_of_period" {
		// Schedule the change for end of current period
		subscription.Metadata["scheduled_plan_change"] = map[string]interface{}{
			"new_plan_id":  req.NewPlanID,
			"effective_at": subscription.CurrentPeriodEnd,
			"old_plan_id":  subscription.PlanID,
			"scheduled_at": time.Now(),
		}

		updates := map[string]interface{}{
			"metadata": subscription.Metadata,
		}

		if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
			return nil, err
		}

		// Send scheduled change email
		s.sendPlanChangeScheduledEmail(ctx, user, subscription, currentPlan, newPlan)

		// Log audit event
		s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionUpdate, "subscription", subscription.ID, true, "Plan change scheduled")

		return s.GetUserSubscription(ctx, userID)
	}

	// Immediate change - calculate proration if enabled
	var prorationAmount int64 = 0
	if req.ProrationBehavior == "create_prorations" {
		prorationAmount = s.calculateProration(subscription, currentPlan, newPlan)
	}

	// Update subscription with new plan
	updates := map[string]interface{}{
		"plan_id":  req.NewPlanID,
		"amount":   newPlan.Price,
		"currency": newPlan.Currency,
	}

	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return nil, err
	}

	// Update user storage limit
	userUpdates := map[string]interface{}{
		"storage_limit": newPlan.StorageLimit,
		"subscription": models.UserSubscription{
			PlanID:    newPlan.ID,
			Status:    string(subscription.Status),
			ExpiresAt: subscription.CurrentPeriodEnd,
		},
	}
	if err := s.userRepo.Update(ctx, userID, userUpdates); err != nil {
		s.logError(ctx, userID, "Failed to update user limits after plan change", err)
	}

	// Handle proration payment
	if prorationAmount != 0 {
		s.createProrationPayment(ctx, subscription, prorationAmount, currentPlan, newPlan)
	}

	// Update payment provider subscription
	s.updatePaymentProviderSubscription(ctx, subscription, newPlan)

	// Send plan change confirmation email
	s.sendPlanChangeConfirmationEmail(ctx, user, subscription, currentPlan, newPlan)

	// Log audit event
	action := "Plan upgraded"
	if newPlan.Price < currentPlan.Price {
		action = "Plan downgraded"
	}
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionUpdate, "subscription", subscription.ID, true, action)

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeSubscription, "plan_change", subscription.ID, newPlan.Name)

	return s.GetUserSubscription(ctx, userID)
}

// CancelSubscription cancels a user's subscription
func (s *SubscriptionService) CancelSubscription(ctx context.Context, userID primitive.ObjectID, req *CancelSubscriptionRequest) (*SubscriptionResponse, error) {
	// Get current subscription
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if subscription.Status == models.SubscriptionStatusCanceled {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Subscription is already canceled",
		})
	}

	// Get user and plan
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	plan, err := s.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
	if err != nil {
		return nil, err
	}

	// Update subscription
	updates := map[string]interface{}{
		"auto_renew": false,
	}

	if req.CancelAtEnd {
		// Cancel at period end
		updates["cancel_at_period_end"] = true
		if req.Reason != "" {
			updates["cancellation_reason"] = req.Reason
		}
	} else {
		// Immediate cancellation
		updates["status"] = models.SubscriptionStatusCanceled
		updates["canceled_at"] = time.Now()
		updates["cancellation_reason"] = req.Reason
	}

	// Store feedback if provided
	if req.Feedback != "" {
		if subscription.Metadata == nil {
			subscription.Metadata = make(map[string]interface{})
		}
		subscription.Metadata["cancellation_feedback"] = req.Feedback
		updates["metadata"] = subscription.Metadata
	}

	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return nil, err
	}

	// Cancel with payment provider
	s.cancelPaymentProviderSubscription(ctx, subscription)

	// If immediate cancellation, revert to free plan
	if !req.CancelAtEnd {
		s.revertToFreePlan(ctx, userID)
	}

	// Send cancellation email
	s.sendCancellationEmail(ctx, user, subscription, plan, req.CancelAtEnd)

	// Log audit event
	reason := "User cancellation"
	if req.Reason != "" {
		reason = req.Reason
	}
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionCancel, "subscription", subscription.ID, true, reason)

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeSubscription, "cancel", subscription.ID, plan.Name)

	return s.GetUserSubscription(ctx, userID)
}

// ReactivateSubscription reactivates a canceled subscription
func (s *SubscriptionService) ReactivateSubscription(ctx context.Context, userID primitive.ObjectID, req *ReactivateSubscriptionRequest) (*SubscriptionResponse, error) {
	// Get current subscription
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if subscription.Status != models.SubscriptionStatusCanceled {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Can only reactivate canceled subscriptions",
		})
	}

	// Get user and plan
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	plan, err := s.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
	if err != nil {
		return nil, err
	}

	// Calculate new period
	now := time.Now()
	var nextPeriodEnd time.Time
	switch subscription.BillingCycle {
	case models.BillingCycleMonthly:
		nextPeriodEnd = now.AddDate(0, 1, 0)
	case models.BillingCycleYearly:
		nextPeriodEnd = now.AddDate(1, 0, 0)
	case models.BillingCycleWeekly:
		nextPeriodEnd = now.AddDate(0, 0, 7)
	default:
		nextPeriodEnd = now.AddDate(0, 1, 0)
	}

	// Update subscription
	updates := map[string]interface{}{
		"status":               models.SubscriptionStatusActive,
		"auto_renew":           true,
		"cancel_at_period_end": false,
		"current_period_start": now,
		"current_period_end":   nextPeriodEnd,
		"reactivated_at":       now,
	}

	// Remove cancellation fields
	updates["canceled_at"] = nil
	updates["cancellation_reason"] = ""

	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return nil, err
	}

	// Reactivate with payment provider if payment method provided
	if req.PaymentMethod != "" {
		s.reactivatePaymentProviderSubscription(ctx, subscription, req)
	}

	// Restore user limits
	userUpdates := map[string]interface{}{
		"storage_limit": plan.StorageLimit,
		"subscription": models.UserSubscription{
			PlanID:    plan.ID,
			Status:    string(models.SubscriptionStatusActive),
			ExpiresAt: nextPeriodEnd,
		},
	}
	s.userRepo.Update(ctx, userID, userUpdates)

	// Send reactivation email
	s.sendReactivationEmail(ctx, user, subscription, plan)

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionUpdate, "subscription", subscription.ID, true, "Subscription reactivated")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeSubscription, "reactivate", subscription.ID, plan.Name)

	return s.GetUserSubscription(ctx, userID)
}

// SuspendSubscription suspends a subscription (admin only)
func (s *SubscriptionService) SuspendSubscription(ctx context.Context, userID primitive.ObjectID, reason string) error {
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if subscription.Status == models.SubscriptionStatusCanceled {
		return pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Cannot suspend canceled subscription",
		})
	}

	updates := map[string]interface{}{
		"status":            models.SubscriptionStatusUnpaid,
		"suspension_reason": reason,
		"suspended_at":      time.Now(),
	}

	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return err
	}

	// Suspend with payment provider
	s.suspendPaymentProviderSubscription(ctx, subscription)

	// Revert to free plan temporarily
	s.revertToFreePlan(ctx, userID)

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionSuspend, "subscription", subscription.ID, true, reason)

	return nil
}

// ============================================================================
// PLAN MANAGEMENT METHODS
// ============================================================================

// GetAvailablePlans retrieves available subscription plans
func (s *SubscriptionService) GetAvailablePlans(ctx context.Context) ([]*models.SubscriptionPlan, error) {
	return s.subscriptionRepo.GetActivePlans(ctx)
}

// GetPlanByID retrieves a specific plan by ID
func (s *SubscriptionService) GetPlanByID(ctx context.Context, planID primitive.ObjectID) (*models.SubscriptionPlan, error) {
	return s.subscriptionRepo.GetPlanByID(ctx, planID)
}

// CreatePlan creates a new subscription plan (admin only)
func (s *SubscriptionService) CreatePlan(ctx context.Context, plan *models.SubscriptionPlan) (*models.SubscriptionPlan, error) {
	// Validate plan data
	if plan.Price < 0 {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Plan price cannot be negative",
		})
	}

	if plan.StorageLimit <= 0 {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Storage limit must be positive",
		})
	}

	// Set defaults
	if plan.Currency == "" {
		plan.Currency = "USD"
	}

	// Set timestamps
	now := time.Now()
	plan.CreatedAt = now
	plan.UpdatedAt = now

	if err := s.subscriptionRepo.CreatePlan(ctx, plan); err != nil {
		return nil, err
	}

	return plan, nil
}

// UpdatePlan updates subscription plan (admin only)
func (s *SubscriptionService) UpdatePlan(ctx context.Context, planID primitive.ObjectID, updates map[string]interface{}) (*models.SubscriptionPlan, error) {
	// Add updated timestamp
	updates["updated_at"] = time.Now()

	if err := s.subscriptionRepo.UpdatePlan(ctx, planID, updates); err != nil {
		return nil, err
	}

	return s.subscriptionRepo.GetPlanByID(ctx, planID)
}

// DeletePlan deletes a subscription plan (admin only)
func (s *SubscriptionService) DeletePlan(ctx context.Context, planID primitive.ObjectID) error {
	// Check if plan has active subscriptions
	subscriptions, err := s.subscriptionRepo.GetActiveSubscriptions(ctx)
	if err != nil {
		return err
	}

	for _, sub := range subscriptions {
		if sub.PlanID == planID {
			return pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
				"message": "Cannot delete plan with active subscriptions",
			})
		}
	}

	return s.subscriptionRepo.DeletePlan(ctx, planID)
}

// ============================================================================
// ADMIN AND ANALYTICS METHODS
// ============================================================================

// ListSubscriptions lists all subscriptions with optional filters (admin only)
func (s *SubscriptionService) ListSubscriptions(ctx context.Context, params *pkg.PaginationParams, status string, userID *primitive.ObjectID) ([]*SubscriptionResponse, int64, error) {
	// Apply filters
	if status != "" {
		if params.Filter == nil {
			params.Filter = make(map[string]interface{})
		}
		params.Filter["status"] = status
	}

	if userID != nil {
		if params.Filter == nil {
			params.Filter = make(map[string]interface{})
		}
		params.Filter["user_id"] = *userID
	}

	subscriptions, total, err := s.subscriptionRepo.List(ctx, params)
	if err != nil {
		return nil, 0, err
	}

	// Convert to response format
	responses := make([]*SubscriptionResponse, len(subscriptions))
	for i, sub := range subscriptions {
		plan, _ := s.subscriptionRepo.GetPlanByID(ctx, sub.PlanID)
		usage, _ := s.getSubscriptionUsage(ctx, sub.UserID, plan)

		responses[i] = &SubscriptionResponse{
			Subscription: sub,
			Plan:         plan,
			Usage:        usage,
		}
	}

	return responses, total, nil
}

// GetSubscriptionStats returns subscription statistics
func (s *SubscriptionService) GetSubscriptionStats(ctx context.Context) (map[string]interface{}, error) {
	// Get total subscription count
	_, totalCount, err := s.subscriptionRepo.List(ctx, &pkg.PaginationParams{Page: 1, Limit: 1})
	if err != nil {
		return nil, fmt.Errorf("failed to get total subscriptions: %w", err)
	}

	activeSubscriptions, err := s.subscriptionRepo.GetActiveSubscriptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active subscriptions: %w", err)
	}

	trialingSubscriptions, err := s.subscriptionRepo.GetSubscriptionsByStatus(ctx, models.SubscriptionStatusTrialing)
	if err != nil {
		return nil, fmt.Errorf("failed to get trialing subscriptions: %w", err)
	}

	canceledSubscriptions, err := s.subscriptionRepo.GetSubscriptionsByStatus(ctx, models.SubscriptionStatusCanceled)
	if err != nil {
		return nil, fmt.Errorf("failed to get canceled subscriptions: %w", err)
	}

	// Calculate MRR (Monthly Recurring Revenue)
	var mrr int64 = 0
	var arr int64 = 0 // Annual Recurring Revenue

	for _, sub := range activeSubscriptions {
		switch sub.BillingCycle {
		case models.BillingCycleMonthly:
			mrr += sub.Amount
			arr += sub.Amount * 12
		case models.BillingCycleYearly:
			mrr += sub.Amount / 12
			arr += sub.Amount
		case models.BillingCycleWeekly:
			mrr += sub.Amount * 4 // Approximate monthly
			arr += sub.Amount * 52
		}
	}

	return map[string]interface{}{
		"total_subscriptions":    totalCount,
		"active_subscriptions":   len(activeSubscriptions),
		"trialing_subscriptions": len(trialingSubscriptions),
		"canceled_subscriptions": len(canceledSubscriptions),
		"mrr":                    mrr,
		"arr":                    arr,
		"conversion_rate":        s.calculateConversionRate(len(trialingSubscriptions), len(activeSubscriptions)),
		"churn_rate":             s.calculateChurnRate(len(activeSubscriptions), len(canceledSubscriptions)),
	}, nil
}

// GetRevenueStats returns revenue statistics
func (s *SubscriptionService) GetRevenueStats(ctx context.Context, period string, limit int) (map[string]interface{}, error) {
	// This would integrate with your analytics repository
	// For now, return basic structure
	return map[string]interface{}{
		"period": period,
		"data":   []map[string]interface{}{},
	}, nil
}

// ============================================================================
// INVOICE AND BILLING METHODS
// ============================================================================

// GetUserInvoices retrieves invoices for a user
func (s *SubscriptionService) GetUserInvoices(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Invoice, int64, error) {
	// Apply user filter
	if params.Filter == nil {
		params.Filter = make(map[string]interface{})
	}
	params.Filter["user_id"] = userID

	return s.paymentRepo.ListInvoices(ctx, params)
}

// GetUsageStatistics retrieves usage statistics for a user
func (s *SubscriptionService) GetUsageStatistics(ctx context.Context, userID primitive.ObjectID) (*SubscriptionUsage, error) {
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	plan, err := s.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
	if err != nil {
		return nil, err
	}

	return s.getSubscriptionUsage(ctx, userID, plan)
}

// ============================================================================
// BACKGROUND PROCESSING METHODS
// ============================================================================

// ProcessSubscriptionRenewals processes subscription renewals
func (s *SubscriptionService) ProcessSubscriptionRenewals(ctx context.Context) error {
	// Get subscriptions expiring in the next 24 hours
	expiringSubscriptions, err := s.subscriptionRepo.GetExpiringSubscriptions(ctx, 1)
	if err != nil {
		return err
	}

	for _, subscription := range expiringSubscriptions {
		if subscription.AutoRenew && !subscription.CancelAtPeriodEnd {
			if err := s.renewSubscription(ctx, subscription); err != nil {
				// Log error but continue with other subscriptions
				s.logError(ctx, subscription.UserID, "Failed to renew subscription", err)
				// Send renewal failure notification
				s.sendRenewalFailureNotification(ctx, subscription, err)
			} else {
				// Send successful renewal notification
				s.sendRenewalSuccessNotification(ctx, subscription)
			}
		} else {
			// Cancel subscription
			updates := map[string]interface{}{
				"status": models.SubscriptionStatusCanceled,
			}
			s.subscriptionRepo.Update(ctx, subscription.ID, updates)
			// Revert to free plan
			s.revertToFreePlan(ctx, subscription.UserID)
		}
	}

	return nil
}

// ProcessScheduledPlanChanges processes scheduled plan changes
func (s *SubscriptionService) ProcessScheduledPlanChanges(ctx context.Context) error {
	subscriptions, err := s.subscriptionRepo.GetActiveSubscriptions(ctx)
	if err != nil {
		return err
	}

	for _, subscription := range subscriptions {
		if scheduledChange, exists := subscription.Metadata["scheduled_plan_change"]; exists {
			changeData := scheduledChange.(map[string]interface{})
			effectiveAt := changeData["effective_at"].(time.Time)

			if time.Now().After(effectiveAt) {
				// Execute the scheduled plan change
				newPlanID := changeData["new_plan_id"].(primitive.ObjectID)
				s.executeScheduledPlanChange(ctx, subscription, newPlanID)
			}
		}
	}

	return nil
}

// ============================================================================
// UTILITY AND HELPER METHODS
// ============================================================================

// getSubscriptionUsage calculates usage statistics
func (s *SubscriptionService) getSubscriptionUsage(ctx context.Context, userID primitive.ObjectID, plan *models.SubscriptionPlan) (*SubscriptionUsage, error) {
	// Get user storage usage
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Calculate percentages
	storagePercent := float64(0)
	if plan.StorageLimit > 0 {
		storagePercent = float64(user.StorageUsed) / float64(plan.StorageLimit) * 100
	}

	// For now, return basic usage. In a real implementation, you'd fetch these from analytics
	return &SubscriptionUsage{
		StorageUsed:      user.StorageUsed,
		StorageLimit:     plan.StorageLimit,
		StoragePercent:   storagePercent,
		BandwidthUsed:    0, // Would come from analytics
		BandwidthLimit:   plan.BandwidthLimit,
		BandwidthPercent: 0,
		FilesUsed:        0, // Would come from file count
		FileLimit:        plan.FileLimit,
		FilesPercent:     0,
		SharesUsed:       0, // Would come from share count
		ShareLimit:       plan.ShareLimit,
		SharesPercent:    0,
	}, nil
}

// applyCoupon applies a coupon code and returns discount amount
func (s *SubscriptionService) applyCoupon(ctx context.Context, couponCode string, amount int64) (int64, error) {
	// Implement coupon logic here
	// For now, return 0 (no discount)
	return 0, nil
}

// calculateProration calculates proration amount for plan changes
func (s *SubscriptionService) calculateProration(subscription *models.Subscription, oldPlan, newPlan *models.SubscriptionPlan) int64 {
	// Calculate proration based on remaining days and price difference
	now := time.Now()
	totalDays := subscription.CurrentPeriodEnd.Sub(subscription.CurrentPeriodStart).Hours() / 24
	remainingDays := subscription.CurrentPeriodEnd.Sub(now).Hours() / 24

	if remainingDays <= 0 {
		return 0
	}

	// Calculate daily rates
	oldDailyRate := float64(oldPlan.Price) / totalDays
	newDailyRate := float64(newPlan.Price) / totalDays

	// Calculate proration
	proratedOldAmount := oldDailyRate * remainingDays
	proratedNewAmount := newDailyRate * remainingDays

	return int64(proratedNewAmount - proratedOldAmount)
}

// calculateConversionRate calculates trial to paid conversion rate
func (s *SubscriptionService) calculateConversionRate(trialCount, activeCount int) float64 {
	if trialCount == 0 {
		return 0
	}
	return float64(activeCount) / float64(trialCount+activeCount) * 100
}

// calculateChurnRate calculates subscription churn rate
func (s *SubscriptionService) calculateChurnRate(activeCount, canceledCount int) float64 {
	total := activeCount + canceledCount
	if total == 0 {
		return 0
	}
	return float64(canceledCount) / float64(total) * 100
}

// revertToFreePlan reverts user to free plan limits
func (s *SubscriptionService) revertToFreePlan(ctx context.Context, userID primitive.ObjectID) {
	userUpdates := map[string]interface{}{
		"storage_limit": int64(5 * 1024 * 1024 * 1024), // 5GB
		"subscription":  nil,
	}
	s.userRepo.Update(ctx, userID, userUpdates)
}

// renewSubscription handles subscription renewal
func (s *SubscriptionService) renewSubscription(ctx context.Context, subscription *models.Subscription) error {
	// Calculate next billing period
	var nextPeriodEnd time.Time
	switch subscription.BillingCycle {
	case models.BillingCycleMonthly:
		nextPeriodEnd = subscription.CurrentPeriodEnd.AddDate(0, 1, 0)
	case models.BillingCycleYearly:
		nextPeriodEnd = subscription.CurrentPeriodEnd.AddDate(1, 0, 0)
	case models.BillingCycleWeekly:
		nextPeriodEnd = subscription.CurrentPeriodEnd.AddDate(0, 0, 7)
	default:
		nextPeriodEnd = subscription.CurrentPeriodEnd.AddDate(0, 1, 0)
	}

	// Process payment
	if err := s.processRenewalPayment(ctx, subscription); err != nil {
		return err
	}

	// Update subscription
	updates := map[string]interface{}{
		"current_period_start": subscription.CurrentPeriodEnd,
		"current_period_end":   nextPeriodEnd,
		"status":               models.SubscriptionStatusActive,
	}

	return s.subscriptionRepo.Update(ctx, subscription.ID, updates)
}

// executeScheduledPlanChange executes a scheduled plan change
func (s *SubscriptionService) executeScheduledPlanChange(ctx context.Context, subscription *models.Subscription, newPlanID primitive.ObjectID) error {
	newPlan, err := s.subscriptionRepo.GetPlanByID(ctx, newPlanID)
	if err != nil {
		return err
	}

	updates := map[string]interface{}{
		"plan_id":  newPlanID,
		"amount":   newPlan.Price,
		"currency": newPlan.Currency,
	}

	// Remove scheduled change from metadata
	delete(subscription.Metadata, "scheduled_plan_change")
	updates["metadata"] = subscription.Metadata

	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return err
	}

	// Update user storage limit
	userUpdates := map[string]interface{}{
		"storage_limit": newPlan.StorageLimit,
	}
	return s.userRepo.Update(ctx, subscription.UserID, userUpdates)
}

// createProrationPayment creates a proration payment
func (s *SubscriptionService) createProrationPayment(ctx context.Context, subscription *models.Subscription, amount int64, oldPlan, newPlan *models.SubscriptionPlan) {
	if amount == 0 {
		return
	}

	paymentType := models.PaymentTypeOneTime
	description := fmt.Sprintf("Proration for plan change from %s to %s", oldPlan.Name, newPlan.Name)

	if amount < 0 {
		paymentType = models.PaymentTypeRefund
		description = fmt.Sprintf("Refund for plan downgrade from %s to %s", oldPlan.Name, newPlan.Name)
		amount = -amount
	}

	payment := &models.Payment{
		UserID:         subscription.UserID,
		SubscriptionID: &subscription.ID,
		Amount:         amount,
		Currency:       subscription.Currency,
		Status:         models.PaymentStatusSucceeded,
		Type:           paymentType,
		Description:    description,
	}

	s.paymentRepo.Create(ctx, payment)
}

// ============================================================================
// PAYMENT PROVIDER INTEGRATION
// ============================================================================

// createStripeSubscription creates subscription with Stripe
func (s *SubscriptionService) createStripeSubscription(ctx context.Context, subscription *models.Subscription, plan *models.SubscriptionPlan, user *models.User, req *CreateSubscriptionRequest) error {
	// Implement Stripe subscription creation
	// This is a placeholder implementation
	subscription.Metadata["stripe_subscription_id"] = "sub_" + primitive.NewObjectID().Hex()
	return nil
}

// createPayPalSubscription creates subscription with PayPal
func (s *SubscriptionService) createPayPalSubscription(ctx context.Context, subscription *models.Subscription, plan *models.SubscriptionPlan, user *models.User, req *CreateSubscriptionRequest) error {
	// Implement PayPal subscription creation
	// This is a placeholder implementation
	subscription.Metadata["paypal_subscription_id"] = "I-" + primitive.NewObjectID().Hex()
	return nil
}

// updatePaymentProviderSubscription updates subscription with payment provider
func (s *SubscriptionService) updatePaymentProviderSubscription(ctx context.Context, subscription *models.Subscription, plan *models.SubscriptionPlan) {
	// Implement payment provider update logic
}

// cancelPaymentProviderSubscription cancels subscription with payment provider
func (s *SubscriptionService) cancelPaymentProviderSubscription(ctx context.Context, subscription *models.Subscription) {
	// Implement payment provider cancellation logic
}

// suspendPaymentProviderSubscription suspends subscription with payment provider
func (s *SubscriptionService) suspendPaymentProviderSubscription(ctx context.Context, subscription *models.Subscription) {
	// Implement payment provider suspension logic
}

// reactivatePaymentProviderSubscription reactivates subscription with payment provider
func (s *SubscriptionService) reactivatePaymentProviderSubscription(ctx context.Context, subscription *models.Subscription, req *ReactivateSubscriptionRequest) {
	// Implement payment provider reactivation logic
}

// rollbackPaymentProviderSubscription rolls back payment provider subscription
func (s *SubscriptionService) rollbackPaymentProviderSubscription(ctx context.Context, subscription *models.Subscription, paymentMethod string) {
	// Implement rollback logic
}

// processRenewalPayment processes renewal payment
func (s *SubscriptionService) processRenewalPayment(ctx context.Context, subscription *models.Subscription) error {
	// Implement renewal payment processing
	return nil
}

// ============================================================================
// EMAIL NOTIFICATION METHODS
// ============================================================================

// sendSubscriptionConfirmationEmail sends subscription confirmation
func (s *SubscriptionService) sendSubscriptionConfirmationEmail(ctx context.Context, user *models.User, subscription *models.Subscription, plan *models.SubscriptionPlan) {
	subject := "Subscription Confirmed - Welcome to CloudDrive Premium!"

	message := fmt.Sprintf(`
Dear %s %s,

Your subscription to CloudDrive %s has been confirmed!

Subscription Details:
- Plan: %s
- Billing Cycle: %s
- Amount: $%.2f %s
- Next Billing Date: %s

You now have access to:
- %s storage
- %s bandwidth per month
- Up to %d files
- Priority support

Thank you for choosing CloudDrive!

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, plan.Name, plan.Name,
		strings.Title(string(subscription.BillingCycle)),
		float64(subscription.Amount)/100, subscription.Currency,
		subscription.CurrentPeriodEnd.Format("January 2, 2006"),
		pkg.FormatFileSize(plan.StorageLimit),
		pkg.FormatFileSize(plan.BandwidthLimit),
		plan.FileLimit)

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendPlanChangeConfirmationEmail sends plan change confirmation
func (s *SubscriptionService) sendPlanChangeConfirmationEmail(ctx context.Context, user *models.User, subscription *models.Subscription, oldPlan, newPlan *models.SubscriptionPlan) {
	effectiveText := "immediately"
	subject := "Subscription Plan Changed"

	message := fmt.Sprintf(`
Dear %s %s,

Your subscription plan has been changed %s.

Plan Change:
- From: %s ($%.2f)
- To: %s ($%.2f)

Your new plan includes:
- %s storage
- %s bandwidth per month
- Up to %d files

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, effectiveText, oldPlan.Name, float64(oldPlan.Price)/100,
		newPlan.Name, float64(newPlan.Price)/100, pkg.FormatFileSize(newPlan.StorageLimit),
		pkg.FormatFileSize(newPlan.BandwidthLimit), newPlan.FileLimit)

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendPlanChangeScheduledEmail sends scheduled plan change notification
func (s *SubscriptionService) sendPlanChangeScheduledEmail(ctx context.Context, user *models.User, subscription *models.Subscription, oldPlan, newPlan *models.SubscriptionPlan) {
	subject := "Subscription Plan Change Scheduled"

	message := fmt.Sprintf(`
Dear %s %s,

Your subscription plan change has been scheduled for %s.

Plan Change:
- From: %s ($%.2f)
- To: %s ($%.2f)

The change will take effect at the end of your current billing period.

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, subscription.CurrentPeriodEnd.Format("January 2, 2006"),
		oldPlan.Name, float64(oldPlan.Price)/100,
		newPlan.Name, float64(newPlan.Price)/100)

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendCancellationEmail sends cancellation confirmation
func (s *SubscriptionService) sendCancellationEmail(ctx context.Context, user *models.User, subscription *models.Subscription, plan *models.SubscriptionPlan, cancelAtEnd bool) {
	subject := "Subscription Canceled"

	effectiveText := "immediately"
	if cancelAtEnd {
		effectiveText = fmt.Sprintf("at the end of your current billing period (%s)", subscription.CurrentPeriodEnd.Format("January 2, 2006"))
	}

	message := fmt.Sprintf(`
Dear %s %s,

Your subscription has been canceled %s.

We're sorry to see you go! Your premium features will remain available until %s.

If you change your mind, you can reactivate your subscription anytime from your account settings.

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, effectiveText, subscription.CurrentPeriodEnd.Format("January 2, 2006"))

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendReactivationEmail sends reactivation confirmation
func (s *SubscriptionService) sendReactivationEmail(ctx context.Context, user *models.User, subscription *models.Subscription, plan *models.SubscriptionPlan) {
	subject := "Subscription Reactivated - Welcome Back!"

	message := fmt.Sprintf(`
Dear %s %s,

Your subscription has been successfully reactivated!

You now have full access to your %s plan benefits until %s.

Welcome back to CloudDrive!

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, plan.Name, subscription.CurrentPeriodEnd.Format("January 2, 2006"))

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendRenewalSuccessNotification sends renewal success notification
func (s *SubscriptionService) sendRenewalSuccessNotification(ctx context.Context, subscription *models.Subscription) {
	user, err := s.userRepo.GetByID(ctx, subscription.UserID)
	if err != nil {
		return
	}

	plan, err := s.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
	if err != nil {
		return
	}

	subject := "Subscription Renewed Successfully"
	message := fmt.Sprintf(`
Dear %s %s,

Your subscription has been successfully renewed.

Subscription Details:
- Plan: %s
- Amount Charged: $%.2f %s
- Next Billing Date: %s

Thank you for continuing with CloudDrive!

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, plan.Name, float64(subscription.Amount)/100,
		subscription.Currency, subscription.CurrentPeriodEnd.Format("January 2, 2006"))

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendRenewalFailureNotification sends renewal failure notification
func (s *SubscriptionService) sendRenewalFailureNotification(ctx context.Context, subscription *models.Subscription, renewalErr error) {
	user, userErr := s.userRepo.GetByID(ctx, subscription.UserID)
	if userErr != nil {
		return
	}

	subject := "Subscription Renewal Failed"
	message := fmt.Sprintf(`
Dear %s %s,

We were unable to renew your subscription due to a payment issue.

Your subscription will remain active until %s, after which it will be suspended.

Please update your payment information to continue enjoying CloudDrive premium features.

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, subscription.CurrentPeriodEnd.Format("January 2, 2006"))

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// ============================================================================
// LOGGING AND ANALYTICS METHODS
// ============================================================================

// logAuditEvent logs an audit event
func (s *SubscriptionService) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action, resource string, resourceID primitive.ObjectID, success bool, details string) {
	auditLog := &models.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Success:    success,
		Details:    details,
		Timestamp:  time.Now(),
	}

	if err := s.auditRepo.Create(ctx, auditLog); err != nil {
		s.logger.Error("Failed to create audit log", map[string]interface{}{
			"user_id": userID.Hex(),
			"action":  action,
			"error":   err.Error(),
		})
	}
}

// trackAnalytics tracks analytics event
func (s *SubscriptionService) trackAnalytics(ctx context.Context, userID primitive.ObjectID, eventType, action string, resourceID primitive.ObjectID, resourceName string) {
	event := &models.AnalyticsEvent{
		UserID:       userID,
		EventType:    eventType,
		Action:       action,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Timestamp:    time.Now(),
	}

	if err := s.analyticsRepo.TrackEvent(ctx, event); err != nil {
		s.logger.Error("Failed to track analytics event", map[string]interface{}{
			"user_id":    userID.Hex(),
			"event_type": eventType,
			"error":      err.Error(),
		})
	}
}

// logError logs an error with context
func (s *SubscriptionService) logError(ctx context.Context, userID primitive.ObjectID, message string, err error) {
	s.logger.Error(message, map[string]interface{}{
		"user_id": userID.Hex(),
		"error":   err.Error(),
	})
}
