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
) *SubscriptionService {
	return &SubscriptionService{
		subscriptionRepo: subscriptionRepo,
		userRepo:         userRepo,
		paymentRepo:      paymentRepo,
		auditRepo:        auditRepo,
		analyticsRepo:    analyticsRepo,
		paymentService:   paymentService,
		emailService:     emailService,
	}
}

// CreateSubscriptionRequest represents subscription creation request
type CreateSubscriptionRequest struct {
	PlanID         primitive.ObjectID     `json:"planId" validate:"required"`
	PaymentMethod  string                 `json:"paymentMethod" validate:"required,oneof=stripe paypal"`
	BillingCycle   models.BillingCycle    `json:"billingCycle" validate:"required"`
	PaymentTokenID string                 `json:"paymentTokenId,omitempty"`
	CouponCode     string                 `json:"couponCode,omitempty"`
	BillingAddress *models.BillingAddress `json:"billingAddress,omitempty"`
}

// SubscriptionResponse represents subscription response
type SubscriptionResponse struct {
	*models.Subscription
	Plan  *models.SubscriptionPlan `json:"plan"`
	Usage *SubscriptionUsage       `json:"usage,omitempty"`
}

// SubscriptionUsage represents current usage statistics
type SubscriptionUsage struct {
	StorageUsed     int64   `json:"storageUsed"`
	StorageLimit    int64   `json:"storageLimit"`
	BandwidthUsed   int64   `json:"bandwidthUsed"`
	BandwidthLimit  int64   `json:"bandwidthLimit"`
	FilesCount      int64   `json:"filesCount"`
	FilesLimit      int64   `json:"filesLimit"`
	UsagePercentage float64 `json:"usagePercentage"`
}

// UpgradeDowngradeRequest represents plan change request
type UpgradeDowngradeRequest struct {
	NewPlanID     primitive.ObjectID `json:"newPlanId" validate:"required"`
	EffectiveAt   *time.Time         `json:"effectiveAt,omitempty"`   // nil = immediate
	ProrationMode string             `json:"prorationMode,omitempty"` // "create_prorations", "none"
}

// Subscribe creates a new subscription
func (s *SubscriptionService) Subscribe(ctx context.Context, userID primitive.ObjectID, req *CreateSubscriptionRequest) (*SubscriptionResponse, error) {
	// Validate request
	if err := pkg.DefaultValidator.Validate(req); err != nil {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"errors": err,
		})
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Check if user already has active subscription
	if existingSub, err := s.subscriptionRepo.GetByUserID(ctx, userID); err == nil {
		if existingSub.Status == models.SubscriptionStatusActive || existingSub.Status == models.SubscriptionStatusTrialing {
			return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
				"message": "User already has an active subscription",
			})
		}
	}

	// Get subscription plan
	plan, err := s.subscriptionRepo.GetPlanByID(ctx, req.PlanID)
	if err != nil {
		return nil, err
	}

	if !plan.IsActive {
		return nil, pkg.ErrInvalidPlan
	}

	// Validate billing cycle is supported by plan
	if !s.isPlanBillingCycleSupported(plan, req.BillingCycle) {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": fmt.Sprintf("Billing cycle %s is not supported for this plan", req.BillingCycle),
		})
	}

	// Calculate pricing with discounts/coupons
	finalAmount, discountAmount, err := s.calculateSubscriptionPricing(ctx, plan, req.BillingCycle, req.CouponCode)
	if err != nil {
		return nil, err
	}

	// Calculate subscription period
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

	// Create subscription with payment provider
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

	// Save subscription
	if err := s.subscriptionRepo.Create(ctx, subscription); err != nil {
		// Rollback payment provider subscription if database save fails
		s.rollbackPaymentProviderSubscription(ctx, subscription, req.PaymentMethod)
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

// UpgradeDowngradeSubscription changes the subscription plan
func (s *SubscriptionService) UpgradeDowngradeSubscription(ctx context.Context, userID primitive.ObjectID, req *UpgradeDowngradeRequest) (*SubscriptionResponse, error) {
	// Validate request
	if err := pkg.DefaultValidator.Validate(req); err != nil {
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
		return nil, pkg.ErrInvalidPlan
	}

	if currentPlan.ID == newPlan.ID {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Cannot change to the same plan",
		})
	}

	// Calculate prorations if applicable
	var prorationAmount int64
	if req.ProrationMode == "create_prorations" {
		prorationAmount = s.calculateProration(subscription, currentPlan, newPlan)
	}

	// Update subscription with payment provider
	if subscription.StripeSubscriptionID != "" {
		if err := s.updateStripeSubscription(ctx, subscription, newPlan, req); err != nil {
			return nil, err
		}
	} else if subscription.PayPalSubscriptionID != "" {
		if err := s.updatePayPalSubscription(ctx, subscription, newPlan, req); err != nil {
			return nil, err
		}
	}

	// Update subscription in database
	updates := map[string]interface{}{
		"plan_id":  req.NewPlanID,
		"amount":   newPlan.Price,
		"currency": newPlan.Currency,
	}

	// Handle immediate vs scheduled changes
	if req.EffectiveAt == nil || req.EffectiveAt.Before(time.Now()) {
		// Immediate change
		if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
			return nil, err
		}

		// Update user storage limit
		userUpdates := map[string]interface{}{
			"storage_limit": newPlan.StorageLimit,
		}
		s.userRepo.Update(ctx, subscription.UserID, userUpdates)
	} else {
		// Scheduled change - store in metadata
		subscription.Metadata["scheduled_plan_change"] = map[string]interface{}{
			"new_plan_id":      req.NewPlanID,
			"effective_at":     req.EffectiveAt,
			"proration_amount": prorationAmount,
		}
		updates["metadata"] = subscription.Metadata
		s.subscriptionRepo.Update(ctx, subscription.ID, updates)
	}

	// Create proration payment if needed
	if prorationAmount != 0 {
		s.createProrationPayment(ctx, subscription, prorationAmount, currentPlan, newPlan)
	}

	// Send notification email
	user, _ := s.userRepo.GetByID(ctx, subscription.UserID)
	if user != nil {
		s.sendPlanChangeNotificationEmail(ctx, user, currentPlan, newPlan, req.EffectiveAt)
	}

	// Log audit event
	action := "upgrade"
	if newPlan.Price < currentPlan.Price {
		action = "downgrade"
	}
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionUpdate, "subscription", subscription.ID, true,
		fmt.Sprintf("Plan changed from %s to %s", currentPlan.Name, newPlan.Name))

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeSubscription, action, subscription.ID,
		fmt.Sprintf("%s -> %s", currentPlan.Name, newPlan.Name))

	// Return updated subscription
	return s.GetUserSubscription(ctx, userID)
}

// UpdateSubscription updates subscription settings
func (s *SubscriptionService) UpdateSubscription(ctx context.Context, userID primitive.ObjectID, updates map[string]interface{}) (*SubscriptionResponse, error) {
	// Get current subscription
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Validate allowed updates
	allowedUpdates := map[string]interface{}{}
	for key, value := range updates {
		switch key {
		case "auto_renew", "cancel_reason", "metadata":
			allowedUpdates[key] = value
		default:
			return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
				"message": fmt.Sprintf("Field '%s' cannot be updated directly", key),
			})
		}
	}

	// Update subscription
	if err := s.subscriptionRepo.Update(ctx, subscription.ID, allowedUpdates); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionUpdate, "subscription", subscription.ID, true, "")

	// Get updated subscription
	return s.GetUserSubscription(ctx, userID)
}

// CancelSubscription cancels user's subscription
func (s *SubscriptionService) CancelSubscription(ctx context.Context, userID primitive.ObjectID, cancelAtPeriodEnd bool, reason string) error {
	// Get current subscription
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if subscription.Status == models.SubscriptionStatusCanceled {
		return pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Subscription is already canceled",
		})
	}

	// Cancel with payment provider
	if subscription.StripeSubscriptionID != "" {
		if err := s.cancelStripeSubscription(ctx, subscription, cancelAtPeriodEnd); err != nil {
			return err
		}
	} else if subscription.PayPalSubscriptionID != "" {
		if err := s.cancelPayPalSubscription(ctx, subscription); err != nil {
			return err
		}
	}

	// Update subscription
	updates := map[string]interface{}{
		"cancel_at_period_end": cancelAtPeriodEnd,
		"canceled_at":          time.Now(),
		"cancel_reason":        reason,
	}

	if !cancelAtPeriodEnd {
		updates["status"] = models.SubscriptionStatusCanceled
		// Revert to free plan storage limit
		s.revertToFreePlan(ctx, userID)
	}

	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return err
	}

	// Get user for email
	user, err := s.userRepo.GetByID(ctx, userID)
	if err == nil {
		s.sendCancellationEmail(ctx, user, subscription, cancelAtPeriodEnd)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionCancel, "subscription", subscription.ID, true, reason)

	return nil
}

// ReactivateSubscription reactivates a canceled subscription
func (s *SubscriptionService) ReactivateSubscription(ctx context.Context, userID primitive.ObjectID) (*SubscriptionResponse, error) {
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if subscription.Status != models.SubscriptionStatusCanceled {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Can only reactivate canceled subscriptions",
		})
	}

	// Check if still within the current period
	if time.Now().After(subscription.CurrentPeriodEnd) {
		return nil, pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Subscription period has expired, please create a new subscription",
		})
	}

	// Reactivate with payment provider
	if subscription.StripeSubscriptionID != "" {
		if err := s.reactivateStripeSubscription(ctx, subscription); err != nil {
			return nil, err
		}
	} else if subscription.PayPalSubscriptionID != "" {
		if err := s.reactivatePayPalSubscription(ctx, subscription); err != nil {
			return nil, err
		}
	}

	// Update subscription status
	updates := map[string]interface{}{
		"status":               models.SubscriptionStatusActive,
		"cancel_at_period_end": false,
		"canceled_at":          nil,
		"cancel_reason":        "",
	}

	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return nil, err
	}

	// Restore user limits
	plan, _ := s.subscriptionRepo.GetPlanByID(ctx, subscription.PlanID)
	if plan != nil {
		userUpdates := map[string]interface{}{
			"storage_limit": plan.StorageLimit,
		}
		s.userRepo.Update(ctx, userID, userUpdates)
	}

	// Send reactivation email
	user, _ := s.userRepo.GetByID(ctx, userID)
	if user != nil && plan != nil {
		s.sendReactivationEmail(ctx, user, subscription, plan)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionUpdate, "subscription", subscription.ID, true, "Subscription reactivated")

	return s.GetUserSubscription(ctx, userID)
}

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

// GetAvailablePlans retrieves available subscription plans
func (s *SubscriptionService) GetAvailablePlans(ctx context.Context) ([]*models.SubscriptionPlan, error) {
	return s.subscriptionRepo.GetActivePlans(ctx)
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

	if err := s.subscriptionRepo.CreatePlan(ctx, plan); err != nil {
		return nil, err
	}

	return plan, nil
}

// UpdatePlan updates subscription plan (admin only)
func (s *SubscriptionService) UpdatePlan(ctx context.Context, planID primitive.ObjectID, updates map[string]interface{}) (*models.SubscriptionPlan, error) {
	if err := s.subscriptionRepo.UpdatePlan(ctx, planID, updates); err != nil {
		return nil, err
	}

	return s.subscriptionRepo.GetPlanByID(ctx, planID)
}

// GetSubscriptionStats returns subscription statistics
func (s *SubscriptionService) GetSubscriptionStats(ctx context.Context) (map[string]interface{}, error) {
	// Get total subscription count using the count return value, not the slice length
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

	// Calculate conversion rate
	var conversionRate float64
	if totalCount > 0 {
		conversionRate = float64(len(activeSubscriptions)) / float64(totalCount) * 100
	}

	// Calculate churn rate (simplified)
	var churnRate float64
	if len(activeSubscriptions)+len(canceledSubscriptions) > 0 {
		churnRate = float64(len(canceledSubscriptions)) / float64(len(activeSubscriptions)+len(canceledSubscriptions)) * 100
	}

	return map[string]interface{}{
		"total_subscriptions":    totalCount,
		"active_subscriptions":   len(activeSubscriptions),
		"trialing_subscriptions": len(trialingSubscriptions),
		"canceled_subscriptions": len(canceledSubscriptions),
		"conversion_rate":        conversionRate,
		"churn_rate":             churnRate,
	}, nil
}

// GetSubscriptionsByPlan returns subscription count by plan
func (s *SubscriptionService) GetSubscriptionsByPlan(ctx context.Context) (map[string]interface{}, error) {
	plans, err := s.subscriptionRepo.GetActivePlans(ctx)
	if err != nil {
		return nil, err
	}

	planStats := make(map[string]interface{})

	for _, plan := range plans {
		// Get subscriptions for this plan
		params := &pkg.PaginationParams{
			Page:  1,
			Limit: 1,
			Filter: map[string]interface{}{
				"plan_id": plan.ID,
				"status":  models.SubscriptionStatusActive,
			},
		}
		_, count, err := s.subscriptionRepo.List(ctx, params)
		if err != nil {
			continue
		}

		planStats[plan.Name] = map[string]interface{}{
			"plan_id":     plan.ID,
			"subscribers": count,
			"price":       plan.Price,
			"currency":    plan.Currency,
		}
	}

	return planStats, nil
}

// Helper Methods

// isPlanBillingCycleSupported checks if billing cycle is supported by plan
func (s *SubscriptionService) isPlanBillingCycleSupported(_ *models.SubscriptionPlan, cycle models.BillingCycle) bool {
	// You can implement specific logic here based on plan features
	// For now, assume all plans support monthly and yearly
	return cycle == models.BillingCycleMonthly || cycle == models.BillingCycleYearly
}

// calculateSubscriptionPricing calculates final pricing with discounts
func (s *SubscriptionService) calculateSubscriptionPricing(_ context.Context, plan *models.SubscriptionPlan, cycle models.BillingCycle, couponCode string) (int64, int64, error) {
	baseAmount := plan.Price
	discountAmount := int64(0)

	// Apply yearly discount if applicable
	if cycle == models.BillingCycleYearly {
		// 10% discount for yearly billing
		discountAmount = baseAmount / 10
	}

	// Apply coupon discount if provided
	if couponCode != "" {
		// This would integrate with your coupon system
		// For now, apply a simple discount
		switch couponCode {
		case "SAVE20":
			additionalDiscount := baseAmount / 5 // 20% discount
			discountAmount += additionalDiscount
		case "SAVE10":
			additionalDiscount := baseAmount / 10 // 10% discount
			discountAmount += additionalDiscount
		case "FIRSTMONTH":
			if cycle == models.BillingCycleMonthly {
				discountAmount += baseAmount // First month free
			}
		}
	}

	finalAmount := baseAmount - discountAmount
	if finalAmount < 0 {
		finalAmount = 0
	}

	return finalAmount, discountAmount, nil
}

// getSubscriptionUsage calculates current usage statistics
func (s *SubscriptionService) getSubscriptionUsage(ctx context.Context, userID primitive.ObjectID, plan *models.SubscriptionPlan) (*SubscriptionUsage, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Calculate usage percentage
	var usagePercentage float64
	if plan.StorageLimit > 0 {
		usagePercentage = float64(user.StorageUsed) / float64(plan.StorageLimit) * 100
	}

	return &SubscriptionUsage{
		StorageUsed:     user.StorageUsed,
		StorageLimit:    plan.StorageLimit,
		BandwidthUsed:   0, // Would be calculated from analytics
		BandwidthLimit:  plan.BandwidthLimit,
		FilesCount:      0, // Would be calculated from file count
		FilesLimit:      plan.FileLimit,
		UsagePercentage: usagePercentage,
	}, nil
}

// calculateProration calculates proration amount for plan changes
func (s *SubscriptionService) calculateProration(subscription *models.Subscription, _ *models.SubscriptionPlan, newPlan *models.SubscriptionPlan) int64 {
	// Calculate remaining days in current period
	now := time.Now()
	totalDays := subscription.CurrentPeriodEnd.Sub(subscription.CurrentPeriodStart).Hours() / 24
	remainingDays := subscription.CurrentPeriodEnd.Sub(now).Hours() / 24

	if remainingDays <= 0 {
		return 0
	}

	// Calculate unused amount from old plan
	unusedAmount := int64(float64(subscription.Amount) * (remainingDays / totalDays))

	// Calculate new amount for remaining period
	newAmount := int64(float64(newPlan.Price) * (remainingDays / totalDays))

	return newAmount - unusedAmount
}

// revertToFreePlan reverts user to free plan limits
func (s *SubscriptionService) revertToFreePlan(ctx context.Context, userID primitive.ObjectID) {
	updates := map[string]interface{}{
		"storage_limit": 5 * 1024 * 1024 * 1024, // 5GB free limit
		"subscription":  nil,
	}
	s.userRepo.Update(ctx, userID, updates)
}

// Payment Provider Integration Methods

// createStripeSubscription creates subscription with Stripe
func (s *SubscriptionService) createStripeSubscription(_ context.Context, subscription *models.Subscription, _ *models.SubscriptionPlan, _ *models.User, req *CreateSubscriptionRequest) error {
	// In a real implementation, this would integrate with Stripe API
	// Create customer if doesn't exist
	customerToken, err := pkg.GenerateRandomToken(14)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}
	customerID := fmt.Sprintf("cus_%s", customerToken)

	// Create subscription
	subscriptionToken, err := pkg.GenerateRandomToken(14)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}
	subscriptionID := fmt.Sprintf("sub_%s", subscriptionToken)

	subscription.StripeCustomerID = customerID
	subscription.StripeSubscriptionID = subscriptionID

	// Store billing address if provided
	if req.BillingAddress != nil {
		subscription.Metadata["billing_address"] = *req.BillingAddress
	}

	return nil
}

// createPayPalSubscription creates subscription with PayPal
func (s *SubscriptionService) createPayPalSubscription(_ context.Context, subscription *models.Subscription, _ *models.SubscriptionPlan, _ *models.User, _ *CreateSubscriptionRequest) error {
	// In a real implementation, this would integrate with PayPal API
	subscriptionToken, err := pkg.GenerateRandomToken(10)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}
	subscriptionID := fmt.Sprintf("I-%s", subscriptionToken)
	subscription.PayPalSubscriptionID = subscriptionID

	return nil
}

// updateStripeSubscription updates Stripe subscription
func (s *SubscriptionService) updateStripeSubscription(_ context.Context, _ *models.Subscription, _ *models.SubscriptionPlan, _ *UpgradeDowngradeRequest) error {
	// Stripe API integration would go here
	return nil
}

// updatePayPalSubscription updates PayPal subscription
func (s *SubscriptionService) updatePayPalSubscription(_ context.Context, _ *models.Subscription, _ *models.SubscriptionPlan, _ *UpgradeDowngradeRequest) error {
	// PayPal API integration would go here
	return nil
}

// cancelStripeSubscription cancels Stripe subscription
func (s *SubscriptionService) cancelStripeSubscription(_ context.Context, _ *models.Subscription, _ bool) error {
	// Stripe API call to cancel subscription
	return nil
}

// cancelPayPalSubscription cancels PayPal subscription
func (s *SubscriptionService) cancelPayPalSubscription(_ context.Context, _ *models.Subscription) error {
	// PayPal API call to cancel subscription
	return nil
}

// reactivateStripeSubscription reactivates Stripe subscription
func (s *SubscriptionService) reactivateStripeSubscription(_ context.Context, _ *models.Subscription) error {
	// Stripe API call to reactivate subscription
	return nil
}

// reactivatePayPalSubscription reactivates PayPal subscription
func (s *SubscriptionService) reactivatePayPalSubscription(_ context.Context, _ *models.Subscription) error {
	// PayPal API call to reactivate subscription
	return nil
}

// rollbackPaymentProviderSubscription rolls back payment provider subscription
func (s *SubscriptionService) rollbackPaymentProviderSubscription(ctx context.Context, subscription *models.Subscription, paymentMethod string) {
	switch paymentMethod {
	case "stripe":
		// Cancel Stripe subscription
		if subscription.StripeSubscriptionID != "" {
			s.cancelStripeSubscription(ctx, subscription, false)
		}
	case "paypal":
		// Cancel PayPal subscription
		if subscription.PayPalSubscriptionID != "" {
			s.cancelPayPalSubscription(ctx, subscription)
		}
	}
}

// renewSubscription renews a subscription
func (s *SubscriptionService) renewSubscription(ctx context.Context, subscription *models.Subscription) error {
	// Calculate next period
	var nextPeriodEnd time.Time
	switch subscription.BillingCycle {
	case models.BillingCycleMonthly:
		nextPeriodEnd = subscription.CurrentPeriodEnd.AddDate(0, 1, 0)
	case models.BillingCycleYearly:
		nextPeriodEnd = subscription.CurrentPeriodEnd.AddDate(1, 0, 0)
	case models.BillingCycleWeekly:
		nextPeriodEnd = subscription.CurrentPeriodEnd.AddDate(0, 0, 7)
	}

	// Create payment for renewal
	payment := &models.Payment{
		UserID:         subscription.UserID,
		SubscriptionID: &subscription.ID,
		Amount:         subscription.Amount,
		Currency:       subscription.Currency,
		Status:         models.PaymentStatusSucceeded,
		Type:           models.PaymentTypeSubscription,
		Description:    "Subscription renewal",
	}

	if err := s.paymentRepo.Create(ctx, payment); err != nil {
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

// Email Notification Methods

// sendSubscriptionConfirmationEmail sends subscription confirmation
func (s *SubscriptionService) sendSubscriptionConfirmationEmail(ctx context.Context, user *models.User, subscription *models.Subscription, plan *models.SubscriptionPlan) {
	subject := "Subscription Confirmed"
	message := fmt.Sprintf(`
Dear %s %s,

Your subscription to %s has been confirmed!

Subscription Details:
- Plan: %s
- Billing Cycle: %s
- Amount: $%.2f %s
- Next Billing Date: %s

You now have access to:
- %s storage
- %s bandwidth per month
- Up to %d files

Thank you for choosing CloudDrive!

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, plan.Name, plan.Name, strings.Title(string(subscription.BillingCycle)),
		float64(subscription.Amount)/100, subscription.Currency, subscription.CurrentPeriodEnd.Format("2006-01-02"),
		pkg.Files.FormatFileSize(plan.StorageLimit), pkg.Files.FormatFileSize(plan.BandwidthLimit), plan.FileLimit)

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendCancellationEmail sends cancellation confirmation
func (s *SubscriptionService) sendCancellationEmail(ctx context.Context, user *models.User, subscription *models.Subscription, cancelAtPeriodEnd bool) {
	subject := "Subscription Canceled"
	var message string

	if cancelAtPeriodEnd {
		message = fmt.Sprintf(`
Dear %s %s,

Your subscription has been scheduled for cancellation.

Your subscription will remain active until %s, after which it will be canceled and you'll be moved to our free plan.

You can reactivate your subscription at any time before the cancellation date.

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, subscription.CurrentPeriodEnd.Format("2006-01-02"))
	} else {
		message = fmt.Sprintf(`
Dear %s %s,

Your subscription has been canceled immediately.

You have been moved to our free plan with limited storage and features.

You can resubscribe at any time to regain access to premium features.

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName)
	}

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendPlanChangeNotificationEmail sends plan change notification
func (s *SubscriptionService) sendPlanChangeNotificationEmail(ctx context.Context, user *models.User, oldPlan, newPlan *models.SubscriptionPlan, effectiveAt *time.Time) {
	subject := "Subscription Plan Updated"
	effectiveText := "immediately"

	if effectiveAt != nil && effectiveAt.After(time.Now()) {
		effectiveText = fmt.Sprintf("on %s", effectiveAt.Format("2006-01-02"))
	}

	message := fmt.Sprintf(`
Dear %s %s,

Your subscription plan has been updated %s.

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
		newPlan.Name, float64(newPlan.Price)/100, pkg.Files.FormatFileSize(newPlan.StorageLimit),
		pkg.Files.FormatFileSize(newPlan.BandwidthLimit), newPlan.FileLimit)

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendReactivationEmail sends reactivation confirmation
func (s *SubscriptionService) sendReactivationEmail(ctx context.Context, user *models.User, subscription *models.Subscription, plan *models.SubscriptionPlan) {
	subject := "Subscription Reactivated"
	message := fmt.Sprintf(`
Dear %s %s,

Your subscription has been successfully reactivated!

You now have full access to your %s plan benefits until %s.

Welcome back to CloudDrive!

Best regards,
The CloudDrive Team
`, user.FirstName, user.LastName, plan.Name, subscription.CurrentPeriodEnd.Format("2006-01-02"))

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

	subject := "Subscription Renewed"
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
		subscription.Currency, subscription.CurrentPeriodEnd.Format("2006-01-02"))

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// sendRenewalFailureNotification sends renewal failure notification
func (s *SubscriptionService) sendRenewalFailureNotification(ctx context.Context, subscription *models.Subscription, _ error) {
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
`, user.FirstName, user.LastName, subscription.CurrentPeriodEnd.Format("2006-01-02"))

	go s.emailService.SendNotificationEmail(ctx, user.Email, subject, message)
}

// Audit and Analytics Methods

// logAuditEvent logs an audit event
func (s *SubscriptionService) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
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

	s.auditRepo.Create(ctx, auditLog)
}

// trackAnalytics tracks analytics event
func (s *SubscriptionService) trackAnalytics(ctx context.Context, userID primitive.ObjectID, eventType models.AnalyticsEventType, action string, resourceID primitive.ObjectID, resourceName string) {
	analytics := &models.Analytics{
		UserID:    &userID,
		EventType: eventType,
		Action:    action,
		Resource: models.AnalyticsResource{
			Type: "subscription",
			ID:   resourceID,
			Name: resourceName,
		},
		Timestamp: time.Now(),
	}

	s.analyticsRepo.Create(ctx, analytics)
}

// logError logs an error
func (s *SubscriptionService) logError(ctx context.Context, userID primitive.ObjectID, message string, err error) {
	auditLog := &models.AuditLog{
		UserID:       &userID,
		Action:       models.AuditActionSecurityBreach,
		Success:      false,
		ErrorMessage: fmt.Sprintf("%s: %v", message, err),
		Severity:     models.AuditSeverityHigh,
		Timestamp:    time.Now(),
	}

	s.auditRepo.Create(ctx, auditLog)
}
