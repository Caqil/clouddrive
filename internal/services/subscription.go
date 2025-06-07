package services

import (
	"context"
	"fmt"
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
	PlanID        primitive.ObjectID  `json:"planId" validate:"required"`
	PaymentMethod string              `json:"paymentMethod" validate:"required,oneof=stripe paypal"`
	BillingCycle  models.BillingCycle `json:"billingCycle" validate:"required"`
}

// SubscriptionResponse represents subscription response
type SubscriptionResponse struct {
	*models.Subscription
	Plan *models.SubscriptionPlan `json:"plan"`
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
		if existingSub.Status == models.SubscriptionStatusActive {
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

	// Calculate subscription period
	now := time.Now()
	var periodEnd time.Time
	switch req.BillingCycle {
	case models.BillingCycleMonthly:
		periodEnd = now.AddDate(0, 1, 0)
	case models.BillingCycleYearly:
		periodEnd = now.AddDate(1, 0, 0)
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
		Amount:             plan.Price,
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

	// Create subscription with payment provider
	switch req.PaymentMethod {
	case "stripe":
		if err := s.createStripeSubscription(ctx, subscription, plan, user); err != nil {
			return nil, err
		}
	case "paypal":
		if err := s.createPayPalSubscription(ctx, subscription, plan, user); err != nil {
			return nil, err
		}
	default:
		return nil, pkg.ErrInvalidPaymentMethod
	}

	// Save subscription
	if err := s.subscriptionRepo.Create(ctx, subscription); err != nil {
		return nil, err
	}

	// Update user storage limit
	userUpdates := map[string]interface{}{
		"storage_limit": plan.StorageLimit,
		"subscription": models.UserSubscription{
			PlanID:    plan.ID,
			Status:    string(subscription.Status),
			ExpiresAt: subscription.CurrentPeriodEnd,
		},
	}
	s.userRepo.Update(ctx, userID, userUpdates)

	// Send confirmation email
	s.emailService.SendNotificationEmail(ctx, user.Email,
		"Subscription Confirmed",
		fmt.Sprintf("Your subscription to %s has been confirmed!", plan.Name))

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionCreate, "subscription", subscription.ID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypeSubscription, "create", subscription.ID, plan.Name)

	return &SubscriptionResponse{
		Subscription: subscription,
		Plan:         plan,
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

	return &SubscriptionResponse{
		Subscription: subscription,
		Plan:         plan,
	}, nil
}

// UpdateSubscription updates subscription
func (s *SubscriptionService) UpdateSubscription(ctx context.Context, userID primitive.ObjectID, updates map[string]interface{}) (*SubscriptionResponse, error) {
	// Get current subscription
	subscription, err := s.subscriptionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Update subscription
	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionUpdate, "subscription", subscription.ID, true, "")

	// Get updated subscription
	return s.GetUserSubscription(ctx, userID)
}

// CancelSubscription cancels user's subscription
func (s *SubscriptionService) CancelSubscription(ctx context.Context, userID primitive.ObjectID, cancelAtPeriodEnd bool) error {
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
	}

	if !cancelAtPeriodEnd {
		updates["status"] = models.SubscriptionStatusCanceled
	}

	if err := s.subscriptionRepo.Update(ctx, subscription.ID, updates); err != nil {
		return err
	}

	// Get user for email
	user, err := s.userRepo.GetByID(ctx, userID)
	if err == nil {
		// Send cancellation email
		message := "Your subscription has been canceled"
		if cancelAtPeriodEnd {
			message = fmt.Sprintf("Your subscription will be canceled at the end of the current period (%s)", subscription.CurrentPeriodEnd.Format("2006-01-02"))
		}
		s.emailService.SendNotificationEmail(ctx, user.Email, "Subscription Canceled", message)
	}

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionSubscriptionCancel, "subscription", subscription.ID, true, "")

	return nil
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
			}
		} else {
			// Cancel subscription
			updates := map[string]interface{}{
				"status": models.SubscriptionStatusCanceled,
			}
			s.subscriptionRepo.Update(ctx, subscription.ID, updates)
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

// createStripeSubscription creates subscription with Stripe
func (s *SubscriptionService) createStripeSubscription(ctx context.Context, subscription *models.Subscription, plan *models.SubscriptionPlan, user *models.User) error {
	// This would integrate with Stripe API
	// For now, we'll set dummy values
	subscription.StripeCustomerID = fmt.Sprintf("cus_%s", pkg.GenerateRandomToken(14))
	subscription.StripeSubscriptionID = fmt.Sprintf("sub_%s", pkg.GenerateRandomToken(14))
	return nil
}

// createPayPalSubscription creates subscription with PayPal
func (s *SubscriptionService) createPayPalSubscription(ctx context.Context, subscription *models.Subscription, plan *models.SubscriptionPlan, user *models.User) error {
	// This would integrate with PayPal API
	subscription.PayPalSubscriptionID = fmt.Sprintf("I-%s", pkg.GenerateRandomToken(10))
	return nil
}

// cancelStripeSubscription cancels Stripe subscription
func (s *SubscriptionService) cancelStripeSubscription(ctx context.Context, subscription *models.Subscription, atPeriodEnd bool) error {
	// This would call Stripe API to cancel subscription
	return nil
}

// cancelPayPalSubscription cancels PayPal subscription
func (s *SubscriptionService) cancelPayPalSubscription(ctx context.Context, subscription *models.Subscription) error {
	// This would call PayPal API to cancel subscription
	return nil
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
