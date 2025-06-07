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

// PaymentService handles payment operations
type PaymentService struct {
	paymentRepo    repository.PaymentRepository
	userRepo       repository.UserRepository
	auditRepo      repository.AuditLogRepository
	analyticsRepo  repository.AnalyticsRepository
	emailService   EmailService
	stripeProvider PaymentProvider
	paypalProvider PaymentProvider
}

// PaymentProvider interface for payment providers
type PaymentProvider interface {
	CreatePayment(ctx context.Context, payment *models.Payment) error
	ProcessPayment(ctx context.Context, paymentID string, amount int64) error
	RefundPayment(ctx context.Context, paymentID string, amount int64) error
	GetPayment(ctx context.Context, paymentID string) (*models.Payment, error)
}

// NewPaymentService creates a new payment service
func NewPaymentService(
	paymentRepo repository.PaymentRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditLogRepository,
	analyticsRepo repository.AnalyticsRepository,
	emailService EmailService,
) *PaymentService {
	return &PaymentService{
		paymentRepo:   paymentRepo,
		userRepo:      userRepo,
		auditRepo:     auditRepo,
		analyticsRepo: analyticsRepo,
		emailService:  emailService,
	}
}

// CreatePaymentRequest represents payment creation request
type CreatePaymentRequest struct {
	Amount         int64                  `json:"amount" validate:"required,gt=0"`
	Currency       string                 `json:"currency" validate:"required,len=3"`
	PaymentMethod  models.PaymentMethod   `json:"paymentMethod" validate:"required"`
	Provider       models.PaymentProvider `json:"provider" validate:"required"`
	Description    string                 `json:"description" validate:"required"`
	BillingAddress *models.BillingAddress `json:"billingAddress,omitempty"`
}

// ProcessPayment processes a payment
func (s *PaymentService) ProcessPayment(ctx context.Context, userID primitive.ObjectID, req *CreatePaymentRequest) (*models.Payment, error) {
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

	// Create payment record
	payment := &models.Payment{
		UserID:        userID,
		PaymentMethod: req.PaymentMethod,
		Provider:      req.Provider,
		Amount:        req.Amount,
		Currency:      req.Currency,
		Status:        models.PaymentStatusPending,
		Type:          models.PaymentTypeOneTime,
		Description:   req.Description,
	}

	if req.BillingAddress != nil {
		payment.BillingAddress = *req.BillingAddress
	}

	// Save payment record
	if err := s.paymentRepo.Create(ctx, payment); err != nil {
		return nil, err
	}

	// Process with payment provider
	var provider PaymentProvider
	switch req.Provider {
	case models.PaymentProviderStripe:
		provider = s.stripeProvider
	case models.PaymentProviderPayPal:
		provider = s.paypalProvider
	default:
		return nil, pkg.ErrInvalidPaymentMethod
	}

	if provider != nil {
		if err := provider.CreatePayment(ctx, payment); err != nil {
			// Update payment status to failed
			updates := map[string]interface{}{
				"status":          models.PaymentStatusFailed,
				"failure_message": err.Error(),
			}
			s.paymentRepo.Update(ctx, payment.ID, updates)
			return nil, pkg.ErrPaymentFailed.WithCause(err)
		}

		// Process the payment
		if err := provider.ProcessPayment(ctx, payment.ProviderPaymentID, req.Amount); err != nil {
			// Update payment status to failed
			updates := map[string]interface{}{
				"status":          models.PaymentStatusFailed,
				"failure_message": err.Error(),
			}
			s.paymentRepo.Update(ctx, payment.ID, updates)
			return nil, pkg.ErrPaymentFailed.WithCause(err)
		}
	}

	// Update payment status to succeeded
	updates := map[string]interface{}{
		"status":       models.PaymentStatusSucceeded,
		"processed_at": time.Now(),
	}
	s.paymentRepo.Update(ctx, payment.ID, updates)

	// Send confirmation email
	s.emailService.SendNotificationEmail(ctx, user.Email,
		"Payment Confirmed",
		fmt.Sprintf("Your payment of %s %.2f has been processed successfully.", req.Currency, float64(req.Amount)/100))

	// Log audit event
	s.logAuditEvent(ctx, userID, models.AuditActionPaymentCreate, "payment", payment.ID, true, "")

	// Track analytics
	s.trackAnalytics(ctx, userID, models.EventTypePayment, "create", payment.ID, req.Description)

	// Get updated payment
	return s.paymentRepo.GetByID(ctx, payment.ID)
}

// GetPayment retrieves payment by ID
func (s *PaymentService) GetPayment(ctx context.Context, userID primitive.ObjectID, paymentID primitive.ObjectID) (*models.Payment, error) {
	payment, err := s.paymentRepo.GetByID(ctx, paymentID)
	if err != nil {
		return nil, err
	}

	// Check if user owns the payment
	if payment.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	return payment, nil
}

// ListUserPayments lists user's payments
func (s *PaymentService) ListUserPayments(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Payment, int64, error) {
	return s.paymentRepo.ListByUser(ctx, userID, params)
}

// RefundPayment processes a payment refund
func (s *PaymentService) RefundPayment(ctx context.Context, paymentID primitive.ObjectID, amount int64, reason string) error {
	// Get payment
	payment, err := s.paymentRepo.GetByID(ctx, paymentID)
	if err != nil {
		return err
	}

	// Check if payment can be refunded
	if payment.Status != models.PaymentStatusSucceeded {
		return pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Payment cannot be refunded",
		})
	}

	// Validate refund amount
	if amount <= 0 || amount > payment.Amount {
		return pkg.ErrValidationFailed.WithDetails(map[string]interface{}{
			"message": "Invalid refund amount",
		})
	}

	// Process refund with provider
	var provider PaymentProvider
	switch payment.Provider {
	case models.PaymentProviderStripe:
		provider = s.stripeProvider
	case models.PaymentProviderPayPal:
		provider = s.paypalProvider
	}

	if provider != nil {
		if err := provider.RefundPayment(ctx, payment.ProviderPaymentID, amount); err != nil {
			return pkg.ErrPaymentProviderError.WithCause(err)
		}
	}

	// Update payment record
	refundType := models.PaymentTypeRefund
	if amount < payment.Amount {
		refundType = models.PaymentTypePartialRefund
	}

	updates := map[string]interface{}{
		"refund_amount": amount,
		"refund_reason": reason,
		"refunded_at":   time.Now(),
		"type":          refundType,
	}

	if amount == payment.Amount {
		updates["status"] = models.PaymentStatusRefunded
	}

	if err := s.paymentRepo.Update(ctx, payment.ID, updates); err != nil {
		return err
	}

	// Get user for notification
	user, err := s.userRepo.GetByID(ctx, payment.UserID)
	if err == nil {
		// Send refund notification
		s.emailService.SendNotificationEmail(ctx, user.Email,
			"Payment Refunded",
			fmt.Sprintf("A refund of %s %.2f has been processed for your payment.", payment.Currency, float64(amount)/100))
	}

	// Log audit event
	s.logAuditEvent(ctx, payment.UserID, models.AuditActionPaymentRefund, "payment", payment.ID, true, reason)

	return nil
}

// ProcessWebhook processes payment provider webhooks
func (s *PaymentService) ProcessWebhook(ctx context.Context, provider models.PaymentProvider, webhookData map[string]interface{}) error {
	// This would handle webhooks from payment providers
	// For Stripe: handle events like payment_intent.succeeded, invoice.payment_failed, etc.
	// For PayPal: handle events like PAYMENT.CAPTURE.COMPLETED, etc.

	eventType := ""
	if eventTypeRaw, exists := webhookData["type"]; exists {
		eventType = eventTypeRaw.(string)
	}

	switch provider {
	case models.PaymentProviderStripe:
		return s.processStripeWebhook(ctx, eventType, webhookData)
	case models.PaymentProviderPayPal:
		return s.processPayPalWebhook(ctx, eventType, webhookData)
	default:
		return pkg.ErrInvalidPaymentMethod
	}
}

// processStripeWebhook processes Stripe webhooks
func (s *PaymentService) processStripeWebhook(ctx context.Context, eventType string, data map[string]interface{}) error {
	switch eventType {
	case "payment_intent.succeeded":
		// Handle successful payment
		return s.handleSuccessfulPayment(ctx, data)
	case "payment_intent.payment_failed":
		// Handle failed payment
		return s.handleFailedPayment(ctx, data)
	case "invoice.payment_succeeded":
		// Handle successful subscription payment
		return s.handleSubscriptionPayment(ctx, data)
	default:
		// Log unhandled event
		return nil
	}
}

// processPayPalWebhook processes PayPal webhooks
func (s *PaymentService) processPayPalWebhook(ctx context.Context, eventType string, data map[string]interface{}) error {
	switch eventType {
	case "PAYMENT.CAPTURE.COMPLETED":
		return s.handleSuccessfulPayment(ctx, data)
	case "PAYMENT.CAPTURE.DENIED":
		return s.handleFailedPayment(ctx, data)
	default:
		return nil
	}
}

// handleSuccessfulPayment handles successful payment webhook
func (s *PaymentService) handleSuccessfulPayment(ctx context.Context, data map[string]interface{}) error {
	// Extract payment ID from webhook data
	paymentID := "" // Extract from data

	// Get payment by provider payment ID
	payment, err := s.paymentRepo.GetByProviderPaymentID(ctx, paymentID)
	if err != nil {
		return err
	}

	// Update payment status
	updates := map[string]interface{}{
		"status":       models.PaymentStatusSucceeded,
		"processed_at": time.Now(),
	}

	return s.paymentRepo.Update(ctx, payment.ID, updates)
}

// handleFailedPayment handles failed payment webhook
func (s *PaymentService) handleFailedPayment(ctx context.Context, data map[string]interface{}) error {
	// Extract payment ID and failure reason from webhook data
	paymentID := ""     // Extract from data
	failureReason := "" // Extract from data

	// Get payment by provider payment ID
	payment, err := s.paymentRepo.GetByProviderPaymentID(ctx, paymentID)
	if err != nil {
		return err
	}

	// Update payment status
	updates := map[string]interface{}{
		"status":          models.PaymentStatusFailed,
		"failure_message": failureReason,
	}

	return s.paymentRepo.Update(ctx, payment.ID, updates)
}

// handleSubscriptionPayment handles subscription payment webhook
func (s *PaymentService) handleSubscriptionPayment(ctx context.Context, data map[string]interface{}) error {
	// This would handle subscription renewal payments
	return nil
}

// CreateInvoice creates an invoice
func (s *PaymentService) CreateInvoice(ctx context.Context, userID primitive.ObjectID, items []models.InvoiceItem) (*models.Invoice, error) {
	// Calculate totals
	var subtotal int64
	for _, item := range items {
		subtotal += item.Amount * int64(item.Quantity)
	}

	// Calculate tax (simplified - would use proper tax calculation)
	taxRate := 0.1 // 10% tax
	taxAmount := int64(float64(subtotal) * taxRate)
	total := subtotal + taxAmount

	// Generate invoice number
	invoiceNumber := fmt.Sprintf("INV-%d", time.Now().Unix())

	// Create invoice
	invoice := &models.Invoice{
		InvoiceNumber: invoiceNumber,
		UserID:        userID,
		Status:        models.InvoiceStatusOpen,
		Subtotal:      subtotal,
		TaxAmount:     taxAmount,
		Total:         total,
		Currency:      "USD",
		Items:         items,
		DueDate:       time.Now().AddDate(0, 0, 30), // 30 days
	}

	if err := s.paymentRepo.CreateInvoice(ctx, invoice); err != nil {
		return nil, err
	}

	// Get user for invoice email
	user, err := s.userRepo.GetByID(ctx, userID)
	if err == nil {
		// Send invoice email
		invoiceData := fmt.Sprintf("Invoice #%s\nTotal: $%.2f", invoiceNumber, float64(total)/100)
		s.emailService.SendInvoiceEmail(ctx, user.Email, invoiceData)
	}

	return invoice, nil
}

// GetInvoice retrieves invoice by ID
func (s *PaymentService) GetInvoice(ctx context.Context, userID primitive.ObjectID, invoiceID primitive.ObjectID) (*models.Invoice, error) {
	invoice, err := s.paymentRepo.GetInvoiceByID(ctx, invoiceID)
	if err != nil {
		return nil, err
	}

	// Check if user owns the invoice
	if invoice.UserID != userID {
		return nil, pkg.ErrForbidden
	}

	return invoice, nil
}

// ListUserInvoices lists user's invoices
func (s *PaymentService) ListUserInvoices(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Invoice, int64, error) {
	return s.paymentRepo.ListInvoicesByUser(ctx, userID, params)
}

// logAuditEvent logs an audit event
func (s *PaymentService) logAuditEvent(ctx context.Context, userID primitive.ObjectID, action models.AuditAction, resourceType string, resourceID primitive.ObjectID, success bool, message string) {
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
func (s *PaymentService) trackAnalytics(ctx context.Context, userID primitive.ObjectID, eventType models.AnalyticsEventType, action string, resourceID primitive.ObjectID, resourceName string) {
	analytics := &models.Analytics{
		UserID:    &userID,
		EventType: eventType,
		Action:    action,
		Resource: models.AnalyticsResource{
			Type: "payment",
			ID:   resourceID,
			Name: resourceName,
		},
		Timestamp: time.Now(),
	}

	s.analyticsRepo.Create(ctx, analytics)
}
