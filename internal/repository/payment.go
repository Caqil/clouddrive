package repository

import (
	"context"
	"fmt"
	"time"

	"clouddrive/internal/models"
	"clouddrive/internal/pkg"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type paymentRepository struct {
	*BaseRepository
	invoiceCollection *mongo.Collection
}

// NewPaymentRepository creates a new payment repository
func NewPaymentRepository(mongodb *MongoDB) PaymentRepository {
	return &paymentRepository{
		BaseRepository:    NewBaseRepository(mongodb, "payments"),
		invoiceCollection: mongodb.Collection("invoices"),
	}
}

// Create creates a new payment
func (r *paymentRepository) Create(ctx context.Context, payment *models.Payment) error {
	payment.ID = primitive.NewObjectID()
	payment.CreatedAt = time.Now()
	payment.UpdatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, payment)
	if err != nil {
		return fmt.Errorf("failed to create payment: %w", err)
	}
	return nil
}

// GetByID retrieves payment by ID
func (r *paymentRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.Payment, error) {
	var payment models.Payment
	filter := bson.M{"_id": id}

	err := r.collection.FindOne(ctx, filter).Decode(&payment)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrPaymentNotFound
		}
		return nil, fmt.Errorf("failed to get payment by ID: %w", err)
	}

	return &payment, nil
}

// GetByProviderPaymentID retrieves payment by provider payment ID
func (r *paymentRepository) GetByProviderPaymentID(ctx context.Context, providerID string) (*models.Payment, error) {
	var payment models.Payment
	filter := bson.M{"provider_payment_id": providerID}

	err := r.collection.FindOne(ctx, filter).Decode(&payment)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrPaymentNotFound
		}
		return nil, fmt.Errorf("failed to get payment by provider ID: %w", err)
	}

	return &payment, nil
}

// Update updates payment data
func (r *paymentRepository) Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	filter := bson.M{"_id": id}
	return r.BaseRepository.Update(ctx, filter, updates)
}

// Delete permanently deletes payment
func (r *paymentRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	return r.BaseRepository.Delete(ctx, filter)
}

// List retrieves payments with pagination
func (r *paymentRepository) List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Payment, int64, error) {
	var payments []*models.Payment
	filter := bson.M{}

	// Add filters
	for key, value := range params.Filter {
		switch key {
		case "status", "provider", "payment_method":
			filter[key] = value
		case "amount_min":
			if val, ok := value.(string); ok {
				if amount := pkg.Conversions.StringToInt64(val, 0); amount > 0 {
					filter["amount"] = bson.M{"$gte": amount}
				}
			}
		case "amount_max":
			if val, ok := value.(string); ok {
				if amount := pkg.Conversions.StringToInt64(val, 0); amount > 0 {
					filter["amount"] = bson.M{"$lte": amount}
				}
			}
		}
	}

	total, err := r.BaseRepository.List(ctx, filter, params, &payments)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list payments: %w", err)
	}

	return payments, total, nil
}

// ListByUser retrieves user's payments
func (r *paymentRepository) ListByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Payment, int64, error) {
	var payments []*models.Payment
	filter := bson.M{"user_id": userID}

	total, err := r.BaseRepository.List(ctx, filter, params, &payments)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list user payments: %w", err)
	}

	return payments, total, nil
}

// GetPaymentsByStatus retrieves payments by status
func (r *paymentRepository) GetPaymentsByStatus(ctx context.Context, status models.PaymentStatus) ([]*models.Payment, error) {
	var payments []*models.Payment
	filter := bson.M{"status": status}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get payments by status: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &payments); err != nil {
		return nil, fmt.Errorf("failed to decode payments: %w", err)
	}

	return payments, nil
}

// GetRevenueByPeriod calculates revenue for a period
func (r *paymentRepository) GetRevenueByPeriod(ctx context.Context, start, end time.Time) (int64, error) {
	pipeline := []bson.M{
		{"$match": bson.M{
			"status": models.PaymentStatusSucceeded,
			"created_at": bson.M{
				"$gte": start,
				"$lte": end,
			},
		}},
		{"$group": bson.M{
			"_id":   nil,
			"total": bson.M{"$sum": "$amount"},
		}},
	}

	cursor, err := r.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return 0, fmt.Errorf("failed to calculate revenue: %w", err)
	}
	defer cursor.Close(ctx)

	var result struct {
		Total int64 `bson:"total"`
	}

	if cursor.Next(ctx) {
		if err := cursor.Decode(&result); err != nil {
			return 0, fmt.Errorf("failed to decode revenue result: %w", err)
		}
	}

	return result.Total, nil
}

// CreateInvoice creates a new invoice
func (r *paymentRepository) CreateInvoice(ctx context.Context, invoice *models.Invoice) error {
	invoice.ID = primitive.NewObjectID()
	invoice.CreatedAt = time.Now()
	invoice.UpdatedAt = time.Now()

	_, err := r.invoiceCollection.InsertOne(ctx, invoice)
	if err != nil {
		return fmt.Errorf("failed to create invoice: %w", err)
	}
	return nil
}

// GetInvoiceByID retrieves invoice by ID
func (r *paymentRepository) GetInvoiceByID(ctx context.Context, id primitive.ObjectID) (*models.Invoice, error) {
	var invoice models.Invoice
	filter := bson.M{"_id": id}

	err := r.invoiceCollection.FindOne(ctx, filter).Decode(&invoice)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrPaymentNotFound
		}
		return nil, fmt.Errorf("failed to get invoice by ID: %w", err)
	}

	return &invoice, nil
}

// GetInvoiceByNumber retrieves invoice by number
func (r *paymentRepository) GetInvoiceByNumber(ctx context.Context, number string) (*models.Invoice, error) {
	var invoice models.Invoice
	filter := bson.M{"invoice_number": number}

	err := r.invoiceCollection.FindOne(ctx, filter).Decode(&invoice)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, pkg.ErrPaymentNotFound
		}
		return nil, fmt.Errorf("failed to get invoice by number: %w", err)
	}

	return &invoice, nil
}

// UpdateInvoice updates invoice data
func (r *paymentRepository) UpdateInvoice(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error {
	filter := bson.M{"_id": id}
	updates["updated_at"] = time.Now()
	update := bson.M{"$set": updates}

	result, err := r.invoiceCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update invoice: %w", err)
	}

	if result.MatchedCount == 0 {
		return pkg.ErrPaymentNotFound
	}

	return nil
}

// ListInvoices retrieves invoices with pagination
func (r *paymentRepository) ListInvoices(ctx context.Context, params *pkg.PaginationParams) ([]*models.Invoice, int64, error) {
	var invoices []*models.Invoice
	filter := bson.M{}

	// Add filters
	for key, value := range params.Filter {
		if key == "status" {
			filter[key] = value
		}
	}

	// Count total documents
	total, err := r.invoiceCollection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count invoices: %w", err)
	}

	// Find options
	opts := options.Find()
	opts.SetSkip(int64(params.GetOffset()))
	opts.SetLimit(int64(params.Limit))
	opts.SetSort(bson.M{params.Sort: params.GetSortDirection()})

	cursor, err := r.invoiceCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to find invoices: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &invoices); err != nil {
		return nil, 0, fmt.Errorf("failed to decode invoices: %w", err)
	}

	return invoices, total, nil
}

// ListInvoicesByUser retrieves user's invoices
func (r *paymentRepository) ListInvoicesByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Invoice, int64, error) {
	var invoices []*models.Invoice
	filter := bson.M{"user_id": userID}

	// Count total documents
	total, err := r.invoiceCollection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count user invoices: %w", err)
	}

	// Find options
	opts := options.Find()
	opts.SetSkip(int64(params.GetOffset()))
	opts.SetLimit(int64(params.Limit))
	opts.SetSort(bson.M{params.Sort: params.GetSortDirection()})

	cursor, err := r.invoiceCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to find user invoices: %w", err)
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &invoices); err != nil {
		return nil, 0, fmt.Errorf("failed to decode invoices: %w", err)
	}

	return invoices, total, nil
}
