package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Payment struct {
	ID                 primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	UserID             primitive.ObjectID     `bson:"user_id" json:"userId"`
	SubscriptionID     *primitive.ObjectID    `bson:"subscription_id,omitempty" json:"subscriptionId,omitempty"`
	PaymentMethod      PaymentMethod          `bson:"payment_method" json:"paymentMethod"`
	Provider           PaymentProvider        `bson:"provider" json:"provider"`
	ProviderPaymentID  string                 `bson:"provider_payment_id" json:"providerPaymentId"`
	ProviderCustomerID string                 `bson:"provider_customer_id" json:"providerCustomerId"`
	Amount             int64                  `bson:"amount" json:"amount"` // Amount in cents
	Currency           string                 `bson:"currency" json:"currency"`
	Status             PaymentStatus          `bson:"status" json:"status"`
	Type               PaymentType            `bson:"type" json:"type"`
	Description        string                 `bson:"description" json:"description"`
	InvoiceID          string                 `bson:"invoice_id" json:"invoiceId"`
	RefundAmount       int64                  `bson:"refund_amount" json:"refundAmount"`
	RefundReason       string                 `bson:"refund_reason" json:"refundReason"`
	RefundedAt         *time.Time             `bson:"refunded_at" json:"refundedAt,omitempty"`
	TaxAmount          int64                  `bson:"tax_amount" json:"taxAmount"`
	TaxRate            float64                `bson:"tax_rate" json:"taxRate"`
	DiscountAmount     int64                  `bson:"discount_amount" json:"discountAmount"`
	CouponCode         string                 `bson:"coupon_code" json:"couponCode"`
	BillingAddress     BillingAddress         `bson:"billing_address" json:"billingAddress"`
	PaymentDetails     PaymentDetails         `bson:"payment_details" json:"paymentDetails"`
	FailureCode        string                 `bson:"failure_code" json:"failureCode"`
	FailureMessage     string                 `bson:"failure_message" json:"failureMessage"`
	ProcessedAt        *time.Time             `bson:"processed_at" json:"processedAt,omitempty"`
	Metadata           map[string]interface{} `bson:"metadata" json:"metadata"`
	CreatedAt          time.Time              `bson:"created_at" json:"createdAt"`
	UpdatedAt          time.Time              `bson:"updated_at" json:"updatedAt"`
}

type Invoice struct {
	ID             primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	InvoiceNumber  string              `bson:"invoice_number" json:"invoiceNumber"`
	UserID         primitive.ObjectID  `bson:"user_id" json:"userId"`
	SubscriptionID *primitive.ObjectID `bson:"subscription_id,omitempty" json:"subscriptionId,omitempty"`
	PaymentID      *primitive.ObjectID `bson:"payment_id,omitempty" json:"paymentId,omitempty"`
	Status         InvoiceStatus       `bson:"status" json:"status"`
	Subtotal       int64               `bson:"subtotal" json:"subtotal"`
	TaxAmount      int64               `bson:"tax_amount" json:"taxAmount"`
	Total          int64               `bson:"total" json:"total"`
	Currency       string              `bson:"currency" json:"currency"`
	Items          []InvoiceItem       `bson:"items" json:"items"`
	BillingAddress BillingAddress      `bson:"billing_address" json:"billingAddress"`
	DueDate        time.Time           `bson:"due_date" json:"dueDate"`
	PaidAt         *time.Time          `bson:"paid_at" json:"paidAt,omitempty"`
	VoidedAt       *time.Time          `bson:"voided_at" json:"voidedAt,omitempty"`
	CreatedAt      time.Time           `bson:"created_at" json:"createdAt"`
	UpdatedAt      time.Time           `bson:"updated_at" json:"updatedAt"`
}

type InvoiceItem struct {
	Description string  `bson:"description" json:"description"`
	Amount      int64   `bson:"amount" json:"amount"`
	Quantity    int     `bson:"quantity" json:"quantity"`
	UnitPrice   int64   `bson:"unit_price" json:"unitPrice"`
	TaxRate     float64 `bson:"tax_rate" json:"taxRate"`
}

type BillingAddress struct {
	Name       string `bson:"name" json:"name"`
	Company    string `bson:"company" json:"company"`
	Line1      string `bson:"line1" json:"line1"`
	Line2      string `bson:"line2" json:"line2"`
	City       string `bson:"city" json:"city"`
	State      string `bson:"state" json:"state"`
	PostalCode string `bson:"postal_code" json:"postalCode"`
	Country    string `bson:"country" json:"country"`
}

type PaymentDetails struct {
	Last4        string `bson:"last4" json:"last4"`
	Brand        string `bson:"brand" json:"brand"`
	ExpiryMonth  int    `bson:"expiry_month" json:"expiryMonth"`
	ExpiryYear   int    `bson:"expiry_year" json:"expiryYear"`
	Fingerprint  string `bson:"fingerprint" json:"fingerprint"`
	PayPalEmail  string `bson:"paypal_email" json:"paypalEmail"`
	BankName     string `bson:"bank_name" json:"bankName"`
	AccountLast4 string `bson:"account_last4" json:"accountLast4"`
}

type PaymentMethod string

const (
	PaymentMethodCard         PaymentMethod = "card"
	PaymentMethodBankTransfer PaymentMethod = "bank_transfer"
	PaymentMethodPayPal       PaymentMethod = "paypal"
	PaymentMethodApplePay     PaymentMethod = "apple_pay"
	PaymentMethodGooglePay    PaymentMethod = "google_pay"
)

type PaymentProvider string

const (
	PaymentProviderStripe PaymentProvider = "stripe"
	PaymentProviderPayPal PaymentProvider = "paypal"
)

type PaymentStatus string

const (
	PaymentStatusPending    PaymentStatus = "pending"
	PaymentStatusProcessing PaymentStatus = "processing"
	PaymentStatusSucceeded  PaymentStatus = "succeeded"
	PaymentStatusFailed     PaymentStatus = "failed"
	PaymentStatusCanceled   PaymentStatus = "canceled"
	PaymentStatusRefunded   PaymentStatus = "refunded"
)

type PaymentType string

const (
	PaymentTypeSubscription  PaymentType = "subscription"
	PaymentTypeOneTime       PaymentType = "one_time"
	PaymentTypeRefund        PaymentType = "refund"
	PaymentTypePartialRefund PaymentType = "partial_refund"
)

type InvoiceStatus string

const (
	InvoiceStatusDraft  InvoiceStatus = "draft"
	InvoiceStatusOpen   InvoiceStatus = "open"
	InvoiceStatusPaid   InvoiceStatus = "paid"
	InvoiceStatusVoided InvoiceStatus = "voided"
)
