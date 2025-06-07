package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Subscription struct {
	ID                   primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	UserID               primitive.ObjectID     `bson:"user_id" json:"userId"`
	PlanID               primitive.ObjectID     `bson:"plan_id" json:"planId"`
	Status               SubscriptionStatus     `bson:"status" json:"status"`
	StripeCustomerID     string                 `bson:"stripe_customer_id" json:"stripeCustomerId"`
	StripeSubscriptionID string                 `bson:"stripe_subscription_id" json:"stripeSubscriptionId"`
	PayPalSubscriptionID string                 `bson:"paypal_subscription_id" json:"paypalSubscriptionId"`
	CurrentPeriodStart   time.Time              `bson:"current_period_start" json:"currentPeriodStart"`
	CurrentPeriodEnd     time.Time              `bson:"current_period_end" json:"currentPeriodEnd"`
	TrialStart           *time.Time             `bson:"trial_start" json:"trialStart,omitempty"`
	TrialEnd             *time.Time             `bson:"trial_end" json:"trialEnd,omitempty"`
	CanceledAt           *time.Time             `bson:"canceled_at" json:"canceledAt,omitempty"`
	CancelAtPeriodEnd    bool                   `bson:"cancel_at_period_end" json:"cancelAtPeriodEnd"`
	CancelReason         string                 `bson:"cancel_reason" json:"cancelReason"`
	AutoRenew            bool                   `bson:"auto_renew" json:"autoRenew"`
	BillingCycle         BillingCycle           `bson:"billing_cycle" json:"billingCycle"`
	Currency             string                 `bson:"currency" json:"currency"`
	Amount               int64                  `bson:"amount" json:"amount"` // Amount in cents
	TaxAmount            int64                  `bson:"tax_amount" json:"taxAmount"`
	DiscountAmount       int64                  `bson:"discount_amount" json:"discountAmount"`
	Metadata             map[string]interface{} `bson:"metadata" json:"metadata"`
	CreatedAt            time.Time              `bson:"created_at" json:"createdAt"`
	UpdatedAt            time.Time              `bson:"updated_at" json:"updatedAt"`
}

type SubscriptionPlan struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name           string             `bson:"name" json:"name" validate:"required"`
	Description    string             `bson:"description" json:"description"`
	Price          int64              `bson:"price" json:"price"` // Price in cents
	Currency       string             `bson:"currency" json:"currency"`
	BillingCycle   BillingCycle       `bson:"billing_cycle" json:"billingCycle"`
	StorageLimit   int64              `bson:"storage_limit" json:"storageLimit"`     // In bytes
	BandwidthLimit int64              `bson:"bandwidth_limit" json:"bandwidthLimit"` // In bytes per month
	FileLimit      int64              `bson:"file_limit" json:"fileLimit"`
	FolderLimit    int64              `bson:"folder_limit" json:"folderLimit"`
	ShareLimit     int64              `bson:"share_limit" json:"shareLimit"`
	UserLimit      int64              `bson:"user_limit" json:"userLimit"`
	Features       []PlanFeature      `bson:"features" json:"features"`
	IsActive       bool               `bson:"is_active" json:"isActive"`
	IsPopular      bool               `bson:"is_popular" json:"isPopular"`
	TrialDays      int                `bson:"trial_days" json:"trialDays"`
	SetupFee       int64              `bson:"setup_fee" json:"setupFee"`
	SortOrder      int                `bson:"sort_order" json:"sortOrder"`
	StripePriceID  string             `bson:"stripe_price_id" json:"stripePriceId"`
	PayPalPlanID   string             `bson:"paypal_plan_id" json:"paypalPlanId"`
	CreatedAt      time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt      time.Time          `bson:"updated_at" json:"updatedAt"`
}

type PlanFeature struct {
	Name        string `bson:"name" json:"name"`
	Description string `bson:"description" json:"description"`
	Included    bool   `bson:"included" json:"included"`
	Limit       *int64 `bson:"limit,omitempty" json:"limit,omitempty"`
}

type SubscriptionStatus string

const (
	SubscriptionStatusActive     SubscriptionStatus = "active"
	SubscriptionStatusTrialing   SubscriptionStatus = "trialing"
	SubscriptionStatusPastDue    SubscriptionStatus = "past_due"
	SubscriptionStatusCanceled   SubscriptionStatus = "canceled"
	SubscriptionStatusUnpaid     SubscriptionStatus = "unpaid"
	SubscriptionStatusIncomplete SubscriptionStatus = "incomplete"
)

type BillingCycle string

const (
	BillingCycleMonthly BillingCycle = "monthly"
	BillingCycleYearly  BillingCycle = "yearly"
	BillingCycleWeekly  BillingCycle = "weekly"
	BillingCycleOneTime BillingCycle = "one_time"
)
