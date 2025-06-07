package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email            string             `bson:"email" json:"email" validate:"required,email"`
	Username         string             `bson:"username" json:"username" validate:"required,min=3,max=50"`
	Password         string             `bson:"password" json:"-"`
	FirstName        string             `bson:"first_name" json:"firstName" validate:"required,min=1,max=50"`
	LastName         string             `bson:"last_name" json:"lastName" validate:"required,min=1,max=50"`
	Avatar           string             `bson:"avatar" json:"avatar"`
	Bio              string             `bson:"bio" json:"bio" validate:"max=500"`
	Phone            string             `bson:"phone" json:"phone"`
	Role             UserRole           `bson:"role" json:"role"`
	Status           UserStatus         `bson:"status" json:"status"`
	EmailVerified    bool               `bson:"email_verified" json:"emailVerified"`
	EmailVerifiedAt  *time.Time         `bson:"email_verified_at" json:"emailVerifiedAt,omitempty"`
	TwoFactorEnabled bool               `bson:"two_factor_enabled" json:"twoFactorEnabled"`
	TwoFactorSecret  string             `bson:"two_factor_secret" json:"-"`
	Subscription     *UserSubscription  `bson:"subscription" json:"subscription,omitempty"`
	StorageUsed      int64              `bson:"storage_used" json:"storageUsed"`
	StorageLimit     int64              `bson:"storage_limit" json:"storageLimit"`
	LastLoginAt      *time.Time         `bson:"last_login_at" json:"lastLoginAt,omitempty"`
	LastLoginIP      string             `bson:"last_login_ip" json:"lastLoginIP"`
	LoginCount       int64              `bson:"login_count" json:"loginCount"`
	Timezone         string             `bson:"timezone" json:"timezone"`
	Language         string             `bson:"language" json:"language"`
	Preferences      UserPreferences    `bson:"preferences" json:"preferences"`
	OAuthProviders   []OAuthProvider    `bson:"oauth_providers" json:"oauthProviders"`
	APIKeys          []APIKey           `bson:"api_keys" json:"apiKeys,omitempty"`
	CreatedAt        time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt        time.Time          `bson:"updated_at" json:"updatedAt"`
	DeletedAt        *time.Time         `bson:"deleted_at,omitempty" json:"deletedAt,omitempty"`
}

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
	RoleGuest UserRole = "guest"
)

type UserStatus string

const (
	StatusActive    UserStatus = "active"
	StatusInactive  UserStatus = "inactive"
	StatusSuspended UserStatus = "suspended"
	StatusPending   UserStatus = "pending"
)

type UserSubscription struct {
	PlanID    primitive.ObjectID `bson:"plan_id" json:"planId"`
	Status    string             `bson:"status" json:"status"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expiresAt"`
}

type UserPreferences struct {
	Theme          string `bson:"theme" json:"theme"`
	Notifications  bool   `bson:"notifications" json:"notifications"`
	EmailUpdates   bool   `bson:"email_updates" json:"emailUpdates"`
	DefaultView    string `bson:"default_view" json:"defaultView"`
	AutoBackup     bool   `bson:"auto_backup" json:"autoBackup"`
	ShareByDefault bool   `bson:"share_by_default" json:"shareByDefault"`
}

type OAuthProvider struct {
	Provider     string    `bson:"provider" json:"provider"`
	ProviderID   string    `bson:"provider_id" json:"providerId"`
	AccessToken  string    `bson:"access_token" json:"-"`
	RefreshToken string    `bson:"refresh_token" json:"-"`
	ConnectedAt  time.Time `bson:"connected_at" json:"connectedAt"`
}

type APIKey struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`
	Key         string             `bson:"key" json:"key"`
	Permissions []string           `bson:"permissions" json:"permissions"`
	LastUsedAt  *time.Time         `bson:"last_used_at" json:"lastUsedAt,omitempty"`
	ExpiresAt   *time.Time         `bson:"expires_at" json:"expiresAt,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"createdAt"`
	IsActive    bool               `bson:"is_active" json:"isActive"`
}
