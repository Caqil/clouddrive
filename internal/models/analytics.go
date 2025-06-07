package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Analytics struct {
	ID        primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	UserID    *primitive.ObjectID    `bson:"user_id,omitempty" json:"userId,omitempty"`
	EventType AnalyticsEventType     `bson:"event_type" json:"eventType"`
	Action    string                 `bson:"action" json:"action"`
	Resource  AnalyticsResource      `bson:"resource" json:"resource"`
	Metadata  map[string]interface{} `bson:"metadata" json:"metadata"`
	UserAgent string                 `bson:"user_agent" json:"userAgent"`
	IP        string                 `bson:"ip" json:"ip"`
	Country   string                 `bson:"country" json:"country"`
	City      string                 `bson:"city" json:"city"`
	Referrer  string                 `bson:"referrer" json:"referrer"`
	Timestamp time.Time              `bson:"timestamp" json:"timestamp"`
	CreatedAt time.Time              `bson:"created_at" json:"createdAt"`
}

type AnalyticsResource struct {
	Type string             `bson:"type" json:"type"`
	ID   primitive.ObjectID `bson:"id" json:"id"`
	Name string             `bson:"name" json:"name"`
	Size *int64             `bson:"size,omitempty" json:"size,omitempty"`
}

type AnalyticsEventType string

const (
	EventTypeFileUpload   AnalyticsEventType = "file_upload"
	EventTypeFileDownload AnalyticsEventType = "file_download"
	EventTypeFileView     AnalyticsEventType = "file_view"
	EventTypeFileShare    AnalyticsEventType = "file_share"
	EventTypeFileDelete   AnalyticsEventType = "file_delete"
	EventTypeFolderCreate AnalyticsEventType = "folder_create"
	EventTypeFolderDelete AnalyticsEventType = "folder_delete"
	EventTypeUserLogin    AnalyticsEventType = "user_login"
	EventTypeUserRegister AnalyticsEventType = "user_register"
	EventTypeUserLogout   AnalyticsEventType = "user_logout"
	EventTypePayment      AnalyticsEventType = "payment"
	EventTypeSubscription AnalyticsEventType = "subscription"
	EventTypeShareAccess  AnalyticsEventType = "share_access"
	EventTypeAPICall      AnalyticsEventType = "api_call"
	EventTypeError        AnalyticsEventType = "error"
	EventTypePageView     AnalyticsEventType = "page_view"
)

type AnalyticsSummary struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Date             time.Time          `bson:"date" json:"date"`
	TotalUsers       int64              `bson:"total_users" json:"totalUsers"`
	ActiveUsers      int64              `bson:"active_users" json:"activeUsers"`
	NewUsers         int64              `bson:"new_users" json:"newUsers"`
	TotalFiles       int64              `bson:"total_files" json:"totalFiles"`
	FilesUploaded    int64              `bson:"files_uploaded" json:"filesUploaded"`
	FilesDownloaded  int64              `bson:"files_downloaded" json:"filesDownloaded"`
	StorageUsed      int64              `bson:"storage_used" json:"storageUsed"`
	BandwidthUsed    int64              `bson:"bandwidth_used" json:"bandwidthUsed"`
	TotalRevenue     int64              `bson:"total_revenue" json:"totalRevenue"`
	NewSubscriptions int64              `bson:"new_subscriptions" json:"newSubscriptions"`
	Churn            float64            `bson:"churn" json:"churn"`
	PageViews        int64              `bson:"page_views" json:"pageViews"`
	UniqueVisitors   int64              `bson:"unique_visitors" json:"uniqueVisitors"`
	ApiCalls         int64              `bson:"api_calls" json:"apiCalls"`
	Errors           int64              `bson:"errors" json:"errors"`
	SharesCreated    int64              `bson:"shares_created" json:"sharesCreated"`
	SharesAccessed   int64              `bson:"shares_accessed" json:"sharesAccessed"`
	CreatedAt        time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt        time.Time          `bson:"updated_at" json:"updatedAt"`
}

type UserAnalytics struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID          primitive.ObjectID `bson:"user_id" json:"userId"`
	Date            time.Time          `bson:"date" json:"date"`
	FilesUploaded   int64              `bson:"files_uploaded" json:"filesUploaded"`
	FilesDownloaded int64              `bson:"files_downloaded" json:"filesDownloaded"`
	StorageUsed     int64              `bson:"storage_used" json:"storageUsed"`
	BandwidthUsed   int64              `bson:"bandwidth_used" json:"bandwidthUsed"`
	LoginCount      int64              `bson:"login_count" json:"loginCount"`
	SessionDuration int64              `bson:"session_duration" json:"sessionDuration"`
	PageViews       int64              `bson:"page_views" json:"pageViews"`
	ApiCalls        int64              `bson:"api_calls" json:"apiCalls"`
	SharesCreated   int64              `bson:"shares_created" json:"sharesCreated"`
	SharesAccessed  int64              `bson:"shares_accessed" json:"sharesAccessed"`
	CreatedAt       time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt       time.Time          `bson:"updated_at" json:"updatedAt"`
}
