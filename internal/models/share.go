package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Share struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Token          string             `bson:"token" json:"token" validate:"required"`
	ResourceType   ShareResourceType  `bson:"resource_type" json:"resourceType"`
	ResourceID     primitive.ObjectID `bson:"resource_id" json:"resourceId"`
	UserID         primitive.ObjectID `bson:"user_id" json:"userId"`
	ShareType      ShareType          `bson:"share_type" json:"shareType"`
	Permission     SharePermission    `bson:"permission" json:"permission"`
	Password       string             `bson:"password" json:"-"`
	HasPassword    bool               `bson:"has_password" json:"hasPassword"`
	ExpiresAt      *time.Time         `bson:"expires_at" json:"expiresAt,omitempty"`
	MaxDownloads   int                `bson:"max_downloads" json:"maxDownloads"`
	DownloadCount  int                `bson:"download_count" json:"downloadCount"`
	ViewCount      int                `bson:"view_count" json:"viewCount"`
	AllowedIPs     []string           `bson:"allowed_ips" json:"allowedIPs"`
	AllowedDomains []string           `bson:"allowed_domains" json:"allowedDomains"`
	IsActive       bool               `bson:"is_active" json:"isActive"`
	NotifyOnAccess bool               `bson:"notify_on_access" json:"notifyOnAccess"`
	CustomMessage  string             `bson:"custom_message" json:"customMessage"`
	Recipients     []ShareRecipient   `bson:"recipients" json:"recipients"`
	AccessLog      []ShareAccess      `bson:"access_log" json:"accessLog"`
	CreatedAt      time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt      time.Time          `bson:"updated_at" json:"updatedAt"`
	DeletedAt      *time.Time         `bson:"deleted_at,omitempty" json:"deletedAt,omitempty"`
}

type ShareResourceType string

const (
	ShareResourceFile   ShareResourceType = "file"
	ShareResourceFolder ShareResourceType = "folder"
)

type ShareType string

const (
	ShareTypePublic   ShareType = "public"
	ShareTypePrivate  ShareType = "private"
	ShareTypeInternal ShareType = "internal"
)

type SharePermission string

const (
	SharePermissionView     SharePermission = "view"
	SharePermissionDownload SharePermission = "download"
	SharePermissionEdit     SharePermission = "edit"
	SharePermissionComment  SharePermission = "comment"
)

type ShareRecipient struct {
	Email     string              `bson:"email" json:"email"`
	UserID    *primitive.ObjectID `bson:"user_id,omitempty" json:"userId,omitempty"`
	Name      string              `bson:"name" json:"name"`
	InvitedAt time.Time           `bson:"invited_at" json:"invitedAt"`
	ViewedAt  *time.Time          `bson:"viewed_at" json:"viewedAt,omitempty"`
}

type ShareAccess struct {
	IP         string    `bson:"ip" json:"ip"`
	UserAgent  string    `bson:"user_agent" json:"userAgent"`
	Country    string    `bson:"country" json:"country"`
	City       string    `bson:"city" json:"city"`
	AccessedAt time.Time `bson:"accessed_at" json:"accessedAt"`
	Action     string    `bson:"action" json:"action"`
	Email      string    `bson:"email" json:"email"`
}
