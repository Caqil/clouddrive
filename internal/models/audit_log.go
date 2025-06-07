package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AuditLog struct {
	ID           primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	UserID       *primitive.ObjectID    `bson:"user_id,omitempty" json:"userId,omitempty"`
	AdminID      *primitive.ObjectID    `bson:"admin_id,omitempty" json:"adminId,omitempty"`
	Action       AuditAction            `bson:"action" json:"action"`
	Resource     AuditResource          `bson:"resource" json:"resource"`
	OldValues    map[string]interface{} `bson:"old_values,omitempty" json:"oldValues,omitempty"`
	NewValues    map[string]interface{} `bson:"new_values,omitempty" json:"newValues,omitempty"`
	IP           string                 `bson:"ip" json:"ip"`
	UserAgent    string                 `bson:"user_agent" json:"userAgent"`
	Success      bool                   `bson:"success" json:"success"`
	ErrorMessage string                 `bson:"error_message,omitempty" json:"errorMessage,omitempty"`
	Severity     AuditSeverity          `bson:"severity" json:"severity"`
	Context      AuditContext           `bson:"context" json:"context"`
	Tags         []string               `bson:"tags" json:"tags"`
	Metadata     map[string]interface{} `bson:"metadata,omitempty" json:"metadata,omitempty"`
	Timestamp    time.Time              `bson:"timestamp" json:"timestamp"`
	CreatedAt    time.Time              `bson:"created_at" json:"createdAt"`
}

type AuditResource struct {
	Type string             `bson:"type" json:"type"`
	ID   primitive.ObjectID `bson:"id" json:"id"`
	Name string             `bson:"name" json:"name"`
}

type AuditContext struct {
	Module    string `bson:"module" json:"module"`
	Function  string `bson:"function" json:"function"`
	Endpoint  string `bson:"endpoint" json:"endpoint"`
	Method    string `bson:"method" json:"method"`
	SessionID string `bson:"session_id" json:"sessionId"`
	RequestID string `bson:"request_id" json:"requestId"`
}

type AuditAction string

const (
	// User actions
	AuditActionUserLogin      AuditAction = "user_login"
	AuditActionUserLogout     AuditAction = "user_logout"
	AuditActionUserRegister   AuditAction = "user_register"
	AuditActionUserUpdate     AuditAction = "user_update"
	AuditActionUserDelete     AuditAction = "user_delete"
	AuditActionPasswordChange AuditAction = "password_change"
	AuditActionPasswordReset  AuditAction = "password_reset"
	AuditActionEmailVerify    AuditAction = "email_verify"
	AuditAction2FAEnable      AuditAction = "2fa_enable"
	AuditAction2FADisable     AuditAction = "2fa_disable"

	// File actions
	AuditActionFileUpload   AuditAction = "file_upload"
	AuditActionFileDownload AuditAction = "file_download"
	AuditActionFileView     AuditAction = "file_view"
	AuditActionFileUpdate   AuditAction = "file_update"
	AuditActionFileDelete   AuditAction = "file_delete"
	AuditActionFileMove     AuditAction = "file_move"
	AuditActionFileCopy     AuditAction = "file_copy"
	AuditActionFileRename   AuditAction = "file_rename"

	// Folder actions
	AuditActionFolderCreate AuditAction = "folder_create"
	AuditActionFolderUpdate AuditAction = "folder_update"
	AuditActionFolderDelete AuditAction = "folder_delete"
	AuditActionFolderMove   AuditAction = "folder_move"

	// Share actions
	AuditActionShareCreate AuditAction = "share_create"
	AuditActionShareUpdate AuditAction = "share_update"
	AuditActionShareDelete AuditAction = "share_delete"
	AuditActionShareAccess AuditAction = "share_access"

	// Subscription actions
	AuditActionSubscriptionCreate AuditAction = "subscription_create"
	AuditActionSubscriptionUpdate AuditAction = "subscription_update"
	AuditActionSubscriptionCancel AuditAction = "subscription_cancel"

	// Payment actions
	AuditActionPaymentCreate AuditAction = "payment_create"
	AuditActionPaymentUpdate AuditAction = "payment_update"
	AuditActionPaymentRefund AuditAction = "payment_refund"

	// Admin actions
	AuditActionAdminLogin     AuditAction = "admin_login"
	AuditActionAdminLogout    AuditAction = "admin_logout"
	AuditActionSettingsUpdate AuditAction = "settings_update"
	AuditActionUserSuspend    AuditAction = "user_suspend"
	AuditActionUserUnsuspend  AuditAction = "user_unsuspend"

	// Security actions
	AuditActionSecurityBreach     AuditAction = "security_breach"
	AuditActionSuspiciousActivity AuditAction = "suspicious_activity"
	AuditActionLoginFailure       AuditAction = "login_failure"
	AuditActionAPIKeyCreate       AuditAction = "api_key_create"
	AuditActionAPIKeyDelete       AuditAction = "api_key_delete"
)

type AuditSeverity string

const (
	AuditSeverityLow      AuditSeverity = "low"
	AuditSeverityMedium   AuditSeverity = "medium"
	AuditSeverityHigh     AuditSeverity = "high"
	AuditSeverityCritical AuditSeverity = "critical"
)
