package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AdminSettings struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Category  SettingsCategory   `bson:"category" json:"category"`
	Key       string             `bson:"key" json:"key"`
	Value     interface{}        `bson:"value" json:"value"`
	Type      SettingsType       `bson:"type" json:"type"`
	IsPublic  bool               `bson:"is_public" json:"isPublic"`
	UpdatedBy primitive.ObjectID `bson:"updated_by" json:"updatedBy"`
	CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updatedAt"`
}

type SettingsCategory string

const (
	SettingsCategoryApp      SettingsCategory = "app"
	SettingsCategoryStorage  SettingsCategory = "storage"
	SettingsCategoryEmail    SettingsCategory = "email"
	SettingsCategoryPayment  SettingsCategory = "payment"
	SettingsCategorySecurity SettingsCategory = "security"
	SettingsCategoryAPI      SettingsCategory = "api"
	SettingsCategoryBackup   SettingsCategory = "backup"
	SettingsCategoryFeature  SettingsCategory = "feature"
)

type SettingsType string

const (
	SettingsTypeString  SettingsType = "string"
	SettingsTypeNumber  SettingsType = "number"
	SettingsTypeBoolean SettingsType = "boolean"
	SettingsTypeJSON    SettingsType = "json"
	SettingsTypeArray   SettingsType = "array"
)

type AppSettings struct {
	Name                     string `json:"name"`
	Description              string `json:"description"`
	Logo                     string `json:"logo"`
	Favicon                  string `json:"favicon"`
	URL                      string `json:"url"`
	SupportEmail             string `json:"supportEmail"`
	AllowRegistration        bool   `json:"allowRegistration"`
	RequireEmailVerification bool   `json:"requireEmailVerification"`
	DefaultTheme             string `json:"defaultTheme"`
	DefaultLanguage          string `json:"defaultLanguage"`
	Timezone                 string `json:"timezone"`
	MaintenanceMode          bool   `json:"maintenanceMode"`
	MaintenanceMessage       string `json:"maintenanceMessage"`
}

type StorageSettings struct {
	DefaultProvider     string                     `json:"defaultProvider"`
	MaxFileSize         int64                      `json:"maxFileSize"`
	AllowedFileTypes    []string                   `json:"allowedFileTypes"`
	BlockedFileTypes    []string                   `json:"blockedFileTypes"`
	EnableVirusScanning bool                       `json:"enableVirusScanning"`
	EnableEncryption    bool                       `json:"enableEncryption"`
	StorageQuota        int64                      `json:"storageQuota"`
	Providers           map[string]StorageProvider `json:"providers"`
}

type StorageProvider struct {
	Enabled   bool              `json:"enabled"`
	Config    map[string]string `json:"config"`
	IsDefault bool              `json:"isDefault"`
	Priority  int               `json:"priority"`
}

type EmailSettings struct {
	Provider            string            `json:"provider"`
	FromEmail           string            `json:"fromEmail"`
	FromName            string            `json:"fromName"`
	ReplyToEmail        string            `json:"replyToEmail"`
	Config              map[string]string `json:"config"`
	EnableWelcomeEmail  bool              `json:"enableWelcomeEmail"`
	EnableNotifications bool              `json:"enableNotifications"`
}

type PaymentSettings struct {
	Currency         string                           `json:"currency"`
	TaxRate          float64                          `json:"taxRate"`
	EnabledProviders []string                         `json:"enabledProviders"`
	Providers        map[string]PaymentProviderConfig `json:"providers"`
	EnableInvoices   bool                             `json:"enableInvoices"`
	InvoicePrefix    string                           `json:"invoicePrefix"`
}

type PaymentProviderConfig struct {
	Enabled       bool              `json:"enabled"`
	PublicKey     string            `json:"publicKey"`
	SecretKey     string            `json:"secretKey"`
	WebhookSecret string            `json:"webhookSecret"`
	Config        map[string]string `json:"config"`
}

type SecuritySettings struct {
	EnableTwoFactor          bool     `json:"enableTwoFactor"`
	RequireTwoFactor         bool     `json:"requireTwoFactor"`
	SessionTimeout           int      `json:"sessionTimeout"`
	MaxLoginAttempts         int      `json:"maxLoginAttempts"`
	LockoutDuration          int      `json:"lockoutDuration"`
	PasswordMinLength        int      `json:"passwordMinLength"`
	PasswordRequireUppercase bool     `json:"passwordRequireUppercase"`
	PasswordRequireLowercase bool     `json:"passwordRequireLowercase"`
	PasswordRequireNumbers   bool     `json:"passwordRequireNumbers"`
	PasswordRequireSymbols   bool     `json:"passwordRequireSymbols"`
	AllowedDomains           []string `json:"allowedDomains"`
	BlockedIPs               []string `json:"blockedIPs"`
	EnableAuditLog           bool     `json:"enableAuditLog"`
	AuditLogRetention        int      `json:"auditLogRetention"`
}

type APISettings struct {
	EnableAPI         bool     `json:"enableAPI"`
	RateLimitRequests int      `json:"rateLimitRequests"`
	RateLimitWindow   int      `json:"rateLimitWindow"`
	AllowedOrigins    []string `json:"allowedOrigins"`
	RequireAuth       bool     `json:"requireAuth"`
	EnableWebhooks    bool     `json:"enableWebhooks"`
	WebhookSecret     string   `json:"webhookSecret"`
}

type BackupSettings struct {
	EnableAutoBackup  bool   `json:"enableAutoBackup"`
	BackupFrequency   string `json:"backupFrequency"`
	BackupRetention   int    `json:"backupRetention"`
	BackupLocation    string `json:"backupLocation"`
	BackupEncryption  bool   `json:"backupEncryption"`
	BackupCompression bool   `json:"backupCompression"`
	NotifyOnSuccess   bool   `json:"notifyOnSuccess"`
	NotifyOnFailure   bool   `json:"notifyOnFailure"`
}

type FeatureSettings struct {
	EnableSharing       bool `json:"enableSharing"`
	EnablePublicShares  bool `json:"enablePublicShares"`
	EnableComments      bool `json:"enableComments"`
	EnableVersioning    bool `json:"enableVersioning"`
	EnableThumbnails    bool `json:"enableThumbnails"`
	EnablePreview       bool `json:"enablePreview"`
	EnableSearch        bool `json:"enableSearch"`
	EnableAnalytics     bool `json:"enableAnalytics"`
	EnableNotifications bool `json:"enableNotifications"`
}
