package repository

import (
	"context"
	"time"

	"clouddrive/internal/models"
	"clouddrive/internal/pkg"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserRepository defines user repository interface
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error
	Delete(ctx context.Context, id primitive.ObjectID) error
	List(ctx context.Context, params *pkg.PaginationParams) ([]*models.User, int64, error)
	Search(ctx context.Context, query string, params *pkg.PaginationParams) ([]*models.User, int64, error)
	GetByOAuthProvider(ctx context.Context, provider, providerID string) (*models.User, error)
	UpdateStorageUsed(ctx context.Context, userID primitive.ObjectID, size int64) error
	GetActiveUsers(ctx context.Context, since time.Time) (int64, error)
	GetUsersByRole(ctx context.Context, role models.UserRole) ([]*models.User, error)
	SoftDelete(ctx context.Context, id primitive.ObjectID) error
	GetDeletedUsers(ctx context.Context, params *pkg.PaginationParams) ([]*models.User, int64, error)
	Restore(ctx context.Context, id primitive.ObjectID) error
}

// FileRepository defines file repository interface
type FileRepository interface {
	Create(ctx context.Context, file *models.File) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.File, error)
	GetByPath(ctx context.Context, userID primitive.ObjectID, path string) (*models.File, error)
	GetByHash(ctx context.Context, hash string) (*models.File, error)
	Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error
	Delete(ctx context.Context, id primitive.ObjectID) error
	List(ctx context.Context, params *pkg.PaginationParams) ([]*models.File, int64, error)
	ListByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.File, int64, error)
	ListByFolder(ctx context.Context, folderID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.File, int64, error)
	Search(ctx context.Context, userID primitive.ObjectID, query string, params *pkg.PaginationParams) ([]*models.File, int64, error)
	GetFilesByMimeType(ctx context.Context, mimeType string) ([]*models.File, error)
	GetLargestFiles(ctx context.Context, limit int) ([]*models.File, error)
	GetRecentFiles(ctx context.Context, userID primitive.ObjectID, limit int) ([]*models.File, error)
	GetFavoriteFiles(ctx context.Context, userID primitive.ObjectID) ([]*models.File, error)
	UpdateDownloadCount(ctx context.Context, id primitive.ObjectID) error
	UpdateViewCount(ctx context.Context, id primitive.ObjectID) error
	GetTotalStorageUsed(ctx context.Context) (int64, error)
	GetStorageByUser(ctx context.Context, userID primitive.ObjectID) (int64, error)
	SoftDelete(ctx context.Context, id primitive.ObjectID) error
	GetDeletedFiles(ctx context.Context, params *pkg.PaginationParams) ([]*models.File, int64, error)
	Restore(ctx context.Context, id primitive.ObjectID) error
	GetOrphanedFiles(ctx context.Context) ([]*models.File, error)
}

// FolderRepository defines folder repository interface
type FolderRepository interface {
	Create(ctx context.Context, folder *models.Folder) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.Folder, error)
	GetByPath(ctx context.Context, userID primitive.ObjectID, path string) (*models.Folder, error)
	GetRootFolder(ctx context.Context, userID primitive.ObjectID) (*models.Folder, error)
	Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error
	Delete(ctx context.Context, id primitive.ObjectID) error
	List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Folder, int64, error)
	ListByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Folder, int64, error)
	ListByParent(ctx context.Context, parentID primitive.ObjectID) ([]*models.Folder, error)
	GetChildren(ctx context.Context, folderID primitive.ObjectID) ([]*models.Folder, error)
	GetFolderTree(ctx context.Context, userID primitive.ObjectID) ([]*models.Folder, error)
	UpdateSize(ctx context.Context, id primitive.ObjectID, size int64) error
	UpdateCounts(ctx context.Context, id primitive.ObjectID, fileCount, folderCount int64) error
	SoftDelete(ctx context.Context, id primitive.ObjectID) error
	GetDeletedFolders(ctx context.Context, params *pkg.PaginationParams) ([]*models.Folder, int64, error)
	Restore(ctx context.Context, id primitive.ObjectID) error
}

// ShareRepository defines share repository interface
type ShareRepository interface {
	Create(ctx context.Context, share *models.Share) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.Share, error)
	GetByToken(ctx context.Context, token string) (*models.Share, error)
	Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error
	Delete(ctx context.Context, id primitive.ObjectID) error
	List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Share, int64, error)
	ListByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Share, int64, error)
	ListByResource(ctx context.Context, resourceType models.ShareResourceType, resourceID primitive.ObjectID) ([]*models.Share, error)
	GetExpiredShares(ctx context.Context) ([]*models.Share, error)
	UpdateDownloadCount(ctx context.Context, id primitive.ObjectID) error
	UpdateViewCount(ctx context.Context, id primitive.ObjectID) error
	AddAccessLog(ctx context.Context, id primitive.ObjectID, access models.ShareAccess) error
	SoftDelete(ctx context.Context, id primitive.ObjectID) error
}

// SubscriptionRepository defines subscription repository interface
type SubscriptionRepository interface {
	Create(ctx context.Context, subscription *models.Subscription) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.Subscription, error)
	GetByUserID(ctx context.Context, userID primitive.ObjectID) (*models.Subscription, error)
	GetByStripeSubscriptionID(ctx context.Context, stripeID string) (*models.Subscription, error)
	GetByPayPalSubscriptionID(ctx context.Context, paypalID string) (*models.Subscription, error)
	Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error
	Delete(ctx context.Context, id primitive.ObjectID) error
	List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Subscription, int64, error)
	GetActiveSubscriptions(ctx context.Context) ([]*models.Subscription, error)
	GetExpiringSubscriptions(ctx context.Context, days int) ([]*models.Subscription, error)
	GetSubscriptionsByStatus(ctx context.Context, status models.SubscriptionStatus) ([]*models.Subscription, error)
	CreatePlan(ctx context.Context, plan *models.SubscriptionPlan) error
	GetPlanByID(ctx context.Context, id primitive.ObjectID) (*models.SubscriptionPlan, error)
	GetActivePlans(ctx context.Context) ([]*models.SubscriptionPlan, error)
	UpdatePlan(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error
	DeletePlan(ctx context.Context, id primitive.ObjectID) error
}

// PaymentRepository defines payment repository interface
type PaymentRepository interface {
	Create(ctx context.Context, payment *models.Payment) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.Payment, error)
	GetByProviderPaymentID(ctx context.Context, providerID string) (*models.Payment, error)
	Update(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error
	Delete(ctx context.Context, id primitive.ObjectID) error
	List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Payment, int64, error)
	ListByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Payment, int64, error)
	GetPaymentsByStatus(ctx context.Context, status models.PaymentStatus) ([]*models.Payment, error)
	GetRevenueByPeriod(ctx context.Context, start, end time.Time) (int64, error)
	CreateInvoice(ctx context.Context, invoice *models.Invoice) error
	GetInvoiceByID(ctx context.Context, id primitive.ObjectID) (*models.Invoice, error)
	GetInvoiceByNumber(ctx context.Context, number string) (*models.Invoice, error)
	UpdateInvoice(ctx context.Context, id primitive.ObjectID, updates map[string]interface{}) error
	ListInvoices(ctx context.Context, params *pkg.PaginationParams) ([]*models.Invoice, int64, error)
	ListInvoicesByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.Invoice, int64, error)
}

// AnalyticsRepository defines analytics repository interface
type AnalyticsRepository interface {
	Create(ctx context.Context, analytics *models.Analytics) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.Analytics, error)
	List(ctx context.Context, params *pkg.PaginationParams) ([]*models.Analytics, int64, error)
	GetByEventType(ctx context.Context, eventType models.AnalyticsEventType, start, end time.Time) ([]*models.Analytics, error)
	GetByUser(ctx context.Context, userID primitive.ObjectID, start, end time.Time) ([]*models.Analytics, error)
	CreateSummary(ctx context.Context, summary *models.AnalyticsSummary) error
	GetSummaryByDate(ctx context.Context, date time.Time) (*models.AnalyticsSummary, error)
	GetSummariesByPeriod(ctx context.Context, start, end time.Time) ([]*models.AnalyticsSummary, error)
	UpdateSummary(ctx context.Context, date time.Time, updates map[string]interface{}) error
	CreateUserAnalytics(ctx context.Context, userAnalytics *models.UserAnalytics) error
	GetUserAnalyticsByDate(ctx context.Context, userID primitive.ObjectID, date time.Time) (*models.UserAnalytics, error)
	GetUserAnalyticsByPeriod(ctx context.Context, userID primitive.ObjectID, start, end time.Time) ([]*models.UserAnalytics, error)
	UpdateUserAnalytics(ctx context.Context, userID primitive.ObjectID, date time.Time, updates map[string]interface{}) error
	GetTopUsers(ctx context.Context, metric string, limit int, start, end time.Time) ([]*models.UserAnalytics, error)
	GetEventCounts(ctx context.Context, start, end time.Time) (map[string]int64, error)
}

// AdminRepository defines admin repository interface
type AdminRepository interface {
	CreateSettings(ctx context.Context, settings *models.AdminSettings) error
	GetSettings(ctx context.Context, category models.SettingsCategory, key string) (*models.AdminSettings, error)
	GetSettingsByCategory(ctx context.Context, category models.SettingsCategory) ([]*models.AdminSettings, error)
	UpdateSettings(ctx context.Context, category models.SettingsCategory, key string, value interface{}) error
	DeleteSettings(ctx context.Context, category models.SettingsCategory, key string) error
	GetAllSettings(ctx context.Context) ([]*models.AdminSettings, error)
	GetPublicSettings(ctx context.Context) ([]*models.AdminSettings, error)
}

// AuditLogRepository defines audit log repository interface
type AuditLogRepository interface {
	Create(ctx context.Context, log *models.AuditLog) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.AuditLog, error)
	List(ctx context.Context, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error)
	GetByUser(ctx context.Context, userID primitive.ObjectID, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error)
	GetByAction(ctx context.Context, action models.AuditAction, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error)
	GetByResource(ctx context.Context, resourceType string, resourceID primitive.ObjectID) ([]*models.AuditLog, error)
	GetBySeverity(ctx context.Context, severity models.AuditSeverity, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error)
	GetByTimeRange(ctx context.Context, start, end time.Time, params *pkg.PaginationParams) ([]*models.AuditLog, int64, error)
	DeleteOldLogs(ctx context.Context, before time.Time) error
}

// Repository aggregates all repositories
type Repository struct {
	User         UserRepository
	File         FileRepository
	Folder       FolderRepository
	Share        ShareRepository
	Subscription SubscriptionRepository
	Payment      PaymentRepository
	Analytics    AnalyticsRepository
	Admin        AdminRepository
	AuditLog     AuditLogRepository
}
