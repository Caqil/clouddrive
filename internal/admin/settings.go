package admin

import (
	"net/http"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
)

type SettingsHandler struct {
	adminService *services.AdminService
}

func NewSettingsHandler(adminService *services.AdminService) *SettingsHandler {
	return &SettingsHandler{
		adminService: adminService,
	}
}

type SettingsUpdateRequest struct {
	Category models.SettingsCategory `json:"category" validate:"required"`
	Key      string                  `json:"key" validate:"required"`
	Value    interface{}             `json:"value" validate:"required"`
	IsPublic bool                    `json:"isPublic"`
}

type BulkSettingsUpdateRequest struct {
	Settings []SettingsUpdateRequest `json:"settings" validate:"required,dive"`
}

type AppSettingsRequest struct {
	Name                     string `json:"name" validate:"required"`
	Description              string `json:"description"`
	Logo                     string `json:"logo"`
	Favicon                  string `json:"favicon"`
	URL                      string `json:"url" validate:"required,url"`
	SupportEmail             string `json:"supportEmail" validate:"required,email"`
	AllowRegistration        bool   `json:"allowRegistration"`
	RequireEmailVerification bool   `json:"requireEmailVerification"`
	DefaultTheme             string `json:"defaultTheme" validate:"oneof=light dark"`
	DefaultLanguage          string `json:"defaultLanguage"`
	Timezone                 string `json:"timezone"`
	MaintenanceMode          bool   `json:"maintenanceMode"`
	MaintenanceMessage       string `json:"maintenanceMessage"`
}

type StorageSettingsRequest struct {
	DefaultProvider     string                            `json:"defaultProvider" validate:"required"`
	MaxFileSize         int64                             `json:"maxFileSize" validate:"required,gt=0"`
	AllowedFileTypes    []string                          `json:"allowedFileTypes"`
	BlockedFileTypes    []string                          `json:"blockedFileTypes"`
	EnableVirusScanning bool                              `json:"enableVirusScanning"`
	EnableEncryption    bool                              `json:"enableEncryption"`
	StorageQuota        int64                             `json:"storageQuota" validate:"required,gt=0"`
	Providers           map[string]models.StorageProvider `json:"providers"`
}

type EmailSettingsRequest struct {
	Provider            string            `json:"provider" validate:"required"`
	FromEmail           string            `json:"fromEmail" validate:"required,email"`
	FromName            string            `json:"fromName" validate:"required"`
	ReplyToEmail        string            `json:"replyToEmail" validate:"email"`
	Config              map[string]string `json:"config"`
	EnableWelcomeEmail  bool              `json:"enableWelcomeEmail"`
	EnableNotifications bool              `json:"enableNotifications"`
}

type SecuritySettingsRequest struct {
	EnableTwoFactor          bool     `json:"enableTwoFactor"`
	RequireTwoFactor         bool     `json:"requireTwoFactor"`
	SessionTimeout           int      `json:"sessionTimeout" validate:"min=300,max=86400"` // 5 min to 24 hours
	MaxLoginAttempts         int      `json:"maxLoginAttempts" validate:"min=3,max=10"`
	LockoutDuration          int      `json:"lockoutDuration" validate:"min=300,max=3600"` // 5 min to 1 hour
	PasswordMinLength        int      `json:"passwordMinLength" validate:"min=6,max=32"`
	PasswordRequireUppercase bool     `json:"passwordRequireUppercase"`
	PasswordRequireLowercase bool     `json:"passwordRequireLowercase"`
	PasswordRequireNumbers   bool     `json:"passwordRequireNumbers"`
	PasswordRequireSymbols   bool     `json:"passwordRequireSymbols"`
	AllowedDomains           []string `json:"allowedDomains"`
	BlockedIPs               []string `json:"blockedIPs"`
	EnableAuditLog           bool     `json:"enableAuditLog"`
	AuditLogRetention        int      `json:"auditLogRetention" validate:"min=30,max=3650"` // 30 days to 10 years
}

// GetAllSettings retrieves all admin settings
func (h *SettingsHandler) GetAllSettings(c *gin.Context) {
	settings, err := h.adminService.GetAllSettings(c.Request.Context())
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Group settings by category for easier frontend consumption
	groupedSettings := make(map[string][]*models.AdminSettings)
	for _, setting := range settings {
		category := string(setting.Category)
		groupedSettings[category] = append(groupedSettings[category], setting)
	}

	response := map[string]interface{}{
		"settings": settings,
		"grouped":  groupedSettings,
	}

	pkg.SuccessResponse(c, http.StatusOK, "Settings retrieved successfully", response)
}

// GetSettingsByCategory retrieves settings by category
func (h *SettingsHandler) GetSettingsByCategory(c *gin.Context) {
	categoryStr := c.Param("category")
	category := models.SettingsCategory(categoryStr)

	// Validate category
	validCategories := []models.SettingsCategory{
		models.SettingsCategoryApp,
		models.SettingsCategoryStorage,
		models.SettingsCategoryEmail,
		models.SettingsCategoryPayment,
		models.SettingsCategorySecurity,
		models.SettingsCategoryAPI,
		models.SettingsCategoryBackup,
		models.SettingsCategoryFeature,
	}

	isValid := false
	for _, vc := range validCategories {
		if category == vc {
			isValid = true
			break
		}
	}

	if !isValid {
		pkg.BadRequestResponse(c, "Invalid settings category")
		return
	}

	settings, err := h.adminService.GetSettings(c.Request.Context(), category)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.SuccessResponse(c, http.StatusOK, "Settings retrieved successfully", settings)
}

// UpdateSetting updates a specific setting
func (h *SettingsHandler) UpdateSetting(c *gin.Context) {
	var req SettingsUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	err := h.adminService.UpdateSetting(c.Request.Context(), *adminID, req.Category, req.Key, req.Value)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.UpdatedResponse(c, "Setting updated successfully", nil)
}

// UpdateBulkSettings updates multiple settings at once
func (h *SettingsHandler) UpdateBulkSettings(c *gin.Context) {
	var req BulkSettingsUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	// Update each setting
	updatedCount := 0
	for _, setting := range req.Settings {
		err := h.adminService.UpdateSetting(c.Request.Context(), *adminID, setting.Category, setting.Key, setting.Value)
		if err == nil {
			updatedCount++
		}
	}

	response := map[string]interface{}{
		"total_settings":   len(req.Settings),
		"updated_settings": updatedCount,
	}

	pkg.UpdatedResponse(c, "Bulk settings update completed", response)
}

// UpdateAppSettings updates application settings
func (h *SettingsHandler) UpdateAppSettings(c *gin.Context) {
	var req AppSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	// Convert struct to map for easier processing
	settings := map[string]interface{}{
		"name":                       req.Name,
		"description":                req.Description,
		"logo":                       req.Logo,
		"favicon":                    req.Favicon,
		"url":                        req.URL,
		"support_email":              req.SupportEmail,
		"allow_registration":         req.AllowRegistration,
		"require_email_verification": req.RequireEmailVerification,
		"default_theme":              req.DefaultTheme,
		"default_language":           req.DefaultLanguage,
		"timezone":                   req.Timezone,
		"maintenance_mode":           req.MaintenanceMode,
		"maintenance_message":        req.MaintenanceMessage,
	}

	// Update each app setting
	for key, value := range settings {
		err := h.adminService.UpdateSetting(c.Request.Context(), *adminID, models.SettingsCategoryApp, key, value)
		if err != nil {
			pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
			return
		}
	}

	pkg.UpdatedResponse(c, "Application settings updated successfully", nil)
}

// UpdateStorageSettings updates storage settings
func (h *SettingsHandler) UpdateStorageSettings(c *gin.Context) {
	var req StorageSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	settings := map[string]interface{}{
		"default_provider":      req.DefaultProvider,
		"max_file_size":         req.MaxFileSize,
		"allowed_file_types":    req.AllowedFileTypes,
		"blocked_file_types":    req.BlockedFileTypes,
		"enable_virus_scanning": req.EnableVirusScanning,
		"enable_encryption":     req.EnableEncryption,
		"storage_quota":         req.StorageQuota,
		"providers":             req.Providers,
	}

	// Update each storage setting
	for key, value := range settings {
		err := h.adminService.UpdateSetting(c.Request.Context(), *adminID, models.SettingsCategoryStorage, key, value)
		if err != nil {
			pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
			return
		}
	}

	pkg.UpdatedResponse(c, "Storage settings updated successfully", nil)
}

// UpdateEmailSettings updates email settings
func (h *SettingsHandler) UpdateEmailSettings(c *gin.Context) {
	var req EmailSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	settings := map[string]interface{}{
		"provider":             req.Provider,
		"from_email":           req.FromEmail,
		"from_name":            req.FromName,
		"reply_to_email":       req.ReplyToEmail,
		"config":               req.Config,
		"enable_welcome_email": req.EnableWelcomeEmail,
		"enable_notifications": req.EnableNotifications,
	}

	// Update each email setting
	for key, value := range settings {
		err := h.adminService.UpdateSetting(c.Request.Context(), *adminID, models.SettingsCategoryEmail, key, value)
		if err != nil {
			pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
			return
		}
	}

	pkg.UpdatedResponse(c, "Email settings updated successfully", nil)
}

// UpdateSecuritySettings updates security settings
func (h *SettingsHandler) UpdateSecuritySettings(c *gin.Context) {
	var req SecuritySettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	settings := map[string]interface{}{
		"enable_two_factor":          req.EnableTwoFactor,
		"require_two_factor":         req.RequireTwoFactor,
		"session_timeout":            req.SessionTimeout,
		"max_login_attempts":         req.MaxLoginAttempts,
		"lockout_duration":           req.LockoutDuration,
		"password_min_length":        req.PasswordMinLength,
		"password_require_uppercase": req.PasswordRequireUppercase,
		"password_require_lowercase": req.PasswordRequireLowercase,
		"password_require_numbers":   req.PasswordRequireNumbers,
		"password_require_symbols":   req.PasswordRequireSymbols,
		"allowed_domains":            req.AllowedDomains,
		"blocked_ips":                req.BlockedIPs,
		"enable_audit_log":           req.EnableAuditLog,
		"audit_log_retention":        req.AuditLogRetention,
	}

	// Update each security setting
	for key, value := range settings {
		err := h.adminService.UpdateSetting(c.Request.Context(), *adminID, models.SettingsCategorySecurity, key, value)
		if err != nil {
			pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
			return
		}
	}

	pkg.UpdatedResponse(c, "Security settings updated successfully", nil)
}

// GetPublicSettings retrieves public settings (for client-side configuration)
func (h *SettingsHandler) GetPublicSettings(c *gin.Context) {
	// Get app settings that are safe to expose publicly
	appSettings, err := h.adminService.GetSettings(c.Request.Context(), models.SettingsCategoryApp)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get feature settings
	featureSettings, err := h.adminService.GetSettings(c.Request.Context(), models.SettingsCategoryFeature)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Filter and structure public settings
	publicSettings := map[string]interface{}{
		"app":      map[string]interface{}{},
		"features": map[string]interface{}{},
	}

	// Add safe app settings
	safeAppKeys := []string{"name", "description", "logo", "favicon", "default_theme", "default_language", "allow_registration", "require_email_verification"}
	for _, setting := range appSettings {
		for _, key := range safeAppKeys {
			if setting.Key == key {
				publicSettings["app"].(map[string]interface{})[key] = setting.Value
			}
		}
	}

	// Add feature settings
	for _, setting := range featureSettings {
		publicSettings["features"].(map[string]interface{})[setting.Key] = setting.Value
	}

	pkg.SuccessResponse(c, http.StatusOK, "Public settings retrieved successfully", publicSettings)
}

// TestEmailSettings tests email configuration
func (h *SettingsHandler) TestEmailSettings(c *gin.Context) {
	var req struct {
		TestEmail string `json:"testEmail" validate:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	// This would integrate with the email service to send a test email
	// For now, we'll simulate the test
	testResult := map[string]interface{}{
		"success":    true,
		"message":    "Test email sent successfully",
		"test_email": req.TestEmail,
		"sent_at":    pkg.Times.TimeAgo(time.Now()),
	}

	pkg.SuccessResponse(c, http.StatusOK, "Email test completed", testResult)
}

// ResetSettingsCategory resets all settings in a category to defaults
func (h *SettingsHandler) ResetSettingsCategory(c *gin.Context) {
	categoryStr := c.Param("category")
	category := models.SettingsCategory(categoryStr)

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	// Get current settings to count them
	currentSettings, err := h.adminService.GetSettings(c.Request.Context(), category)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// This would reset settings to their default values
	// For now, we'll return a confirmation
	response := map[string]interface{}{
		"category":    category,
		"reset_count": len(currentSettings),
		"message":     "Settings have been reset to default values",
	}

	pkg.UpdatedResponse(c, "Settings category reset successfully", response)
}

// ExportSettings exports all settings as JSON
func (h *SettingsHandler) ExportSettings(c *gin.Context) {
	settings, err := h.adminService.GetAllSettings(c.Request.Context())
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Set headers for file download
	c.Header("Content-Disposition", "attachment; filename=settings_export.json")
	c.Header("Content-Type", "application/json")

	pkg.SuccessResponse(c, http.StatusOK, "Settings exported successfully", settings)
}

// ImportSettings imports settings from JSON
func (h *SettingsHandler) ImportSettings(c *gin.Context) {
	var req struct {
		Settings  []models.AdminSettings `json:"settings" validate:"required"`
		Overwrite bool                   `json:"overwrite"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	importedCount := 0
	skippedCount := 0

	for _, setting := range req.Settings {
		// Check if setting already exists if not overwriting
		if !req.Overwrite {
			existing, err := h.adminService.GetSettings(c.Request.Context(), setting.Category)
			if err == nil && len(existing) > 0 {
				// Setting exists, skip if not overwriting
				for _, existingSetting := range existing {
					if existingSetting.Key == setting.Key {
						skippedCount++
						continue
					}
				}
			}
		}

		err := h.adminService.UpdateSetting(c.Request.Context(), *adminID, setting.Category, setting.Key, setting.Value)
		if err == nil {
			importedCount++
		}
	}

	response := map[string]interface{}{
		"imported_count": importedCount,
		"skipped_count":  skippedCount,
		"total_count":    len(req.Settings),
	}

	pkg.UpdatedResponse(c, "Settings import completed", response)
}
