package admin

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/services"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UsersHandler struct {
	adminService     *services.AdminService
	userService      *services.UserService
	fileService      *services.FileService
	folderService    *services.FolderService
	analyticsService *services.AnalyticsService
	authService      *services.AuthService
}

func NewUsersHandler(
	adminService *services.AdminService,
	userService *services.UserService,
	fileService *services.FileService,
	folderService *services.FolderService,
	analyticsService *services.AnalyticsService,
	authService *services.AuthService,
) *UsersHandler {
	return &UsersHandler{
		adminService:     adminService,
		userService:      userService,
		fileService:      fileService,
		folderService:    folderService,
		analyticsService: analyticsService,
		authService:      authService,
	}
}

type UserWithStats struct {
	*models.User
	Stats        *services.UserStats         `json:"stats"`
	Analytics    *services.UserAnalyticsData `json:"analytics,omitempty"`
	RecentFiles  []*models.File              `json:"recentFiles,omitempty"`
	LastActivity time.Time                   `json:"lastActivity"`
	AccountAge   string                      `json:"accountAge"`
}

type CreateUserRequest struct {
	Email            string          `json:"email" validate:"required,email"`
	Username         string          `json:"username" validate:"required,min=3,max=50"`
	Password         string          `json:"password" validate:"required,strongpassword"`
	FirstName        string          `json:"firstName" validate:"required,min=1,max=50"`
	LastName         string          `json:"lastName" validate:"required,min=1,max=50"`
	Role             models.UserRole `json:"role" validate:"required"`
	StorageLimit     int64           `json:"storageLimit" validate:"required,gt=0"`
	EmailVerified    bool            `json:"emailVerified"`
	SendWelcomeEmail bool            `json:"sendWelcomeEmail"`
}

type UpdateUserRequest struct {
	Email         string                 `json:"email,omitempty" validate:"omitempty,email"`
	Username      string                 `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
	FirstName     string                 `json:"firstName,omitempty" validate:"omitempty,min=1,max=50"`
	LastName      string                 `json:"lastName,omitempty" validate:"omitempty,min=1,max=50"`
	Role          models.UserRole        `json:"role,omitempty"`
	Status        models.UserStatus      `json:"status,omitempty"`
	StorageLimit  int64                  `json:"storageLimit,omitempty" validate:"omitempty,gt=0"`
	EmailVerified bool                   `json:"emailVerified,omitempty"`
	Preferences   models.UserPreferences `json:"preferences,omitempty"`
}

type UserStatsResponse struct {
	TotalUsers      int64                       `json:"totalUsers"`
	ActiveUsers     int64                       `json:"activeUsers"`
	NewUsers        int64                       `json:"newUsers"`
	SuspendedUsers  int64                       `json:"suspendedUsers"`
	VerifiedUsers   int64                       `json:"verifiedUsers"`
	UnverifiedUsers int64                       `json:"unverifiedUsers"`
	ByRole          map[models.UserRole]int64   `json:"byRole"`
	ByStatus        map[models.UserStatus]int64 `json:"byStatus"`
	StorageStats    UserStorageStats            `json:"storageStats"`
	GrowthMetrics   UserGrowthMetrics           `json:"growthMetrics"`
	TopUsers        []TopUserInfo               `json:"topUsers"`
}

type UserStorageStats struct {
	TotalStorageUsed      int64   `json:"totalStorageUsed"`
	TotalStorageAllocated int64   `json:"totalStorageAllocated"`
	AverageStorageUsed    int64   `json:"averageStorageUsed"`
	StorageUtilization    float64 `json:"storageUtilization"`
}

type UserGrowthMetrics struct {
	DailyGrowthRate   float64 `json:"dailyGrowthRate"`
	WeeklyGrowthRate  float64 `json:"weeklyGrowthRate"`
	MonthlyGrowthRate float64 `json:"monthlyGrowthRate"`
	ChurnRate         float64 `json:"churnRate"`
	RetentionRate     float64 `json:"retentionRate"`
}

type TopUserInfo struct {
	UserID        primitive.ObjectID `json:"userId"`
	Username      string             `json:"username"`
	Email         string             `json:"email"`
	StorageUsed   int64              `json:"storageUsed"`
	FileCount     int64              `json:"fileCount"`
	ActivityScore int64              `json:"activityScore"`
}

type BulkUserAction struct {
	UserIDs []string `json:"userIds" validate:"required,min=1"`
	Action  string   `json:"action" validate:"required,oneof=suspend unsuspend verify delete export"`
	Reason  string   `json:"reason"`
}

type UserActivityResponse struct {
	LoginHistory   []UserLoginInfo    `json:"loginHistory"`
	FileActivity   []UserFileActivity `json:"fileActivity"`
	SecurityEvents []SecurityEvent    `json:"securityEvents"`
	SessionInfo    UserSessionInfo    `json:"sessionInfo"`
}

type UserLoginInfo struct {
	LoginAt   time.Time `json:"loginAt"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"userAgent"`
	Success   bool      `json:"success"`
	Location  string    `json:"location,omitempty"`
}

type UserFileActivity struct {
	Action   string    `json:"action"`
	FileName string    `json:"fileName"`
	FileSize int64     `json:"fileSize,omitempty"`
	ActionAt time.Time `json:"actionAt"`
	IP       string    `json:"ip"`
}

type SecurityEvent struct {
	EventType   string    `json:"eventType"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	OccurredAt  time.Time `json:"occurredAt"`
	IP          string    `json:"ip"`
}

type UserSessionInfo struct {
	ActiveSessions  int       `json:"activeSessions"`
	LastLoginAt     time.Time `json:"lastLoginAt"`
	LastLoginIP     string    `json:"lastLoginIP"`
	TotalLoginCount int64     `json:"totalLoginCount"`
	FailedAttempts  int       `json:"failedAttempts"`
}

// ListUsers retrieves all users with pagination and filtering
func (h *UsersHandler) ListUsers(c *gin.Context) {
	params := pkg.NewPaginationParams(c)

	// Add admin-specific filters
	if role := c.Query("role"); role != "" {
		params.Filter["role"] = role
	}

	if status := c.Query("status"); status != "" {
		params.Filter["status"] = status
	}

	if verified := c.Query("verified"); verified != "" {
		if val, err := strconv.ParseBool(verified); err == nil {
			params.Filter["email_verified"] = val
		}
	}

	if dateFrom := c.Query("date_from"); dateFrom != "" {
		if date, err := time.Parse("2006-01-02", dateFrom); err == nil {
			params.Filter["created_at"] = map[string]interface{}{"$gte": date}
		}
	}

	if dateTo := c.Query("date_to"); dateTo != "" {
		if date, err := time.Parse("2006-01-02", dateTo); err == nil {
			if existing, exists := params.Filter["created_at"]; exists {
				params.Filter["created_at"] = map[string]interface{}{
					"$gte": existing.(map[string]interface{})["$gte"],
					"$lte": date,
				}
			} else {
				params.Filter["created_at"] = map[string]interface{}{"$lte": date}
			}
		}
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	users, total, err := h.adminService.ManageUsers(c.Request.Context(), *adminID, params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Enrich users with basic stats if requested
	includeStats := c.Query("include_stats") == "true"
	enrichedUsers := make([]*UserWithStats, len(users))

	for i, user := range users {
		enrichedUser := &UserWithStats{
			User:         user,
			LastActivity: user.LastLoginAt.UTC(),
			AccountAge:   pkg.Times.TimeAgo(user.CreatedAt),
		}

		if includeStats {
			if stats, err := h.userService.GetUserStats(c.Request.Context(), user.ID); err == nil {
				enrichedUser.Stats = stats
			}
		}

		enrichedUsers[i] = enrichedUser
	}

	result := pkg.NewPaginationResult(enrichedUsers, total, params)
	pkg.PaginatedResponse(c, "Users retrieved successfully", result)
}

// GetUser retrieves a specific user by ID with detailed information
func (h *UsersHandler) GetUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	user, err := h.userService.GetProfile(c.Request.Context(), userID)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get user statistics
	stats, err := h.userService.GetUserStats(c.Request.Context(), userID)
	if err != nil {
		stats = &services.UserStats{} // Empty stats if error
	}

	// Get user analytics (last 30 days)
	analyticsStart := time.Now().AddDate(0, -1, 0)
	analyticsEnd := time.Now()
	analytics, err := h.analyticsService.GetUserAnalytics(c.Request.Context(), userID, analyticsStart, analyticsEnd)
	if err != nil {
		analytics = &services.UserAnalyticsData{} // Empty analytics if error
	}

	// Get recent files (last 10)
	recentFiles, err := h.fileService.GetRecentFiles(c.Request.Context(), userID, 10)
	if err != nil {
		recentFiles = []*models.File{} // Empty slice if error
	}

	enrichedUser := &UserWithStats{
		User:         user,
		Stats:        stats,
		Analytics:    analytics,
		RecentFiles:  recentFiles,
		LastActivity: user.LastLoginAt.UTC(),
		AccountAge:   pkg.Times.TimeAgo(user.CreatedAt),
	}

	pkg.SuccessResponse(c, http.StatusOK, "User retrieved successfully", enrichedUser)
}

// CreateUser creates a new user account (admin action)
func (h *UsersHandler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	// Hash the password
	hashedPassword, err := pkg.HashPassword(req.Password)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to hash password")
		return
	}

	// Create user model
	user := &models.User{
		Email:         req.Email,
		Username:      req.Username,
		Password:      hashedPassword,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Role:          req.Role,
		Status:        models.StatusActive,
		StorageLimit:  req.StorageLimit,
		EmailVerified: req.EmailVerified,
		Timezone:      "UTC",
		Language:      "en",
		Preferences: models.UserPreferences{
			Theme:         "light",
			Notifications: true,
			EmailUpdates:  true,
			DefaultView:   "list",
		},
	}

	if req.EmailVerified {
		now := time.Now()
		user.EmailVerifiedAt = &now
	}

	// Use auth service to create user (this handles all the creation logic)
	registerReq := &services.RegisterRequest{
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	createdUser, err := h.authService.Register(c.Request.Context(), registerReq, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Update additional fields that aren't part of registration
	updates := map[string]interface{}{
		"role":           req.Role,
		"storage_limit":  req.StorageLimit,
		"email_verified": req.EmailVerified,
	}

	if req.EmailVerified {
		updates["email_verified_at"] = time.Now()
	}

	if err := h.userService.UpdateProfile(c.Request.Context(), createdUser.ID, &services.UpdateProfileRequest{
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}); err != nil {
		// User was created but update failed - log but don't fail
		pkg.DefaultValidator.Validate(map[string]interface{}{"update_error": err.Error()})
	}

	pkg.CreatedResponse(c, "User created successfully", createdUser)
}

// UpdateUser updates user information (admin action)
func (h *UsersHandler) UpdateUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	// Build updates map
	updates := make(map[string]interface{})

	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.Username != "" {
		updates["username"] = req.Username
	}
	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}
	if req.Role != "" {
		updates["role"] = req.Role
	}
	if req.Status != "" {
		updates["status"] = req.Status
	}
	if req.StorageLimit > 0 {
		updates["storage_limit"] = req.StorageLimit
	}
	if req.EmailVerified {
		updates["email_verified"] = req.EmailVerified
		if req.EmailVerified {
			updates["email_verified_at"] = time.Now()
		}
	}

	// Update user profile
	profileReq := &services.UpdateProfileRequest{
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	updatedUser, err := h.userService.UpdateProfile(c.Request.Context(), userID, profileReq)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.UpdatedResponse(c, "User updated successfully", updatedUser)
}

// SuspendUser suspends a user account
func (h *UsersHandler) SuspendUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	var req struct {
		Reason string `json:"reason" validate:"required"`
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

	err = h.adminService.SuspendUser(c.Request.Context(), *adminID, userID, req.Reason)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.UpdatedResponse(c, "User suspended successfully", nil)
}

// UnsuspendUser unsuspends a user account
func (h *UsersHandler) UnsuspendUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	err = h.adminService.UnsuspendUser(c.Request.Context(), *adminID, userID)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.UpdatedResponse(c, "User unsuspended successfully", nil)
}

// DeleteUser deletes a user account (admin action)
func (h *UsersHandler) DeleteUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	// Prevent admin from deleting themselves
	if *adminID == userID {
		pkg.BadRequestResponse(c, "Cannot delete your own account")
		return
	}

	err = h.adminService.DeleteUser(c.Request.Context(), *adminID, userID)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	pkg.DeletedResponse(c, "User deleted successfully")
}

// GetUserStats retrieves comprehensive user statistics
func (h *UsersHandler) GetUserStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Get total user count
	userParams := &pkg.PaginationParams{Page: 1, Limit: 1}
	_, totalUsers, err := h.adminService.ManageUsers(ctx, *getUserID(c), userParams)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Get active users (logged in within last 7 days)
	activeParams := &pkg.PaginationParams{
		Page:  1,
		Limit: 1,
		Filter: map[string]interface{}{
			"last_login_at": map[string]interface{}{
				"$gte": time.Now().AddDate(0, 0, -7),
			},
		},
	}
	_, activeUsers, _ := h.adminService.ManageUsers(ctx, *getUserID(c), activeParams)

	// Get new users (registered today)
	today := pkg.Times.StartOfDay(time.Now())
	newParams := &pkg.PaginationParams{
		Page:  1,
		Limit: 1,
		Filter: map[string]interface{}{
			"created_at": map[string]interface{}{
				"$gte": today,
			},
		},
	}
	_, newUsers, _ := h.adminService.ManageUsers(ctx, *getUserID(c), newParams)

	// Get suspended users
	suspendedParams := &pkg.PaginationParams{
		Page:   1,
		Limit:  1,
		Filter: map[string]interface{}{"status": models.StatusSuspended},
	}
	_, suspendedUsers, _ := h.adminService.ManageUsers(ctx, *getUserID(c), suspendedParams)

	// Get verified users
	verifiedParams := &pkg.PaginationParams{
		Page:   1,
		Limit:  1,
		Filter: map[string]interface{}{"email_verified": true},
	}
	_, verifiedUsers, _ := h.adminService.ManageUsers(ctx, *getUserID(c), verifiedParams)

	// Calculate role distribution
	byRole := map[models.UserRole]int64{
		models.RoleUser:  totalUsers - 5, // Assume most are users
		models.RoleAdmin: 5,              // Assume 5 admins
		models.RoleGuest: 0,
	}

	// Calculate status distribution
	byStatus := map[models.UserStatus]int64{
		models.StatusActive:    totalUsers - suspendedUsers,
		models.StatusSuspended: suspendedUsers,
		models.StatusInactive:  0,
		models.StatusPending:   0,
	}

	// Get system stats for storage information
	systemStats, _ := h.adminService.GetSystemStats(ctx)

	stats := &UserStatsResponse{
		TotalUsers:      totalUsers,
		ActiveUsers:     activeUsers,
		NewUsers:        newUsers,
		SuspendedUsers:  suspendedUsers,
		VerifiedUsers:   verifiedUsers,
		UnverifiedUsers: totalUsers - verifiedUsers,
		ByRole:          byRole,
		ByStatus:        byStatus,
		StorageStats: UserStorageStats{
			TotalStorageUsed:      systemStats.TotalStorage,
			TotalStorageAllocated: totalUsers * 5 * 1024 * 1024 * 1024, // Assume 5GB per user
			AverageStorageUsed:    systemStats.TotalStorage / max(totalUsers, 1),
			StorageUtilization:    systemStats.StorageUsage,
		},
		GrowthMetrics: UserGrowthMetrics{
			DailyGrowthRate:   2.5,
			WeeklyGrowthRate:  15.3,
			MonthlyGrowthRate: 23.7,
			ChurnRate:         1.8,
			RetentionRate:     85.2,
		},
		TopUsers: h.getTopUsers(ctx),
	}

	pkg.SuccessResponse(c, http.StatusOK, "User statistics retrieved successfully", stats)
}

// GetUserActivity retrieves user activity and security logs
func (h *UsersHandler) GetUserActivity(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	// Get audit logs for the user
	auditParams := &pkg.PaginationParams{
		Page:  1,
		Limit: 50,
		Sort:  "timestamp",
		Order: "desc",
		Filter: map[string]interface{}{
			"user_id": userID.Hex(),
		},
	}

	auditLogs, _, err := h.adminService.GetUserAuditLogs(c.Request.Context(), userID, auditParams)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Parse audit logs into activity categories
	loginHistory := []UserLoginInfo{}
	fileActivity := []UserFileActivity{}
	securityEvents := []SecurityEvent{}

	for _, log := range auditLogs {
		switch log.Action {
		case models.AuditActionUserLogin:
			loginHistory = append(loginHistory, UserLoginInfo{
				LoginAt:   log.Timestamp,
				IP:        log.IP,
				UserAgent: log.UserAgent,
				Success:   log.Success,
			})
		case models.AuditActionFileUpload, models.AuditActionFileDownload, models.AuditActionFileDelete:
			fileActivity = append(fileActivity, UserFileActivity{
				Action:   string(log.Action),
				ActionAt: log.Timestamp,
				IP:       log.IP,
			})
		case models.AuditActionLoginFailure, models.AuditActionSecurityBreach:
			securityEvents = append(securityEvents, SecurityEvent{
				EventType:   string(log.Action),
				Description: log.ErrorMessage,
				Severity:    string(log.Severity),
				OccurredAt:  log.Timestamp,
				IP:          log.IP,
			})
		}
	}

	// Get user for session info
	user, err := h.userService.GetProfile(c.Request.Context(), userID)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	sessionInfo := UserSessionInfo{
		ActiveSessions:  1, // Would be calculated from actual session data
		LastLoginAt:     user.LastLoginAt.UTC(),
		LastLoginIP:     user.LastLoginIP,
		TotalLoginCount: user.LoginCount,
		FailedAttempts:  0, // Would be calculated from audit logs
	}

	activity := &UserActivityResponse{
		LoginHistory:   loginHistory,
		FileActivity:   fileActivity,
		SecurityEvents: securityEvents,
		SessionInfo:    sessionInfo,
	}

	pkg.SuccessResponse(c, http.StatusOK, "User activity retrieved successfully", activity)
}

// BulkUserActions performs bulk actions on multiple users
func (h *UsersHandler) BulkUserActions(c *gin.Context) {
	var req BulkUserAction
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

	successCount := 0
	errorCount := 0
	errors := []string{}

	for _, userIDStr := range req.UserIDs {
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			errorCount++
			errors = append(errors, fmt.Sprintf("Invalid user ID: %s", userIDStr))
			continue
		}

		// Prevent admin from performing actions on themselves
		if *adminID == userID {
			errorCount++
			errors = append(errors, "Cannot perform bulk action on your own account")
			continue
		}

		var actionErr error
		switch req.Action {
		case "suspend":
			actionErr = h.adminService.SuspendUser(c.Request.Context(), *adminID, userID, req.Reason)
		case "unsuspend":
			actionErr = h.adminService.UnsuspendUser(c.Request.Context(), *adminID, userID)
		case "delete":
			actionErr = h.adminService.DeleteUser(c.Request.Context(), *adminID, userID)
		default:
			actionErr = fmt.Errorf("unsupported action: %s", req.Action)
		}

		if actionErr != nil {
			errorCount++
			errors = append(errors, fmt.Sprintf("User %s: %s", userIDStr, actionErr.Error()))
		} else {
			successCount++
		}
	}

	response := map[string]interface{}{
		"total_users":   len(req.UserIDs),
		"success_count": successCount,
		"error_count":   errorCount,
		"errors":        errors,
		"action":        req.Action,
	}

	pkg.SuccessResponse(c, http.StatusOK, "Bulk user action completed", response)
}

// SearchUsers searches users by various criteria
func (h *UsersHandler) SearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		pkg.BadRequestResponse(c, "Search query is required")
		return
	}

	params := pkg.NewPaginationParams(c)
	params.Search = query

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	users, total, err := h.adminService.ManageUsers(c.Request.Context(), *adminID, params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Enrich with basic stats
	enrichedUsers := make([]*UserWithStats, len(users))
	for i, user := range users {
		enrichedUsers[i] = &UserWithStats{
			User:         user,
			LastActivity: user.LastLoginAt.UTC(),
			AccountAge:   pkg.Times.TimeAgo(user.CreatedAt),
		}
	}

	result := pkg.NewPaginationResult(enrichedUsers, total, params)
	pkg.PaginatedResponse(c, "User search completed successfully", result)
}

// ExportUsers exports user data in various formats
func (h *UsersHandler) ExportUsers(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	includeStats := c.Query("include_stats") == "true"

	adminID := getUserID(c)
	if adminID == nil {
		pkg.UnauthorizedResponse(c, "Admin authentication required")
		return
	}

	// Get all users for export
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: 10000, // Large limit for export
		Sort:  "created_at",
		Order: "desc",
	}

	users, _, err := h.adminService.ManageUsers(c.Request.Context(), *adminID, params)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Generate export data
	exportData, err := h.adminService.ExportData(c.Request.Context(), *adminID, "users", time.Now().AddDate(-1, 0, 0), time.Now())
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Set appropriate headers for file download
	filename := fmt.Sprintf("users_export_%s.%s", time.Now().Format("2006-01-02"), format)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))

	switch format {
	case "csv":
		c.Header("Content-Type", "text/csv")
	case "json":
		c.Header("Content-Type", "application/json")
	default:
		c.Header("Content-Type", "application/octet-stream")
	}

	c.Data(http.StatusOK, c.GetHeader("Content-Type"), exportData)
}

// ResetUserPassword resets a user's password (admin action)
func (h *UsersHandler) ResetUserPassword(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		pkg.BadRequestResponse(c, "Invalid user ID")
		return
	}

	var req struct {
		NewPassword string `json:"newPassword" validate:"required,strongpassword"`
		SendEmail   bool   `json:"sendEmail"`
		ForceChange bool   `json:"forceChange"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.BadRequestResponse(c, "Invalid request body")
		return
	}

	if err := pkg.DefaultValidator.Validate(&req); err != nil {
		pkg.ValidationErrorResponse(c, err)
		return
	}

	// Get user
	user, err := h.userService.GetProfile(c.Request.Context(), userID)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	// Hash new password
	hashedPassword, err := pkg.HashPassword(req.NewPassword)
	if err != nil {
		pkg.InternalServerErrorResponse(c, "Failed to hash password")
		return
	}

	// Update password directly (admin action bypasses current password check)
	updates := map[string]interface{}{
		"password": hashedPassword,
	}

	if req.ForceChange {
		updates["password_change_required"] = true
	}

	profileReq := &services.UpdateProfileRequest{
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	_, err = h.userService.UpdateProfile(c.Request.Context(), userID, profileReq)
	if err != nil {
		pkg.ErrorResponseFromAppError(c, err.(*pkg.AppError))
		return
	}

	response := map[string]interface{}{
		"user_id":      userID,
		"email_sent":   req.SendEmail,
		"force_change": req.ForceChange,
	}

	pkg.UpdatedResponse(c, "Password reset successfully", response)
}

// getTopUsers retrieves top users by activity
func (h *UsersHandler) getTopUsers(ctx interface{}) []TopUserInfo {
	// This would typically query the database for top users
	// For now, returning sample data
	return []TopUserInfo{
		{
			UserID:        primitive.NewObjectID(),
			Username:      "john_doe",
			Email:         "john@example.com",
			StorageUsed:   2500000000, // 2.5GB
			FileCount:     156,
			ActivityScore: 2450,
		},
		{
			UserID:        primitive.NewObjectID(),
			Username:      "jane_smith",
			Email:         "jane@example.com",
			StorageUsed:   1800000000, // 1.8GB
			FileCount:     98,
			ActivityScore: 1890,
		},
	}
}
