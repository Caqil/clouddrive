package middleware

import (
	"strings"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AdminMiddleware ensures only admin users can access protected routes
type AdminMiddleware struct {
	userRepo repository.UserRepository
	logger   *pkg.Logger
}

// NewAdminMiddleware creates a new admin middleware
func NewAdminMiddleware(userRepo repository.UserRepository, logger *pkg.Logger) *AdminMiddleware {
	return &AdminMiddleware{
		userRepo: userRepo,
		logger:   logger,
	}
}

// RequireAdmin middleware that checks if user has admin role
func (m *AdminMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user from context (set by auth middleware)
		userID, exists := c.Get("user_id")
		if !exists {
			m.logger.Warn("Admin middleware: No user ID in context")
			pkg.UnauthorizedResponse(c, "Authentication required")
			c.Abort()
			return
		}

		// Convert to ObjectID
		userObjectID, ok := userID.(primitive.ObjectID)
		if !ok {
			m.logger.Error("Admin middleware: Invalid user ID type in context")
			pkg.InternalServerErrorResponse(c, "Invalid user context")
			c.Abort()
			return
		}

		// Get user from database
		user, err := m.userRepo.GetByID(c.Request.Context(), userObjectID)
		if err != nil {
			m.logger.Error("Admin middleware: Failed to get user", map[string]interface{}{
				"user_id": userObjectID.Hex(),
				"error":   err.Error(),
			})
			pkg.UnauthorizedResponse(c, "User not found")
			c.Abort()
			return
		}

		// Check if user has admin role
		if user.Role != models.RoleAdmin {
			m.logger.Warn("Admin middleware: Non-admin user attempted to access admin route", map[string]interface{}{
				"user_id": userObjectID.Hex(),
				"role":    string(user.Role),
				"path":    c.Request.URL.Path,
				"method":  c.Request.Method,
			})
			pkg.ForbiddenResponse(c, "Admin privileges required")
			c.Abort()
			return
		}

		// Check if user account is active
		if user.Status != models.StatusActive {
			m.logger.Warn("Admin middleware: Inactive admin user attempted access", map[string]interface{}{
				"user_id": userObjectID.Hex(),
				"status":  string(user.Status),
			})
			pkg.ForbiddenResponse(c, "Account is not active")
			c.Abort()
			return
		}

		// Store admin user in context
		c.Set("admin_user", user)

		m.logger.Info("Admin middleware: Admin access granted", map[string]interface{}{
			"user_id": userObjectID.Hex(),
			"email":   user.Email,
			"path":    c.Request.URL.Path,
			"method":  c.Request.Method,
		})

		c.Next()
	}
}

// RequireSuperAdmin middleware for super admin only operations
func (m *AdminMiddleware) RequireSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check if user is admin
		m.RequireAdmin()(c)
		if c.IsAborted() {
			return
		}

		// Get admin user from context
		adminUser, exists := c.Get("admin_user")
		if !exists {
			pkg.InternalServerErrorResponse(c, "Admin user not found in context")
			c.Abort()
			return
		}

		user := adminUser.(*models.User)

		// Check if user email is in super admin list (you can configure this)
		superAdmins := []string{
			"admin@clouddrive.com",
			"superadmin@clouddrive.com",
		}

		isSuperAdmin := false
		for _, email := range superAdmins {
			if user.Email == email {
				isSuperAdmin = true
				break
			}
		}

		if !isSuperAdmin {
			m.logger.Warn("Super admin middleware: Regular admin attempted super admin action", map[string]interface{}{
				"user_id": user.ID.Hex(),
				"email":   user.Email,
				"path":    c.Request.URL.Path,
			})
			pkg.ForbiddenResponse(c, "Super admin privileges required")
			c.Abort()
			return
		}

		c.Set("super_admin", true)
		c.Next()
	}
}

// RestrictToAdminIPs middleware that restricts access to specific IP addresses
func (m *AdminMiddleware) RestrictToAdminIPs(allowedIPs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(allowedIPs) == 0 {
			// No IP restrictions configured
			c.Next()
			return
		}

		clientIP := c.ClientIP()

		// Check if client IP is in allowed list
		allowed := false
		for _, ip := range allowedIPs {
			if clientIP == ip || ip == "*" {
				allowed = true
				break
			}
		}

		if !allowed {
			m.logger.Warn("Admin IP restriction: Access denied", map[string]interface{}{
				"client_ip":   clientIP,
				"allowed_ips": allowedIPs,
				"path":        c.Request.URL.Path,
				"user_agent":  c.GetHeader("User-Agent"),
			})
			pkg.ForbiddenResponse(c, "Access denied from this IP address")
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireMaintenanceMode middleware for maintenance operations
func (m *AdminMiddleware) RequireMaintenanceMode() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if system is in maintenance mode
		// This could be checked from database or environment variable
		maintenanceMode := false // Get from settings

		if !maintenanceMode {
			pkg.BadRequestResponse(c, "System must be in maintenance mode for this operation")
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdminAuditLog middleware that logs all admin actions
func (m *AdminMiddleware) AdminAuditLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log the admin action before processing
		adminUser, exists := c.Get("admin_user")
		if exists {
			user := adminUser.(*models.User)
			m.logger.Info("Admin action started", map[string]interface{}{
				"admin_id":   user.ID.Hex(),
				"email":      user.Email,
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
				"query":      c.Request.URL.RawQuery,
				"user_agent": c.GetHeader("User-Agent"),
				"ip":         c.ClientIP(),
			})
		}

		// Process request
		c.Next()

		// Log the result
		if exists {
			user := adminUser.(*models.User)
			status := c.Writer.Status()
			m.logger.Info("Admin action completed", map[string]interface{}{
				"admin_id":    user.ID.Hex(),
				"email":       user.Email,
				"method":      c.Request.Method,
				"path":        c.Request.URL.Path,
				"status_code": status,
				"success":     status < 400,
			})
		}
	}
}

// ValidateAdminPermissions middleware for specific admin permissions
func (m *AdminMiddleware) ValidateAdminPermissions(requiredPermissions []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		adminUser, exists := c.Get("admin_user")
		if !exists {
			pkg.UnauthorizedResponse(c, "Admin authentication required")
			c.Abort()
			return
		}

		user := adminUser.(*models.User)

		// Check if user has required permissions
		// This could be enhanced with a proper permission system
		userPermissions := m.getUserPermissions(user)

		for _, required := range requiredPermissions {
			if !m.hasPermission(userPermissions, required) {
				m.logger.Warn("Admin permission denied", map[string]interface{}{
					"admin_id":            user.ID.Hex(),
					"required_permission": required,
					"user_permissions":    userPermissions,
				})
				pkg.ForbiddenResponse(c, "Insufficient permissions")
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// getUserPermissions returns permissions for a user based on role
func (m *AdminMiddleware) getUserPermissions(user *models.User) []string {
	switch user.Role {
	case models.RoleAdmin:
		return []string{
			"users.read", "users.write", "users.delete",
			"files.read", "files.write", "files.delete",
			"settings.read", "settings.write",
			"analytics.read",
			"subscriptions.read", "subscriptions.write",
		}
	default:
		return []string{}
	}
}

// hasPermission checks if user has a specific permission
func (m *AdminMiddleware) hasPermission(userPermissions []string, required string) bool {
	for _, perm := range userPermissions {
		if perm == required || perm == "*" {
			return true
		}
		// Check wildcard permissions (e.g., "users.*" includes "users.read")
		if strings.HasSuffix(perm, ".*") {
			prefix := strings.TrimSuffix(perm, ".*")
			if strings.HasPrefix(required, prefix+".") {
				return true
			}
		}
	}
	return false
}

// CheckMaintenanceMode middleware that checks if system is in maintenance
func (m *AdminMiddleware) CheckMaintenanceMode() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip maintenance check for admin users
		if _, exists := c.Get("admin_user"); exists {
			c.Next()
			return
		}

		// Check maintenance mode from database/config
		maintenanceMode := false // Get from settings
		if maintenanceMode {
			pkg.ServiceUnavailableResponse(c, "System is under maintenance")
			c.Abort()
			return
		}

		c.Next()
	}
}
