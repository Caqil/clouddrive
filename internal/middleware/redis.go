package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

// RedisClientImpl implements RedisClient interface using go-redis
type RedisClientImpl struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis client
func NewRedisClient(addr, password string, db int) (*RedisClientImpl, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisClientImpl{client: rdb}, nil
}

// Get retrieves a value from Redis
func (r *RedisClientImpl) Get(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", errors.New("key not found")
	}
	return val, err
}

// Set stores a value in Redis with expiration
func (r *RedisClientImpl) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Del deletes keys from Redis
func (r *RedisClientImpl) Del(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

// Exists checks if keys exist in Redis
func (r *RedisClientImpl) Exists(ctx context.Context, keys ...string) (int64, error) {
	return r.client.Exists(ctx, keys...).Result()
}

// Close closes the Redis connection
func (r *RedisClientImpl) Close() error {
	return r.client.Close()
}

// MemoryRateLimitStore implements RateLimitStore interface using in-memory storage
type MemoryRateLimitStore struct {
	mu       sync.RWMutex
	counters map[string]*rateLimitEntry
	blocked  map[string]*blockEntry
}

type rateLimitEntry struct {
	Count     int
	ExpiresAt time.Time
}

type blockEntry struct {
	BlockedUntil time.Time
}

// NewMemoryRateLimitStore creates a new memory-based rate limit store
func NewMemoryRateLimitStore() *MemoryRateLimitStore {
	return &MemoryRateLimitStore{
		counters: make(map[string]*rateLimitEntry),
		blocked:  make(map[string]*blockEntry),
	}
}

// Get retrieves current count and reset time for a key
func (m *MemoryRateLimitStore) Get(ctx context.Context, key string) (int, time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.counters[key]
	if !exists || entry.ExpiresAt.Before(time.Now()) {
		return 0, time.Time{}, nil
	}

	return entry.Count, entry.ExpiresAt, nil
}

// Set sets the count and expiry for a key
func (m *MemoryRateLimitStore) Set(ctx context.Context, key string, count int, expiry time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.counters[key] = &rateLimitEntry{
		Count:     count,
		ExpiresAt: expiry,
	}

	return nil
}

// Increment increments the counter for a key
func (m *MemoryRateLimitStore) Increment(ctx context.Context, key string, expiry time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	entry, exists := m.counters[key]

	if !exists || entry.ExpiresAt.Before(now) {
		// Create new entry
		m.counters[key] = &rateLimitEntry{
			Count:     1,
			ExpiresAt: expiry,
		}
		return 1, nil
	}

	// Increment existing entry
	entry.Count++
	return entry.Count, nil
}

// Delete removes a key from the store
func (m *MemoryRateLimitStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.counters, key)
	delete(m.blocked, key)
	return nil
}

// IsBlocked checks if a key is blocked
func (m *MemoryRateLimitStore) IsBlocked(ctx context.Context, key string) (bool, time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.blocked[key]
	if !exists {
		return false, time.Time{}, nil
	}

	if entry.BlockedUntil.Before(time.Now()) {
		// Block has expired, remove it
		go func() {
			m.mu.Lock()
			delete(m.blocked, key)
			m.mu.Unlock()
		}()
		return false, time.Time{}, nil
	}

	return true, entry.BlockedUntil, nil
}

// Block blocks a key for the specified duration
func (m *MemoryRateLimitStore) Block(ctx context.Context, key string, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.blocked[key] = &blockEntry{
		BlockedUntil: time.Now().Add(duration),
	}

	return nil
}

// Cleanup removes expired entries
func (m *MemoryRateLimitStore) Cleanup(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Clean up expired rate limit entries
	for key, entry := range m.counters {
		if entry.ExpiresAt.Before(now) {
			delete(m.counters, key)
		}
	}

	// Clean up expired block entries
	for key, entry := range m.blocked {
		if entry.BlockedUntil.Before(now) {
			delete(m.blocked, key)
		}
	}

	return nil
}

// RedisRateLimitStore implements RateLimitStore interface using Redis
type RedisRateLimitStore struct {
	client *RedisClientImpl
	prefix string
}

// NewRedisRateLimitStore creates a new Redis-based rate limit store
func NewRedisRateLimitStore(client *RedisClientImpl, prefix string) *RedisRateLimitStore {
	if prefix == "" {
		prefix = "rate_limit:"
	}
	return &RedisRateLimitStore{
		client: client,
		prefix: prefix,
	}
}

// Get retrieves current count and reset time for a key
func (r *RedisRateLimitStore) Get(ctx context.Context, key string) (int, time.Time, error) {
	redisKey := r.prefix + key

	// Get the current count
	countStr, err := r.client.Get(ctx, redisKey)
	if err != nil {
		return 0, time.Time{}, nil // Key doesn't exist
	}

	count, err := strconv.Atoi(countStr)
	if err != nil {
		return 0, time.Time{}, err
	}

	// Get TTL to determine reset time
	ttl := r.client.client.TTL(ctx, redisKey).Val()
	resetTime := time.Now().Add(ttl)

	return count, resetTime, nil
}

// Set sets the count and expiry for a key
func (r *RedisRateLimitStore) Set(ctx context.Context, key string, count int, expiry time.Time) error {
	redisKey := r.prefix + key
	duration := time.Until(expiry)
	if duration <= 0 {
		return nil // Don't set expired keys
	}

	return r.client.Set(ctx, redisKey, count, duration)
}

// Increment increments the counter for a key
func (r *RedisRateLimitStore) Increment(ctx context.Context, key string, expiry time.Time) (int, error) {
	redisKey := r.prefix + key
	duration := time.Until(expiry)
	if duration <= 0 {
		return 0, nil
	}

	// Use Redis pipeline for atomic increment with expiry
	pipe := r.client.client.Pipeline()
	incrCmd := pipe.Incr(ctx, redisKey)
	pipe.Expire(ctx, redisKey, duration)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return int(incrCmd.Val()), nil
}

// Delete removes a key from the store
func (r *RedisRateLimitStore) Delete(ctx context.Context, key string) error {
	redisKey := r.prefix + key
	blockKey := r.prefix + "block:" + key
	return r.client.Del(ctx, redisKey, blockKey)
}

// IsBlocked checks if a key is blocked
func (r *RedisRateLimitStore) IsBlocked(ctx context.Context, key string) (bool, time.Time, error) {
	blockKey := r.prefix + "block:" + key

	val, err := r.client.Get(ctx, blockKey)
	if err != nil {
		return false, time.Time{}, nil // Key doesn't exist
	}

	// Parse the blocked until timestamp
	var blockedUntil int64
	if err := json.Unmarshal([]byte(val), &blockedUntil); err != nil {
		return false, time.Time{}, err
	}

	blockTime := time.Unix(blockedUntil, 0)
	if blockTime.Before(time.Now()) {
		// Block has expired, remove it
		r.client.Del(ctx, blockKey)
		return false, time.Time{}, nil
	}

	return true, blockTime, nil
}

// Block blocks a key for the specified duration
func (r *RedisRateLimitStore) Block(ctx context.Context, key string, duration time.Duration) error {
	blockKey := r.prefix + "block:" + key
	blockedUntil := time.Now().Add(duration).Unix()

	data, err := json.Marshal(blockedUntil)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, blockKey, string(data), duration)
}

// Cleanup removes expired entries (Redis handles this automatically)
func (r *RedisRateLimitStore) Cleanup(ctx context.Context) error {
	// Redis automatically removes expired keys, so this is a no-op
	return nil
}

// EmailNotifier implements ErrorNotifier interface for email notifications
type EmailNotifier struct {
	enabled     bool
	smtpHost    string
	smtpPort    int
	username    string
	password    string
	fromEmail   string
	adminEmails []string
}

// NewEmailNotifier creates a new email notifier
func NewEmailNotifier(config EmailNotifierConfig) *EmailNotifier {
	return &EmailNotifier{
		enabled:     config.Enabled,
		smtpHost:    config.SMTPHost,
		smtpPort:    config.SMTPPort,
		username:    config.Username,
		password:    config.Password,
		fromEmail:   config.FromEmail,
		adminEmails: config.AdminEmails,
	}
}

// EmailNotifierConfig represents email notifier configuration
type EmailNotifierConfig struct {
	Enabled     bool     `json:"enabled"`
	SMTPHost    string   `json:"smtp_host"`
	SMTPPort    int      `json:"smtp_port"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	FromEmail   string   `json:"from_email"`
	AdminEmails []string `json:"admin_emails"`
}

// NotifyPanic sends panic notification via email
func (e *EmailNotifier) NotifyPanic(ctx *gin.Context, panicInfo *PanicInfo) error {
	if !e.enabled || len(e.adminEmails) == 0 {
		return nil
	}

	subject := fmt.Sprintf("🚨 Panic Alert - %s", panicInfo.ID)
	body := e.formatPanicEmail(panicInfo)

	// Send email to all admin emails
	for _, email := range e.adminEmails {
		go e.sendEmail(email, subject, body)
	}

	return nil
}

// NotifyAdmins sends general admin notification
func (e *EmailNotifier) NotifyAdmins(message string, details map[string]interface{}) error {
	if !e.enabled || len(e.adminEmails) == 0 {
		return nil
	}

	subject := "🔔 CloudDrive Admin Alert"
	body := e.formatAdminEmail(message, details)

	for _, email := range e.adminEmails {
		go e.sendEmail(email, subject, body)
	}

	return nil
}

// formatPanicEmail formats panic information for email
func (e *EmailNotifier) formatPanicEmail(panicInfo *PanicInfo) string {
	return fmt.Sprintf(`
PANIC ALERT - CloudDrive

Panic ID: %s
Timestamp: %s
Request ID: %s

Error: %v

Request Information:
- Method: %s
- Path: %s
- IP: %s
- User Agent: %s

User Information:
- User ID: %s
- Email: %s
- Role: %s

System Information:
- Go Version: %s
- OS: %s
- Goroutines: %d
- Memory Usage: %d MB

Recovery Information:
- Action: %s
- Successful: %t
- Duration: %s

Stack Trace:
%s

Please investigate this issue immediately.
`,
		panicInfo.ID,
		panicInfo.Timestamp.Format(time.RFC3339),
		panicInfo.RequestID,
		panicInfo.Error,
		panicInfo.Request.Method,
		panicInfo.Request.Path,
		panicInfo.Request.IP,
		panicInfo.Request.UserAgent,
		getStringOrDefault(panicInfo.User, "ID"),
		getStringOrDefault(panicInfo.User, "Email"),
		getStringOrDefault(panicInfo.User, "Role"),
		panicInfo.System.GoVersion,
		panicInfo.System.OS,
		panicInfo.System.NumGoroutine,
		panicInfo.System.MemStats.Alloc/1024/1024,
		getRecoveryAction(panicInfo.Recovery),
		getRecoverySuccess(panicInfo.Recovery),
		getRecoveryDuration(panicInfo.Recovery),
		panicInfo.Stack,
	)
}

// formatAdminEmail formats admin notification email
func (e *EmailNotifier) formatAdminEmail(message string, details map[string]interface{}) string {
	detailsStr := ""
	for key, value := range details {
		detailsStr += fmt.Sprintf("- %s: %v\n", key, value)
	}

	return fmt.Sprintf(`
ADMIN ALERT - CloudDrive

Message: %s

Details:
%s

Timestamp: %s
`,
		message,
		detailsStr,
		time.Now().Format(time.RFC3339),
	)
}

// sendEmail sends email (placeholder implementation)
func (e *EmailNotifier) sendEmail(to, subject, body string) {
	// This is a placeholder implementation
	// In a real application, you would use an email service like:
	// - net/smtp for direct SMTP
	// - SendGrid SDK
	// - AWS SES SDK
	// - Mailgun SDK
	// etc.

	fmt.Printf("EMAIL TO: %s\nSUBJECT: %s\nBODY:\n%s\n", to, subject, body)
}

// MockNotifier implements ErrorNotifier interface for testing
type MockNotifier struct {
	PanicNotifications []PanicInfo
	AdminNotifications []AdminNotification
}

type AdminNotification struct {
	Message string
	Details map[string]interface{}
	Time    time.Time
}

// NewMockNotifier creates a new mock notifier
func NewMockNotifier() *MockNotifier {
	return &MockNotifier{
		PanicNotifications: make([]PanicInfo, 0),
		AdminNotifications: make([]AdminNotification, 0),
	}
}

// NotifyPanic records panic notification for testing
func (m *MockNotifier) NotifyPanic(ctx *gin.Context, panicInfo *PanicInfo) error {
	m.PanicNotifications = append(m.PanicNotifications, *panicInfo)
	return nil
}

// NotifyAdmins records admin notification for testing
func (m *MockNotifier) NotifyAdmins(message string, details map[string]interface{}) error {
	m.AdminNotifications = append(m.AdminNotifications, AdminNotification{
		Message: message,
		Details: details,
		Time:    time.Now(),
	})
	return nil
}

// Helper functions

func getStringOrDefault(user *UserInfo, field string) string {
	if user == nil {
		return "N/A"
	}
	switch field {
	case "ID":
		return user.ID
	case "Email":
		return user.Email
	case "Role":
		return user.Role
	default:
		return "N/A"
	}
}

func getRecoveryAction(recovery *RecoveryInfo) string {
	if recovery == nil {
		return "N/A"
	}
	return recovery.Action
}

func getRecoverySuccess(recovery *RecoveryInfo) bool {
	if recovery == nil {
		return false
	}
	return recovery.Successful
}

func getRecoveryDuration(recovery *RecoveryInfo) string {
	if recovery == nil {
		return "N/A"
	}
	return recovery.Duration.String()
}
