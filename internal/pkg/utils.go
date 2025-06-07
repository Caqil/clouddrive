package pkg

import (
	"encoding/json"
	"fmt"
	"mime"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// StringUtils provides string utility functions
type StringUtils struct{}

// IsEmpty checks if string is empty or contains only whitespace
func (StringUtils) IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// Contains checks if string contains substring (case-insensitive)
func (StringUtils) Contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// Truncate truncates string to specified length
func (StringUtils) Truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

// Slugify converts string to URL-friendly slug
func (StringUtils) Slugify(s string) string {
	// Convert to lowercase
	s = strings.ToLower(s)

	// Replace spaces and special characters with hyphens
	reg := regexp.MustCompile(`[^a-z0-9]+`)
	s = reg.ReplaceAllString(s, "-")

	// Remove leading and trailing hyphens
	s = strings.Trim(s, "-")

	return s
}

// ToCamelCase converts string to camelCase
func (StringUtils) ToCamelCase(s string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}

	result := strings.ToLower(words[0])
	for i := 1; i < len(words); i++ {
		result += strings.Title(strings.ToLower(words[i]))
	}

	return result
}

// ToSnakeCase converts string to snake_case
func (StringUtils) ToSnakeCase(s string) string {
	var result []rune
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			result = append(result, '_')
		}
		result = append(result, unicode.ToLower(r))
	}
	return string(result)
}

// TimeUtils provides time utility functions
type TimeUtils struct{}

// FormatDuration formats duration in human-readable format
func (TimeUtils) FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// StartOfDay returns start of day (00:00:00)
func (TimeUtils) StartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// EndOfDay returns end of day (23:59:59)
func (TimeUtils) EndOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, t.Location())
}

// IsToday checks if time is today
func (TimeUtils) IsToday(t time.Time) bool {
	now := time.Now()
	return t.Year() == now.Year() && t.Month() == now.Month() && t.Day() == now.Day()
}

// TimeAgo returns human-readable time difference
func (TimeUtils) TimeAgo(t time.Time) string {
	diff := time.Since(t)

	if diff < time.Minute {
		return "just now"
	}
	if diff < time.Hour {
		minutes := int(diff.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	}
	if diff < 24*time.Hour {
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}

	days := int(diff.Hours() / 24)
	if days == 1 {
		return "1 day ago"
	}
	if days < 7 {
		return fmt.Sprintf("%d days ago", days)
	}
	if days < 30 {
		weeks := days / 7
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	}
	if days < 365 {
		months := days / 30
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	}

	years := days / 365
	if years == 1 {
		return "1 year ago"
	}
	return fmt.Sprintf("%d years ago", years)
}

// FileUtils provides file utility functions
type FileUtils struct{}

// GetMimeType returns MIME type from file extension
func (FileUtils) GetMimeType(filename string) string {
	ext := filepath.Ext(filename)
	return mime.TypeByExtension(ext)
}

// IsImageFile checks if file is an image
func (FileUtils) IsImageFile(filename string) bool {
	mimeType := FileUtils{}.GetMimeType(filename)
	return strings.HasPrefix(mimeType, "image/")
}

// IsVideoFile checks if file is a video
func (FileUtils) IsVideoFile(filename string) bool {
	mimeType := FileUtils{}.GetMimeType(filename)
	return strings.HasPrefix(mimeType, "video/")
}

// IsAudioFile checks if file is an audio file
func (FileUtils) IsAudioFile(filename string) bool {
	mimeType := FileUtils{}.GetMimeType(filename)
	return strings.HasPrefix(mimeType, "audio/")
}

// IsDocumentFile checks if file is a document
func (FileUtils) IsDocumentFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	documentExts := []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf"}

	for _, docExt := range documentExts {
		if ext == docExt {
			return true
		}
	}
	return false
}

// FormatFileSize formats file size in human-readable format
func (FileUtils) FormatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(size)/float64(div), units[exp])
}

// SanitizeFilename removes or replaces invalid characters in filename
func (FileUtils) SanitizeFilename(filename string) string {
	// Remove or replace invalid characters
	reg := regexp.MustCompile(`[<>:"/\\|?*]`)
	filename = reg.ReplaceAllString(filename, "_")

	// Remove leading and trailing spaces and dots
	filename = strings.Trim(filename, " .")

	// Limit length
	if len(filename) > 255 {
		ext := filepath.Ext(filename)
		name := filename[:255-len(ext)]
		filename = name + ext
	}

	return filename
}

// ConversionUtils provides data conversion utilities
type ConversionUtils struct{}

// StringToObjectID converts string to ObjectID
func (ConversionUtils) StringToObjectID(s string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(s)
}

// ObjectIDToString converts ObjectID to string
func (ConversionUtils) ObjectIDToString(id primitive.ObjectID) string {
	return id.Hex()
}

// StringToInt converts string to int with default value
func (ConversionUtils) StringToInt(s string, defaultValue int) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return defaultValue
}

// StringToInt64 converts string to int64 with default value
func (ConversionUtils) StringToInt64(s string, defaultValue int64) int64 {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	return defaultValue
}

// StringToBool converts string to bool with default value
func (ConversionUtils) StringToBool(s string, defaultValue bool) bool {
	if b, err := strconv.ParseBool(s); err == nil {
		return b
	}
	return defaultValue
}

// ToJSON converts interface to JSON string
func (ConversionUtils) ToJSON(v interface{}) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// FromJSON parses JSON string to interface
func (ConversionUtils) FromJSON(jsonStr string, v interface{}) error {
	return json.Unmarshal([]byte(jsonStr), v)
}

// ValidationUtils provides validation utilities
type ValidationUtils struct{}

// IsValidEmail validates email format
func (ValidationUtils) IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// IsValidURL validates URL format
func (ValidationUtils) IsValidURL(url string) bool {
	urlRegex := regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	return urlRegex.MatchString(url)
}

// IsValidPhone validates phone number format
func (ValidationUtils) IsValidPhone(phone string) bool {
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	return phoneRegex.MatchString(phone)
}

// IsStrongPassword validates password strength
func (ValidationUtils) IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// SliceUtils provides slice utility functions
type SliceUtils struct{}

// Contains checks if slice contains item
func (SliceUtils) Contains(slice interface{}, item interface{}) bool {
	s := reflect.ValueOf(slice)
	if s.Kind() != reflect.Slice {
		return false
	}

	for i := 0; i < s.Len(); i++ {
		if reflect.DeepEqual(s.Index(i).Interface(), item) {
			return true
		}
	}
	return false
}

// Unique removes duplicate items from slice
func (SliceUtils) Unique(slice interface{}) interface{} {
	s := reflect.ValueOf(slice)
	if s.Kind() != reflect.Slice {
		return slice
	}

	seen := make(map[interface{}]bool)
	result := reflect.MakeSlice(s.Type(), 0, s.Len())

	for i := 0; i < s.Len(); i++ {
		item := s.Index(i).Interface()
		if !seen[item] {
			seen[item] = true
			result = reflect.Append(result, s.Index(i))
		}
	}

	return result.Interface()
}

// Global utility instances
var (
	Strings     = StringUtils{}
	Times       = TimeUtils{}
	Files       = FileUtils{}
	Conversions = ConversionUtils{}
	Validations = ValidationUtils{}
	Slices      = SliceUtils{}
)
