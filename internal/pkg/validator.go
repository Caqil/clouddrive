package pkg

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

// Validator wraps the go-playground validator
type Validator struct {
	validate *validator.Validate
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	v := validator.New()

	// Register custom validators
	v.RegisterValidation("strongpassword", validateStrongPassword)
	v.RegisterValidation("objectid", validateObjectID)
	v.RegisterValidation("phone", validatePhone)
	v.RegisterValidation("slug", validateSlug)
	v.RegisterValidation("color", validateColor)
	v.RegisterValidation("timezone", validateTimezone)
	v.RegisterValidation("language", validateLanguage)

	// Register custom field name function
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return &Validator{validate: v}
}

// Validate validates a struct
func (v *Validator) Validate(s interface{}) ValidationErrors {
	err := v.validate.Struct(s)
	if err == nil {
		return nil
	}

	var errors ValidationErrors
	for _, err := range err.(validator.ValidationErrors) {
		errors = append(errors, ValidationError{
			Field:   err.Field(),
			Message: v.getErrorMessage(err),
			Value:   err.Value(),
		})
	}

	return errors
}

// ValidateField validates a single field
func (v *Validator) ValidateField(field interface{}, tag string) error {
	return v.validate.Var(field, tag)
}

// getErrorMessage returns a human-readable error message
func (v *Validator) getErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", err.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", err.Field())
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", err.Field(), err.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", err.Field(), err.Param())
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters long", err.Field(), err.Param())
	case "gte":
		return fmt.Sprintf("%s must be greater than or equal to %s", err.Field(), err.Param())
	case "lte":
		return fmt.Sprintf("%s must be less than or equal to %s", err.Field(), err.Param())
	case "gt":
		return fmt.Sprintf("%s must be greater than %s", err.Field(), err.Param())
	case "lt":
		return fmt.Sprintf("%s must be less than %s", err.Field(), err.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", err.Field(), err.Param())
	case "url":
		return fmt.Sprintf("%s must be a valid URL", err.Field())
	case "uri":
		return fmt.Sprintf("%s must be a valid URI", err.Field())
	case "strongpassword":
		return fmt.Sprintf("%s must contain at least 8 characters with uppercase, lowercase, number, and special character", err.Field())
	case "objectid":
		return fmt.Sprintf("%s must be a valid ObjectID", err.Field())
	case "phone":
		return fmt.Sprintf("%s must be a valid phone number", err.Field())
	case "slug":
		return fmt.Sprintf("%s must be a valid slug (lowercase, alphanumeric, hyphens)", err.Field())
	case "color":
		return fmt.Sprintf("%s must be a valid hex color", err.Field())
	case "timezone":
		return fmt.Sprintf("%s must be a valid timezone", err.Field())
	case "language":
		return fmt.Sprintf("%s must be a valid language code", err.Field())
	default:
		return fmt.Sprintf("%s is invalid", err.Field())
	}
}

// Custom validation functions

// validateStrongPassword validates password strength
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	if len(password) < 8 {
		return false
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)

	return hasUpper && hasLower && hasNumber && hasSpecial
}

// validateObjectID validates MongoDB ObjectID
func validateObjectID(fl validator.FieldLevel) bool {
	id := fl.Field().String()
	if len(id) != 24 {
		return false
	}

	match, _ := regexp.MatchString("^[a-fA-F0-9]{24}$", id)
	return match
}

// validatePhone validates phone number
func validatePhone(fl validator.FieldLevel) bool {
	phone := fl.Field().String()
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	return phoneRegex.MatchString(phone)
}

// validateSlug validates URL slug
func validateSlug(fl validator.FieldLevel) bool {
	slug := fl.Field().String()
	slugRegex := regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	return slugRegex.MatchString(slug)
}

// validateColor validates hex color
func validateColor(fl validator.FieldLevel) bool {
	color := fl.Field().String()
	colorRegex := regexp.MustCompile(`^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$`)
	return colorRegex.MatchString(color)
}

// validateTimezone validates timezone
func validateTimezone(fl validator.FieldLevel) bool {
	timezone := fl.Field().String()
	validTimezones := []string{
		"UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
		"Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo", "Asia/Shanghai",
		"Australia/Sydney", "Pacific/Auckland",
	}

	for _, tz := range validTimezones {
		if timezone == tz {
			return true
		}
	}
	return false
}

// validateLanguage validates language code
func validateLanguage(fl validator.FieldLevel) bool {
	language := fl.Field().String()
	languageRegex := regexp.MustCompile(`^[a-z]{2}(-[A-Z]{2})?$`)
	return languageRegex.MatchString(language)
}

// PasswordStrength represents password strength level
type PasswordStrength int

const (
	PasswordWeak PasswordStrength = iota
	PasswordMedium
	PasswordStrong
	PasswordVeryStrong
)

// CheckPasswordStrength checks password strength
func CheckPasswordStrength(password string) PasswordStrength {
	score := 0

	// Length check
	if len(password) >= 8 {
		score++
	}
	if len(password) >= 12 {
		score++
	}

	// Character type checks
	if regexp.MustCompile(`[a-z]`).MatchString(password) {
		score++
	}
	if regexp.MustCompile(`[A-Z]`).MatchString(password) {
		score++
	}
	if regexp.MustCompile(`[0-9]`).MatchString(password) {
		score++
	}
	if regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password) {
		score++
	}

	switch {
	case score <= 2:
		return PasswordWeak
	case score <= 4:
		return PasswordMedium
	case score <= 5:
		return PasswordStrong
	default:
		return PasswordVeryStrong
	}
}

// GetPasswordRequirements returns password requirements message
func GetPasswordRequirements() string {
	return "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character."
}

// ValidatePasswordRequirements validates password against specific requirements
func ValidatePasswordRequirements(password string, minLength int, requireUpper, requireLower, requireNumber, requireSpecial bool) []string {
	var errors []string

	if len(password) < minLength {
		errors = append(errors, fmt.Sprintf("Password must be at least %d characters long", minLength))
	}

	if requireUpper && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}

	if requireLower && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}

	if requireNumber && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one number")
	}

	if requireSpecial && !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one special character")
	}

	return errors
}

// Global validator instance
var DefaultValidator = NewValidator()
