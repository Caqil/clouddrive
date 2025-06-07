package services

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/smtp"

	"github.com/Caqil/clouddrive/internal/pkg"
)

// EmailService handles email operations
type EmailService interface {
	SendVerificationEmail(ctx context.Context, email, name, token string) error
	SendPasswordResetEmail(ctx context.Context, email, name, token string) error
	SendWelcomeEmail(ctx context.Context, email, name string) error
	SendNotificationEmail(ctx context.Context, email, subject, message string) error
	SendInvoiceEmail(ctx context.Context, email, invoiceData string) error
}

// SMTPEmailService implements email service using SMTP
type SMTPEmailService struct {
	host      string
	port      string
	username  string
	password  string
	fromEmail string
	fromName  string
	baseURL   string
	templates map[string]*template.Template
}

// EmailConfig represents email configuration
type EmailConfig struct {
	Host      string `json:"host"`
	Port      string `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	FromEmail string `json:"from_email"`
	FromName  string `json:"from_name"`
	BaseURL   string `json:"base_url"`
}

// NewSMTPEmailService creates a new SMTP email service
func NewSMTPEmailService(config *EmailConfig) EmailService {
	service := &SMTPEmailService{
		host:      config.Host,
		port:      config.Port,
		username:  config.Username,
		password:  config.Password,
		fromEmail: config.FromEmail,
		fromName:  config.FromName,
		baseURL:   config.BaseURL,
		templates: make(map[string]*template.Template),
	}

	// Load email templates
	service.loadTemplates()

	return service
}

// loadTemplates loads email templates
func (s *SMTPEmailService) loadTemplates() {
	// Verification email template
	verifyTemplate := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your Email</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #4CAF50; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .button { background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to CloudDrive!</h1>
        </div>
        <div class="content">
            <h2>Hi {{.Name}},</h2>
            <p>Thank you for signing up for CloudDrive. To complete your registration, please verify your email address by clicking the button below:</p>
            <a href="{{.VerifyURL}}" class="button">Verify Email Address</a>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p>{{.VerifyURL}}</p>
            <p>This link will expire in 24 hours for security reasons.</p>
            <p>If you didn't create an account with CloudDrive, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	// Password reset template
	resetTemplate := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reset Your Password</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #FF9800; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .button { background: #FF9800; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <h2>Hi {{.Name}},</h2>
            <p>We received a request to reset your CloudDrive password. Click the button below to reset it:</p>
            <a href="{{.ResetURL}}" class="button">Reset Password</a>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p>{{.ResetURL}}</p>
            <p>This link will expire in 1 hour for security reasons.</p>
            <p>If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	// Welcome email template
	welcomeTemplate := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome to CloudDrive!</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #2196F3; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .feature { margin: 20px 0; padding: 15px; background: white; border-radius: 4px; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to CloudDrive!</h1>
        </div>
        <div class="content">
            <h2>Hi {{.Name}},</h2>
            <p>Welcome to CloudDrive! Your account has been successfully created and verified.</p>
            <p>Here's what you can do with CloudDrive:</p>
            <div class="feature">
                <h3>🗄️ Store Files Securely</h3>
                <p>Upload and store your files with enterprise-grade security.</p>
            </div>
            <div class="feature">
                <h3>🔗 Share with Anyone</h3>
                <p>Create secure share links to collaborate with others.</p>
            </div>
            <div class="feature">
                <h3>📱 Access Anywhere</h3>
                <p>Access your files from any device, anywhere in the world.</p>
            </div>
            <p>You started with 5GB of free storage. Need more? Check out our subscription plans.</p>
            <p>Get started by uploading your first file!</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	// Parse templates
	s.templates["verify"] = template.Must(template.New("verify").Parse(verifyTemplate))
	s.templates["reset"] = template.Must(template.New("reset").Parse(resetTemplate))
	s.templates["welcome"] = template.Must(template.New("welcome").Parse(welcomeTemplate))
}

// SendVerificationEmail sends email verification email
func (s *SMTPEmailService) SendVerificationEmail(ctx context.Context, email, name, token string) error {
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)

	data := map[string]interface{}{
		"Name":      name,
		"VerifyURL": verifyURL,
	}

	body, err := s.renderTemplate("verify", data)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}

	return s.sendEmail(email, "Verify Your Email Address", body)
}

// SendPasswordResetEmail sends password reset email
func (s *SMTPEmailService) SendPasswordResetEmail(ctx context.Context, email, name, token string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.baseURL, token)

	data := map[string]interface{}{
		"Name":     name,
		"ResetURL": resetURL,
	}

	body, err := s.renderTemplate("reset", data)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}

	return s.sendEmail(email, "Reset Your Password", body)
}

// SendWelcomeEmail sends welcome email
func (s *SMTPEmailService) SendWelcomeEmail(ctx context.Context, email, name string) error {
	data := map[string]interface{}{
		"Name": name,
	}

	body, err := s.renderTemplate("welcome", data)
	if err != nil {
		return pkg.ErrInternalServer.WithCause(err)
	}

	return s.sendEmail(email, "Welcome to CloudDrive!", body)
}

// SendNotificationEmail sends a notification email
func (s *SMTPEmailService) SendNotificationEmail(ctx context.Context, email, subject, message string) error {
	// Simple notification template
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>%s</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .content { padding: 20px; background: #f9f9f9; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <p>%s</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, subject, message)

	return s.sendEmail(email, subject, body)
}

// SendInvoiceEmail sends invoice email
func (s *SMTPEmailService) SendInvoiceEmail(ctx context.Context, email, invoiceData string) error {
	// Simple invoice email - in production, this would use a proper invoice template
	subject := "Your CloudDrive Invoice"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Invoice</title>
</head>
<body>
    <h1>CloudDrive Invoice</h1>
    <p>Thank you for your payment!</p>
    <pre>%s</pre>
</body>
</html>`, invoiceData)

	return s.sendEmail(email, subject, body)
}

// renderTemplate renders email template with data
func (s *SMTPEmailService) renderTemplate(templateName string, data map[string]interface{}) (string, error) {
	tmpl, exists := s.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render template: %w", err)
	}

	return buf.String(), nil
}

// sendEmail sends email using SMTP
func (s *SMTPEmailService) sendEmail(to, subject, body string) error {
	// Set up authentication
	auth := smtp.PlainAuth("", s.username, s.password, s.host)

	// Compose message
	from := fmt.Sprintf("%s <%s>", s.fromName, s.fromEmail)
	msg := s.composeMessage(from, to, subject, body)

	// Send email
	addr := fmt.Sprintf("%s:%s", s.host, s.port)
	if err := smtp.SendMail(addr, auth, s.fromEmail, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// composeMessage composes email message
func (s *SMTPEmailService) composeMessage(from, to, subject, body string) string {
	msg := fmt.Sprintf("From: %s\r\n", from)
	msg += fmt.Sprintf("To: %s\r\n", to)
	msg += fmt.Sprintf("Subject: %s\r\n", subject)
	msg += "MIME-Version: 1.0\r\n"
	msg += "Content-Type: text/html; charset=UTF-8\r\n"
	msg += "\r\n"
	msg += body

	return msg
}

// MockEmailService implements email service for testing
type MockEmailService struct{}

// NewMockEmailService creates a mock email service
func NewMockEmailService() EmailService {
	return &MockEmailService{}
}

func (m *MockEmailService) SendVerificationEmail(ctx context.Context, email, name, token string) error {
	// Mock implementation - just log or store for testing
	fmt.Printf("Mock: Sending verification email to %s\n", email)
	return nil
}

func (m *MockEmailService) SendPasswordResetEmail(ctx context.Context, email, name, token string) error {
	fmt.Printf("Mock: Sending password reset email to %s\n", email)
	return nil
}

func (m *MockEmailService) SendWelcomeEmail(ctx context.Context, email, name string) error {
	fmt.Printf("Mock: Sending welcome email to %s\n", email)
	return nil
}

func (m *MockEmailService) SendNotificationEmail(ctx context.Context, email, subject, message string) error {
	fmt.Printf("Mock: Sending notification email to %s with subject: %s\n", email, subject)
	return nil
}

func (m *MockEmailService) SendInvoiceEmail(ctx context.Context, email, invoiceData string) error {
	fmt.Printf("Mock: Sending invoice email to %s\n", email)
	return nil
}
