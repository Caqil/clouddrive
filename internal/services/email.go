package services

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/pkg"
)

// EmailService handles email operations
type EmailService interface {
	SendVerificationEmail(ctx context.Context, email, name, token string) error
	SendPasswordResetEmail(ctx context.Context, email, name, token string) error
	SendWelcomeEmail(ctx context.Context, email, name string) error
	SendNotificationEmail(ctx context.Context, email, subject, message string) error
	SendInvoiceEmail(ctx context.Context, email, invoiceData string) error
	SendSubscriptionEmail(ctx context.Context, email, templateName string, data map[string]interface{}) error
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
	logger    *pkg.Logger
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
func NewSMTPEmailService(config *EmailConfig, logger *pkg.Logger) EmailService {
	service := &SMTPEmailService{
		host:      config.Host,
		port:      config.Port,
		username:  config.Username,
		password:  config.Password,
		fromEmail: config.FromEmail,
		fromName:  config.FromName,
		baseURL:   config.BaseURL,
		templates: make(map[string]*template.Template),
		logger:    logger,
	}

	// Load email templates
	service.loadTemplates()

	return service
}

// loadTemplates loads email templates
func (s *SMTPEmailService) loadTemplates() {
	// Base template functions
	funcMap := template.FuncMap{
		"formatCurrency": func(amount int64, currency string) string {
			return fmt.Sprintf("$%.2f %s", float64(amount)/100, strings.ToUpper(currency))
		},
		"formatDate": func(t time.Time) string {
			return t.Format("January 2, 2006")
		},
		"formatDateTime": func(t time.Time) string {
			return t.Format("January 2, 2006 at 3:04 PM")
		},
		"title": strings.Title,
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
	}

	// Verification email template
	verifyTemplate := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your Email - CloudDrive</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 28px; font-weight: 300; }
        .content { padding: 40px 30px; }
        .button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 30px 0; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
        .button:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); }
        .footer { text-align: center; padding: 30px; font-size: 14px; color: #666; background: #f8f9fa; border-top: 1px solid #e9ecef; }
        .highlight { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107; }
        .security-note { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #dc3545; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to CloudDrive!</h1>
        </div>
        <div class="content">
            <h2>Hi {{.Name}},</h2>
            <p>Thank you for signing up for CloudDrive. To complete your registration and start using our secure cloud storage, please verify your email address.</p>
            
            <div class="highlight">
                <strong>Why verify your email?</strong><br>
                Email verification helps us ensure the security of your account and allows us to send you important updates about your files and storage.
            </div>
            
            <div style="text-align: center;">
                <a href="{{.BaseURL}}/verify-email?token={{.Token}}" class="button">Verify Email Address</a>
            </div>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 5px;">{{.BaseURL}}/verify-email?token={{.Token}}</p>
            
            <div class="security-note">
                <strong>Security Note:</strong> This link will expire in 24 hours. If you didn't create this account, please ignore this email.
            </div>
        </div>
        <div class="footer">
            <p>This email was sent from CloudDrive. If you have questions, contact us at support@clouddrive.com</p>
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	// Password reset template
	resetTemplate := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reset Your Password - CloudDrive</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; }
        .header { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 40px 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 28px; font-weight: 300; }
        .content { padding: 40px 30px; }
        .button { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 30px 0; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
        .button:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(220, 53, 69, 0.4); }
        .footer { text-align: center; padding: 30px; font-size: 14px; color: #666; background: #f8f9fa; border-top: 1px solid #e9ecef; }
        .security-note { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #dc3545; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <h2>Hi {{.Name}},</h2>
            <p>We received a request to reset your CloudDrive password. If you made this request, click the button below to reset your password:</p>
            
            <div style="text-align: center;">
                <a href="{{.BaseURL}}/reset-password?token={{.Token}}" class="button">Reset Password</a>
            </div>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 5px;">{{.BaseURL}}/reset-password?token={{.Token}}</p>
            
            <div class="security-note">
                <strong>Security Note:</strong> This link will expire in 1 hour. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
            </div>
        </div>
        <div class="footer">
            <p>This email was sent from CloudDrive. If you have questions, contact us at support@clouddrive.com</p>
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	// Welcome email template
	welcomeTemplate := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome to CloudDrive!</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; }
        .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 40px 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 28px; font-weight: 300; }
        .content { padding: 40px 30px; }
        .button { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 30px 0; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
        .footer { text-align: center; padding: 30px; font-size: 14px; color: #666; background: #f8f9fa; border-top: 1px solid #e9ecef; }
        .feature-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 30px 0; }
        .feature-card { padding: 20px; border: 1px solid #e9ecef; border-radius: 8px; text-align: center; }
        .feature-icon { font-size: 40px; margin-bottom: 10px; }
        @media (max-width: 600px) { .feature-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome to CloudDrive!</h1>
        </div>
        <div class="content">
            <h2>Hi {{.Name}},</h2>
            <p>Welcome to CloudDrive! Your account has been successfully created and verified. You're now ready to start using our secure cloud storage platform.</p>
            
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-icon">☁️</div>
                    <h4>Secure Storage</h4>
                    <p>Your files are encrypted and stored securely in the cloud</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🔗</div>
                    <h4>Easy Sharing</h4>
                    <p>Share files and folders with anyone, anywhere</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">📱</div>
                    <h4>Access Anywhere</h4>
                    <p>Access your files from any device, anytime</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🔄</div>
                    <h4>Auto Sync</h4>
                    <p>Automatically sync files across all your devices</p>
                </div>
            </div>
            
            <div style="text-align: center;">
                <a href="{{.BaseURL}}/dashboard" class="button">Get Started</a>
            </div>
            
            <p><strong>What's next?</strong></p>
            <ul>
                <li>Upload your first files to the cloud</li>
                <li>Install our mobile app for on-the-go access</li>
                <li>Explore our premium plans for more storage</li>
                <li>Set up two-factor authentication for extra security</li>
            </ul>
        </div>
        <div class="footer">
            <p>Need help getting started? Check out our <a href="{{.BaseURL}}/help">Help Center</a> or contact support.</p>
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	// Subscription confirmation template
	subscriptionTemplate := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Subscription Confirmed - CloudDrive</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; }
        .header { background: linear-gradient(135deg, #6f42c1 0%, #e83e8c 100%); color: white; padding: 40px 20px; text-align: center; }
        .header h1 { margin: 0; font-size: 28px; font-weight: 300; }
        .content { padding: 40px 30px; }
        .subscription-details { background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 30px 0; border-left: 4px solid #6f42c1; }
        .detail-row { display: flex; justify-content: space-between; margin: 10px 0; padding: 5px 0; border-bottom: 1px solid #e9ecef; }
        .detail-row:last-child { border-bottom: none; }
        .footer { text-align: center; padding: 30px; font-size: 14px; color: #666; background: #f8f9fa; border-top: 1px solid #e9ecef; }
        .premium-badge { background: linear-gradient(135deg, #ffc107 0%, #fd7e14 100%); color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Subscription Confirmed!</h1>
            <span class="premium-badge">Premium Member</span>
        </div>
        <div class="content">
            <h2>Hi {{.FirstName}},</h2>
            <p>Congratulations! Your CloudDrive {{.PlanName}} subscription has been confirmed. You now have access to all premium features.</p>
            
            <div class="subscription-details">
                <h3 style="margin-top: 0; color: #6f42c1;">Subscription Details</h3>
                <div class="detail-row">
                    <span><strong>Plan:</strong></span>
                    <span>{{.PlanName}}</span>
                </div>
                <div class="detail-row">
                    <span><strong>Billing Cycle:</strong></span>
                    <span>{{.BillingCycle | title}}</span>
                </div>
                <div class="detail-row">
                    <span><strong>Amount:</strong></span>
                    <span>{{formatCurrency .Amount .Currency}}</span>
                </div>
                <div class="detail-row">
                    <span><strong>Next Billing Date:</strong></span>
                    <span>{{formatDate .NextBillingDate}}</span>
                </div>
                {{if .TrialEnd}}
                <div class="detail-row">
                    <span><strong>Trial Ends:</strong></span>
                    <span>{{formatDate .TrialEnd}}</span>
                </div>
                {{end}}
            </div>
            
            <h3>🚀 Your Premium Benefits:</h3>
            <ul style="list-style: none; padding: 0;">
                <li style="margin: 10px 0;"><span style="color: #28a745; font-weight: bold;">✓</span> {{.StorageLimit}} of secure cloud storage</li>
                <li style="margin: 10px 0;"><span style="color: #28a745; font-weight: bold;">✓</span> {{.BandwidthLimit}} monthly bandwidth</li>
                <li style="margin: 10px 0;"><span style="color: #28a745; font-weight: bold;">✓</span> Up to {{.FileLimit}} files</li>
                <li style="margin: 10px 0;"><span style="color: #28a745; font-weight: bold;">✓</span> Priority customer support</li>
                <li style="margin: 10px 0;"><span style="color: #28a745; font-weight: bold;">✓</span> Advanced sharing controls</li>
                <li style="margin: 10px 0;"><span style="color: #28a745; font-weight: bold;">✓</span> File versioning and recovery</li>
            </ul>
            
            <p><strong>Getting Started:</strong></p>
            <ol>
                <li>Log in to your dashboard to see your increased storage</li>
                <li>Upload files and take advantage of your expanded limits</li>
                <li>Explore advanced features like file versioning</li>
                <li>Contact our priority support if you need any help</li>
            </ol>
        </div>
        <div class="footer">
            <p>Questions about your subscription? Contact our support team at <a href="mailto:support@clouddrive.com">support@clouddrive.com</a></p>
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	// Invoice template
	invoiceTemplate := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Invoice - CloudDrive</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; }
        .header { background: linear-gradient(135deg, #495057 0%, #6c757d 100%); color: white; padding: 40px 20px; text-align: center; }
        .content { padding: 40px 30px; }
        .invoice-details { background: #f8f9fa; padding: 25px; border-radius: 8px; margin: 30px 0; }
        .invoice-row { display: flex; justify-content: space-between; margin: 10px 0; padding: 5px 0; border-bottom: 1px solid #e9ecef; }
        .invoice-total { background: #e9ecef; padding: 15px; margin: 20px 0; border-radius: 5px; font-weight: bold; }
        .footer { text-align: center; padding: 30px; font-size: 14px; color: #666; background: #f8f9fa; border-top: 1px solid #e9ecef; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📄 Invoice</h1>
        </div>
        <div class="content">
            <div style="display: flex; justify-content: space-between; margin-bottom: 30px;">
                <div>
                    <h3>Bill To:</h3>
                    <p>{{.CustomerName}}<br>{{.CustomerEmail}}</p>
                </div>
                <div style="text-align: right;">
                    <h3>Invoice #{{.InvoiceNumber}}</h3>
                    <p>Date: {{formatDate .Date}}<br>Due: {{formatDate .DueDate}}</p>
                </div>
            </div>
            
            <div class="invoice-details">
                <h3 style="margin-top: 0;">Invoice Details</h3>
                {{range .Items}}
                <div class="invoice-row">
                    <span>{{.Description}}</span>
                    <span>{{formatCurrency .Amount .Currency}}</span>
                </div>
                {{end}}
                {{if .Discount}}
                <div class="invoice-row" style="color: #28a745;">
                    <span>Discount</span>
                    <span>-{{formatCurrency .Discount .Currency}}</span>
                </div>
                {{end}}
                {{if .Tax}}
                <div class="invoice-row">
                    <span>Tax</span>
                    <span>{{formatCurrency .Tax .Currency}}</span>
                </div>
                {{end}}
            </div>
            
            <div class="invoice-total">
                <div style="display: flex; justify-content: space-between; font-size: 18px;">
                    <span>Total:</span>
                    <span>{{formatCurrency .Total .Currency}}</span>
                </div>
            </div>
            
            {{if .PaymentMethod}}
            <p><strong>Payment Method:</strong> {{.PaymentMethod}}</p>
            {{end}}
            
            <p>Thank you for your business!</p>
        </div>
        <div class="footer">
            <p>Questions about this invoice? Contact us at <a href="mailto:billing@clouddrive.com">billing@clouddrive.com</a></p>
            <p>&copy; 2024 CloudDrive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`

	// Parse templates
	s.templates["verification"] = template.Must(template.New("verification").Funcs(funcMap).Parse(verifyTemplate))
	s.templates["password_reset"] = template.Must(template.New("password_reset").Funcs(funcMap).Parse(resetTemplate))
	s.templates["welcome"] = template.Must(template.New("welcome").Funcs(funcMap).Parse(welcomeTemplate))
	s.templates["subscription"] = template.Must(template.New("subscription").Funcs(funcMap).Parse(subscriptionTemplate))
	s.templates["invoice"] = template.Must(template.New("invoice").Funcs(funcMap).Parse(invoiceTemplate))
}

// SendVerificationEmail sends email verification email
func (s *SMTPEmailService) SendVerificationEmail(ctx context.Context, email, name, token string) error {
	data := map[string]interface{}{
		"Name":    name,
		"Token":   token,
		"BaseURL": s.baseURL,
	}

	subject := "Verify Your Email Address - CloudDrive"
	return s.sendTemplateEmail(ctx, email, subject, "verification", data)
}

// SendPasswordResetEmail sends password reset email
func (s *SMTPEmailService) SendPasswordResetEmail(ctx context.Context, email, name, token string) error {
	data := map[string]interface{}{
		"Name":    name,
		"Token":   token,
		"BaseURL": s.baseURL,
	}

	subject := "Reset Your Password - CloudDrive"
	return s.sendTemplateEmail(ctx, email, subject, "password_reset", data)
}

// SendWelcomeEmail sends welcome email to new users
func (s *SMTPEmailService) SendWelcomeEmail(ctx context.Context, email, name string) error {
	data := map[string]interface{}{
		"Name":    name,
		"BaseURL": s.baseURL,
	}

	subject := "Welcome to CloudDrive! 🎉"
	return s.sendTemplateEmail(ctx, email, subject, "welcome", data)
}

// SendNotificationEmail sends a general notification email
func (s *SMTPEmailService) SendNotificationEmail(ctx context.Context, email, subject, message string) error {
	// For plain text notifications, create a simple HTML wrapper
	htmlMessage := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>%s</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-bottom: 3px solid #007bff; margin-bottom: 20px; }
        .content { padding: 20px 0; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; border-top: 1px solid #e9ecef; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h2 style="margin: 0; color: #007bff;">CloudDrive</h2>
    </div>
    <div class="content">
        %s
    </div>
    <div class="footer">
        <p>This email was sent from CloudDrive. If you have questions, contact us at support@clouddrive.com</p>
        <p>&copy; 2024 CloudDrive. All rights reserved.</p>
    </div>
</body>
</html>`, subject, strings.ReplaceAll(message, "\n", "<br>"))

	return s.sendHTMLEmail(ctx, email, subject, htmlMessage)
}

// SendInvoiceEmail sends invoice email
func (s *SMTPEmailService) SendInvoiceEmail(ctx context.Context, email, invoiceData string) error {
	// Parse invoice data (this would be JSON in real implementation)
	// For now, use placeholder data
	data := map[string]interface{}{
		"CustomerName":  "Customer",
		"CustomerEmail": email,
		"InvoiceNumber": "INV-001",
		"Date":          time.Now(),
		"DueDate":       time.Now().AddDate(0, 0, 30),
		"Items":         []map[string]interface{}{},
		"Total":         int64(0),
		"Currency":      "USD",
	}

	subject := "Your CloudDrive Invoice"
	return s.sendTemplateEmail(ctx, email, subject, "invoice", data)
}

// SendSubscriptionEmail sends subscription-related emails using templates
func (s *SMTPEmailService) SendSubscriptionEmail(ctx context.Context, email, templateName string, data map[string]interface{}) error {
	// Add base URL to data
	data["BaseURL"] = s.baseURL

	subject := "CloudDrive Subscription Update"
	switch templateName {
	case "subscription_confirmed":
		subject = "Subscription Confirmed - Welcome to CloudDrive Premium!"
		templateName = "subscription"
	case "subscription_canceled":
		subject = "Subscription Canceled - CloudDrive"
	case "subscription_renewed":
		subject = "Subscription Renewed - CloudDrive"
	case "plan_changed":
		subject = "Plan Changed - CloudDrive"
	}

	return s.sendTemplateEmail(ctx, email, subject, templateName, data)
}

// sendTemplateEmail sends email using a template
func (s *SMTPEmailService) sendTemplateEmail(ctx context.Context, to, subject, templateName string, data map[string]interface{}) error {
	template, exists := s.templates[templateName]
	if !exists {
		return fmt.Errorf("template %s not found", templateName)
	}

	var body bytes.Buffer
	if err := template.Execute(&body, data); err != nil {
		s.logger.Error("Failed to execute email template", map[string]interface{}{
			"template": templateName,
			"error":    err.Error(),
		})
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return s.sendHTMLEmail(ctx, to, subject, body.String())
}

// sendHTMLEmail sends HTML email
func (s *SMTPEmailService) sendHTMLEmail(ctx context.Context, to, subject, htmlBody string) error {
	// Prepare message
	from := fmt.Sprintf("%s <%s>", s.fromName, s.fromEmail)

	headers := map[string]string{
		"From":         from,
		"To":           to,
		"Subject":      subject,
		"MIME-Version": "1.0",
		"Content-Type": "text/html; charset=UTF-8",
		"Date":         time.Now().Format(time.RFC1123Z),
	}

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + htmlBody

	// Send email
	return s.sendEmail(ctx, []string{to}, []byte(message))
}

// sendEmail sends email via SMTP
func (s *SMTPEmailService) sendEmail(ctx context.Context, to []string, message []byte) error {
	// Create connection
	addr := fmt.Sprintf("%s:%s", s.host, s.port)

	// Try TLS first, fallback to plain if needed
	auth := smtp.PlainAuth("", s.username, s.password, s.host)

	// Attempt to send with TLS
	if err := s.sendWithTLS(addr, auth, to, message); err != nil {
		s.logger.Warn("TLS email sending failed, trying without TLS", map[string]interface{}{
			"error": err.Error(),
		})

		// Fallback to plain SMTP
		return smtp.SendMail(addr, auth, s.fromEmail, to, message)
	}

	s.logger.Info("Email sent successfully", map[string]interface{}{
		"to":     strings.Join(to, ", "),
		"method": "TLS",
	})

	return nil
}

// sendWithTLS sends email with TLS encryption
func (s *SMTPEmailService) sendWithTLS(addr string, auth smtp.Auth, to []string, message []byte) error {
	// Create TLS connection
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: s.host,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return err
	}
	defer client.Quit()

	// Authenticate
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	// Set sender
	if err := client.Mail(s.fromEmail); err != nil {
		return err
	}

	// Set recipients
	for _, addr := range to {
		if err := client.Rcpt(addr); err != nil {
			return err
		}
	}

	// Send message
	writer, err := client.Data()
	if err != nil {
		return err
	}
	defer writer.Close()

	_, err = writer.Write(message)
	return err
}

// MockEmailService for testing
type MockEmailService struct {
	sentEmails []map[string]interface{}
	logger     *pkg.Logger
}

// NewMockEmailService creates a mock email service for testing
func NewMockEmailService(logger *pkg.Logger) EmailService {
	return &MockEmailService{
		sentEmails: make([]map[string]interface{}, 0),
		logger:     logger,
	}
}

func (m *MockEmailService) SendVerificationEmail(ctx context.Context, email, name, token string) error {
	m.sentEmails = append(m.sentEmails, map[string]interface{}{
		"type":  "verification",
		"email": email,
		"name":  name,
		"token": token,
		"time":  time.Now(),
	})
	m.logger.Info("Mock: Verification email sent", map[string]interface{}{
		"email": email,
		"name":  name,
	})
	return nil
}

func (m *MockEmailService) SendPasswordResetEmail(ctx context.Context, email, name, token string) error {
	m.sentEmails = append(m.sentEmails, map[string]interface{}{
		"type":  "password_reset",
		"email": email,
		"name":  name,
		"token": token,
		"time":  time.Now(),
	})
	m.logger.Info("Mock: Password reset email sent", map[string]interface{}{
		"email": email,
		"name":  name,
	})
	return nil
}

func (m *MockEmailService) SendWelcomeEmail(ctx context.Context, email, name string) error {
	m.sentEmails = append(m.sentEmails, map[string]interface{}{
		"type":  "welcome",
		"email": email,
		"name":  name,
		"time":  time.Now(),
	})
	m.logger.Info("Mock: Welcome email sent", map[string]interface{}{
		"email": email,
		"name":  name,
	})
	return nil
}

func (m *MockEmailService) SendNotificationEmail(ctx context.Context, email, subject, message string) error {
	m.sentEmails = append(m.sentEmails, map[string]interface{}{
		"type":    "notification",
		"email":   email,
		"subject": subject,
		"message": message,
		"time":    time.Now(),
	})
	m.logger.Info("Mock: Notification email sent", map[string]interface{}{
		"email":   email,
		"subject": subject,
	})
	return nil
}

func (m *MockEmailService) SendInvoiceEmail(ctx context.Context, email, invoiceData string) error {
	m.sentEmails = append(m.sentEmails, map[string]interface{}{
		"type":    "invoice",
		"email":   email,
		"invoice": invoiceData,
		"time":    time.Now(),
	})
	m.logger.Info("Mock: Invoice email sent", map[string]interface{}{
		"email": email,
	})
	return nil
}

func (m *MockEmailService) SendSubscriptionEmail(ctx context.Context, email, templateName string, data map[string]interface{}) error {
	m.sentEmails = append(m.sentEmails, map[string]interface{}{
		"type":     "subscription",
		"email":    email,
		"template": templateName,
		"data":     data,
		"time":     time.Now(),
	})
	m.logger.Info("Mock: Subscription email sent", map[string]interface{}{
		"email":    email,
		"template": templateName,
	})
	return nil
}

// GetSentEmails returns all sent emails (for testing)
func (m *MockEmailService) GetSentEmails() []map[string]interface{} {
	return m.sentEmails
}

// ClearSentEmails clears sent emails list (for testing)
func (m *MockEmailService) ClearSentEmails() {
	m.sentEmails = make([]map[string]interface{}, 0)
}
