package services

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/pkg"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// StorageProvider represents storage provider interface
type StorageProvider interface {
	Upload(ctx context.Context, key string, file multipart.File, size int64, contentType string) (*UploadResult, error)
	Download(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	GetURL(ctx context.Context, key string) (string, error)
	GetPresignedURL(ctx context.Context, key string, expiry int) (string, error)
}

// UploadResult represents upload result
type UploadResult struct {
	Key      string `json:"key"`
	URL      string `json:"url"`
	Size     int64  `json:"size"`
	ETag     string `json:"etag,omitempty"`
	Location string `json:"location,omitempty"`
}

// StorageService handles file storage operations
type StorageService struct {
	provider     StorageProvider
	providerType string
	bucket       string
	baseURL      string
	allowedTypes []string
	maxFileSize  int64
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	Provider     string   `json:"provider"`
	Bucket       string   `json:"bucket"`
	Region       string   `json:"region"`
	AccessKey    string   `json:"access_key"`
	SecretKey    string   `json:"secret_key"`
	Endpoint     string   `json:"endpoint,omitempty"`
	BaseURL      string   `json:"base_url"`
	AllowedTypes []string `json:"allowed_types"`
	MaxFileSize  int64    `json:"max_file_size"`
}

// NewStorageService creates a new storage service
func NewStorageService(config *StorageConfig) (*StorageService, error) {
	var provider StorageProvider
	var err error

	switch strings.ToLower(config.Provider) {
	case "s3", "aws":
		provider, err = NewS3Provider(config)
	case "spaces", "digitalocean":
		provider, err = NewDigitalOceanSpacesProvider(config)
	case "gcs", "google":
		provider, err = NewGCSProvider(config)
	case "local":
		provider, err = NewLocalProvider(config)
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", config.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage provider: %w", err)
	}

	return &StorageService{
		provider:     provider,
		providerType: config.Provider,
		bucket:       config.Bucket,
		baseURL:      config.BaseURL,
		allowedTypes: config.AllowedTypes,
		maxFileSize:  config.MaxFileSize,
	}, nil
}

// Upload uploads a file to storage
func (s *StorageService) Upload(ctx context.Context, key string, file multipart.File, header *multipart.FileHeader) (*UploadResult, error) {
	// Validate file size
	if header.Size > s.maxFileSize {
		return nil, pkg.ErrFileTooLarge
	}

	// Validate file type
	contentType := header.Header.Get("Content-Type")
	if !s.isAllowedType(contentType) {
		return nil, pkg.ErrInvalidFileType
	}

	// Upload to provider
	result, err := s.provider.Upload(ctx, key, file, header.Size, contentType)
	if err != nil {
		return nil, pkg.ErrFileUploadFailed.WithCause(err)
	}

	return result, nil
}

// Download downloads a file from storage
func (s *StorageService) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	reader, err := s.provider.Download(ctx, key)
	if err != nil {
		return nil, pkg.ErrFileNotFound.WithCause(err)
	}

	return reader, nil
}

// Delete deletes a file from storage
func (s *StorageService) Delete(ctx context.Context, key string) error {
	if err := s.provider.Delete(ctx, key); err != nil {
		return pkg.ErrStorageProviderError.WithCause(err)
	}

	return nil
}

// GetURL gets public URL for a file
func (s *StorageService) GetURL(ctx context.Context, key string) (string, error) {
	url, err := s.provider.GetURL(ctx, key)
	if err != nil {
		return "", pkg.ErrStorageProviderError.WithCause(err)
	}

	return url, nil
}

// GetPresignedURL gets presigned URL for a file
func (s *StorageService) GetPresignedURL(ctx context.Context, key string, expiry int) (string, error) {
	url, err := s.provider.GetPresignedURL(ctx, key, expiry)
	if err != nil {
		return "", pkg.ErrStorageProviderError.WithCause(err)
	}

	return url, nil
}

// isAllowedType checks if file type is allowed
func (s *StorageService) isAllowedType(contentType string) bool {
	if len(s.allowedTypes) == 0 {
		return true // Allow all types if none specified
	}

	for _, allowedType := range s.allowedTypes {
		if strings.HasPrefix(contentType, allowedType) {
			return true
		}
	}

	return false
}

// S3Provider implements S3-compatible storage
type S3Provider struct {
	s3Client   *s3.S3
	uploader   *s3manager.Uploader
	downloader *s3manager.Downloader
	bucket     string
	region     string
	baseURL    string
}

// NewS3Provider creates a new S3 provider
func NewS3Provider(config *StorageConfig) (*S3Provider, error) {
	// Create AWS session
	sess, err := session.NewSession(&aws.Config{
		Region:   aws.String(config.Region),
		Endpoint: aws.String(config.Endpoint),
		Credentials: credentials.NewStaticCredentials(
			config.AccessKey,
			config.SecretKey,
			"",
		),
		S3ForcePathStyle: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	s3Client := s3.New(sess)

	return &S3Provider{
		s3Client:   s3Client,
		uploader:   s3manager.NewUploader(sess),
		downloader: s3manager.NewDownloader(sess),
		bucket:     config.Bucket,
		region:     config.Region,
		baseURL:    config.BaseURL,
	}, nil
}

// Upload uploads file to S3
func (p *S3Provider) Upload(ctx context.Context, key string, file multipart.File, size int64, contentType string) (*UploadResult, error) {
	// Reset file pointer
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to reset file pointer: %w", err)
	}

	// Upload to S3
	result, err := p.uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket:      aws.String(p.bucket),
		Key:         aws.String(key),
		Body:        file,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload to S3: %w", err)
	}

	return &UploadResult{
		Key:      key,
		URL:      result.Location,
		Size:     size,
		ETag:     strings.Trim(*result.ETag, "\""),
		Location: result.Location,
	}, nil
}

// Download downloads file from S3
func (p *S3Provider) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	result, err := p.s3Client.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download from S3: %w", err)
	}

	return result.Body, nil
}

// Delete deletes file from S3
func (p *S3Provider) Delete(ctx context.Context, key string) error {
	_, err := p.s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	return nil
}

// GetURL gets public URL for S3 object
func (p *S3Provider) GetURL(ctx context.Context, key string) (string, error) {
	if p.baseURL != "" {
		return fmt.Sprintf("%s/%s", strings.TrimRight(p.baseURL, "/"), key), nil
	}

	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", p.bucket, p.region, key), nil
}

// GetPresignedURL gets presigned URL for S3 object
func (p *S3Provider) GetPresignedURL(ctx context.Context, key string, expiry int) (string, error) {
	req, _ := p.s3Client.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	})

	url, err := req.Presign(time.Duration(expiry) * time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	return url, nil
}

// NewDigitalOceanSpacesProvider creates DigitalOcean Spaces provider
func NewDigitalOceanSpacesProvider(config *StorageConfig) (*S3Provider, error) {
	// DigitalOcean Spaces is S3-compatible
	if config.Endpoint == "" {
		config.Endpoint = fmt.Sprintf("https://%s.digitaloceanspaces.com", config.Region)
	}
	return NewS3Provider(config)
}

// LocalProvider implements local file storage
type LocalProvider struct {
	basePath string
	baseURL  string
}

// NewLocalProvider creates a new local provider
func NewLocalProvider(config *StorageConfig) (*LocalProvider, error) {
	return &LocalProvider{
		basePath: "./storage",
		baseURL:  config.BaseURL,
	}, nil
}

// Upload uploads file to local storage
func (p *LocalProvider) Upload(ctx context.Context, key string, file multipart.File, size int64, contentType string) (*UploadResult, error) {
	// Implementation for local file storage
	// This is a simplified version - full implementation would handle directory creation, etc.
	return &UploadResult{
		Key:  key,
		URL:  fmt.Sprintf("%s/%s", p.baseURL, key),
		Size: size,
	}, nil
}

// Download downloads file from local storage
func (p *LocalProvider) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	// Implementation for local file download
	return nil, fmt.Errorf("local provider download not implemented")
}

// Delete deletes file from local storage
func (p *LocalProvider) Delete(ctx context.Context, key string) error {
	// Implementation for local file deletion
	return nil
}

// GetURL gets URL for local file
func (p *LocalProvider) GetURL(ctx context.Context, key string) (string, error) {
	return fmt.Sprintf("%s/%s", p.baseURL, key), nil
}

// GetPresignedURL gets presigned URL (not applicable for local)
func (p *LocalProvider) GetPresignedURL(ctx context.Context, key string, expiry int) (string, error) {
	return p.GetURL(ctx, key)
}

// NewGCSProvider creates Google Cloud Storage provider
func NewGCSProvider(config *StorageConfig) (*S3Provider, error) {
	// GCS can be accessed via S3-compatible API
	return NewS3Provider(config)
}
