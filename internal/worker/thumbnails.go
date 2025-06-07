package worker

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"github.com/Caqil/clouddrive/internal/models"
	"github.com/Caqil/clouddrive/internal/pkg"
	"github.com/Caqil/clouddrive/internal/repository"
	"github.com/Caqil/clouddrive/internal/services"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ThumbnailWorker handles thumbnail generation for files
type ThumbnailWorker struct {
	fileRepo       repository.FileRepository
	storageService *services.StorageService
	logger         *pkg.Logger
	config         *ThumbnailConfig
}

// ThumbnailConfig holds configuration for thumbnail generation
type ThumbnailConfig struct {
	// Size configurations
	SmallSize  ThumbnailSize `json:"smallSize"`
	MediumSize ThumbnailSize `json:"mediumSize"`
	LargeSize  ThumbnailSize `json:"largeSize"`

	// Quality settings
	JPEGQuality int `json:"jpegQuality"`
	PNGQuality  int `json:"pngQuality"`

	// Processing limits
	MaxFileSize       int64         `json:"maxFileSize"`       // Max file size to process (bytes)
	ProcessingTimeout time.Duration `json:"processingTimeout"` // Max time to spend processing one file
	BatchSize         int           `json:"batchSize"`         // Number of files to process per batch

	// Storage settings
	ThumbnailPath   string `json:"thumbnailPath"`   // Base path for thumbnails
	ThumbnailPrefix string `json:"thumbnailPrefix"` // Prefix for thumbnail files

	// Feature flags
	EnableImageThumbnails    bool `json:"enableImageThumbnails"`
	EnableVideoThumbnails    bool `json:"enableVideoThumbnails"`
	EnableDocumentThumbnails bool `json:"enableDocumentThumbnails"`
	EnablePDFThumbnails      bool `json:"enablePDFThumbnails"`

	// Supported formats
	SupportedImageFormats    []string `json:"supportedImageFormats"`
	SupportedVideoFormats    []string `json:"supportedVideoFormats"`
	SupportedDocumentFormats []string `json:"supportedDocumentFormats"`
}

// ThumbnailSize represents thumbnail dimensions
type ThumbnailSize struct {
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Name   string `json:"name"`
}

// ThumbnailJob represents a thumbnail generation job
type ThumbnailJob struct {
	ID           primitive.ObjectID `json:"id"`
	FileID       primitive.ObjectID `json:"fileId"`
	FileName     string             `json:"fileName"`
	MimeType     string             `json:"mimeType"`
	StoragePath  string             `json:"storagePath"`
	Size         int64              `json:"size"`
	Priority     ThumbnailPriority  `json:"priority"`
	Status       ThumbnailStatus    `json:"status"`
	Attempts     int                `json:"attempts"`
	MaxAttempts  int                `json:"maxAttempts"`
	ErrorMessage string             `json:"errorMessage,omitempty"`
	CreatedAt    time.Time          `json:"createdAt"`
	ProcessedAt  *time.Time         `json:"processedAt,omitempty"`
	CompletedAt  *time.Time         `json:"completedAt,omitempty"`
}

// ThumbnailPriority represents processing priority
type ThumbnailPriority int

const (
	ThumbnailPriorityLow ThumbnailPriority = iota
	ThumbnailPriorityNormal
	ThumbnailPriorityHigh
	ThumbnailPriorityCritical
)

// ThumbnailStatus represents processing status
type ThumbnailStatus string

const (
	ThumbnailStatusPending    ThumbnailStatus = "pending"
	ThumbnailStatusProcessing ThumbnailStatus = "processing"
	ThumbnailStatusCompleted  ThumbnailStatus = "completed"
	ThumbnailStatusFailed     ThumbnailStatus = "failed"
	ThumbnailStatusSkipped    ThumbnailStatus = "skipped"
)

// ThumbnailResult represents the result of thumbnail generation
type ThumbnailResult struct {
	FileID         primitive.ObjectID     `json:"fileId"`
	Thumbnails     []models.FileThumbnail `json:"thumbnails"`
	Success        bool                   `json:"success"`
	Error          string                 `json:"error,omitempty"`
	ProcessingTime time.Duration          `json:"processingTime"`
}

// NewThumbnailWorker creates a new thumbnail worker
func NewThumbnailWorker(
	fileRepo repository.FileRepository,
	storageService *services.StorageService,
	logger *pkg.Logger,
) *ThumbnailWorker {
	return &ThumbnailWorker{
		fileRepo:       fileRepo,
		storageService: storageService,
		logger:         logger,
		config:         DefaultThumbnailConfig(),
	}
}

// DefaultThumbnailConfig returns default thumbnail configuration
func DefaultThumbnailConfig() *ThumbnailConfig {
	return &ThumbnailConfig{
		SmallSize:  ThumbnailSize{Width: 150, Height: 150, Name: "small"},
		MediumSize: ThumbnailSize{Width: 300, Height: 300, Name: "medium"},
		LargeSize:  ThumbnailSize{Width: 800, Height: 600, Name: "large"},

		JPEGQuality: 85,
		PNGQuality:  90,

		MaxFileSize:       100 * 1024 * 1024, // 100MB
		ProcessingTimeout: 5 * time.Minute,
		BatchSize:         50,

		ThumbnailPath:   "thumbnails",
		ThumbnailPrefix: "thumb_",

		EnableImageThumbnails:    true,
		EnableVideoThumbnails:    true,
		EnableDocumentThumbnails: false, // Requires additional dependencies
		EnablePDFThumbnails:      false, // Requires additional dependencies

		SupportedImageFormats:    []string{"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp", "image/tiff"},
		SupportedVideoFormats:    []string{"video/mp4", "video/webm", "video/ogg", "video/avi", "video/mov", "video/wmv"},
		SupportedDocumentFormats: []string{"application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	}
}

// ProcessPendingThumbnails processes files that need thumbnails
func (w *ThumbnailWorker) ProcessPendingThumbnails(ctx context.Context) error {
	w.logger.Info("Starting thumbnail processing", map[string]interface{}{
		"batch_size": w.config.BatchSize,
	})

	// Get files that need thumbnail processing
	jobs, err := w.getPendingThumbnailJobs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get pending thumbnail jobs: %w", err)
	}

	if len(jobs) == 0 {
		w.logger.Info("No pending thumbnail jobs found")
		return nil
	}

	w.logger.Info("Found pending thumbnail jobs", map[string]interface{}{
		"job_count": len(jobs),
	})

	var processed, successful, failed int64

	// Process jobs by priority
	for priority := ThumbnailPriorityCritical; priority >= ThumbnailPriorityLow; priority-- {
		priorityJobs := w.getJobsByPriority(jobs, priority)

		for _, job := range priorityJobs {
			if processed >= int64(w.config.BatchSize) {
				w.logger.Info("Reached batch size limit", map[string]interface{}{
					"processed":  processed,
					"batch_size": w.config.BatchSize,
				})
				break
			}

			result := w.processJob(ctx, job)
			if result.Success {
				successful++
			} else {
				failed++
				w.logger.Error("Failed to process thumbnail job", map[string]interface{}{
					"job_id":  job.ID.Hex(),
					"file_id": job.FileID.Hex(),
					"error":   result.Error,
				})
			}

			processed++
		}
	}

	w.logger.Info("Completed thumbnail processing batch", map[string]interface{}{
		"processed":  processed,
		"successful": successful,
		"failed":     failed,
	})

	return nil
}

// GenerateThumbnailsForFile generates thumbnails for a specific file
func (w *ThumbnailWorker) GenerateThumbnailsForFile(ctx context.Context, fileID primitive.ObjectID) (*ThumbnailResult, error) {
	w.logger.Info("Generating thumbnails for file", map[string]interface{}{
		"file_id": fileID.Hex(),
	})

	// Get file details
	file, err := w.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return &ThumbnailResult{
			FileID:  fileID,
			Success: false,
			Error:   fmt.Sprintf("failed to get file: %v", err),
		}, nil
	}

	// Create job
	job := &ThumbnailJob{
		ID:          primitive.NewObjectID(),
		FileID:      file.ID,
		FileName:    file.Name,
		MimeType:    file.MimeType,
		StoragePath: file.StoragePath,
		Size:        file.Size,
		Priority:    ThumbnailPriorityHigh,
		Status:      ThumbnailStatusPending,
		MaxAttempts: 3,
		CreatedAt:   time.Now(),
	}

	return w.processJob(ctx, job), nil
}

// RegenerateThumbnails regenerates thumbnails for files with existing thumbnails
func (w *ThumbnailWorker) RegenerateThumbnails(ctx context.Context, fileIDs []primitive.ObjectID) error {
	w.logger.Info("Regenerating thumbnails", map[string]interface{}{
		"file_count": len(fileIDs),
	})

	var processed, successful, failed int64

	for _, fileID := range fileIDs {
		// Delete existing thumbnails
		if err := w.deleteExistingThumbnails(ctx, fileID); err != nil {
			w.logger.Error("Failed to delete existing thumbnails", map[string]interface{}{
				"file_id": fileID.Hex(),
				"error":   err.Error(),
			})
		}

		// Generate new thumbnails
		result, err := w.GenerateThumbnailsForFile(ctx, fileID)
		if err != nil {
			w.logger.Error("Failed to regenerate thumbnails", map[string]interface{}{
				"file_id": fileID.Hex(),
				"error":   err.Error(),
			})
			failed++
			continue
		}

		if result.Success {
			successful++
		} else {
			failed++
		}

		processed++
	}

	w.logger.Info("Completed thumbnail regeneration", map[string]interface{}{
		"processed":  processed,
		"successful": successful,
		"failed":     failed,
	})

	return nil
}

// CleanupOrphanedThumbnails removes thumbnails for files that no longer exist
func (w *ThumbnailWorker) CleanupOrphanedThumbnails(ctx context.Context) error {
	w.logger.Info("Starting orphaned thumbnails cleanup")

	// This would list all thumbnail files in storage and check if corresponding files exist
	// For now, we'll implement a simplified version

	params := &pkg.PaginationParams{Page: 1, Limit: 1000}
	files, _, err := w.fileRepo.List(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to get files: %w", err)
	}

	var cleaned int64

	for _, file := range files {
		if len(file.Thumbnails) == 0 {
			continue
		}

		// Check if thumbnail files actually exist in storage
		var validThumbnails []models.FileThumbnail
		var thumbnailsToDelete []string

		for _, thumbnail := range file.Thumbnails {
			// Check if thumbnail exists in storage (simplified check)
			if thumbnail.Path != "" {
				validThumbnails = append(validThumbnails, thumbnail)
			} else {
				thumbnailsToDelete = append(thumbnailsToDelete, thumbnail.Path)
			}
		}

		// Delete orphaned thumbnails from storage
		for _, path := range thumbnailsToDelete {
			if err := w.storageService.Delete(ctx, path); err != nil {
				w.logger.Error("Failed to delete orphaned thumbnail", map[string]interface{}{
					"file_id":        file.ID.Hex(),
					"thumbnail_path": path,
					"error":          err.Error(),
				})
			} else {
				cleaned++
			}
		}

		// Update file with valid thumbnails if any were removed
		if len(validThumbnails) != len(file.Thumbnails) {
			updates := map[string]interface{}{
				"thumbnails": validThumbnails,
			}
			if err := w.fileRepo.Update(ctx, file.ID, updates); err != nil {
				w.logger.Error("Failed to update file thumbnails", map[string]interface{}{
					"file_id": file.ID.Hex(),
					"error":   err.Error(),
				})
			}
		}
	}

	w.logger.Info("Completed orphaned thumbnails cleanup", map[string]interface{}{
		"cleaned": cleaned,
	})

	return nil
}

// Core processing methods

// processJob processes a single thumbnail job
func (w *ThumbnailWorker) processJob(ctx context.Context, job *ThumbnailJob) *ThumbnailResult {
	startTime := time.Now()

	result := &ThumbnailResult{
		FileID:  job.FileID,
		Success: false,
	}

	// Update job status
	job.Status = ThumbnailStatusProcessing
	job.Attempts++
	processedAt := time.Now()
	job.ProcessedAt = &processedAt

	w.logger.Info("Processing thumbnail job", map[string]interface{}{
		"job_id":    job.ID.Hex(),
		"file_id":   job.FileID.Hex(),
		"file_name": job.FileName,
		"mime_type": job.MimeType,
		"attempt":   job.Attempts,
	})

	// Check if file is suitable for thumbnail generation
	if !w.canGenerateThumbnail(job) {
		job.Status = ThumbnailStatusSkipped
		result.Error = "file type not supported for thumbnail generation"
		w.logger.Info("Skipping thumbnail generation", map[string]interface{}{
			"file_id":   job.FileID.Hex(),
			"mime_type": job.MimeType,
			"reason":    result.Error,
		})
		return result
	}

	// Set processing timeout
	jobCtx, cancel := context.WithTimeout(ctx, w.config.ProcessingTimeout)
	defer cancel()

	// Download file from storage
	fileReader, err := w.storageService.Download(jobCtx, job.StoragePath)
	if err != nil {
		job.Status = ThumbnailStatusFailed
		job.ErrorMessage = fmt.Sprintf("failed to download file: %v", err)
		result.Error = job.ErrorMessage
		return result
	}
	defer fileReader.Close()

	// Generate thumbnails based on file type
	var thumbnails []models.FileThumbnail

	if w.isImageFile(job.MimeType) && w.config.EnableImageThumbnails {
		thumbnails, err = w.generateImageThumbnails(jobCtx, job, fileReader)
	} else if w.isVideoFile(job.MimeType) && w.config.EnableVideoThumbnails {
		thumbnails, err = w.generateVideoThumbnails(jobCtx, job, fileReader)
	} else if w.isDocumentFile(job.MimeType) && w.config.EnableDocumentThumbnails {
		thumbnails, err = w.generateDocumentThumbnails(jobCtx, job, fileReader)
	} else {
		job.Status = ThumbnailStatusSkipped
		result.Error = "thumbnail generation not enabled for this file type"
		return result
	}

	if err != nil {
		job.Status = ThumbnailStatusFailed
		job.ErrorMessage = err.Error()
		result.Error = err.Error()

		// Check if should retry
		if job.Attempts < job.MaxAttempts {
			w.logger.Info("Will retry thumbnail generation", map[string]interface{}{
				"job_id":       job.ID.Hex(),
				"attempt":      job.Attempts,
				"max_attempts": job.MaxAttempts,
			})
		}

		return result
	}

	// Update file with generated thumbnails
	if len(thumbnails) > 0 {
		updates := map[string]interface{}{
			"thumbnails": thumbnails,
		}
		if err := w.fileRepo.Update(jobCtx, job.FileID, updates); err != nil {
			job.Status = ThumbnailStatusFailed
			job.ErrorMessage = fmt.Sprintf("failed to update file with thumbnails: %v", err)
			result.Error = job.ErrorMessage
			return result
		}
	}

	// Mark job as completed
	job.Status = ThumbnailStatusCompleted
	completedAt := time.Now()
	job.CompletedAt = &completedAt

	result.Success = true
	result.Thumbnails = thumbnails
	result.ProcessingTime = time.Since(startTime)

	w.logger.Info("Successfully generated thumbnails", map[string]interface{}{
		"job_id":           job.ID.Hex(),
		"file_id":          job.FileID.Hex(),
		"thumbnails_count": len(thumbnails),
		"processing_time":  result.ProcessingTime.String(),
	})

	return result
}

// generateImageThumbnails generates thumbnails for image files
func (w *ThumbnailWorker) generateImageThumbnails(ctx context.Context, job *ThumbnailJob, reader io.Reader) ([]models.FileThumbnail, error) {
	w.logger.Info("Generating image thumbnails", map[string]interface{}{
		"file_id": job.FileID.Hex(),
	})

	// Read image data
	imageData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read image data: %w", err)
	}

	// Decode image
	img, format, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	w.logger.Info("Decoded image", map[string]interface{}{
		"file_id": job.FileID.Hex(),
		"format":  format,
		"bounds":  img.Bounds(),
	})

	var thumbnails []models.FileThumbnail
	sizes := []ThumbnailSize{w.config.SmallSize, w.config.MediumSize, w.config.LargeSize}

	for _, size := range sizes {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		thumbnail, err := w.generateImageThumbnailSize(ctx, job, img, size, format)
		if err != nil {
			w.logger.Error("Failed to generate thumbnail size", map[string]interface{}{
				"file_id": job.FileID.Hex(),
				"size":    size.Name,
				"error":   err.Error(),
			})
			continue
		}

		thumbnails = append(thumbnails, *thumbnail)
	}

	return thumbnails, nil
}

// generateImageThumbnailSize generates a thumbnail of specific size
func (w *ThumbnailWorker) generateImageThumbnailSize(ctx context.Context, job *ThumbnailJob, img image.Image, size ThumbnailSize, format string) (*models.FileThumbnail, error) {
	// Calculate thumbnail dimensions maintaining aspect ratio
	bounds := img.Bounds()
	origWidth := bounds.Dx()
	origHeight := bounds.Dy()

	var newWidth, newHeight int
	if origWidth > origHeight {
		newWidth = size.Width
		newHeight = (origHeight * size.Width) / origWidth
	} else {
		newHeight = size.Height
		newWidth = (origWidth * size.Height) / origHeight
	}

	// Create thumbnail image
	thumbnailImg := w.resizeImage(img, newWidth, newHeight)

	// Generate storage path
	thumbnailPath := w.generateThumbnailPath(job, size.Name)

	// Encode thumbnail
	var buf bytes.Buffer
	var encodeErr error

	switch strings.ToLower(format) {
	case "jpeg", "jpg":
		encodeErr = jpeg.Encode(&buf, thumbnailImg, &jpeg.Options{Quality: w.config.JPEGQuality})
	case "png":
		encodeErr = png.Encode(&buf, thumbnailImg)
	default:
		// Default to JPEG for other formats
		encodeErr = jpeg.Encode(&buf, thumbnailImg, &jpeg.Options{Quality: w.config.JPEGQuality})
	}

	if encodeErr != nil {
		return nil, fmt.Errorf("failed to encode thumbnail: %w", encodeErr)
	}

	// Upload thumbnail to storage
	thumbnailReader := bytes.NewReader(buf.Bytes())

	// Create a multipart file header for upload
	header := &multipart.FileHeader{
		Filename: fmt.Sprintf("%s_%s.jpg", w.config.ThumbnailPrefix, size.Name),
		Size:     int64(buf.Len()),
		Header:   make(map[string][]string),
	}
	header.Header.Set("Content-Type", "image/jpeg")

	uploadResult, err := w.storageService.Upload(ctx, thumbnailPath, thumbnailReader, header)
	if err != nil {
		return nil, fmt.Errorf("failed to upload thumbnail: %w", err)
	}

	// Generate public URL
	thumbnailURL, err := w.storageService.GetURL(ctx, thumbnailPath)
	if err != nil {
		w.logger.Error("Failed to get thumbnail URL", map[string]interface{}{
			"path":  thumbnailPath,
			"error": err.Error(),
		})
		thumbnailURL = ""
	}

	return &models.FileThumbnail{
		Size: size.Name,
		Path: thumbnailPath,
		URL:  thumbnailURL,
	}, nil
}

// generateVideoThumbnails generates thumbnails for video files
func (w *ThumbnailWorker) generateVideoThumbnails(ctx context.Context, job *ThumbnailJob, reader io.Reader) ([]models.FileThumbnail, error) {
	w.logger.Info("Generating video thumbnails", map[string]interface{}{
		"file_id": job.FileID.Hex(),
	})

	// Video thumbnail generation would require FFmpeg or similar
	// For now, return a placeholder implementation

	// In a real implementation, you would:
	// 1. Save the video file temporarily
	// 2. Use FFmpeg to extract frames at specific timestamps
	// 3. Generate thumbnails from those frames
	// 4. Clean up temporary files

	// Placeholder implementation - would need actual video processing
	var thumbnails []models.FileThumbnail

	// Generate placeholder thumbnails
	sizes := []ThumbnailSize{w.config.SmallSize, w.config.MediumSize, w.config.LargeSize}

	for _, size := range sizes {
		placeholder, err := w.generateVideoPlaceholderThumbnail(ctx, job, size)
		if err != nil {
			w.logger.Error("Failed to generate video placeholder thumbnail", map[string]interface{}{
				"file_id": job.FileID.Hex(),
				"size":    size.Name,
				"error":   err.Error(),
			})
			continue
		}

		thumbnails = append(thumbnails, *placeholder)
	}

	return thumbnails, nil
}

// generateVideoPlaceholderThumbnail generates a placeholder thumbnail for videos
func (w *ThumbnailWorker) generateVideoPlaceholderThumbnail(ctx context.Context, job *ThumbnailJob, size ThumbnailSize) (*models.FileThumbnail, error) {
	// Create a simple colored rectangle as placeholder
	img := w.createVideoPlaceholderImage(size.Width, size.Height)

	// Generate storage path
	thumbnailPath := w.generateThumbnailPath(job, size.Name)

	// Encode as JPEG
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: w.config.JPEGQuality}); err != nil {
		return nil, fmt.Errorf("failed to encode placeholder thumbnail: %w", err)
	}

	// Upload to storage
	thumbnailReader := bytes.NewReader(buf.Bytes())
	header := &multipart.FileHeader{
		Filename: fmt.Sprintf("%s_%s.jpg", w.config.ThumbnailPrefix, size.Name),
		Size:     int64(buf.Len()),
		Header:   make(map[string][]string),
	}
	header.Header.Set("Content-Type", "image/jpeg")

	_, err := w.storageService.Upload(ctx, thumbnailPath, thumbnailReader, header)
	if err != nil {
		return nil, fmt.Errorf("failed to upload placeholder thumbnail: %w", err)
	}

	// Generate public URL
	thumbnailURL, err := w.storageService.GetURL(ctx, thumbnailPath)
	if err != nil {
		thumbnailURL = ""
	}

	return &models.FileThumbnail{
		Size: size.Name,
		Path: thumbnailPath,
		URL:  thumbnailURL,
	}, nil
}

// generateDocumentThumbnails generates thumbnails for document files
func (w *ThumbnailWorker) generateDocumentThumbnails(ctx context.Context, job *ThumbnailJob, reader io.Reader) ([]models.FileThumbnail, error) {
	w.logger.Info("Generating document thumbnails", map[string]interface{}{
		"file_id": job.FileID.Hex(),
	})

	// Document thumbnail generation would require libraries like:
	// - PDF: pdfium, poppler, or similar
	// - Word/Excel: libreoffice, pandoc, or similar
	// - PowerPoint: libreoffice or similar

	// For now, return placeholder implementation
	var thumbnails []models.FileThumbnail
	sizes := []ThumbnailSize{w.config.SmallSize, w.config.MediumSize, w.config.LargeSize}

	for _, size := range sizes {
		placeholder, err := w.generateDocumentPlaceholderThumbnail(ctx, job, size)
		if err != nil {
			w.logger.Error("Failed to generate document placeholder thumbnail", map[string]interface{}{
				"file_id": job.FileID.Hex(),
				"size":    size.Name,
				"error":   err.Error(),
			})
			continue
		}

		thumbnails = append(thumbnails, *placeholder)
	}

	return thumbnails, nil
}

// generateDocumentPlaceholderThumbnail generates a placeholder thumbnail for documents
func (w *ThumbnailWorker) generateDocumentPlaceholderThumbnail(ctx context.Context, job *ThumbnailJob, size ThumbnailSize) (*models.FileThumbnail, error) {
	// Create a document-style placeholder
	img := w.createDocumentPlaceholderImage(size.Width, size.Height)

	// Generate storage path
	thumbnailPath := w.generateThumbnailPath(job, size.Name)

	// Encode as JPEG
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: w.config.JPEGQuality}); err != nil {
		return nil, fmt.Errorf("failed to encode document placeholder: %w", err)
	}

	// Upload to storage
	thumbnailReader := bytes.NewReader(buf.Bytes())
	header := &multipart.FileHeader{
		Filename: fmt.Sprintf("%s_%s.jpg", w.config.ThumbnailPrefix, size.Name),
		Size:     int64(buf.Len()),
		Header:   make(map[string][]string),
	}
	header.Header.Set("Content-Type", "image/jpeg")

	_, err := w.storageService.Upload(ctx, thumbnailPath, thumbnailReader, header)
	if err != nil {
		return nil, fmt.Errorf("failed to upload document placeholder: %w", err)
	}

	// Generate public URL
	thumbnailURL, err := w.storageService.GetURL(ctx, thumbnailPath)
	if err != nil {
		thumbnailURL = ""
	}

	return &models.FileThumbnail{
		Size: size.Name,
		Path: thumbnailPath,
		URL:  thumbnailURL,
	}, nil
}

// Helper methods

// getPendingThumbnailJobs gets files that need thumbnail processing
func (w *ThumbnailWorker) getPendingThumbnailJobs(ctx context.Context) ([]*ThumbnailJob, error) {
	// Get files without thumbnails
	params := &pkg.PaginationParams{
		Page:  1,
		Limit: w.config.BatchSize * 2, // Get more than batch size to have options
		Filter: map[string]interface{}{
			"thumbnails_empty": true,
		},
	}

	files, _, err := w.fileRepo.List(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get files without thumbnails: %w", err)
	}

	var jobs []*ThumbnailJob

	for _, file := range files {
		// Skip files that are too large
		if file.Size > w.config.MaxFileSize {
			continue
		}

		// Skip files that don't support thumbnails
		if !w.isFileTypeSupported(file.MimeType) {
			continue
		}

		// Determine priority based on file type and recency
		priority := w.calculateJobPriority(file)

		job := &ThumbnailJob{
			ID:          primitive.NewObjectID(),
			FileID:      file.ID,
			FileName:    file.Name,
			MimeType:    file.MimeType,
			StoragePath: file.StoragePath,
			Size:        file.Size,
			Priority:    priority,
			Status:      ThumbnailStatusPending,
			MaxAttempts: 3,
			CreatedAt:   time.Now(),
		}

		jobs = append(jobs, job)
	}

	return jobs, nil
}

// getJobsByPriority filters jobs by priority level
func (w *ThumbnailWorker) getJobsByPriority(jobs []*ThumbnailJob, priority ThumbnailPriority) []*ThumbnailJob {
	var filtered []*ThumbnailJob
	for _, job := range jobs {
		if job.Priority == priority {
			filtered = append(filtered, job)
		}
	}
	return filtered
}

// canGenerateThumbnail checks if a file can have thumbnails generated
func (w *ThumbnailWorker) canGenerateThumbnail(job *ThumbnailJob) bool {
	// Check file size
	if job.Size > w.config.MaxFileSize {
		return false
	}

	// Check if file type is supported
	return w.isFileTypeSupported(job.MimeType)
}

// isFileTypeSupported checks if the file type is supported for thumbnail generation
func (w *ThumbnailWorker) isFileTypeSupported(mimeType string) bool {
	if w.isImageFile(mimeType) && w.config.EnableImageThumbnails {
		return true
	}
	if w.isVideoFile(mimeType) && w.config.EnableVideoThumbnails {
		return true
	}
	if w.isDocumentFile(mimeType) && w.config.EnableDocumentThumbnails {
		return true
	}
	return false
}

// isImageFile checks if the file is an image
func (w *ThumbnailWorker) isImageFile(mimeType string) bool {
	for _, supportedType := range w.config.SupportedImageFormats {
		if mimeType == supportedType {
			return true
		}
	}
	return false
}

// isVideoFile checks if the file is a video
func (w *ThumbnailWorker) isVideoFile(mimeType string) bool {
	for _, supportedType := range w.config.SupportedVideoFormats {
		if mimeType == supportedType {
			return true
		}
	}
	return false
}

// isDocumentFile checks if the file is a document
func (w *ThumbnailWorker) isDocumentFile(mimeType string) bool {
	for _, supportedType := range w.config.SupportedDocumentFormats {
		if mimeType == supportedType {
			return true
		}
	}
	return false
}

// calculateJobPriority determines the priority for a thumbnail job
func (w *ThumbnailWorker) calculateJobPriority(file *models.File) ThumbnailPriority {
	// Recent files get higher priority
	if time.Since(file.CreatedAt) < 1*time.Hour {
		return ThumbnailPriorityHigh
	}

	// Images get higher priority than videos/documents
	if w.isImageFile(file.MimeType) {
		return ThumbnailPriorityNormal
	}

	// Large files get lower priority
	if file.Size > 50*1024*1024 { // 50MB
		return ThumbnailPriorityLow
	}

	return ThumbnailPriorityNormal
}

// generateThumbnailPath generates the storage path for a thumbnail
func (w *ThumbnailWorker) generateThumbnailPath(job *ThumbnailJob, sizeName string) string {
	fileExt := filepath.Ext(job.FileName)
	baseName := strings.TrimSuffix(job.FileName, fileExt)

	return fmt.Sprintf("%s/%s/%s_%s_%s.jpg",
		w.config.ThumbnailPath,
		job.FileID.Hex(),
		w.config.ThumbnailPrefix,
		baseName,
		sizeName,
	)
}

// deleteExistingThumbnails deletes existing thumbnails for a file
func (w *ThumbnailWorker) deleteExistingThumbnails(ctx context.Context, fileID primitive.ObjectID) error {
	file, err := w.fileRepo.GetByID(ctx, fileID)
	if err != nil {
		return fmt.Errorf("failed to get file: %w", err)
	}

	// Delete thumbnail files from storage
	for _, thumbnail := range file.Thumbnails {
		if err := w.storageService.Delete(ctx, thumbnail.Path); err != nil {
			w.logger.Error("Failed to delete thumbnail from storage", map[string]interface{}{
				"file_id":        fileID.Hex(),
				"thumbnail_path": thumbnail.Path,
				"error":          err.Error(),
			})
		}
	}

	// Clear thumbnails from file record
	updates := map[string]interface{}{
		"thumbnails": []models.FileThumbnail{},
	}

	return w.fileRepo.Update(ctx, fileID, updates)
}

// Image processing utilities

// resizeImage resizes an image using simple nearest neighbor algorithm
func (w *ThumbnailWorker) resizeImage(src image.Image, width, height int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	bounds := src.Bounds()

	scaleX := float64(bounds.Dx()) / float64(width)
	scaleY := float64(bounds.Dy()) / float64(height)

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			srcX := int(float64(x) * scaleX)
			srcY := int(float64(y) * scaleY)

			if srcX >= bounds.Dx() {
				srcX = bounds.Dx() - 1
			}
			if srcY >= bounds.Dy() {
				srcY = bounds.Dy() - 1
			}

			dst.Set(x, y, src.At(bounds.Min.X+srcX, bounds.Min.Y+srcY))
		}
	}

	return dst
}

// createVideoPlaceholderImage creates a placeholder image for videos
func (w *ThumbnailWorker) createVideoPlaceholderImage(width, height int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Fill with dark gray background
	darkGray := image.Uniform{C: image.NewColorRGBA(64, 64, 64, 255)}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, darkGray.C)
		}
	}

	// Add play button icon (simplified)
	centerX, centerY := width/2, height/2
	playSize := min(width, height) / 4

	white := image.NewColorRGBA(255, 255, 255, 255)

	// Draw simple triangle (play button)
	for y := centerY - playSize/2; y < centerY+playSize/2; y++ {
		for x := centerX - playSize/3; x < centerX+playSize/3; x++ {
			// Simple triangle approximation
			if x > centerX-playSize/3+(y-(centerY-playSize/2))*2/3 {
				img.Set(x, y, white)
			}
		}
	}

	return img
}

// createDocumentPlaceholderImage creates a placeholder image for documents
func (w *ThumbnailWorker) createDocumentPlaceholderImage(width, height int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Fill with light gray background
	lightGray := image.Uniform{C: image.NewColorRGBA(240, 240, 240, 255)}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, lightGray.C)
		}
	}

	// Add document-like lines
	darkGray := image.NewColorRGBA(160, 160, 160, 255)
	lineHeight := height / 10

	for line := 2; line < 8; line++ {
		y := line * lineHeight
		for x := width / 8; x < width*7/8; x++ {
			if y < height {
				img.Set(x, y, darkGray)
			}
		}
	}

	return img
}

// Utility function for minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetThumbnailStats returns statistics about thumbnail processing
func (w *ThumbnailWorker) GetThumbnailStats(ctx context.Context) (map[string]interface{}, error) {
	// Get files with and without thumbnails
	params := &pkg.PaginationParams{Page: 1, Limit: 1}

	// Files with thumbnails
	paramsWithThumbs := &pkg.PaginationParams{
		Page:   1,
		Limit:  1,
		Filter: map[string]interface{}{"has_thumbnails": true},
	}

	// Files without thumbnails
	paramsWithoutThumbs := &pkg.PaginationParams{
		Page:   1,
		Limit:  1,
		Filter: map[string]interface{}{"thumbnails_empty": true},
	}

	_, totalFiles, err := w.fileRepo.List(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get total files: %w", err)
	}

	_, filesWithThumbnails, err := w.fileRepo.List(ctx, paramsWithThumbs)
	if err != nil {
		return nil, fmt.Errorf("failed to get files with thumbnails: %w", err)
	}

	_, filesWithoutThumbnails, err := w.fileRepo.List(ctx, paramsWithoutThumbs)
	if err != nil {
		return nil, fmt.Errorf("failed to get files without thumbnails: %w", err)
	}

	completion := float64(0)
	if totalFiles > 0 {
		completion = float64(filesWithThumbnails) / float64(totalFiles) * 100
	}

	return map[string]interface{}{
		"total_files":              totalFiles,
		"files_with_thumbnails":    filesWithThumbnails,
		"files_without_thumbnails": filesWithoutThumbnails,
		"completion_percentage":    completion,
		"config":                   w.config,
	}, nil
}
