package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type File struct {
	ID              primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Name            string              `bson:"name" json:"name" validate:"required,min=1,max=255"`
	OriginalName    string              `bson:"original_name" json:"originalName"`
	Path            string              `bson:"path" json:"path"`
	StoragePath     string              `bson:"storage_path" json:"-"`
	FolderID        *primitive.ObjectID `bson:"folder_id,omitempty" json:"folderId,omitempty"`
	UserID          primitive.ObjectID  `bson:"user_id" json:"userId"`
	Size            int64               `bson:"size" json:"size"`
	MimeType        string              `bson:"mime_type" json:"mimeType"`
	Extension       string              `bson:"extension" json:"extension"`
	Hash            string              `bson:"hash" json:"hash"`
	Checksum        string              `bson:"checksum" json:"checksum"`
	EncryptionKey   string              `bson:"encryption_key" json:"-"`
	IsEncrypted     bool                `bson:"is_encrypted" json:"isEncrypted"`
	IsPublic        bool                `bson:"is_public" json:"isPublic"`
	IsFavorite      bool                `bson:"is_favorite" json:"isFavorite"`
	Description     string              `bson:"description" json:"description"`
	Tags            []string            `bson:"tags" json:"tags"`
	Metadata        FileMetadata        `bson:"metadata" json:"metadata"`
	Versions        []FileVersion       `bson:"versions" json:"versions"`
	Thumbnails      []FileThumbnail     `bson:"thumbnails" json:"thumbnails"`
	ShareCount      int64               `bson:"share_count" json:"shareCount"`
	DownloadCount   int64               `bson:"download_count" json:"downloadCount"`
	ViewCount       int64               `bson:"view_count" json:"viewCount"`
	LastAccessedAt  *time.Time          `bson:"last_accessed_at" json:"lastAccessedAt,omitempty"`
	LastModifiedAt  time.Time           `bson:"last_modified_at" json:"lastModifiedAt"`
	VirusScanStatus VirusScanStatus     `bson:"virus_scan_status" json:"virusScanStatus"`
	VirusScanResult string              `bson:"virus_scan_result" json:"virusScanResult"`
	CreatedAt       time.Time           `bson:"created_at" json:"createdAt"`
	UpdatedAt       time.Time           `bson:"updated_at" json:"updatedAt"`
	DeletedAt       *time.Time          `bson:"deleted_at,omitempty" json:"deletedAt,omitempty"`
}

type FileMetadata struct {
	Width       int                    `bson:"width,omitempty" json:"width,omitempty"`
	Height      int                    `bson:"height,omitempty" json:"height,omitempty"`
	Duration    float64                `bson:"duration,omitempty" json:"duration,omitempty"`
	Bitrate     int                    `bson:"bitrate,omitempty" json:"bitrate,omitempty"`
	ColorSpace  string                 `bson:"color_space,omitempty" json:"colorSpace,omitempty"`
	Compression string                 `bson:"compression,omitempty" json:"compression,omitempty"`
	EXIF        map[string]interface{} `bson:"exif,omitempty" json:"exif,omitempty"`
	GPS         *GPSMetadata           `bson:"gps,omitempty" json:"gps,omitempty"`
	Author      string                 `bson:"author,omitempty" json:"author,omitempty"`
	Title       string                 `bson:"title,omitempty" json:"title,omitempty"`
	Subject     string                 `bson:"subject,omitempty" json:"subject,omitempty"`
	Keywords    []string               `bson:"keywords,omitempty" json:"keywords,omitempty"`
	Language    string                 `bson:"language,omitempty" json:"language,omitempty"`
	PageCount   int                    `bson:"page_count,omitempty" json:"pageCount,omitempty"`
}

type GPSMetadata struct {
	Latitude  float64 `bson:"latitude" json:"latitude"`
	Longitude float64 `bson:"longitude" json:"longitude"`
	Altitude  float64 `bson:"altitude" json:"altitude"`
}

type FileVersion struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Version   int                `bson:"version" json:"version"`
	Size      int64              `bson:"size" json:"size"`
	Hash      string             `bson:"hash" json:"hash"`
	Path      string             `bson:"path" json:"path"`
	Comment   string             `bson:"comment" json:"comment"`
	CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
}

type FileThumbnail struct {
	Size string `bson:"size" json:"size"` // small, medium, large
	Path string `bson:"path" json:"path"`
	URL  string `bson:"url" json:"url"`
}

type VirusScanStatus string

const (
	ScanPending  VirusScanStatus = "pending"
	ScanComplete VirusScanStatus = "complete"
	ScanFailed   VirusScanStatus = "failed"
	ScanSkipped  VirusScanStatus = "skipped"
)
