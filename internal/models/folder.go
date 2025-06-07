package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Folder struct {
	ID          primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Name        string              `bson:"name" json:"name" validate:"required,min=1,max=255"`
	Path        string              `bson:"path" json:"path"`
	ParentID    *primitive.ObjectID `bson:"parent_id,omitempty" json:"parentId,omitempty"`
	UserID      primitive.ObjectID  `bson:"user_id" json:"userId"`
	IsRoot      bool                `bson:"is_root" json:"isRoot"`
	IsPublic    bool                `bson:"is_public" json:"isPublic"`
	IsFavorite  bool                `bson:"is_favorite" json:"isFavorite"`
	Color       string              `bson:"color" json:"color"`
	Description string              `bson:"description" json:"description"`
	Tags        []string            `bson:"tags" json:"tags"`
	FileCount   int64               `bson:"file_count" json:"fileCount"`
	FolderCount int64               `bson:"folder_count" json:"folderCount"`
	Size        int64               `bson:"size" json:"size"`
	ShareCount  int64               `bson:"share_count" json:"shareCount"`
	Permissions []FolderPermission  `bson:"permissions" json:"permissions"`
	CreatedAt   time.Time           `bson:"created_at" json:"createdAt"`
	UpdatedAt   time.Time           `bson:"updated_at" json:"updatedAt"`
	DeletedAt   *time.Time          `bson:"deleted_at,omitempty" json:"deletedAt,omitempty"`
}

type FolderPermission struct {
	UserID     primitive.ObjectID `bson:"user_id" json:"userId"`
	Permission PermissionType     `bson:"permission" json:"permission"`
	GrantedAt  time.Time          `bson:"granted_at" json:"grantedAt"`
	GrantedBy  primitive.ObjectID `bson:"granted_by" json:"grantedBy"`
}

type PermissionType string

const (
	PermissionRead   PermissionType = "read"
	PermissionWrite  PermissionType = "write"
	PermissionDelete PermissionType = "delete"
	PermissionShare  PermissionType = "share"
	PermissionAdmin  PermissionType = "admin"
)
