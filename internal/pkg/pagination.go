package pkg

import (
	"math"
	"strconv"

	"github.com/gin-gonic/gin"
)

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Page   int                    `json:"page" form:"page"`
	Limit  int                    `json:"limit" form:"limit"`
	Sort   string                 `json:"sort" form:"sort"`
	Order  string                 `json:"order" form:"order"`
	Search string                 `json:"search" form:"search"`
	Filter map[string]interface{} `json:"filter,omitempty"`
}

// PaginationResult represents pagination result
type PaginationResult struct {
	Data       interface{}    `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}

// PaginationMeta represents pagination metadata
type PaginationMeta struct {
	CurrentPage  int   `json:"current_page"`
	TotalPages   int   `json:"total_pages"`
	TotalItems   int64 `json:"total_items"`
	ItemsPerPage int   `json:"items_per_page"`
	HasNext      bool  `json:"has_next"`
	HasPrev      bool  `json:"has_prev"`
	NextPage     *int  `json:"next_page,omitempty"`
	PrevPage     *int  `json:"prev_page,omitempty"`
}

// SortOrder represents sort order
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// Default pagination values
const (
	DefaultPage  = 1
	DefaultLimit = 20
	MaxLimit     = 100
	DefaultSort  = "created_at"
	DefaultOrder = "desc"
)

// NewPaginationParams creates pagination parameters from Gin context
func NewPaginationParams(c *gin.Context) *PaginationParams {
	params := &PaginationParams{
		Page:  DefaultPage,
		Limit: DefaultLimit,
		Sort:  DefaultSort,
		Order: DefaultOrder,
	}

	// Parse page
	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			params.Page = page
		}
	}

	// Parse limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			if limit > MaxLimit {
				params.Limit = MaxLimit
			} else {
				params.Limit = limit
			}
		}
	}

	// Parse sort
	if sort := c.Query("sort"); sort != "" {
		params.Sort = sort
	}

	// Parse order
	if order := c.Query("order"); order != "" {
		if order == "asc" || order == "desc" {
			params.Order = order
		}
	}

	// Parse search
	params.Search = c.Query("search")

	// Parse filters
	params.Filter = make(map[string]interface{})
	for key, values := range c.Request.URL.Query() {
		if key != "page" && key != "limit" && key != "sort" && key != "order" && key != "search" {
			if len(values) == 1 {
				params.Filter[key] = values[0]
			} else {
				params.Filter[key] = values
			}
		}
	}

	return params
}

// GetOffset calculates the offset for database queries
func (p *PaginationParams) GetOffset() int {
	return (p.Page - 1) * p.Limit
}

// GetSortDirection returns the sort direction for MongoDB
func (p *PaginationParams) GetSortDirection() int {
	if p.Order == "asc" {
		return 1
	}
	return -1
}

// NewPaginationResult creates a pagination result
func NewPaginationResult(data interface{}, totalItems int64, params *PaginationParams) *PaginationResult {
	totalPages := int(math.Ceil(float64(totalItems) / float64(params.Limit)))

	meta := PaginationMeta{
		CurrentPage:  params.Page,
		TotalPages:   totalPages,
		TotalItems:   totalItems,
		ItemsPerPage: params.Limit,
		HasNext:      params.Page < totalPages,
		HasPrev:      params.Page > 1,
	}

	if meta.HasNext {
		nextPage := params.Page + 1
		meta.NextPage = &nextPage
	}

	if meta.HasPrev {
		prevPage := params.Page - 1
		meta.PrevPage = &prevPage
	}

	return &PaginationResult{
		Data:       data,
		Pagination: meta,
	}
}

// Validate validates pagination parameters
func (p *PaginationParams) Validate() error {
	if p.Page <= 0 {
		p.Page = DefaultPage
	}

	if p.Limit <= 0 {
		p.Limit = DefaultLimit
	}

	if p.Limit > MaxLimit {
		p.Limit = MaxLimit
	}

	if p.Order != "asc" && p.Order != "desc" {
		p.Order = DefaultOrder
	}

	return nil
}
