// Package admin is account management: who has signed up, and the three things
// an operator ever needs to do about it — suspend, restore, remove.
//
// It is a separate package rather than more routes on internal/user because the
// two answer different questions. Everything in user is scoped to "me" and can
// never reach another row; everything here reaches every row, and keeping that
// power in one file is what makes it reviewable.
package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/phunganhtuan123/technical-infographic-api/internal/auth"
	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

type Handler struct {
	db      *gorm.DB
	manager *auth.Manager
}

func NewHandler(db *gorm.DB, manager *auth.Manager) *Handler {
	return &Handler{db: db, manager: manager}
}

// Register mounts the admin routes on a group that already requires a valid
// access token. RequireAdmin is applied to the group, not to each route, so a
// route added later cannot be forgotten.
func (h *Handler) Register(secure *echo.Group) {
	group := secure.Group("/admin", auth.RequireAdmin)
	group.GET("/users", h.listUsers)
	group.PATCH("/users/:id", h.updateUser)
	group.DELETE("/users/:id", h.deleteUser)
}

// Row is one account as the admin screen shows it. Deliberately not model.User:
// that struct carries the identity list and would grow fields over time that
// nobody meant to hand to this endpoint.
type Row struct {
	ID           uuid.UUID  `json:"id"`
	Email        *string    `json:"email,omitempty"`
	DisplayName  string     `json:"displayName"`
	AvatarURL    *string    `json:"avatarUrl,omitempty"`
	Role         model.Role `json:"role"`
	DisabledAt   *time.Time `json:"disabledAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	ProjectCount int64      `json:"projectCount"`
}

type listResponse struct {
	Users []Row `json:"users"`
	Total int64 `json:"total"`
}

const (
	defaultLimit = 50
	maxLimit     = 200
)

func (h *Handler) listUsers(c echo.Context) error {
	db := h.db.WithContext(c.Request().Context())

	query := db.Model(&model.User{})
	if search := strings.TrimSpace(c.QueryParam("query")); search != "" {
		like := "%" + strings.ToLower(search) + "%"
		query = query.Where("lower(email::text) LIKE ? OR lower(display_name) LIKE ?", like, like)
	}
	switch c.QueryParam("status") {
	case "disabled":
		query = query.Where("disabled_at IS NOT NULL")
	case "active":
		query = query.Where("disabled_at IS NULL")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return err
	}

	limit := defaultLimit
	if value, err := strconv.Atoi(c.QueryParam("limit")); err == nil && value > 0 {
		limit = min(value, maxLimit)
	}
	offset := 0
	if value, err := strconv.Atoi(c.QueryParam("offset")); err == nil && value > 0 {
		offset = value
	}

	rows := []Row{}
	// The project count is a correlated subquery rather than a join with a
	// GROUP BY: with a LIMIT on the outer query it reads only the page being
	// shown, and it still returns a row for an account that owns nothing.
	err := query.
		Select(`users.id, users.email, users.display_name, users.avatar_url, users.role,
			users.disabled_at, users.created_at, users.updated_at,
			(SELECT count(*) FROM projects
			  WHERE projects.owner_id = users.id AND projects.deleted_at IS NULL) AS project_count`).
		Order("users.created_at DESC").
		Limit(limit).Offset(offset).
		Scan(&rows).Error
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, listResponse{Users: rows, Total: total})
}

type updateBody struct {
	Disabled *bool   `json:"disabled"`
	Role     *string `json:"role"`
}

func (h *Handler) updateUser(c echo.Context) error {
	actor, target, err := h.resolve(c)
	if err != nil {
		return err
	}
	var body updateBody
	if err := c.Bind(&body); err != nil {
		return httpx.BadRequest("The request body is not valid JSON.")
	}

	if body.Disabled == nil && body.Role == nil {
		return httpx.BadRequest("Send 'disabled' or 'role'.")
	}

	ctx := c.Request().Context()
	others, err := h.otherActiveAdmins(ctx, target.ID)
	if err != nil {
		return err
	}
	updates := map[string]any{}

	if body.Disabled != nil {
		if err := checkSuspend(actor, target, *body.Disabled, others); err != nil {
			return err
		}
		if *body.Disabled {
			now := time.Now()
			updates["disabled_at"] = &now
		} else {
			updates["disabled_at"] = nil
		}
	}

	if body.Role != nil {
		role := model.Role(strings.TrimSpace(*body.Role))
		if err := checkRole(actor, target, role, others); err != nil {
			return err
		}
		updates["role"] = role
	}
	if err := h.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ?", target.ID).Updates(updates).Error; err != nil {
		return err
	}

	// A suspension has to reach the open tabs, not just the next sign-in: the
	// refresh timer would otherwise hand the browser a fresh token every few
	// minutes for as long as it stays open.
	if disabled, ok := updates["disabled_at"]; ok && disabled != nil {
		if err := h.manager.RevokeAll(ctx, target.ID); err != nil {
			return err
		}
	}
	return h.respond(c, target.ID)
}

func (h *Handler) deleteUser(c echo.Context) error {
	actor, target, err := h.resolve(c)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	others, err := h.otherActiveAdmins(ctx, target.ID)
	if err != nil {
		return err
	}
	if err := checkDelete(actor, target, others); err != nil {
		return err
	}

	// Soft delete, matching every other destructive path in this service. The
	// projects and assets stay addressable for a support request, and the
	// partial unique index on email frees the address for a new sign-up.
	if err := h.db.WithContext(ctx).Delete(&model.User{}, "id = ?", target.ID).Error; err != nil {
		return err
	}
	if err := h.manager.RevokeAll(ctx, target.ID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// resolve returns the caller and the account being acted on, or the right
// error. Every mutating route starts here so none of them can skip a check.
func (h *Handler) resolve(c echo.Context) (uuid.UUID, model.User, error) {
	actor, err := auth.UserID(c)
	if err != nil {
		return uuid.Nil, model.User{}, err
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return uuid.Nil, model.User{}, httpx.ErrNotFound
	}
	var target model.User
	err = h.db.WithContext(c.Request().Context()).First(&target, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return uuid.Nil, model.User{}, httpx.ErrNotFound
	} else if err != nil {
		return uuid.Nil, model.User{}, err
	}
	return actor, target, nil
}

// otherActiveAdmins counts the administrators who could still sign in if this
// one lost access — the single fact every rule in guard.go turns on.
func (h *Handler) otherActiveAdmins(ctx context.Context, except uuid.UUID) (int64, error) {
	var remaining int64
	err := h.db.WithContext(ctx).Model(&model.User{}).
		Where("role = ? AND id <> ? AND disabled_at IS NULL", model.RoleAdmin, except).
		Count(&remaining).Error
	return remaining, err
}

func (h *Handler) respond(c echo.Context, id uuid.UUID) error {
	var found model.User
	if err := h.db.WithContext(c.Request().Context()).First(&found, "id = ?", id).Error; err != nil {
		return httpx.ErrNotFound
	}
	return c.JSON(http.StatusOK, found)
}
