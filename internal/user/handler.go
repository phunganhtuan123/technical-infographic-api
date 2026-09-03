// Package user serves the account itself: who am I, and what are my editor
// preferences. Small surface, but it is what makes the product feel like it
// remembers a person between machines.
package user

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/phunganhtuan123/technical-infographic-api/internal/auth"
	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler { return &Handler{db: db} }

func (h *Handler) Register(group *echo.Group) {
	group.GET("/me", h.me)
	group.PATCH("/me", h.updateMe)
	group.GET("/me/settings", h.settings)
	group.PUT("/me/settings", h.saveSettings)
}

func (h *Handler) me(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	var found model.User
	if err := h.db.WithContext(c.Request().Context()).
		Preload("Identities").
		First(&found, "id = ?", userID).Error; err != nil {
		return httpx.ErrUnauthorized
	}
	return c.JSON(http.StatusOK, found)
}

type profileBody struct {
	DisplayName *string `json:"displayName"`
	AvatarURL   *string `json:"avatarUrl"`
	Email       *string `json:"email"`
}

func (h *Handler) updateMe(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	var body profileBody
	if err := c.Bind(&body); err != nil {
		return httpx.BadRequest("The request body is not valid JSON.")
	}

	updates := map[string]any{}
	if body.DisplayName != nil {
		name := strings.TrimSpace(*body.DisplayName)
		if name == "" {
			return httpx.BadRequest("A display name cannot be empty.").
				WithFields(map[string]any{"displayName": "required"})
		}
		updates["display_name"] = name
	}
	if body.AvatarURL != nil {
		updates["avatar_url"] = strings.TrimSpace(*body.AvatarURL)
	}

	// Adding an email is allowed only where there is none — this is the path
	// for accounts that arrived from Facebook without one. Changing an existing
	// address has to go through verification, which is a separate flow.
	if body.Email != nil {
		var current model.User
		if err := h.db.WithContext(c.Request().Context()).First(&current, "id = ?", userID).Error; err != nil {
			return httpx.ErrUnauthorized
		}
		if current.HasEmail() {
			return httpx.BadRequest("Changing your email needs verification. Use the email settings page.")
		}
		email := auth.NormalizeEmail(*body.Email)
		if email == "" || !strings.Contains(email, "@") {
			return httpx.BadRequest("Enter a valid email address.").
				WithFields(map[string]any{"email": "invalid"})
		}
		updates["email"] = email
	}

	if len(updates) > 0 {
		if err := h.db.WithContext(c.Request().Context()).
			Model(&model.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
			return err
		}
	}
	return h.me(c)
}

func (h *Handler) settings(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	var found model.UserSettings
	err = h.db.WithContext(c.Request().Context()).First(&found, "user_id = ?", userID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		found = model.UserSettings{UserID: userID, Editor: datatypes.JSON([]byte(`{}`))}
	} else if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, found)
}

type settingsBody struct {
	AIGatewayOrigin *string        `json:"aiGatewayOrigin"`
	AIProvider      *string        `json:"aiProvider"`
	AIModel         *string        `json:"aiModel"`
	Editor          datatypes.JSON `json:"editor"`
}

// saveSettings stores editor preferences and, at most, the *origin* of the AI
// gateway someone uses. It refuses anything that looks like a credential: this
// service is not supposed to be able to call a model on a user's behalf, and
// the fastest way to lose that property is to accept a token "just this once".
func (h *Handler) saveSettings(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	var body settingsBody
	if err := c.Bind(&body); err != nil {
		return httpx.BadRequest("The request body is not valid JSON.")
	}

	if body.AIGatewayOrigin != nil {
		origin := strings.TrimRight(strings.TrimSpace(*body.AIGatewayOrigin), "/")
		if origin != "" {
			if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
				return httpx.BadRequest("The gateway address must start with http:// or https://.").
					WithFields(map[string]any{"aiGatewayOrigin": "invalid"})
			}
			if looksLikeSecret(origin) {
				return httpx.BadRequest("Send only the gateway address. Keys and tokens stay on your machine.").
					WithFields(map[string]any{"aiGatewayOrigin": "looks_like_credential"})
			}
		}
		body.AIGatewayOrigin = &origin
	}

	settings := model.UserSettings{
		UserID:          userID,
		AIGatewayOrigin: body.AIGatewayOrigin,
		AIProvider:      body.AIProvider,
		AIModel:         body.AIModel,
		Editor:          body.Editor,
		UpdatedAt:       time.Now(),
	}
	if len(settings.Editor) == 0 {
		settings.Editor = datatypes.JSON([]byte(`{}`))
	}

	if err := h.db.WithContext(c.Request().Context()).
		Where("user_id = ?", userID).
		Assign(settings).
		FirstOrCreate(&model.UserSettings{UserID: userID}).Error; err != nil {
		return err
	}
	return h.settings(c)
}

func looksLikeSecret(value string) bool {
	lowered := strings.ToLower(value)
	for _, marker := range []string{"sk-", "token=", "key=", "secret", "bearer", "password"} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}
