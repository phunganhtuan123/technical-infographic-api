package auth

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

const refreshCookieName = "ti_refresh"

// CookieOptions decide how the refresh cookie is written. In development the
// API and the editor are both on localhost so Lax works; once they are on
// different sites the cookie has to be SameSite=None and Secure, which is why
// this is configuration rather than a constant.
type CookieOptions struct {
	Domain   string
	Secure   bool
	SameSite http.SameSite
}

type Handler struct {
	manager *Manager
	cookie  CookieOptions
}

func NewHandler(manager *Manager, cookie CookieOptions) *Handler {
	return &Handler{manager: manager, cookie: cookie}
}

// Register mounts the sign-in routes on a group already prefixed with /auth.
// `credential` is applied only to the two routes that take a password, so the
// strict per-account limit does not also throttle refresh and logout — those
// are called on a timer by every open tab and would trip it constantly.
func (h *Handler) Register(group *echo.Group, credential ...echo.MiddlewareFunc) {
	group.POST("/register", h.register, credential...)
	group.POST("/login", h.login, credential...)
	group.POST("/refresh", h.refresh)
	group.POST("/logout", h.logout)
}

type credentials struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName"`
}

type sessionResponse struct {
	User        model.User `json:"user"`
	AccessToken string     `json:"accessToken"`
	ExpiresAt   time.Time  `json:"expiresAt"`
}

func (h *Handler) register(c echo.Context) error {
	var body credentials
	if err := c.Bind(&body); err != nil {
		return httpx.BadRequest("The request body is not valid JSON.")
	}
	user, err := h.manager.Register(c.Request().Context(), body.Email, body.Password, body.DisplayName)
	if err != nil {
		return err
	}
	return h.respondWithSession(c, http.StatusCreated, user)
}

func (h *Handler) login(c echo.Context) error {
	var body credentials
	if err := c.Bind(&body); err != nil {
		return httpx.BadRequest("The request body is not valid JSON.")
	}
	user, err := h.manager.Login(c.Request().Context(), body.Email, body.Password)
	if err != nil {
		return err
	}
	return h.respondWithSession(c, http.StatusOK, user)
}

func (h *Handler) refresh(c echo.Context) error {
	session, err := h.manager.Refresh(c.Request().Context(), h.readRefreshCookie(c),
		c.Request().UserAgent(), c.RealIP())
	if err != nil {
		// A refused refresh means the cookie is worthless — clear it so the
		// browser stops sending it and the client can show the sign-in screen.
		h.clearRefreshCookie(c)
		return err
	}
	h.writeRefreshCookie(c, session.RefreshToken)
	return c.JSON(http.StatusOK, sessionResponse{
		User: session.User, AccessToken: session.AccessToken, ExpiresAt: session.AccessExpiry,
	})
}

func (h *Handler) logout(c echo.Context) error {
	if err := h.manager.Logout(c.Request().Context(), h.readRefreshCookie(c)); err != nil {
		return err
	}
	h.clearRefreshCookie(c)
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) respondWithSession(c echo.Context, status int, user model.User) error {
	session, err := h.manager.StartSession(c.Request().Context(), user,
		c.Request().UserAgent(), c.RealIP())
	if err != nil {
		return err
	}
	h.writeRefreshCookie(c, session.RefreshToken)
	return c.JSON(status, sessionResponse{
		User: session.User, AccessToken: session.AccessToken, ExpiresAt: session.AccessExpiry,
	})
}

func (h *Handler) readRefreshCookie(c echo.Context) string {
	cookie, err := c.Cookie(refreshCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *Handler) writeRefreshCookie(c echo.Context, value string) {
	c.SetCookie(&http.Cookie{
		Name:     refreshCookieName,
		Value:    value,
		Path:     "/v1/auth",
		Domain:   h.cookie.Domain,
		Expires:  time.Now().Add(h.manager.refreshTTL),
		HttpOnly: true,
		Secure:   h.cookie.Secure,
		SameSite: h.cookie.SameSite,
	})
}

func (h *Handler) clearRefreshCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/v1/auth",
		Domain:   h.cookie.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookie.Secure,
		SameSite: h.cookie.SameSite,
	})
}

// These are unexported so nothing outside this package can plant a user id or
// a role in the context and walk past the middleware.
const (
	contextUserKey = "auth.user_id"
	contextRoleKey = "auth.role"
)

// Middleware rejects anything without a valid access token, and confirms the
// account behind it is still live.
//
// The token used to be trusted on its own — a signed, short-lived claim needs
// no database round trip, and that is genuinely most of why requests are cheap.
// Suspension is what broke it: an access token is signed for fifteen minutes,
// and an administrator who locks an account expects it to stop working now, not
// at some point inside the next quarter of an hour. So one primary-key read,
// which also carries the role and saves the admin routes a second query.
func (m *Manager) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			header := c.Request().Header.Get(echo.HeaderAuthorization)
			const prefix = "Bearer "
			if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
				return httpx.ErrUnauthorized
			}
			userID, err := m.ParseAccessToken(header[len(prefix):])
			if err != nil {
				return httpx.New(http.StatusUnauthorized, "token_invalid",
					"Your session expired. Refreshing…")
			}

			var account model.User
			// Soft-deleted rows are excluded by GORM, so a deleted account
			// fails here the same way a forged token does.
			if err := m.db.WithContext(c.Request().Context()).
				Select("id", "role", "disabled_at").
				First(&account, "id = ?", userID).Error; err != nil {
				return httpx.ErrUnauthorized
			}
			if account.IsDisabled() {
				return ErrAccountDisabled
			}

			c.Set(contextUserKey, userID)
			c.Set(contextRoleKey, account.Role)
			return next(c)
		}
	}
}

// RequireAdmin refuses everyone the middleware above did not mark as an
// administrator. Mounted as its own layer rather than checked inside each
// handler: a route that forgets the check is then a route that does not
// compile into the admin group at all.
func RequireAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if RoleOf(c) != model.RoleAdmin {
			return httpx.ErrForbidden
		}
		return next(c)
	}
}

// UserID returns the caller. It is only ever called from handlers mounted
// behind Middleware, so a missing value is a wiring bug, not a request problem.
func UserID(c echo.Context) (uuid.UUID, error) {
	value, ok := c.Get(contextUserKey).(uuid.UUID)
	if !ok {
		return uuid.Nil, httpx.ErrUnauthorized
	}
	return value, nil
}

// RoleOf returns the caller's role, or the ordinary one when the request never
// went through Middleware — failing closed rather than open.
func RoleOf(c echo.Context) model.Role {
	value, ok := c.Get(contextRoleKey).(model.Role)
	if !ok {
		return model.RoleUser
	}
	return value
}
