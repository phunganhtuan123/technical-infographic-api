package project

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/phunganhtuan123/technical-infographic-api/internal/auth"
	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
)

// Echo v4 does not export these two, and they are the whole concurrency story
// for this API, so name them once here.
const (
	headerETag    = "ETag"
	headerIfMatch = "If-Match"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler { return &Handler{service: service} }

// Register mounts the project routes. The group handed in is already behind the
// access-token middleware.
func (h *Handler) Register(group *echo.Group) {
	group.GET("/projects", h.list)
	group.POST("/projects", h.create)
	group.GET("/projects/:id", h.get)
	group.PATCH("/projects/:id", h.patch)
	group.DELETE("/projects/:id", h.remove)
	group.POST("/projects/:id/duplicate", h.duplicate)
	group.GET("/projects/:id/document", h.getDocument)
	group.PUT("/projects/:id/document", h.putDocument)
	group.GET("/projects/:id/versions", h.versions)
	group.POST("/projects/:id/versions/:version/restore", h.restore)
}

func (h *Handler) caller(c echo.Context) (uuid.UUID, uuid.UUID, error) {
	userID, err := auth.UserID(c)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, httpx.ErrNotFound
	}
	return userID, projectID, nil
}

func (h *Handler) list(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	projects, err := h.service.List(c.Request().Context(), userID, c.QueryParam("q"), limit)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"projects": projects})
}

type createBody struct {
	Title    string          `json:"title"`
	Purpose  string          `json:"purpose"`
	Format   string          `json:"format"`
	Mode     string          `json:"mode"`
	Document json.RawMessage `json:"document"`
}

func (h *Handler) create(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	var body createBody
	if err := c.Bind(&body); err != nil {
		return httpx.BadRequest("The request body is not valid JSON.")
	}
	created, err := h.service.Create(c.Request().Context(), userID, CreateInput(body))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, created)
}

func (h *Handler) get(c echo.Context) error {
	userID, projectID, err := h.caller(c)
	if err != nil {
		return err
	}
	found, err := h.service.Get(c.Request().Context(), userID, projectID, false)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, found)
}

func (h *Handler) patch(c echo.Context) error {
	userID, projectID, err := h.caller(c)
	if err != nil {
		return err
	}
	var body PatchInput
	if err := c.Bind(&body); err != nil {
		return httpx.BadRequest("The request body is not valid JSON.")
	}
	updated, err := h.service.Patch(c.Request().Context(), userID, projectID, body)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, updated)
}

func (h *Handler) remove(c echo.Context) error {
	userID, projectID, err := h.caller(c)
	if err != nil {
		return err
	}
	if err := h.service.Delete(c.Request().Context(), userID, projectID); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) duplicate(c echo.Context) error {
	userID, projectID, err := h.caller(c)
	if err != nil {
		return err
	}
	copied, err := h.service.Duplicate(c.Request().Context(), userID, projectID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, copied)
}

// getDocument sends the version back as an ETag so the client can hand it
// straight to If-Match on the next save without tracking it separately.
func (h *Handler) getDocument(c echo.Context) error {
	userID, projectID, err := h.caller(c)
	if err != nil {
		return err
	}
	found, err := h.service.Get(c.Request().Context(), userID, projectID, true)
	if err != nil {
		return err
	}
	c.Response().Header().Set(headerETag, etag(found.Version))
	return c.JSON(http.StatusOK, map[string]any{
		"version":  found.Version,
		"document": json.RawMessage(found.Document),
	})
}

type documentBody struct {
	Document json.RawMessage `json:"document"`
	Version  *int64          `json:"version"`
	Label    *string         `json:"label"`
}

func (h *Handler) putDocument(c echo.Context) error {
	userID, projectID, err := h.caller(c)
	if err != nil {
		return err
	}
	var body documentBody
	if err := c.Bind(&body); err != nil {
		return httpx.BadRequest("The request body is not valid JSON.")
	}
	if len(body.Document) == 0 {
		return httpx.BadRequest("Nothing to save: the document is missing.")
	}

	// If-Match is the standard way to say "only if it still looks like this".
	// The body field is accepted as well so a client that cannot set headers
	// easily is not locked out.
	expected := body.Version
	if header := strings.TrimSpace(c.Request().Header.Get(headerIfMatch)); header != "" && header != "*" {
		parsed, err := strconv.ParseInt(strings.Trim(header, `"W/`), 10, 64)
		if err != nil {
			return httpx.BadRequest("If-Match must carry the version number this edit started from.")
		}
		expected = &parsed
	}
	if expected == nil {
		return httpx.BadRequest("Send the version this edit started from, in If-Match or in the body.").
			WithFields(map[string]any{"version": "required"})
	}

	saved, err := h.service.SaveDocument(c.Request().Context(), userID, projectID, body.Document, *expected, body.Label)
	if err != nil {
		// On a conflict, hand back what is actually stored. The client can then
		// offer "keep mine / take theirs" instead of a dead end.
		var conflict *httpx.Error
		if ok := asError(err, &conflict); ok && conflict.Code == "version_conflict" {
			current, getErr := h.service.Get(c.Request().Context(), userID, projectID, true)
			if getErr == nil {
				return c.JSON(http.StatusConflict, map[string]any{
					"error":   conflict,
					"current": map[string]any{"version": current.Version, "document": json.RawMessage(current.Document)},
				})
			}
		}
		return err
	}

	c.Response().Header().Set(headerETag, etag(saved.Version))
	return c.JSON(http.StatusOK, saved)
}

func (h *Handler) versions(c echo.Context) error {
	userID, projectID, err := h.caller(c)
	if err != nil {
		return err
	}
	list, err := h.service.Versions(c.Request().Context(), userID, projectID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"versions": list})
}

func (h *Handler) restore(c echo.Context) error {
	userID, projectID, err := h.caller(c)
	if err != nil {
		return err
	}
	version, err := strconv.ParseInt(c.Param("version"), 10, 64)
	if err != nil {
		return httpx.ErrNotFound
	}
	restored, err := h.service.Restore(c.Request().Context(), userID, projectID, version)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, restored)
}

func etag(version int64) string {
	return `"` + strconv.FormatInt(version, 10) + `"`
}

func asError(err error, target **httpx.Error) bool {
	candidate, ok := err.(*httpx.Error)
	if ok {
		*target = candidate
	}
	return ok
}
