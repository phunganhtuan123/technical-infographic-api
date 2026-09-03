// Package asset stores the images a diagram points at, so they stop being
// base64 inside the document.
//
// Inlining a 400 KB photo costs ~533 KB of base64, and the editor autosaves —
// which then writes that payload into projects.document *and* a row of
// project_versions, every few seconds. Two images and the whole thing is over
// any sane size limit with nowhere to go. Files live here instead; the document
// keeps a URL.
package asset

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"github.com/phunganhtuan123/technical-infographic-api/internal/auth"
	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
	"github.com/phunganhtuan123/technical-infographic-api/internal/storage"
)

// SVG is missing on purpose. It can carry script, and these files are served
// from the API's own origin — an uploaded "image" would be running code there.
var allowedTypes = map[string]string{
	"image/png":  "png",
	"image/jpeg": "jpg",
	"image/webp": "webp",
	"image/gif":  "gif",
}

type Service struct {
	db      *gorm.DB
	files   storage.Storage
	secret  []byte
	maxSize int64
	urlTTL  time.Duration
}

func NewService(db *gorm.DB, files storage.Storage, secret []byte, maxSize int64, urlTTL time.Duration) *Service {
	return &Service{db: db, files: files, secret: secret, maxSize: maxSize, urlTTL: urlTTL}
}

type Handler struct{ service *Service }

func NewHandler(service *Service) *Handler { return &Handler{service: service} }

// RegisterSecure mounts the routes that need a signed-in user.
func (h *Handler) RegisterSecure(group *echo.Group) {
	group.POST("/projects/:id/assets", h.upload)
	group.GET("/projects/:id/assets", h.list)
	group.DELETE("/assets/:assetID", h.remove)
}

// RegisterPublic mounts the one route a browser reaches without a header.
//
// An <img> tag cannot send Authorization, so serving these behind the normal
// middleware would mean no image ever loads. Instead every URL carries a
// short-lived signature bound to that one asset — enough to fetch it, useless
// for anything else, and expired within the hour.
func (h *Handler) RegisterPublic(group *echo.Group) {
	group.GET("/assets/:assetID", h.download)
}

// signature is an HMAC over the asset id and its expiry.
func (s *Service) signature(assetID uuid.UUID, expiry int64) string {
	mac := hmac.New(sha256.New, s.secret)
	fmt.Fprintf(mac, "%s.%d", assetID, expiry)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) SignedURL(assetID uuid.UUID) string {
	expiry := time.Now().Add(s.urlTTL).Unix()
	return fmt.Sprintf("/v1/assets/%s?exp=%d&sig=%s", assetID, expiry, s.signature(assetID, expiry))
}

func (s *Service) verify(assetID uuid.UUID, rawExpiry, given string) error {
	expiry, err := strconv.ParseInt(rawExpiry, 10, 64)
	if err != nil {
		return httpx.ErrNotFound
	}
	if time.Now().Unix() > expiry {
		return httpx.New(http.StatusForbidden, "link_expired",
			"This image link has expired. Reload the diagram to get a fresh one.")
	}
	if !hmac.Equal([]byte(given), []byte(s.signature(assetID, expiry))) {
		return httpx.ErrNotFound
	}
	return nil
}

type uploaded struct {
	model.Asset
	URL string `json:"url"`
}

func (h *Handler) upload(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return httpx.ErrNotFound
	}

	// Only the owner may attach files, and a stranger must not learn that the
	// project id is real.
	//
	// Scanning straight into a uuid.UUID does not work: it is a [16]byte, and
	// the driver hands back the textual form, so database/sql tries to squeeze
	// a 36-character string into a byte. Read the row instead.
	var owner model.Project
	err = h.service.db.WithContext(c.Request().Context()).
		Select("id", "owner_id").
		First(&owner, "id = ?", projectID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return httpx.ErrNotFound
	} else if err != nil {
		return err
	}
	if owner.OwnerID != userID {
		return httpx.ErrNotFound
	}

	header, err := c.FormFile("file")
	if err != nil {
		return httpx.BadRequest("Attach the image as a form field named \"file\".")
	}
	if header.Size > h.service.maxSize {
		return httpx.New(http.StatusRequestEntityTooLarge, "asset_too_large",
			fmt.Sprintf("That image is %s. The limit is %s — resize it and try again.",
				megabytes(header.Size), megabytes(h.service.maxSize)))
	}

	file, err := header.Open()
	if err != nil {
		return err
	}
	defer file.Close()

	// Trust the bytes, not the declared type: sniff the first 512 and check
	// that against the allowlist.
	preamble := make([]byte, 512)
	read, _ := io.ReadFull(file, preamble)
	mime := http.DetectContentType(preamble[:read])
	extension, ok := allowedTypes[mime]
	if !ok {
		return httpx.BadRequest("Only PNG, JPEG, WebP and GIF images can be uploaded.").
			WithFields(map[string]any{"file": "unsupported_type"})
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	digest := sha256.New()
	assetID := uuid.New()
	key := assetID.String() + "." + extension
	size, err := h.service.files.Put(c.Request().Context(), key, io.TeeReader(file, digest))
	if err != nil {
		return err
	}

	record := model.Asset{
		ID:         assetID,
		OwnerID:    userID,
		ProjectID:  &projectID,
		StorageKey: key,
		MIME:       mime,
		Bytes:      size,
		Checksum:   digest.Sum(nil),
	}
	if err := h.service.db.WithContext(c.Request().Context()).Create(&record).Error; err != nil {
		// Do not leave the file behind if the row failed.
		_ = h.service.files.Delete(c.Request().Context(), key)
		return err
	}
	return c.JSON(http.StatusCreated, uploaded{Asset: record, URL: h.service.SignedURL(record.ID)})
}

func (h *Handler) list(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return httpx.ErrNotFound
	}

	var records []model.Asset
	if err := h.service.db.WithContext(c.Request().Context()).
		Where("project_id = ? AND owner_id = ?", projectID, userID).
		Order("created_at DESC").
		Find(&records).Error; err != nil {
		return err
	}

	out := make([]uploaded, 0, len(records))
	for _, record := range records {
		out = append(out, uploaded{Asset: record, URL: h.service.SignedURL(record.ID)})
	}
	return c.JSON(http.StatusOK, map[string]any{"assets": out})
}

func (h *Handler) download(c echo.Context) error {
	assetID, err := uuid.Parse(c.Param("assetID"))
	if err != nil {
		return httpx.ErrNotFound
	}
	if err := h.service.verify(assetID, c.QueryParam("exp"), c.QueryParam("sig")); err != nil {
		return err
	}

	var record model.Asset
	err = h.service.db.WithContext(c.Request().Context()).First(&record, "id = ?", assetID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return httpx.ErrNotFound
	} else if err != nil {
		return err
	}

	file, err := h.service.files.Open(c.Request().Context(), record.StorageKey)
	if err != nil {
		return httpx.ErrNotFound
	}
	defer file.Close()

	// nosniff so a browser cannot decide these bytes are HTML after all, and a
	// sandbox CSP so nothing in the file can act even if one day it could.
	c.Response().Header().Set("X-Content-Type-Options", "nosniff")
	c.Response().Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	c.Response().Header().Set("Cache-Control", "private, max-age=3600")
	return c.Stream(http.StatusOK, record.MIME, file)
}

func (h *Handler) remove(c echo.Context) error {
	userID, err := auth.UserID(c)
	if err != nil {
		return err
	}
	assetID, err := uuid.Parse(c.Param("assetID"))
	if err != nil {
		return httpx.ErrNotFound
	}

	var record model.Asset
	err = h.service.db.WithContext(c.Request().Context()).
		First(&record, "id = ? AND owner_id = ?", assetID, userID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return httpx.ErrNotFound
	} else if err != nil {
		return err
	}

	// Row first: an orphaned file wastes disk, an orphaned row breaks an image.
	if err := h.service.db.WithContext(c.Request().Context()).Delete(&record).Error; err != nil {
		return err
	}
	_ = h.service.files.Delete(c.Request().Context(), record.StorageKey)
	return c.NoContent(http.StatusNoContent)
}

func megabytes(bytes int64) string {
	return strconv.FormatFloat(float64(bytes)/(1<<20), 'f', 1, 64) + " MB"
}
