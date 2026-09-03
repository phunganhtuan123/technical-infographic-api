package project

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

// How many versions to keep per project. Anything labelled survives the trim,
// so a named snapshot is not lost to routine autosaves.
const keepVersions = 50

type Service struct {
	db               *gorm.DB
	maxDocumentBytes int64
}

func NewService(db *gorm.DB, maxDocumentBytes int64) *Service {
	return &Service{db: db, maxDocumentBytes: maxDocumentBytes}
}

var errVersionConflict = httpx.Conflict("version_conflict",
	"This project changed somewhere else. Open the newer version, or overwrite it with yours.")

// summary is what the diagram document tells us about itself. Kept in columns
// so the project list does not have to read megabytes of JSONB to say
// "12 components".
type summary struct {
	Title  string `json:"title"`
	Scenes []struct {
		Nodes []json.RawMessage `json:"nodes"`
	} `json:"scenes"`
	Nodes []json.RawMessage `json:"nodes"`
}

func describe(document []byte) (scenes, nodes int) {
	var parsed summary
	if err := json.Unmarshal(document, &parsed); err != nil {
		return 1, 0
	}
	scenes = len(parsed.Scenes)
	if scenes == 0 {
		scenes = 1
	}
	nodes = len(parsed.Nodes)
	for _, scene := range parsed.Scenes {
		if len(scene.Nodes) > nodes {
			nodes = len(scene.Nodes)
		}
	}
	return scenes, nodes
}

func (s *Service) checkSize(document []byte) error {
	if int64(len(document)) <= s.maxDocumentBytes {
		return nil
	}
	return httpx.New(http.StatusRequestEntityTooLarge, "document_too_large",
		"This diagram is too big to save. Background images belong in the image library rather than inside the diagram — upload them and the file shrinks.")
}

type CreateInput struct {
	Title    string
	Purpose  string
	Format   string
	Mode     string
	Document json.RawMessage
}

func (s *Service) Create(ctx context.Context, ownerID uuid.UUID, in CreateInput) (model.Project, error) {
	if strings.TrimSpace(in.Title) == "" {
		in.Title = "Untitled diagram"
	}
	if len(in.Document) == 0 {
		in.Document = json.RawMessage(`{"nodes":[],"edges":[]}`)
	}
	if err := s.checkSize(in.Document); err != nil {
		return model.Project{}, err
	}

	scenes, nodes := describe(in.Document)
	project := model.Project{
		OwnerID:    ownerID,
		Title:      strings.TrimSpace(in.Title),
		Purpose:    in.Purpose,
		Format:     firstNonEmpty(in.Format, "16:9"),
		Mode:       firstNonEmpty(in.Mode, "architecture"),
		Document:   datatypes.JSON(in.Document),
		Version:    1,
		SceneCount: scenes,
		NodeCount:  nodes,
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&project).Error; err != nil {
			return err
		}
		return tx.Create(&model.ProjectVersion{
			ProjectID: project.ID,
			Version:   1,
			Document:  project.Document,
			CreatedBy: &ownerID,
		}).Error
	})
	return project, err
}

// List returns metadata only — never the documents. A person with fifty
// projects should not download fifty diagrams to see their names.
func (s *Service) List(ctx context.Context, ownerID uuid.UUID, search string, limit int) ([]model.Project, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := s.db.WithContext(ctx).Model(&model.Project{}).
		Omit("document").
		Where("owner_id = ?", ownerID).
		Order("updated_at DESC").
		Limit(limit)

	if search = strings.TrimSpace(search); search != "" {
		query = query.Where("title ILIKE ?", "%"+search+"%")
	}

	var projects []model.Project
	return projects, query.Find(&projects).Error
}

func (s *Service) Get(ctx context.Context, ownerID, projectID uuid.UUID, withDocument bool) (model.Project, error) {
	query := s.db.WithContext(ctx).Where("id = ?", projectID)
	if !withDocument {
		query = query.Omit("document")
	}

	var project model.Project
	err := query.First(&project).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return model.Project{}, httpx.ErrNotFound
	case err != nil:
		return model.Project{}, err
	case project.OwnerID != ownerID:
		// Deliberately a 404, not a 403: confirming that an id exists is itself
		// a small leak when ids can be guessed from a shared link.
		return model.Project{}, httpx.ErrNotFound
	}
	return project, nil
}

type PatchInput struct {
	Title   *string `json:"title"`
	Purpose *string `json:"purpose"`
	Format  *string `json:"format"`
	Mode    *string `json:"mode"`
}

func (s *Service) Patch(ctx context.Context, ownerID, projectID uuid.UUID, in PatchInput) (model.Project, error) {
	updates := map[string]any{}
	if in.Title != nil {
		title := strings.TrimSpace(*in.Title)
		if title == "" {
			return model.Project{}, httpx.BadRequest("A project needs a name.").
				WithFields(map[string]any{"title": "required"})
		}
		updates["title"] = title
	}
	if in.Purpose != nil {
		updates["purpose"] = *in.Purpose
	}
	if in.Format != nil {
		updates["format"] = *in.Format
	}
	if in.Mode != nil {
		updates["mode"] = *in.Mode
	}
	if len(updates) == 0 {
		return s.Get(ctx, ownerID, projectID, false)
	}

	result := s.db.WithContext(ctx).Model(&model.Project{}).
		Where("id = ? AND owner_id = ?", projectID, ownerID).
		Updates(updates)
	if result.Error != nil {
		return model.Project{}, result.Error
	}
	if result.RowsAffected == 0 {
		return model.Project{}, httpx.ErrNotFound
	}
	return s.Get(ctx, ownerID, projectID, false)
}

func (s *Service) Delete(ctx context.Context, ownerID, projectID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Where("id = ? AND owner_id = ?", projectID, ownerID).
		Delete(&model.Project{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return httpx.ErrNotFound
	}
	return nil
}

// SaveDocument writes a new document only if the caller was holding the version
// that is currently stored. Without that check, two open tabs quietly overwrite
// each other and the loser never finds out.
func (s *Service) SaveDocument(
	ctx context.Context, ownerID, projectID uuid.UUID,
	document json.RawMessage, expected int64, label *string,
) (model.Project, error) {

	if err := s.checkSize(document); err != nil {
		return model.Project{}, err
	}
	scenes, nodes := describe(document)
	next := expected + 1

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&model.Project{}).
			Where("id = ? AND owner_id = ? AND version = ?", projectID, ownerID, expected).
			Updates(map[string]any{
				"document":    datatypes.JSON(document),
				"version":     gorm.Expr("version + 1"),
				"scene_count": scenes,
				"node_count":  nodes,
				"updated_at":  time.Now(),
			})
		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected == 0 {
			// Zero rows has three separate causes and they need three different
			// answers. Reporting a conflict for a project that was deleted
			// sends the person hunting for a newer version that does not exist.
			var current model.Project
			err := tx.Select("id", "owner_id", "version").First(&current, "id = ?", projectID).Error
			switch {
			case errors.Is(err, gorm.ErrRecordNotFound):
				return httpx.ErrNotFound
			case err != nil:
				return err
			case current.OwnerID != ownerID:
				return httpx.ErrNotFound
			default:
				return errVersionConflict
			}
		}

		if err := tx.Create(&model.ProjectVersion{
			ProjectID: projectID,
			Version:   next,
			Document:  datatypes.JSON(document),
			Label:     label,
			CreatedBy: &ownerID,
		}).Error; err != nil {
			return err
		}
		return trimVersions(tx, projectID)
	})
	if err != nil {
		return model.Project{}, err
	}
	return s.Get(ctx, ownerID, projectID, false)
}

// trimVersions keeps history from growing without bound. Labelled versions are
// kept whatever their age — somebody named them for a reason.
func trimVersions(tx *gorm.DB, projectID uuid.UUID) error {
	return tx.Exec(`
		DELETE FROM project_versions
		WHERE project_id = ?
		  AND label IS NULL
		  AND version NOT IN (
		      SELECT version FROM project_versions
		      WHERE project_id = ?
		      ORDER BY version DESC
		      LIMIT ?
		  )`, projectID, projectID, keepVersions).Error
}

func (s *Service) Versions(ctx context.Context, ownerID, projectID uuid.UUID) ([]model.ProjectVersion, error) {
	if _, err := s.Get(ctx, ownerID, projectID, false); err != nil {
		return nil, err
	}
	var versions []model.ProjectVersion
	err := s.db.WithContext(ctx).Model(&model.ProjectVersion{}).
		Omit("document").
		Where("project_id = ?", projectID).
		Order("version DESC").
		Find(&versions).Error
	return versions, err
}

// Restore writes an old document forward as a new version rather than rewinding
// the counter, so the history stays append-only and the restore itself is
// undoable.
func (s *Service) Restore(ctx context.Context, ownerID, projectID uuid.UUID, version int64) (model.Project, error) {
	current, err := s.Get(ctx, ownerID, projectID, false)
	if err != nil {
		return model.Project{}, err
	}

	var snapshot model.ProjectVersion
	err = s.db.WithContext(ctx).
		First(&snapshot, "project_id = ? AND version = ?", projectID, version).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Project{}, httpx.ErrNotFound
	} else if err != nil {
		return model.Project{}, err
	}

	label := "Restored from v" + strconv.FormatInt(version, 10)
	return s.SaveDocument(ctx, ownerID, projectID, json.RawMessage(snapshot.Document), current.Version, &label)
}

func (s *Service) Duplicate(ctx context.Context, ownerID, projectID uuid.UUID) (model.Project, error) {
	source, err := s.Get(ctx, ownerID, projectID, true)
	if err != nil {
		return model.Project{}, err
	}
	return s.Create(ctx, ownerID, CreateInput{
		Title:    source.Title + " copy",
		Purpose:  source.Purpose,
		Format:   source.Format,
		Mode:     source.Mode,
		Document: json.RawMessage(source.Document),
	})
}

func firstNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
