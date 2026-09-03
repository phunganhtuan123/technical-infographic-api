package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

type Manager struct {
	db         *gorm.DB
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewManager(db *gorm.DB, secret []byte, accessTTL, refreshTTL time.Duration) *Manager {
	return &Manager{db: db, secret: secret, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// Session is what a successful sign-in hands back. The refresh value goes into
// an HttpOnly cookie and is never readable by page scripts; the access token is
// returned in the body for the client to hold in memory.
type Session struct {
	User         model.User
	AccessToken  string
	AccessExpiry time.Time
	RefreshToken string
}

var (
	errInvalidCredentials = httpx.New(http.StatusUnauthorized, "invalid_credentials",
		"That email and password do not match an account.")
	errEmailTaken = httpx.Conflict("email_taken",
		"An account already uses that email. Sign in instead, or reset the password.")
)

// A hash of a value nobody knows, so Login can spend the same time on a missing
// account as on a real one. Without it, response timing tells an attacker which
// emails are registered.
const decoyHash = "$argon2id$v=19$m=65536,t=3,p=4$ZGVjb3lzYWx0ZGVjb3lzYQ$ZGVjb3loYXNoZGVjb3loYXNoZGVjb3loYXNoZGVjb3k"

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (m *Manager) Register(ctx context.Context, email, password, displayName string) (model.User, error) {
	email = NormalizeEmail(email)
	if email == "" || !strings.Contains(email, "@") {
		return model.User{}, httpx.BadRequest("Enter a valid email address.").
			WithFields(map[string]any{"email": "invalid"})
	}
	if len(password) < 10 {
		return model.User{}, httpx.BadRequest("Use a password of at least 10 characters.").
			WithFields(map[string]any{"password": "too_short"})
	}

	hash, err := HashPassword(password)
	if err != nil {
		return model.User{}, err
	}
	if displayName = strings.TrimSpace(displayName); displayName == "" {
		displayName, _, _ = strings.Cut(email, "@")
	}

	user := model.User{Email: &email, PasswordHash: &hash, DisplayName: displayName}
	err = m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		identity := model.Identity{
			UserID:   user.ID,
			Provider: model.ProviderPassword,
			Subject:  user.ID.String(),
			Email:    &email,
		}
		if err := tx.Create(&identity).Error; err != nil {
			return err
		}
		settings := model.UserSettings{UserID: user.ID, Editor: datatypes.JSON([]byte(`{}`))}
		return tx.Create(&settings).Error
	})
	if err != nil {
		if isUniqueViolation(err) {
			return model.User{}, errEmailTaken
		}
		return model.User{}, err
	}
	return user, nil
}

func (m *Manager) Login(ctx context.Context, email, password string) (model.User, error) {
	email = NormalizeEmail(email)

	var user model.User
	err := m.db.WithContext(ctx).First(&user, "email = ?", email).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		_ = VerifyPassword(password, decoyHash) // keep the timing flat
		return model.User{}, errInvalidCredentials
	case err != nil:
		return model.User{}, err
	case user.PasswordHash == nil:
		// The account exists but was created through Google or Facebook. Saying
		// so is not a leak — they can already tell by trying that button — and
		// it saves a support ticket.
		_ = VerifyPassword(password, decoyHash)
		return model.User{}, httpx.New(http.StatusUnauthorized, "no_password_set",
			"This account signs in with Google or Facebook. Use that, then add a password from your account page.")
	}

	if err := VerifyPassword(password, *user.PasswordHash); err != nil {
		return model.User{}, errInvalidCredentials
	}
	return user, nil
}

// StartSession opens a new refresh-token family. Every rotation from here keeps
// the same FamilyID, so the whole line can be revoked at once.
func (m *Manager) StartSession(ctx context.Context, user model.User, userAgent, ip string) (Session, error) {
	return m.issue(ctx, user, uuid.New(), userAgent, ip)
}

func (m *Manager) issue(ctx context.Context, user model.User, family uuid.UUID, userAgent, ip string) (Session, error) {
	access, expiry, err := m.NewAccessToken(user.ID)
	if err != nil {
		return Session{}, err
	}
	plain, hash, err := newRefreshToken()
	if err != nil {
		return Session{}, err
	}

	record := model.RefreshToken{
		UserID:    user.ID,
		FamilyID:  family,
		TokenHash: hash,
		UserAgent: truncate(userAgent, 400),
		IP:        ip,
		ExpiresAt: time.Now().Add(m.refreshTTL),
	}
	if err := m.db.WithContext(ctx).Create(&record).Error; err != nil {
		return Session{}, err
	}
	return Session{User: user, AccessToken: access, AccessExpiry: expiry, RefreshToken: plain}, nil
}

// Refresh rotates a token. Presenting one that was already rotated away means
// somebody kept a copy, so the entire family is revoked and everyone holding
// any of it is signed out — including the attacker.
func (m *Manager) Refresh(ctx context.Context, presented, userAgent, ip string) (Session, error) {
	if presented == "" {
		return Session{}, httpx.ErrUnauthorized
	}

	var record model.RefreshToken
	err := m.db.WithContext(ctx).First(&record, "token_hash = ?", hashRefreshToken(presented)).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Session{}, httpx.ErrUnauthorized
	} else if err != nil {
		return Session{}, err
	}

	if record.RevokedAt != nil {
		if err := m.revokeFamily(ctx, record.FamilyID); err != nil {
			return Session{}, err
		}
		return Session{}, httpx.New(http.StatusUnauthorized, "token_reuse",
			"That session was already refreshed elsewhere. Everything on this account has been signed out — sign in again.")
	}
	if time.Now().After(record.ExpiresAt) {
		return Session{}, httpx.ErrUnauthorized
	}

	var user model.User
	if err := m.db.WithContext(ctx).First(&user, "id = ?", record.UserID).Error; err != nil {
		return Session{}, httpx.ErrUnauthorized
	}

	now := time.Now()
	if err := m.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("id = ?", record.ID).
		Update("revoked_at", now).Error; err != nil {
		return Session{}, err
	}
	return m.issue(ctx, user, record.FamilyID, userAgent, ip)
}

// Logout revokes the family the presented token belongs to, so signing out on
// one device does not sign out the others.
func (m *Manager) Logout(ctx context.Context, presented string) error {
	if presented == "" {
		return nil
	}
	var record model.RefreshToken
	err := m.db.WithContext(ctx).First(&record, "token_hash = ?", hashRefreshToken(presented)).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	return m.revokeFamily(ctx, record.FamilyID)
}

func (m *Manager) revokeFamily(ctx context.Context, family uuid.UUID) error {
	return m.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", family).
		Update("revoked_at", time.Now()).Error
}

// RevokeAll signs the account out everywhere. Used after a password reset.
func (m *Manager) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	return m.db.WithContext(ctx).Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", time.Now()).Error
}

func isUniqueViolation(err error) bool {
	return errors.Is(err, gorm.ErrDuplicatedKey) ||
		strings.Contains(strings.ToLower(err.Error()), "duplicate key") ||
		strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
