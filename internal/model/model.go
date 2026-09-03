// Package model holds the GORM models. The tables themselves are created by the
// SQL in migrations/ — AutoMigrate is only wired up for local development,
// because it will not rename a column, drop one, or roll anything back.
package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Provider names a way of signing in. Stored as text rather than a Postgres
// enum so adding one later is a code change, not a migration with a lock.
type Provider string

const (
	ProviderPassword Provider = "password"
	ProviderGoogle   Provider = "google"
	ProviderFacebook Provider = "facebook"
)

// User is the account. Email is a pointer because Facebook does not always
// return one — people who signed up by phone, or who declined the email
// permission, arrive with nothing. A NOT NULL column here breaks that login in
// production rather than in testing.
type User struct {
	ID              uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Email           *string        `gorm:"type:citext" json:"email,omitempty"`
	EmailVerifiedAt *time.Time     `json:"emailVerifiedAt,omitempty"`
	PasswordHash    *string        `gorm:"type:text" json:"-"`
	DisplayName     string         `gorm:"type:text;not null;default:''" json:"displayName"`
	AvatarURL       *string        `gorm:"type:text" json:"avatarUrl,omitempty"`
	CreatedAt       time.Time      `json:"createdAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`

	Identities []Identity    `gorm:"constraint:OnDelete:CASCADE" json:"identities,omitempty"`
	Settings   *UserSettings `gorm:"constraint:OnDelete:CASCADE" json:"settings,omitempty"`
}

// HasEmail reports whether this account can receive mail. Verification,
// password reset and sharing invitations all depend on it.
func (u User) HasEmail() bool { return u.Email != nil && *u.Email != "" }

// Identity links one sign-in method to a user. The key is (provider, subject),
// never email — a person can change the email on their Google account and it
// must stay the same identity.
type Identity struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"-"`
	Provider  Provider  `gorm:"type:text;not null;uniqueIndex:idx_identity_provider_subject,priority:1" json:"provider"`
	Subject   string    `gorm:"type:text;not null;uniqueIndex:idx_identity_provider_subject,priority:2" json:"-"`
	Email     *string   `gorm:"type:citext" json:"email,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// RefreshToken stores only a hash of the token it issued. FamilyID chains
// rotations together: if a token that was already rotated away comes back, the
// whole family is revoked, because the only way that happens is theft.
type RefreshToken struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	FamilyID  uuid.UUID `gorm:"type:uuid;not null;index"`
	TokenHash []byte    `gorm:"type:bytea;not null;uniqueIndex"`
	UserAgent string    `gorm:"type:text"`
	IP        string    `gorm:"type:text"`
	ExpiresAt time.Time `gorm:"not null;index"`
	RevokedAt *time.Time
	CreatedAt time.Time
}

// UserSettings is per-user editor state. There is deliberately no column for an
// API key or token: the editor talks to its AI gateway directly and this
// service never holds that credential. Only the origin is remembered, so people
// do not retype it.
type UserSettings struct {
	UserID          uuid.UUID      `gorm:"type:uuid;primaryKey" json:"-"`
	AIGatewayOrigin *string        `gorm:"type:text" json:"aiGatewayOrigin,omitempty"`
	AIProvider      *string        `gorm:"type:text" json:"aiProvider,omitempty"`
	AIModel         *string        `gorm:"type:text" json:"aiModel,omitempty"`
	Editor          datatypes.JSON `gorm:"type:jsonb;not null;default:'{}'" json:"editor"`
	UpdatedAt       time.Time      `json:"updatedAt"`
}

// Project holds one diagram. The document is stored whole as JSONB: the editor
// already serialises exactly this shape, and nothing on the server ever queries
// inside an individual node, so normalising it into tables would buy nothing
// and cost every read a join.
type Project struct {
	ID         uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OwnerID    uuid.UUID      `gorm:"type:uuid;not null;index" json:"ownerId"`
	Title      string         `gorm:"type:text;not null" json:"title"`
	Purpose    string         `gorm:"type:text;not null;default:''" json:"purpose"`
	Format     string         `gorm:"type:text;not null;default:'16:9'" json:"format"`
	Mode       string         `gorm:"type:text;not null;default:'architecture'" json:"mode"`
	Document   datatypes.JSON `gorm:"type:jsonb;not null" json:"document,omitempty"`
	Version    int64          `gorm:"not null;default:1" json:"version"`
	SceneCount int            `gorm:"not null;default:1" json:"sceneCount"`
	NodeCount  int            `gorm:"not null;default:0" json:"nodeCount"`
	CreatedAt  time.Time      `json:"createdAt"`
	UpdatedAt  time.Time      `json:"updatedAt"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

// ProjectVersion is the saved history. Undo inside the canvas is the browser's
// job and dies with the tab; this is what survives.
type ProjectVersion struct {
	ProjectID uuid.UUID      `gorm:"type:uuid;primaryKey" json:"projectId"`
	Version   int64          `gorm:"primaryKey" json:"version"`
	Document  datatypes.JSON `gorm:"type:jsonb;not null" json:"document,omitempty"`
	Label     *string        `gorm:"type:text" json:"label,omitempty"`
	CreatedBy *uuid.UUID     `gorm:"type:uuid" json:"createdBy,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
}

// Asset is a file a diagram points at — background images, mostly. Keeping
// them here instead of inside the document is what stops autosave writing a
// megabyte of base64 into two tables every few seconds.
type Asset struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OwnerID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"-"`
	ProjectID  *uuid.UUID `gorm:"type:uuid;index" json:"projectId,omitempty"`
	StorageKey string     `gorm:"type:text;not null;uniqueIndex" json:"-"`
	MIME       string     `gorm:"type:text;not null" json:"mime"`
	Bytes      int64      `gorm:"not null" json:"bytes"`
	Checksum   []byte     `gorm:"type:bytea;not null" json:"-"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// All is the AutoMigrate list used only in development.
func All() []any {
	return []any{
		&User{}, &Identity{}, &RefreshToken{},
		&UserSettings{}, &Project{}, &ProjectVersion{}, &Asset{},
	}
}
