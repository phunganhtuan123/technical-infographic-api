// Package config loads everything the service needs from the environment and
// refuses to start when something required is missing. Failing at boot with a
// clear message beats failing on the first request that touches the gap.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env  string
	Port string

	DatabaseURL string

	// JWTSecret signs access tokens. Rotating it logs everyone out, which is
	// the intended emergency lever.
	JWTSecret       []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// EditorOrigins are the browser origins allowed to call this API with
	// credentials. No wildcard: cookies and "*" cannot be combined, and this
	// is the boundary that keeps other sites out of people's projects.
	EditorOrigins []string

	// CookieDomain is empty in development so the cookie is host-only.
	CookieDomain string
	CookieSecure bool

	// MaxDocumentBytes caps a stored diagram. The editor still inlines
	// background images as base64, so this is generous on purpose: a low cap
	// would refuse saves that the client has no other way to make. Once images
	// move to /assets it can come back down.
	MaxDocumentBytes int64

	// Assets
	AssetDir      string
	MaxAssetBytes int64
	AssetURLTTL   time.Duration

	// AdminEmails are promoted to administrator on every boot, and the first
	// of them is created with AdminPassword when no such account exists yet.
	// This is how a fresh deployment gets somebody who can open the account
	// screen, which otherwise only an administrator can open.
	AdminEmails   []string
	AdminPassword string

	// Rate limits. Two layers on the credential endpoints; see
	// internal/auth/ratelimit.go for why neither alone is enough.
	RateLimitEnabled     bool
	AuthAttemptsPerIP    int
	AuthAttemptWindow    time.Duration
	LoginAttemptsPerUser int
	LoginAttemptWindow   time.Duration
	APIRequestsPerIP     int
	APIRequestWindow     time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Env:              env("APP_ENV", "development"),
		Port:             env("PORT", "8080"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		CookieDomain:     env("COOKIE_DOMAIN", ""),
		MaxDocumentBytes: int64(envInt("MAX_DOCUMENT_BYTES", 8<<20)),
		AssetDir:         env("ASSET_DIR", "./data/assets"),
		MaxAssetBytes:    int64(envInt("MAX_ASSET_BYTES", 10<<20)),
	}

	secret := os.Getenv("JWT_SECRET")
	switch {
	case cfg.DatabaseURL == "":
		return cfg, fmt.Errorf("DATABASE_URL is required")
	case secret == "":
		return cfg, fmt.Errorf("JWT_SECRET is required")
	case len(secret) < 32:
		return cfg, fmt.Errorf("JWT_SECRET must be at least 32 characters, got %d", len(secret))
	}
	cfg.JWTSecret = []byte(secret)

	cfg.AccessTokenTTL = envDuration("ACCESS_TOKEN_TTL", 15*time.Minute)
	cfg.RefreshTokenTTL = envDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour)

	for _, origin := range strings.Split(env("EDITOR_ORIGINS", "http://localhost:3000"), ",") {
		if trimmed := strings.TrimRight(strings.TrimSpace(origin), "/"); trimmed != "" {
			cfg.EditorOrigins = append(cfg.EditorOrigins, trimmed)
		}
	}
	if len(cfg.EditorOrigins) == 0 {
		return cfg, fmt.Errorf("EDITOR_ORIGINS must name at least one origin")
	}

	cfg.CookieSecure = envBool("COOKIE_SECURE", cfg.Env != "development")
	cfg.AssetURLTTL = envDuration("ASSET_URL_TTL", time.Hour)

	for _, email := range strings.Split(env("ADMIN_EMAILS", ""), ",") {
		if trimmed := strings.TrimSpace(email); trimmed != "" {
			cfg.AdminEmails = append(cfg.AdminEmails, trimmed)
		}
	}
	cfg.AdminPassword = os.Getenv("ADMIN_PASSWORD")
	if cfg.AdminPassword != "" && len(cfg.AdminPassword) < 10 {
		return cfg, fmt.Errorf("ADMIN_PASSWORD must be at least 10 characters")
	}

	cfg.RateLimitEnabled = envBool("RATE_LIMIT_ENABLED", true)
	cfg.AuthAttemptsPerIP = envInt("AUTH_ATTEMPTS_PER_IP", 20)
	cfg.AuthAttemptWindow = envDuration("AUTH_ATTEMPT_WINDOW", time.Minute)
	cfg.LoginAttemptsPerUser = envInt("LOGIN_ATTEMPTS_PER_USER", 5)
	cfg.LoginAttemptWindow = envDuration("LOGIN_ATTEMPT_WINDOW", 15*time.Minute)
	cfg.APIRequestsPerIP = envInt("API_REQUESTS_PER_IP", 300)
	cfg.APIRequestWindow = envDuration("API_REQUEST_WINDOW", time.Minute)
	return cfg, nil
}

func (c Config) IsProduction() bool { return c.Env == "production" }

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if value, err := strconv.Atoi(env(key, "")); err == nil {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if value, err := strconv.ParseBool(env(key, "")); err == nil {
		return value
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if value, err := time.ParseDuration(env(key, "")); err == nil {
		return value
	}
	return fallback
}
