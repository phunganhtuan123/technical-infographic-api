// Command api runs the Technical Infographic backend: accounts, per-user
// settings, and the projects that hold saved diagrams.
//
// It deliberately does not talk to any AI provider. Prompts, images and model
// calls go straight from the browser to whatever gateway that person connected,
// which is the arrangement the editor's ADR-001 describes. Nothing here should
// ever be able to read a user's diagram prompt or hold their model credential.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/phunganhtuan123/technical-infographic-api/internal/admin"
	"github.com/phunganhtuan123/technical-infographic-api/internal/asset"
	"github.com/phunganhtuan123/technical-infographic-api/internal/auth"
	"github.com/phunganhtuan123/technical-infographic-api/internal/config"
	"github.com/phunganhtuan123/technical-infographic-api/internal/database"
	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
	"github.com/phunganhtuan123/technical-infographic-api/internal/project"
	"github.com/phunganhtuan123/technical-infographic-api/internal/storage"
	"github.com/phunganhtuan123/technical-infographic-api/internal/user"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("startup failed: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	db, err := database.Open(cfg.DatabaseURL, cfg.IsProduction())
	if err != nil {
		return err
	}
	if os.Getenv("AUTO_MIGRATE") == "true" {
		if err := database.AutoMigrate(db); err != nil {
			return err
		}
		log.Println("schema synced with AutoMigrate (development only)")
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = httpx.ErrorHandler

	e.Use(middleware.RequestID())
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.BodyLimit("16M"))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		// No wildcard. Credentials are sent with these requests, and a wildcard
		// origin would let any site drive somebody's account.
		AllowOrigins:     cfg.EditorOrigins,
		AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{echo.HeaderAuthorization, echo.HeaderContentType, echo.HeaderAccept, "If-Match"},
		ExposeHeaders:    []string{"ETag"},
		AllowCredentials: true,
		MaxAge:           600,
	}))

	e.GET("/healthz", func(c echo.Context) error {
		pool, err := db.DB()
		if err != nil || pool.PingContext(c.Request().Context()) != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"status": "database unreachable"})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	manager := auth.NewManager(db, cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	// Before any route is served: a deployment with nobody who can administer
	// it is a deployment that needs a database console to fix.
	if len(cfg.AdminEmails) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := admin.Bootstrap(ctx, db, manager, cfg.AdminEmails, cfg.AdminPassword)
		cancel()
		if err != nil {
			return err
		}
	}

	sameSite := http.SameSiteLaxMode
	if cfg.CookieSecure {
		// Once the editor and the API are on different sites, Lax stops the
		// browser sending the refresh cookie at all.
		sameSite = http.SameSiteNoneMode
	}
	authHandler := auth.NewHandler(manager, auth.CookieOptions{
		Domain:   cfg.CookieDomain,
		Secure:   cfg.CookieSecure,
		SameSite: sameSite,
	})

	// Rate limiting. Three layers, each answering a different attack:
	//
	//   api          a broad ceiling so no single address can flood the service
	//   auth by IP   stops one machine spraying passwords across many accounts
	//   credential   stops a focused attack on one account, keyed by address AND
	//                email so it cannot be turned around to lock a victim out
	//
	// Counters live in this process. With two instances behind a balancer the
	// effective limit doubles — move the store to Redis before scaling out.
	limiter := httpx.NewMemoryStore()
	defer limiter.Close()

	var apiLimit, authLimit, credentialLimit echo.MiddlewareFunc
	if cfg.RateLimitEnabled {
		apiLimit = httpx.RateLimit(limiter, "api", cfg.APIRequestsPerIP, cfg.APIRequestWindow, httpx.ByIP)
		authLimit = httpx.RateLimit(limiter, "auth", cfg.AuthAttemptsPerIP, cfg.AuthAttemptWindow, httpx.ByIP)
		credentialLimit = httpx.RateLimit(limiter, "credential", cfg.LoginAttemptsPerUser, cfg.LoginAttemptWindow, auth.CredentialKey)
	} else {
		log.Println("WARNING: rate limiting is off")
		passthrough := func(next echo.HandlerFunc) echo.HandlerFunc { return next }
		apiLimit, authLimit, credentialLimit = passthrough, passthrough, passthrough
	}

	v1 := e.Group("/v1", apiLimit)
	authHandler.Register(v1.Group("/auth", authLimit), credentialLimit)

	files, err := storage.NewLocalDisk(cfg.AssetDir)
	if err != nil {
		return err
	}
	assets := asset.NewHandler(asset.NewService(db, files, cfg.JWTSecret, cfg.MaxAssetBytes, cfg.AssetURLTTL))
	// Images are fetched by <img>, which cannot send an Authorization header,
	// so this one route authorises with a signature in the URL instead.
	assets.RegisterPublic(v1)

	// Everything below needs a valid access token.
	secure := v1.Group("", manager.Middleware())
	user.NewHandler(db).Register(secure)
	admin.NewHandler(db, manager).Register(secure)
	project.NewHandler(project.NewService(db, cfg.MaxDocumentBytes)).Register(secure)
	assets.RegisterSecure(secure)

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           e,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	go func() {
		log.Printf("listening on :%s (%s) · editors: %v", cfg.Port, cfg.Env, cfg.EditorOrigins)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	// Finish in-flight requests before exiting, so a deploy does not drop
	// somebody's save halfway through.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	log.Println("shutting down")
	return server.Shutdown(ctx)
}
