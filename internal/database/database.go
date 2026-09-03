// Package database opens the pool and keeps GORM quiet in production.
package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

func Open(dsn string, production bool) (*gorm.DB, error) {
	level := logger.Info
	if production {
		level = logger.Warn
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		// Without this, GORM reports every duplicate key the same way and the
		// service cannot tell "email already used" from a real failure.
		TranslateError: true,
		Logger: logger.New(log.New(os.Stdout, "", log.LstdFlags), logger.Config{
			SlowThreshold:             300 * time.Millisecond,
			LogLevel:                  level,
			IgnoreRecordNotFoundError: true,
			Colorful:                  !production,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	pool, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("pool: %w", err)
	}
	pool.SetMaxOpenConns(25)
	pool.SetMaxIdleConns(5)
	pool.SetConnMaxLifetime(time.Hour)
	pool.SetConnMaxIdleTime(10 * time.Minute)
	return db, nil
}

// AutoMigrate is for local development only. Production schema changes go
// through migrations/, because AutoMigrate will not rename a column, will not
// drop one, and cannot be rolled back.
func AutoMigrate(db *gorm.DB) error {
	if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS citext`).Error; err != nil {
		return err
	}
	if err := db.Exec(`CREATE EXTENSION IF NOT EXISTS pgcrypto`).Error; err != nil {
		return err
	}
	if err := db.AutoMigrate(model.All()...); err != nil {
		return err
	}
	// AutoMigrate has no way to express a partial index, so the constraint that
	// actually stops two accounts claiming one email has to be added by hand.
	// Without it, development quietly allows what production forbids — and the
	// bug only shows up after launch.
	return db.Exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (email)
		WHERE email IS NOT NULL AND deleted_at IS NULL`).Error
}
