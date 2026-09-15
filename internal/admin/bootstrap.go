package admin

import (
	"context"
	"errors"
	"log"
	"strings"

	"gorm.io/gorm"

	"github.com/phunganhtuan123/technical-infographic-api/internal/auth"
	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

// Bootstrap makes sure somebody can administer a fresh deployment.
//
// The alternative is a chicken-and-egg problem: the only screen that can
// promote an administrator is the one only an administrator can open. A
// first-run flow ("the first account to register becomes admin") answers it
// too, but on a public sign-up page that is a race anyone can win. The
// environment is the one place an operator already controls.
//
// Every address in `emails` is promoted if an account exists. The first one is
// also *created* when it does not exist and `password` is set — so a brand-new
// database goes from nothing to a working administrator with no SQL console.
// Runs on every boot and is idempotent; removing an address here never demotes
// anyone, because silently taking access away at deploy time is worse than
// leaving it to be revoked on the screen built for it.
func Bootstrap(ctx context.Context, db *gorm.DB, manager *auth.Manager, emails []string, password string) error {
	for index, raw := range emails {
		email := auth.NormalizeEmail(raw)
		if email == "" {
			continue
		}

		var existing model.User
		err := db.WithContext(ctx).First(&existing, "email = ?", email).Error
		switch {
		case err == nil:
			if existing.IsAdmin() && !existing.IsDisabled() {
				continue
			}
			// Restoring the account as well as the role: an operator who has
			// put an address in this list wants to be able to sign in with it,
			// and a suspended administrator cannot.
			if err := db.WithContext(ctx).Model(&model.User{}).
				Where("id = ?", existing.ID).
				Updates(map[string]any{"role": model.RoleAdmin, "disabled_at": nil}).Error; err != nil {
				return err
			}
			log.Printf("admin: %s promoted to administrator", email)

		case errors.Is(err, gorm.ErrRecordNotFound):
			// Only the first address is worth creating. Creating them all would
			// quietly mint accounts nobody asked for from a stale list.
			if index != 0 || password == "" {
				log.Printf("admin: no account for %s yet — it becomes an administrator when it registers", email)
				continue
			}
			name, _, _ := strings.Cut(email, "@")
			created, err := manager.Register(ctx, email, password, name)
			if err != nil {
				return err
			}
			if err := db.WithContext(ctx).Model(&model.User{}).
				Where("id = ?", created.ID).
				Update("role", model.RoleAdmin).Error; err != nil {
				return err
			}
			log.Printf("admin: created administrator %s — change the password after signing in", email)

		default:
			return err
		}
	}
	return nil
}
