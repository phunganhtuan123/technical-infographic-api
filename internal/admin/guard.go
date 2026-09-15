package admin

import (
	"github.com/google/uuid"

	"github.com/phunganhtuan123/technical-infographic-api/internal/httpx"
	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

// The rules that stop this screen destroying the access it depends on.
//
// Pure functions taking the one fact they need from the database — how many
// other administrators are still able to sign in — so the rules can be tested
// without a Postgres. Every one of them protects against the same shape of
// mistake: an operator removing the last way back in, then needing a database
// console to undo it.

var (
	errSuspendSelf = httpx.BadRequest("You cannot suspend your own account.")
	errDemoteSelf  = httpx.BadRequest("You cannot remove your own administrator access.")
	errDeleteSelf  = httpx.BadRequest("You cannot delete your own account from here.")
	errLastAdmin   = httpx.BadRequest("This is the only active administrator. Promote someone else first.")
	errBadRole     = httpx.BadRequest("A role is either 'user' or 'admin'.").
			WithFields(map[string]any{"role": "invalid"})
)

// lastAdmin reports whether removing this account's access would leave nobody
// able to administer the service. Only administrators count — demoting an
// ordinary user never closes the door.
func lastAdmin(target model.User, otherActiveAdmins int64) bool {
	return target.IsAdmin() && otherActiveAdmins == 0
}

// checkSuspend guards the suspend/restore action. Restoring is always allowed:
// it only ever adds access back.
func checkSuspend(actor uuid.UUID, target model.User, disabled bool, otherActiveAdmins int64) error {
	if !disabled {
		return nil
	}
	if target.ID == actor {
		return errSuspendSelf
	}
	if lastAdmin(target, otherActiveAdmins) {
		return errLastAdmin
	}
	return nil
}

// checkRole guards a role change. Promoting is always allowed; the danger is
// only ever in taking administrator away.
func checkRole(actor uuid.UUID, target model.User, next model.Role, otherActiveAdmins int64) error {
	if next != model.RoleUser && next != model.RoleAdmin {
		return errBadRole
	}
	if next == model.RoleAdmin {
		return nil
	}
	if target.ID == actor {
		return errDemoteSelf
	}
	if lastAdmin(target, otherActiveAdmins) {
		return errLastAdmin
	}
	return nil
}

// checkDelete guards removal. Deleting yourself is refused here even when other
// administrators remain: this screen is for managing other people, and an
// account that deletes itself mid-session leaves the open tab holding a token
// for a row that no longer exists.
func checkDelete(actor uuid.UUID, target model.User, otherActiveAdmins int64) error {
	if target.ID == actor {
		return errDeleteSelf
	}
	if lastAdmin(target, otherActiveAdmins) {
		return errLastAdmin
	}
	return nil
}
