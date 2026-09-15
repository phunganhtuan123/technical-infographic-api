package admin

import (
	"testing"

	"github.com/google/uuid"

	"github.com/phunganhtuan123/technical-infographic-api/internal/model"
)

var (
	me        = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	other     = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	otherUser = model.User{ID: other, Role: model.RoleUser}
	otherBoss = model.User{ID: other, Role: model.RoleAdmin}
	self      = model.User{ID: me, Role: model.RoleAdmin}
)

func TestCheckSuspend(t *testing.T) {
	cases := []struct {
		name     string
		target   model.User
		disabled bool
		others   int64
		wantErr  error
	}{
		{"suspends an ordinary account", otherUser, true, 0, nil},
		{"refuses to suspend yourself", self, true, 5, errSuspendSelf},
		// Restoring only ever gives access back, so none of the guards apply —
		// including to your own account, which is how an operator recovers if
		// two administrators suspended each other.
		{"restoring yourself is fine", self, false, 0, nil},
		{"refuses to suspend the last administrator", otherBoss, true, 0, errLastAdmin},
		{"suspends an administrator when another remains", otherBoss, true, 1, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkSuspend(me, tc.target, tc.disabled, tc.others); err != tc.wantErr {
				t.Errorf("checkSuspend() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckRole(t *testing.T) {
	cases := []struct {
		name    string
		target  model.User
		next    model.Role
		others  int64
		wantErr error
	}{
		{"promotes an ordinary account", otherUser, model.RoleAdmin, 0, nil},
		{"promoting never trips the last-admin rule", otherUser, model.RoleAdmin, 0, nil},
		{"refuses an unknown role", otherUser, model.Role("superuser"), 5, errBadRole},
		{"refuses to demote yourself", self, model.RoleUser, 5, errDemoteSelf},
		{"refuses to demote the last administrator", otherBoss, model.RoleUser, 0, errLastAdmin},
		{"demotes an administrator when another remains", otherBoss, model.RoleUser, 1, nil},
		{"re-promoting yourself is a no-op, not a lockout", self, model.RoleAdmin, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkRole(me, tc.target, tc.next, tc.others); err != tc.wantErr {
				t.Errorf("checkRole() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckDelete(t *testing.T) {
	cases := []struct {
		name    string
		target  model.User
		others  int64
		wantErr error
	}{
		{"deletes an ordinary account", otherUser, 0, nil},
		// Refused even with other administrators around: this screen manages
		// other people, and the open tab would be holding a token for a row
		// that no longer exists.
		{"refuses to delete yourself", self, 5, errDeleteSelf},
		{"refuses to delete the last administrator", otherBoss, 0, errLastAdmin},
		{"deletes an administrator when another remains", otherBoss, 1, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkDelete(me, tc.target, tc.others); err != tc.wantErr {
				t.Errorf("checkDelete() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
