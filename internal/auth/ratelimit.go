package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
)

// Two layers guard the credential endpoints, because either one alone has a
// hole:
//
//   by address        stops one machine spraying many accounts, but an office
//                     behind one NAT shares the budget, and a botnet walks past
//   by address+email  stops a focused attack on one account, and cannot be used
//                     to lock a victim out of their own login — the attacker
//                     would have to come from the victim's own address
//
// Together they cover both. Neither is a substitute for the other.

const peekLimit = 4 << 10 // enough for a credential body, not enough to abuse

// CredentialKey buckets on the caller's address and the account being tried.
func CredentialKey(c echo.Context) string {
	email := peekEmail(c.Request())
	if email == "" {
		return c.RealIP()
	}
	return c.RealIP() + "|" + email
}

// peekEmail reads the email out of the request body and puts the body back, so
// the handler further down the chain still sees an intact request.
func peekEmail(request *http.Request) string {
	if request.Body == nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, peekLimit))
	if err != nil {
		return ""
	}
	// Whatever happens next, the handler must be able to read the body again.
	request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), request.Body))

	var body struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	return NormalizeEmail(body.Email)
}
