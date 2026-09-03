package auth

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPeekEmailLeavesBodyReadable(t *testing.T) {
	payload := `{"email":"  Phung@Example.COM ","password":"secret"}`
	request := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(payload))

	if got := peekEmail(request); got != "phung@example.com" {
		t.Fatalf("peekEmail = %q, want the normalised address", got)
	}

	// The handler downstream must still see the whole body, or every login
	// would fail the moment rate limiting was switched on.
	rest, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("body should still be readable: %v", err)
	}
	if string(rest) != payload {
		t.Fatalf("body was consumed: got %q", rest)
	}
}

func TestPeekEmailHandlesRubbish(t *testing.T) {
	for _, payload := range []string{"", "not json", `{"email":123}`, `{}`} {
		request := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(payload))
		if got := peekEmail(request); got != "" {
			t.Errorf("peekEmail(%q) = %q, want empty", payload, got)
		}
	}
}
