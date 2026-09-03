package auth

import (
	"strings"
	"testing"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Fatalf("unexpected encoding: %s", encoded)
	}
	if err := VerifyPassword("correct-horse-battery-staple", encoded); err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}
	if err := VerifyPassword("not-the-password", encoded); err != ErrPasswordMismatch {
		t.Fatalf("wrong password should not verify, got %v", err)
	}
}

func TestHashPasswordSaltsEachTime(t *testing.T) {
	first, _ := HashPassword("same-password-twice")
	second, _ := HashPassword("same-password-twice")
	if first == second {
		t.Fatal("two hashes of one password must differ; the salt is not random")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, encoded := range []string{"", "plaintext", "$argon2id$broken", "$bcrypt$v=19$m=1,t=1,p=1$aa$bb"} {
		if err := VerifyPassword("anything", encoded); err == nil {
			t.Fatalf("expected an error for %q", encoded)
		}
	}
}

func TestNormalizeEmail(t *testing.T) {
	for input, want := range map[string]string{
		"  Phung@Example.COM ": "phung@example.com",
		"already@lower.com":    "already@lower.com",
	} {
		if got := NormalizeEmail(input); got != want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", input, got, want)
		}
	}
}
