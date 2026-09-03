package httpx

import (
	"testing"
	"time"
)

func TestMemoryStoreAllowsUpToLimit(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	for attempt := 1; attempt <= 3; attempt++ {
		allowed, _ := store.Allow("key", 3, time.Minute)
		if !allowed {
			t.Fatalf("attempt %d should be allowed", attempt)
		}
	}
	allowed, retryAfter := store.Allow("key", 3, time.Minute)
	if allowed {
		t.Fatal("the fourth attempt should be refused")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Fatalf("retryAfter should be inside the window, got %v", retryAfter)
	}
}

func TestMemoryStoreKeysAreIndependent(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	for i := 0; i < 3; i++ {
		store.Allow("first", 3, time.Minute)
	}
	// One caller exhausting their budget must not affect anybody else.
	if allowed, _ := store.Allow("second", 3, time.Minute); !allowed {
		t.Fatal("a different key must have its own budget")
	}
}

func TestMemoryStoreWindowExpires(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()

	store.Allow("key", 1, 30*time.Millisecond)
	if allowed, _ := store.Allow("key", 1, 30*time.Millisecond); allowed {
		t.Fatal("second attempt inside the window should be refused")
	}
	time.Sleep(40 * time.Millisecond)
	if allowed, _ := store.Allow("key", 1, 30*time.Millisecond); !allowed {
		t.Fatal("a new window should start clean")
	}
}
