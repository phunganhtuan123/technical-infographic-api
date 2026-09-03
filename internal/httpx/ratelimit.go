package httpx

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

// Rate limiting, in memory.
//
// One honest caveat up front: this counts inside a single process. Run two
// copies of the API behind a load balancer and each keeps its own tally, so the
// real limit doubles. That is fine for one instance and for staging; the moment
// there are two, move Store to Redis. The interface below is the seam for that
// — nothing outside this file knows where the counters live.

type Store interface {
	// Allow records a hit and reports whether it is within the limit, plus how
	// long until the caller may try again.
	Allow(key string, limit int, window time.Duration) (bool, time.Duration)
}

type counter struct {
	hits      int
	expiresAt time.Time
}

// MemoryStore is a fixed-window counter. Fixed windows let through up to twice
// the limit across a boundary, which is the accepted trade for being cheap and
// having no dependencies. For login attempts that is immaterial: ten tries
// instead of five is still nowhere near enough to brute force a password.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]*counter
	stop    chan struct{}
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{entries: make(map[string]*counter), stop: make(chan struct{})}
	go store.sweep()
	return store
}

func (s *MemoryStore) Allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok || now.After(entry.expiresAt) {
		s.entries[key] = &counter{hits: 1, expiresAt: now.Add(window)}
		return true, 0
	}
	entry.hits++
	if entry.hits > limit {
		return false, time.Until(entry.expiresAt)
	}
	return true, 0
}

// sweep drops expired windows so a stream of one-off keys — every IP that ever
// touched the service — cannot grow the map without bound.
func (s *MemoryStore) sweep() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for key, entry := range s.entries {
				if now.After(entry.expiresAt) {
					delete(s.entries, key)
				}
			}
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}

func (s *MemoryStore) Close() { close(s.stop) }

// RateLimit turns a store into middleware. `key` decides what is being counted:
// the caller's address for a general limit, or address plus the email being
// tried for a login limit, so one attacker cannot lock out a whole office by
// exhausting the shared IP budget.
func RateLimit(store Store, name string, limit int, window time.Duration, key func(echo.Context) string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			identity := key(c)
			if identity == "" {
				return next(c)
			}
			allowed, retryAfter := store.Allow(name+":"+identity, limit, window)
			if allowed {
				return next(c)
			}

			seconds := int(retryAfter.Seconds()) + 1
			c.Response().Header().Set("Retry-After", strconv.Itoa(seconds))
			return New(http.StatusTooManyRequests, "rate_limited",
				"Too many attempts. Wait "+humanise(seconds)+" and try again.")
		}
	}
}

// ByIP is the default key: one bucket per caller address.
func ByIP(c echo.Context) string { return c.RealIP() }

func humanise(seconds int) string {
	switch {
	case seconds < 60:
		return strconv.Itoa(seconds) + " seconds"
	case seconds < 120:
		return "a minute"
	default:
		return strconv.Itoa(seconds/60) + " minutes"
	}
}
