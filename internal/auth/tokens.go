package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Two different kinds of token, on purpose.
//
// The access token is a short-lived JWT: it is checked with a signature and no
// database round trip, which is what makes every request cheap. The price is
// that it cannot be revoked, so it expires in minutes.
//
// The refresh token is a random string with no meaning at all. Only its hash is
// stored, so a leaked database gives an attacker nothing usable, and because
// every use is a database row it can be revoked the moment something looks
// wrong.

type Claims struct {
	jwt.RegisteredClaims
}

func (m *Manager) NewAccessToken(userID uuid.UUID) (string, time.Time, error) {
	now := time.Now()
	expires := now.Add(m.accessTTL)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
			ID:        uuid.NewString(),
		},
	})
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return signed, expires, nil
}

func (m *Manager) ParseAccessToken(raw string) (uuid.UUID, error) {
	var claims Claims
	_, err := jwt.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return m.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(claims.Subject)
}

// newRefreshToken returns the value handed to the browser and the hash kept in
// the database. The plain value is never stored anywhere.
func newRefreshToken() (plain string, hash []byte, err error) {
	buffer := make([]byte, 32)
	if _, err = rand.Read(buffer); err != nil {
		return "", nil, fmt.Errorf("read refresh token: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(buffer)
	sum := sha256.Sum256([]byte(plain))
	return plain, sum[:], nil
}

func hashRefreshToken(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}
