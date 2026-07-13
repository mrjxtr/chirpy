// Package auth handles password hashing and JWT creation/validation for Chirpy.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// tokenIssuer identifies tokens minted by this service.
const tokenIssuer = "chirpy-access"

// HashPassword turns a plaintext password into an argon2id hash string. The
// returned string already carries the salt and params, so it's the only thing
// that needs storing.
func HashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

// CheckPasswordHash reports whether password matches the stored hash. An error
// means the hash itself was malformed, not that the password was wrong.
func CheckPasswordHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}

// MakeJWT mints an HS256 access token for userID that expires after expiresIn.
// The user's id rides in the Subject claim as a string.
func MakeJWT(
	userID uuid.UUID,
	tokenSecret string,
	expiresIn time.Duration,
) (string, error) {
	now := time.Now().UTC()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    tokenIssuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
		Subject:   userID.String(),
	})

	return token.SignedString([]byte(tokenSecret))
}

// ValidateJWT checks a token's signature and expiry, then pulls the user id out
// of the Subject claim. Expired tokens, wrong secrets, and tokens signed with
// an unexpected method all come back as errors.
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(t *jwt.Token) (any, error) {
			// guard against alg swapping, e.g. a token forged with "none"
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(tokenSecret), nil
		},
	)
	if err != nil {
		return uuid.Nil, err
	}
	if !token.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user id in token subject: %w", err)
	}

	return userID, nil
}

// MakeRefreshToken returns a random 256-bit token, hex encoded. Unlike a JWT
// this carries no claims, it's just an opaque lookup key for the
// refresh_tokens table.
func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("could not generate refresh token: %w", err)
	}

	return hex.EncodeToString(key), nil
}

// GetBearerToken pulls the raw token out of an "Authorization: Bearer <token>"
// header. Missing header or a non-Bearer scheme is an error.
func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("no authorization header included")
	}

	token, found := strings.CutPrefix(authHeader, "Bearer ")
	if !found {
		return "", fmt.Errorf("malformed authorization header")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("no token in authorization header")
	}

	return token, nil
}
