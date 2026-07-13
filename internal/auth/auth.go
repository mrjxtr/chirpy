// Package auth handles password hashing and verification for Chirpy.
package auth

import "github.com/alexedwards/argon2id"

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
