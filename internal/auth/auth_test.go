package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "correct horse battery staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == password {
		t.Error("HashPassword() returned the plaintext password")
	}

	// argon2id salts every call, so the same password should never hash twice
	// to the same string
	other, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hash == other {
		t.Error("HashPassword() produced identical hashes, salt is not random")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "correct horse battery staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
		wantErr  bool
	}{
		{"matching password", password, hash, true, false},
		{"wrong password", "hunter2", hash, false, false},
		{"empty password", "", hash, false, false},
		{"malformed hash", password, "not-a-hash", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("CheckPasswordHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMakeJWTAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "super-secret-signing-key"

	token, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	got, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}
	if got != userID {
		t.Errorf("ValidateJWT() = %v, want %v", got, userID)
	}
}

func TestValidateJWTRejectsExpired(t *testing.T) {
	userID := uuid.New()
	secret := "super-secret-signing-key"

	// negative duration puts ExpiresAt in the past
	token, err := MakeJWT(userID, secret, -time.Minute)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	if _, err := ValidateJWT(token, secret); err == nil {
		t.Error("ValidateJWT() accepted an expired token, want error")
	}
}

func TestValidateJWTRejectsWrongSecret(t *testing.T) {
	userID := uuid.New()

	token, err := MakeJWT(userID, "the-right-secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	if _, err := ValidateJWT(token, "the-wrong-secret"); err == nil {
		t.Error("ValidateJWT() accepted a token signed with a different secret, want error")
	}
}

func TestValidateJWTRejectsGarbage(t *testing.T) {
	if _, err := ValidateJWT("not.a.jwt", "super-secret-signing-key"); err == nil {
		t.Error("ValidateJWT() accepted a malformed token, want error")
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		setHeader  bool
		want       string
		wantErr    bool
	}{
		{"valid bearer", "Bearer abc123", true, "abc123", false},
		{"extra whitespace", "Bearer   abc123   ", true, "abc123", false},
		{"no header", "", false, "", true},
		{"empty header", "", true, "", true},
		{"wrong scheme", "Basic abc123", true, "", true},
		{"bearer with no token", "Bearer ", true, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.setHeader {
				headers.Set("Authorization", tt.authHeader)
			}

			got, err := GetBearerToken(headers)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetBearerToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetBearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}
