package auth

import "testing"

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
