package secretsengine

import (
	"encoding/base64"
	"testing"
)

func TestGeneratePassword_Length(t *testing.T) {
	pw, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword() returned error: %v", err)
	}
	// 32 bytes → 43 chars in RawURLEncoding (no padding).
	if len(pw) != 43 {
		t.Errorf("expected length 43, got %d", len(pw))
	}
}

func TestGeneratePassword_ValidBase64URL(t *testing.T) {
	pw, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword() returned error: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(pw); err != nil {
		t.Errorf("password is not valid base64url: %v", err)
	}
}

func TestGeneratePassword_Unique(t *testing.T) {
	seen := make(map[string]struct{})
	for range 50 {
		pw, err := generatePassword()
		if err != nil {
			t.Fatalf("generatePassword() returned error: %v", err)
		}
		if _, dup := seen[pw]; dup {
			t.Fatalf("duplicate password after %d iterations", len(seen)+1)
		}
		seen[pw] = struct{}{}
	}
}
