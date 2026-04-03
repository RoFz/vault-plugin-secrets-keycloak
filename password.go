package secretsengine

import (
	"crypto/rand"
	"encoding/base64"
)

// generatePassword creates a cryptographically random password using 32 bytes of
// entropy, returned as a URL-safe base64 string (43 characters, no padding).
func generatePassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
