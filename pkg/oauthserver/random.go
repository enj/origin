package oauthserver

import (
	"crypto/rand"
	"encoding/base64"
)

func RandomBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand should never fail
	}
	return b
}

// RandomString uses RawURLEncoding to ensure we do not get / characters or trailing ='s
func RandomString(size int) string {
	// each byte (8 bits) gives us 4/3 base64 (6 bits) characters
	// we account for that conversion and add one to handle truncation
	b64size := base64.RawURLEncoding.DecodedLen(size) + 1
	// trim down to the original requested size since we added one above
	return base64.RawURLEncoding.EncodeToString(RandomBytes(b64size))[:size]
}

// Random256BitString uses RandomString with the appropriate length needed for 256 bits of entropy
func Random256BitString() string {
	// 32 bytes (256 bits) = 43 base64-encoded characters
	return RandomString(base64.RawURLEncoding.EncodedLen(256 / 8))
}
