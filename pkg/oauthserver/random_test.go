package oauthserver

import (
	"strconv"
	"testing"
)

func TestRandomString(t *testing.T) {
	for size := 0; size < 1<<10+1; size++ {
		size := size // capture range variable
		t.Run(strconv.FormatInt(int64(size), 10), func(t *testing.T) {
			t.Parallel()
			if got := RandomString(size); len(got) != size {
				t.Errorf("randomString() -> len=%v, want len=%v, diff=%v", len(got), size, len(got)-size)
			}
		})
	}
}
