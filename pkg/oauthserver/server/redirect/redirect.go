package redirect

import (
	"net/url"
	"strings"
)

func IsServerRelativeURL(then string) bool {
	if len(then) == 0 {
		return false
	}

	u, err := url.Parse(then)
	if err != nil {
		return false
	}

	return len(u.Scheme) == 0 && len(u.Host) == 0 && strings.HasPrefix(u.Path, "/")
}
