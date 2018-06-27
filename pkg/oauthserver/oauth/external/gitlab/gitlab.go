package gitlab

import (
	"net/http"

	"github.com/openshift/origin/pkg/oauthserver/oauth/external"
)

func NewProvider(providerName, URL, clientID, clientSecret string, transport http.RoundTripper) (external.Provider, error) {
	return NewOIDCProvider(providerName, URL, clientID, clientSecret, transport)
}
