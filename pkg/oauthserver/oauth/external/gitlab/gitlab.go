package gitlab

import (
	"errors"
	"net/http"
	"net/url"
	"path"

	"github.com/openshift/origin/pkg/oauthserver/oauth/external"
	"github.com/openshift/origin/pkg/oauthserver/oauth/external/openid"
)

const (
	// https://gitlab.com/help/integration/openid_connect_provider.md
	// Uses GitLab OIDC, requires GitLab 11.1.0 or higher
	// Earlier versions do not work: https://gitlab.com/gitlab-org/gitlab-ce/issues/47791#note_81269161
	gitlabAuthorizePath = "/oauth/authorize"
	gitlabTokenPath     = "/oauth/token"
	gitlabUserInfoPath  = "/oauth/userinfo"

	// https://gitlab.com/gitlab-org/gitlab-ce/blob/master/config/locales/doorkeeper.en.yml
	// Authenticate using OpenID Connect
	// The ability to authenticate using GitLab, and read-only access to the user's profile information and group memberships
	gitlabOIDCScope = "openid"

	// An opaque token that uniquely identifies the user
	// Along with providerName, builds the identity object's Name field (see Identity.ProviderUserName)
	gitlabIDClaim = "sub"
	// The user's GitLab username
	// Used as the Name field of the user object (stored in Identity.Extra, see IdentityPreferredUsernameKey)
	gitlabPreferredUsernameClaim = "nickname"
	// The user's public email address
	// The value can optionally be used during manual provisioning (stored in Identity.Extra, see IdentityEmailKey)
	gitlabEmailClaim = "email"
	// The user's full name
	// Used as the FullName field of the user object (stored in Identity.Extra, see IdentityDisplayNameKey)
	gitlabDisplayNameClaim = "name"
)

func NewProvider(providerName, URL, clientID, clientSecret string, transport http.RoundTripper) (external.Provider, error) {
	// Create service URLs
	u, err := url.Parse(URL)
	if err != nil {
		return nil, errors.New("gitlab host URL is invalid")
	}

	config := openid.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,

		AuthorizeURL: appendPath(*u, gitlabAuthorizePath),
		TokenURL:     appendPath(*u, gitlabTokenPath),
		UserInfoURL:  appendPath(*u, gitlabUserInfoPath),

		Scopes: []string{gitlabOIDCScope},

		IDClaims:                []string{gitlabIDClaim},
		PreferredUsernameClaims: []string{gitlabPreferredUsernameClaim},
		EmailClaims:             []string{gitlabEmailClaim},
		NameClaims:              []string{gitlabDisplayNameClaim},
	}

	return openid.NewProvider(providerName, transport, config)
}

func appendPath(u url.URL, subpath string) string {
	u.Path = path.Join(u.Path, subpath)
	return u.String()
}
