package oauth

import (
	"github.com/openshift/origin/pkg/cmd/server/apis/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kauthenticator "k8s.io/apiserver/pkg/authentication/authenticator"
	kuser "k8s.io/apiserver/pkg/authentication/user"

	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
)

type bootstrapAuthenticator struct {
	tokens oauthclient.OAuthAccessTokenInterface
}

func NewBootstrapAuthenticator(tokens oauthclient.OAuthAccessTokenInterface) kauthenticator.Token {
	return &bootstrapAuthenticator{
		tokens: tokens,
	}
}

func (a *bootstrapAuthenticator) AuthenticateToken(name string) (kuser.Info, bool, error) {
	token, err := a.tokens.Get(name, metav1.GetOptions{})
	if err != nil {
		return nil, false, errLookup // mask the error so we do not leak token data in logs
	}

	if token.UserName != config.BootstrapUser {
		return nil, false, nil
	}

	// TODO make sure secret is still valid -- could store the hash as user UID, actually just stored secret UUID
	// TODO make sure token is not expired

	// we explicitly do not set UID as we do not want to leak any derivative of the password
	return &kuser.DefaultInfo{
		Name:   config.BootstrapUser,
		Groups: []string{kuser.SystemPrivilegedGroup},
	}, true, nil
}
