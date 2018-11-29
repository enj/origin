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

	return &kuser.DefaultInfo{
		Name:   token.UserName,
		UID:    token.UserUID,
		Groups: []string{kuser.SystemPrivilegedGroup},
	}, true, nil
}
