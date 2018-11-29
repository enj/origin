package oauth

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kauthenticator "k8s.io/apiserver/pkg/authentication/authenticator"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/typed/core/v1"

	userapi "github.com/openshift/api/user/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	"github.com/openshift/origin/pkg/cmd/server/apis/config"
	"github.com/openshift/origin/pkg/oauthserver/authenticator/password/bootstrap"
)

type bootstrapAuthenticator struct {
	tokens    oauthclient.OAuthAccessTokenInterface
	secrets   v1.SecretInterface
	validator OAuthTokenValidator
}

func NewBootstrapAuthenticator(tokens oauthclient.OAuthAccessTokenInterface, secrets v1.SecretInterface, validators ...OAuthTokenValidator) kauthenticator.Token {
	return &bootstrapAuthenticator{
		tokens:    tokens,
		secrets:   secrets,
		validator: OAuthTokenValidators(validators),
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

	_, uid, ok, err := bootstrap.HashAndUID(a.secrets)
	if err != nil || !ok {
		return nil, ok, err
	}

	// this allows us to reuse existing validators
	fakeUser := &userapi.User{
		ObjectMeta: metav1.ObjectMeta{
			UID: types.UID(uid),
		},
	}

	if err := a.validator.Validate(token, fakeUser); err != nil {
		return nil, false, err
	}

	// we explicitly do not set UID as we do not want to leak any derivative of the password
	return &kuser.DefaultInfo{
		Name:   config.BootstrapUser,
		Groups: []string{kuser.SystemPrivilegedGroup},
	}, true, nil
}
