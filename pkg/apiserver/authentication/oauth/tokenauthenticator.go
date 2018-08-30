package oauth

import (
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kauthenticator "k8s.io/apiserver/pkg/authentication/authenticator"
	kuser "k8s.io/apiserver/pkg/authentication/user"

	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
)

var errLookup = errors.New("token lookup failed")

type tokenAuthenticator struct {
	tokens      oauthclient.OAuthAccessTokenInterface
	users       userclient.UserInterface
	groupMapper UserToGroupMapper
	validators  OAuthTokenValidator
}

func NewTokenAuthenticator(tokens oauthclient.OAuthAccessTokenInterface, users userclient.UserInterface, groupMapper UserToGroupMapper, validators ...OAuthTokenValidator) kauthenticator.Token {
	return &tokenAuthenticator{
		tokens:      tokens,
		users:       users,
		groupMapper: groupMapper,
		validators:  OAuthTokenValidators(validators),
	}
}

func (a *tokenAuthenticator) AuthenticateToken(name string) (kuser.Info, bool, error) {
	token, err := a.tokens.Get(name, metav1.GetOptions{})
	if err != nil {
		return nil, false, errLookup // mask the error so we do not leak token data in logs
	}

	user, err := a.users.Get(token.UserName, metav1.GetOptions{})
	if err != nil {
		return nil, false, err
	}

	if err := a.validators.Validate(token, user); err != nil {
		return nil, false, err
	}

	groups, err := a.groupMapper.GroupsFor(user.Name)
	if err != nil {
		return nil, false, err
	}
	groupNames := make([]string, 0, len(groups)+len(user.Groups)+len(token.ProviderGroups))
	for _, group := range groups {
		groupNames = append(groupNames, group.Name)
	}
	groupNames = append(groupNames, user.Groups...)
	groupNames = append(groupNames, token.ProviderGroups...)
	// TODO needs IDP prefixing, should move out the entire group logic from here
	// TODO make this larger per identity metadata groups (after processing them)
	// append identity metadata groups AFTER filtering them for :, adding IDP prefix, handling IDP mapping
	// the processed group list can be cached since the object is immutable
	// could be an index built on top of an informer that fallback to live lookups

	return &kuser.DefaultInfo{
		Name:   user.Name,
		UID:    string(user.UID),
		Groups: groupNames,
		Extra: map[string][]string{
			authorizationapi.ScopesKey: token.Scopes,
		},
	}, true, nil
}
