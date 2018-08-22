package registrystorage

import (
	"fmt"

	kuser "k8s.io/apiserver/pkg/authentication/user"

	oauthapi "github.com/openshift/api/oauth/v1"
)

// userConversion can convert user.Info to and from an oauth access/authorize token object.
type userConversion struct{}

func (s *userConversion) convertToAuthorizeToken(user interface{}, token *oauthapi.OAuthAuthorizeToken) error {
	var err error
	token.UserName, token.UserUID, err = s.convertFromUser(user)
	return err
}

func (s *userConversion) convertToAccessToken(user interface{}, token *oauthapi.OAuthAccessToken) error {
	var err error
	token.UserName, token.UserUID, err = s.convertFromUser(user)
	return err
}

func (s *userConversion) convertFromAuthorizeToken(token *oauthapi.OAuthAuthorizeToken) (kuser.Info, error) {
	return s.convertFromToken(token.UserName, token.UserUID)
}

func (s *userConversion) convertFromAccessToken(token *oauthapi.OAuthAccessToken) (kuser.Info, error) {
	return s.convertFromToken(token.UserName, token.UserUID)
}

func (s *userConversion) convertFromUser(user interface{}) (name, uid string, err error) {
	info, ok := user.(kuser.Info)
	if !ok {
		return "", "", fmt.Errorf("did not receive user.Info: %#v", user) // should be impossible
	}

	name = info.GetName()
	uid = info.GetUID()
	if len(name) == 0 || len(uid) == 0 {
		return "", "", fmt.Errorf("user.Info has no user name or UID: %#v", info) // should be impossible
	}

	return name, uid, nil
}

func (s *userConversion) convertFromToken(name, uid string) (kuser.Info, error) {
	if len(name) == 0 || len(uid) == 0 {
		return nil, fmt.Errorf("token has no user name or UID stored: name=%s uid=%s", name, uid) // should be impossible
	}

	return &kuser.DefaultInfo{
		Name: name,
		UID:  uid,
	}, nil
}
