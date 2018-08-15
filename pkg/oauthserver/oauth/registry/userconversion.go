package registry

import (
	"errors"

	kuser "k8s.io/apiserver/pkg/authentication/user"

	oauthapi "github.com/openshift/api/oauth/v1"
)

type UserConversion interface {
	ConvertToAuthorizeToken(interface{}, *oauthapi.OAuthAuthorizeToken) error
	ConvertToAccessToken(interface{}, *oauthapi.OAuthAccessToken) error
	ConvertFromAuthorizeToken(*oauthapi.OAuthAuthorizeToken) (kuser.Info, error)
	ConvertFromAccessToken(*oauthapi.OAuthAccessToken) (kuser.Info, error)
}

type userConversion struct{}

// NewUserConversion creates an object that can convert the user.Info object to and from
// an oauth access/authorize token object.
func NewUserConversion() UserConversion {
	return &userConversion{}
}

func (s *userConversion) ConvertToAuthorizeToken(user interface{}, token *oauthapi.OAuthAuthorizeToken) (err error) {
	token.UserName, token.UserUID, err = s.convertFromUser(user)
	return err
}

func (s *userConversion) ConvertToAccessToken(user interface{}, token *oauthapi.OAuthAccessToken) (err error) {
	token.UserName, token.UserUID, err = s.convertFromUser(user)
	return err
}

func (s *userConversion) ConvertFromAuthorizeToken(token *oauthapi.OAuthAuthorizeToken) (kuser.Info, error) {
	return s.convertFromToken(token.UserName, token.UserUID)
}

func (s *userConversion) ConvertFromAccessToken(token *oauthapi.OAuthAccessToken) (kuser.Info, error) {
	return s.convertFromToken(token.UserName, token.UserUID)
}

func (s *userConversion) convertFromUser(user interface{}) (name, uid string, err error) {
	info, ok := user.(kuser.Info)
	if !ok {
		return "", "", errors.New("did not receive user.Info") // should be impossible
	}

	name = info.GetName()
	uid = info.GetUID()
	if len(name) == 0 || len(uid) == 0 {
		return "", "", errors.New("user.Info has no user name or UID") // should be impossible
	}

	return name, uid, nil
}

func (s *userConversion) convertFromToken(name, uid string) (kuser.Info, error) {
	if len(name) == 0 || len(uid) == 0 {
		return nil, errors.New("token has no user name or UID stored") // should be impossible
	}

	return &kuser.DefaultInfo{
		Name: name,
		UID:  uid,
	}, nil
}
