package registry

import (
	"errors"

	kuser "k8s.io/apiserver/pkg/authentication/user"

	oapi "github.com/openshift/api/oauth/v1"
	authapi "github.com/openshift/origin/pkg/oauthserver/api"
)

type UserConversion struct{}

// NewUserConversion creates an object that can convert the user.Info object to and from
// an oauth access/authorize token object.
func NewUserConversion() *UserConversion {
	return &UserConversion{}
}

func (s *UserConversion) ConvertToAuthorizeToken(user interface{}, token *oapi.OAuthAuthorizeToken) error {
	info, ok := user.(kuser.Info)
	if !ok {
		return errors.New("did not receive user.Info")
	}
	token.UserName = info.GetName()
	if token.UserName == "" {
		return errors.New("user name is empty")
	}
	token.UserUID = info.GetUID()
	if userIdentityMetadata, ok := user.(authapi.UserIdentityMetadata); ok {
		_ = userIdentityMetadata.GetIdentityMetadataName() // TODO replace with:
		// token.IdentityMetadataName = userIdentityMetadata.GetIdentityMetadataName()
	}
	return nil
}

func (s *UserConversion) ConvertToAccessToken(user interface{}, token *oapi.OAuthAccessToken) error {
	info, ok := user.(kuser.Info)
	if !ok {
		return errors.New("did not receive user.Info")
	}
	token.UserName = info.GetName()
	if token.UserName == "" {
		return errors.New("user name is empty")
	}
	token.UserUID = info.GetUID()
	if userIdentityMetadata, ok := user.(authapi.UserIdentityMetadata); ok {
		_ = userIdentityMetadata.GetIdentityMetadataName() // TODO replace with:
		// token.IdentityMetadataName = userIdentityMetadata.GetIdentityMetadataName()

		// TODO get+update identity metadata, set expiresIn to zero
		// needs to handle conflicts and retry
		// IdentityMetadata.OwnerReferences = token info
	}
	return nil
}

func (s *UserConversion) ConvertFromAuthorizeToken(token *oapi.OAuthAuthorizeToken) (interface{}, error) {
	if token.UserName == "" {
		return nil, errors.New("token has no user name stored")
	}
	user := &kuser.DefaultInfo{
		Name: token.UserName,
		UID:  token.UserUID,
	}
	// TODO change to:
	// if len(token.IdentityMetadataName) == 0 {
	if true {
		return user, nil
	}
	return authapi.NewDefaultUserIdentityMetadata(user, "replace with -> token.IdentityMetadataName"), nil
}

func (s *UserConversion) ConvertFromAccessToken(token *oapi.OAuthAccessToken) (interface{}, error) {
	if token.UserName == "" {
		return nil, errors.New("token has no user name stored")
	}
	user := &kuser.DefaultInfo{
		Name: token.UserName,
		UID:  token.UserUID,
	}
	// TODO change to:
	// if len(token.IdentityMetadataName) == 0 {
	if true {
		return user, nil
	}
	return authapi.NewDefaultUserIdentityMetadata(user, "replace with -> token.IdentityMetadataName"), nil
}
