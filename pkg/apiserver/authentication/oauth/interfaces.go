package oauth

import (
	oauthv1 "github.com/openshift/api/oauth/v1"
	userapi "github.com/openshift/api/user/v1"
)

type OAuthTokenValidator interface {
	Validate(token *oauthv1.OAuthAccessToken, user *userapi.User) error
}

var _ OAuthTokenValidator = OAuthTokenValidatorFunc(nil)

type OAuthTokenValidatorFunc func(token *oauthv1.OAuthAccessToken, user *userapi.User) error

func (f OAuthTokenValidatorFunc) Validate(token *oauthv1.OAuthAccessToken, user *userapi.User) error {
	return f(token, user)
}

var _ OAuthTokenValidator = OAuthTokenValidators(nil)

type OAuthTokenValidators []OAuthTokenValidator

func (v OAuthTokenValidators) Validate(token *oauthv1.OAuthAccessToken, user *userapi.User) error {
	for _, validator := range v {
		if err := validator.Validate(token, user); err != nil {
			return err
		}
	}
	return nil
}

type GroupMapper interface {
	GroupsFor(token *oauthv1.OAuthAccessToken, user *userapi.User) (groups []string, err error)
}
