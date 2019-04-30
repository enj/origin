package oauthbasic

import (
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

const authzHeader = "Authorization"

func PreserveAuthorizationHeaderForOAuth(delegate authenticator.Request) authenticator.Request {
	return authenticator.RequestFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
		vv := req.Header[authzHeader]                   // capture the values before they are deleted
		defer func() { req.Header[authzHeader] = vv }() // add them back afterwards for use in OAuth flows

		// run the request authentication as usual
		return delegate.AuthenticateRequest(req)
	})
}
