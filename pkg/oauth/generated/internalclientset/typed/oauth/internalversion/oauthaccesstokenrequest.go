package internalversion

import (
	rest "k8s.io/client-go/rest"
)

// OAuthAccessTokenRequestsGetter has a method to return a OAuthAccessTokenRequestInterface.
// A group's client should implement this interface.
type OAuthAccessTokenRequestsGetter interface {
	OAuthAccessTokenRequests() OAuthAccessTokenRequestInterface
}

// OAuthAccessTokenRequestInterface has methods to work with OAuthAccessTokenRequest resources.
type OAuthAccessTokenRequestInterface interface {
	OAuthAccessTokenRequestExpansion
}

// oAuthAccessTokenRequests implements OAuthAccessTokenRequestInterface
type oAuthAccessTokenRequests struct {
	client rest.Interface
}

// newOAuthAccessTokenRequests returns a OAuthAccessTokenRequests
func newOAuthAccessTokenRequests(c *OauthClient) *oAuthAccessTokenRequests {
	return &oAuthAccessTokenRequests{
		client: c.RESTClient(),
	}
}
