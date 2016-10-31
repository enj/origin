package client

import (
	"net/http"

	"k8s.io/kubernetes/pkg/auth/user"
	"k8s.io/kubernetes/pkg/client/restclient"
	kclient "k8s.io/kubernetes/pkg/client/unversioned"

	authenticationapi "github.com/openshift/origin/pkg/auth/api"
	authorizationapi "github.com/openshift/origin/pkg/authorization/api"
	"github.com/openshift/origin/pkg/client"
)

type impersonatingRoundTripper struct {
	user     user.Info
	delegate http.RoundTripper
}

// NewImpersonatingRoundTripper will add headers to impersonate a user, including user, groups, and scopes
func NewImpersonatingRoundTripper(user user.Info, delegate http.RoundTripper) http.RoundTripper {
	return &impersonatingRoundTripper{user, delegate}
}

func (rt *impersonatingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = cloneRequest(req)
	req.Header.Del(authenticationapi.ImpersonateUserHeader)
	req.Header.Del(authenticationapi.ImpersonateGroupHeader)
	req.Header.Del(authenticationapi.ImpersonateUserScopeHeader)

	req.Header.Set(authenticationapi.ImpersonateUserHeader, rt.user.GetName())
	for _, group := range rt.user.GetGroups() {
		req.Header.Add(authenticationapi.ImpersonateGroupHeader, group)
	}
	for _, scope := range rt.user.GetExtra()[authorizationapi.ScopesKey] {
		req.Header.Add(authenticationapi.ImpersonateUserScopeHeader, scope)
	}
	return rt.delegate.RoundTrip(req)
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}
	return r2
}

func buildImpersonatingConfig(user user.Info, impersonatingConfig *restclient.Config) *restclient.Config {
	oldWrapTransport := impersonatingConfig.WrapTransport
	impersonatingConfig.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		return NewImpersonatingRoundTripper(user, oldWrapTransport(rt))
	}
	return impersonatingConfig
}

// NewImpersonatingOpenShiftClient returns an OS client that will impersonate a user, including user, groups, and scopes
func NewImpersonatingOpenShiftClient(user user.Info, privilegedConfig restclient.Config) (*client.Client, error) {
	return client.New(buildImpersonatingConfig(user, &privilegedConfig))
}

// NewImpersonatingKubernetesClient returns a Kube client that will impersonate a user, including user, groups, and scopes
func NewImpersonatingKubernetesClient(user user.Info, privilegedConfig restclient.Config) (*kclient.Client, error) {
	return kclient.New(buildImpersonatingConfig(user, &privilegedConfig))
}
