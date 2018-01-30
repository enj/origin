package etcd

import (
	"net/http"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	oauthapi "github.com/openshift/origin/pkg/oauth/apis/oauth"
	oauthutil "github.com/openshift/origin/pkg/oauth/util"

	"github.com/RangelReale/osincli"
)

// rest implements a RESTStorage for access tokens against etcd
type REST struct {
	roundTripper    http.RoundTripper
	masterPublicURL string
}

var (
	_ rest.Creater = &REST{}
	_ rest.Storage = &REST{}
)

var broken = errors.NewInternalError(es("broken"))

type es string

func (s es) Error() string {
	return string(s)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// NewREST returns a RESTStorage object that will work against access tokens
func NewREST(roundTripper http.RoundTripper, masterPublicURL string) *REST {
	//strategy := oauthaccesstoken.NewStrategy(clientGetter) // TODO

	return &REST{
		roundTripper:    roundTripper,
		masterPublicURL: masterPublicURL,
	}
}

func (r *REST) New() runtime.Object {
	return &oauthapi.OAuthAccessTokenRequest{}
}

func (r *REST) Create(ctx request.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, includeUninitialized bool) (runtime.Object, error) {
	config := &osincli.ClientConfig{
		ClientId:                 "openshift-challenging-client", // TODO
		ClientSecret:             "",                             // TODO
		ErrorsInStatusCode:       true,
		SendClientSecretInParams: true,
		AuthorizeUrl:             oauthutil.OpenShiftOAuthAuthorizeURL(r.masterPublicURL),
		TokenUrl:                 oauthutil.OpenShiftOAuthTokenURL(r.masterPublicURL),
		RedirectUrl:              oauthutil.OpenShiftOAuthTokenImplicitURL(r.masterPublicURL),
		Scope:                    "user:info", // TODO
	}
	if err := osincli.PopulatePKCE(config); err != nil {
		return nil, err
	}
	clientCopy, err := osincli.NewClient(config)
	if err != nil {
		return nil, err
	}
	clientCopy.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.Header.Set("MO_USER_HEADER", obj.(*oauthapi.OAuthAccessTokenRequest).UserName) // TODO
		return r.roundTripper.RoundTrip(req)
	})

	authReq := clientCopy.NewAuthorizeRequest(osincli.CODE)
	resp, err := requestHelper(clientCopy.Transport, authReq.GetAuthorizeUrl().String(), nil) // TODO state
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusFound {
		return nil, broken
	}
	redirectURL := resp.Header.Get("Location")
	if len(redirectURL) == 0 {
		return nil, broken
	}
	req, err := http.NewRequest("GET", redirectURL, nil)
	if err != nil {
		return nil, err
	}

	authData, err := authReq.HandleRequest(req)
	if err != nil {
		return nil, err
	}

	// TODO STATE??
	//// Validate state before making any server-to-server calls
	//ok, err := r.state.Check(authData.State, req)
	//if err != nil {
	//	return nil, err
	//}
	//if !ok {
	//	return nil, errOUT
	//}

	// Exchange code for a token
	accessReq := clientCopy.NewAccessRequest(osincli.AUTHORIZATION_CODE, authData)
	accessData, err := accessReq.GetToken()
	if err != nil {
		return nil, err
	}

	return &oauthapi.OAuthAccessTokenRequest{
		Token: accessData.AccessToken,
	}, nil
}

func requestHelper(rt http.RoundTripper, requestURL string, requestHeaders http.Header) (*http.Response, error) {
	// Build the request
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range requestHeaders {
		req.Header[k] = v
	}
	//req.Header.Set(csrfTokenHeader, "1")

	// Make the request
	return rt.RoundTrip(req)
}
