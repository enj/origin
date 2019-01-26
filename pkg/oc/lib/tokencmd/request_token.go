package tokencmd

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/RangelReale/osincli"
	"github.com/golang/glog"

	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	restclient "k8s.io/client-go/rest"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/origin/pkg/oauth/urls"
	"github.com/openshift/origin/pkg/oauth/util"
)

const (
	// csrfTokenHeader is a marker header that indicates we are not a browser that got tricked into requesting basic auth
	// Corresponds to the header expected by basic-auth challenging authenticators
	// Copied from pkg/auth/authenticator/challenger/passwordchallenger/password_auth_handler.go
	csrfTokenHeader = "X-CSRF-Token"

	// Discovery endpoint for OAuth 2.0 Authorization Server Metadata
	// See IETF Draft:
	// https://tools.ietf.org/html/draft-ietf-oauth-discovery-04#section-2
	// Copied from pkg/cmd/server/origin/nonapiserver.go
	oauthMetadataEndpoint = "/.well-known/oauth-authorization-server"

	// openShiftCLIClientID is the name of the CLI OAuth client, copied from pkg/oauth/apiserver/auth.go
	openShiftCLIClientID = "openshift-challenging-client"

	// pkce_s256 is sha256 hash per RFC7636, copied from github.com/RangelReale/osincli/pkce.go
	pkce_s256 = "S256"

	// token fakes the missing osin.TOKEN const
	token osincli.AuthorizeRequestType = "token"
)

// ChallengeHandler handles responses to WWW-Authenticate challenges.
type ChallengeHandler interface {
	// CanHandle returns true if the handler recognizes a challenge it thinks it can handle.
	CanHandle(headers http.Header) bool
	// HandleChallenge lets the handler attempt to handle a challenge.
	// It is only invoked if CanHandle() returned true for the given headers.
	// Returns response headers and true if the challenge is successfully handled.
	// Returns false if the challenge was not handled, and an optional error in error cases.
	HandleChallenge(requestURL string, headers http.Header) (http.Header, bool, error)
	// CompleteChallenge is invoked with the headers from a successful server response
	// received after having handled one or more challenges.
	// Returns an error if the handler does not consider the challenge/response interaction complete.
	CompleteChallenge(requestURL string, headers http.Header) error
	// Release gives the handler a chance to release any resources held during a challenge/response sequence.
	// It is always invoked, even in cases where no challenges were received or handled.
	Release() error
}

type RequestTokenOptions struct {
	ClientConfig *restclient.Config
	Handler      ChallengeHandler
	OsinConfig   *osincli.ClientConfig
	TokenFlow    bool
}

// RequestToken uses the cmd arguments to locate an openshift oauth server and attempts to authenticate via an
// OAuth code flow and challenge handling.  It returns the access token if it gets one or an error if it does not.
func RequestToken(clientCfg *restclient.Config, reader io.Reader, defaultUsername string, defaultPassword string) (string, error) {
	return NewRequestTokenOptions(clientCfg, reader, defaultUsername, defaultPassword, false).RequestToken()
}

func NewRequestTokenOptions(clientCfg *restclient.Config, reader io.Reader, defaultUsername string, defaultPassword string, tokenFlow bool) *RequestTokenOptions {
	handlers := []ChallengeHandler{}
	if GSSAPIEnabled() {
		handlers = append(handlers, NewNegotiateChallengeHandler(NewGSSAPINegotiator(defaultUsername)))
	}
	if SSPIEnabled() {
		handlers = append(handlers, NewNegotiateChallengeHandler(NewSSPINegotiator(defaultUsername, defaultPassword, clientCfg.Host, reader)))
	}
	if BasicEnabled() {
		handlers = append(handlers, &BasicChallengeHandler{Host: clientCfg.Host, Reader: reader, Username: defaultUsername, Password: defaultPassword})
	}

	var handler ChallengeHandler
	if len(handlers) == 1 {
		handler = handlers[0]
	} else {
		handler = NewMultiHandler(handlers...)
	}

	return &RequestTokenOptions{
		ClientConfig: clientCfg,
		Handler:      handler,
		TokenFlow:    tokenFlow,
	}
}

// SetDefaultOsinConfig overwrites RequestTokenOptions.OsinConfig with the default CLI
// OAuth client and PKCE support if the server supports S256 / a code flow is being used
func (o *RequestTokenOptions) SetDefaultOsinConfig() error {
	if o.OsinConfig != nil {
		return fmt.Errorf("osin config is already set to: %#v", *o.OsinConfig)
	}

	// get the OAuth metadata directly from the api server
	// we only want to use the ca data from our config
	rt, err := restclient.TransportFor(o.ClientConfig)
	if err != nil {
		return err
	}

	requestURL := strings.TrimRight(o.ClientConfig.Host, "/") + oauthMetadataEndpoint
	resp, err := request(rt, requestURL, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("couldn't get %v: unexpected response status %v", requestURL, resp.StatusCode)
	}

	metadata := &util.OauthAuthorizationServerMetadata{}
	if err := json.NewDecoder(resp.Body).Decode(metadata); err != nil {
		return err
	}

	// use the metadata to build the osin config
	config := &osincli.ClientConfig{
		ClientId:     openShiftCLIClientID,
		AuthorizeUrl: metadata.AuthorizationEndpoint,
		TokenUrl:     metadata.TokenEndpoint,
		RedirectUrl:  urls.OpenShiftOAuthTokenImplicitURL(metadata.Issuer),
	}
	if !o.TokenFlow && sets.NewString(metadata.CodeChallengeMethodsSupported...).Has(pkce_s256) {
		if err := osincli.PopulatePKCE(config); err != nil {
			return err
		}
	}

	o.OsinConfig = config
	return nil
}

// RequestToken locates an openshift oauth server and attempts to authenticate.
// It returns the access token if it gets one, or an error if it does not.
// It should only be invoked once on a given RequestTokenOptions instance.
// The Handler held by the options is released as part of this call.
// If RequestTokenOptions.OsinConfig is nil, it will be defaulted using SetDefaultOsinConfig.
// The caller is responsible for setting up the entire OsinConfig if the value is not nil.
func (o *RequestTokenOptions) RequestToken() (string, error) {
	defer func() {
		// Always release the handler
		if err := o.Handler.Release(); err != nil {
			// Release errors shouldn't fail the token request, just log
			glog.V(4).Infof("error releasing handler: %v", err)
		}
	}()

	// we are going to use this config to talk
	// with a server that may not be the api server
	// thus we need to include the system roots
	// in our ca data otherwise an external
	// oauth server with a valid cert will fail with
	// error: x509: certificate signed by unknown authority
	clientConfig, err := clientConfigWithSystemRoots(o.ClientConfig)
	if err != nil {
		return "", err
	}

	rt, err := restclient.TransportFor(clientConfig)
	if err != nil {
		return "", err
	}

	if o.OsinConfig == nil {
		if err := o.SetDefaultOsinConfig(); err != nil {
			return "", err
		}
	}

	client, err := osincli.NewClient(o.OsinConfig)
	if err != nil {
		return "", err
	}
	client.Transport = rt
	authorizeRequest := client.NewAuthorizeRequest(osincli.CODE) // assume code flow to start with

	var oauthTokenFunc func(redirectURL string) (accessToken string, oauthError error)
	if o.TokenFlow {
		// access_token in fragment or error parameter
		authorizeRequest.Type = token // manually override to token flow if necessary
		oauthTokenFunc = oauthTokenFlow
	} else {
		// code or error parameter
		oauthTokenFunc = func(redirectURL string) (accessToken string, oauthError error) {
			return oauthCodeFlow(client, authorizeRequest, redirectURL)
		}
	}

	// requestURL holds the current URL to make requests to. This can change if the server responds with a redirect
	requestURL := authorizeRequest.GetAuthorizeUrl().String()
	// requestHeaders holds additional headers to add to the request. This can be changed by o.Handlers
	requestHeaders := http.Header{}
	// requestedURLSet/requestedURLList hold the URLs we have requested, to prevent redirect loops. Gets reset when a challenge is handled.
	requestedURLSet := sets.NewString()
	requestedURLList := []string{}
	handledChallenge := false

	for {
		// Make the request
		resp, err := request(rt, requestURL, requestHeaders)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			if resp.Header.Get("WWW-Authenticate") != "" {
				if !o.Handler.CanHandle(resp.Header) {
					return "", apierrs.NewUnauthorized("unhandled challenge")
				}
				// Handle the challenge
				newRequestHeaders, shouldRetry, err := o.Handler.HandleChallenge(requestURL, resp.Header)
				if err != nil {
					return "", err
				}
				if !shouldRetry {
					return "", apierrs.NewUnauthorized("challenger chose not to retry the request")
				}
				// Remember if we've ever handled a challenge
				handledChallenge = true

				// Reset request set/list. Since we're setting different headers, it is legitimate to request the same urls
				requestedURLSet = sets.NewString()
				requestedURLList = []string{}
				// Use the response to the challenge as the new headers
				requestHeaders = newRequestHeaders
				continue
			}

			// Unauthorized with no challenge
			unauthorizedError := apierrs.NewUnauthorized("")
			// Attempt to read body content and include as an error detail
			if details, err := ioutil.ReadAll(resp.Body); err == nil && len(details) > 0 {
				unauthorizedError.ErrStatus.Details = &metav1.StatusDetails{
					Causes: []metav1.StatusCause{
						{Message: string(details)},
					},
				}
			}

			return "", unauthorizedError
		}

		// if we've ever handled a challenge, see if the handler also considers the interaction complete.
		// this is required for negotiate flows with mutual authentication.
		if handledChallenge {
			if err := o.Handler.CompleteChallenge(requestURL, resp.Header); err != nil {
				return "", err
			}
		}

		if resp.StatusCode == http.StatusFound {
			redirectURL := resp.Header.Get("Location")

			// OAuth response case
			accessToken, err := oauthTokenFunc(redirectURL)
			if err != nil {
				return "", err
			}
			if len(accessToken) > 0 {
				return accessToken, nil
			}

			// Non-OAuth response, just follow the URL
			// add to our list of redirects
			requestedURLList = append(requestedURLList, redirectURL)
			// detect loops
			if !requestedURLSet.Has(redirectURL) {
				requestedURLSet.Insert(redirectURL)
				requestURL = redirectURL
				continue
			}
			return "", apierrs.NewInternalError(fmt.Errorf("redirect loop: %s", strings.Join(requestedURLList, " -> ")))
		}

		// Unknown response
		return "", apierrs.NewInternalError(fmt.Errorf("unexpected response: %d", resp.StatusCode))
	}
}

// oauthTokenFlow attempts to extract an OAuth token from location's fragment's access_token value.
// It only returns an error if something "impossible" happens (location is not a valid URL) or a definite
// OAuth error is contained in the location URL.  No error is returned if location does not contain a token.
// It is assumed that location was not part of the OAuth flow; it was a redirect that the client needs to follow
// as part of the challenge flow (an authenticating proxy for example) and not a redirect step in the OAuth flow.
func oauthTokenFlow(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", err
	}

	if oauthErr := oauthErrFromValues(u.Query()); oauthErr != nil {
		return "", oauthErr
	}

	// Grab the raw fragment ourselves, since the stdlib URL parsing decodes parts of it
	fragment := ""
	if parts := strings.SplitN(location, "#", 2); len(parts) == 2 {
		fragment = parts[1]
	}
	fragmentValues, err := url.ParseQuery(fragment)
	if err != nil {
		return "", err
	}

	return fragmentValues.Get("access_token"), nil
}

// oauthCodeFlow performs the OAuth code flow if location has a code parameter.
// It only returns an error if something "impossible" happens (location is not a valid URL)
// or a definite OAuth error is encountered during the code flow.  Other errors are assumed to be caused
// by location not being part of the OAuth flow; it was a redirect that the client needs to follow as part
// of the challenge flow (an authenticating proxy for example) and not a redirect step in the OAuth flow.
func oauthCodeFlow(client *osincli.Client, authorizeRequest *osincli.AuthorizeRequest, location string) (string, error) {
	// Make a request out of the URL since that is what AuthorizeRequest.HandleRequest expects to extract data from
	req, err := http.NewRequest("GET", location, nil)
	if err != nil {
		return "", err
	}

	req.ParseForm()
	if oauthErr := oauthErrFromValues(req.Form); oauthErr != nil {
		return "", oauthErr
	}
	if len(req.Form.Get("code")) == 0 {
		return "", nil // no code parameter so this is not part of the OAuth flow
	}

	// any errors after this are fatal because we are committed to an OAuth flow now
	authorizeData, err := authorizeRequest.HandleRequest(req)
	if err != nil {
		return "", osinToOAuthError(err)
	}

	accessRequest := client.NewAccessRequest(osincli.AUTHORIZATION_CODE, authorizeData)
	accessData, err := accessRequest.GetToken()
	if err != nil {
		return "", osinToOAuthError(err)
	}

	return accessData.AccessToken, nil
}

// osinToOAuthError creates a better error message for osincli.Error
func osinToOAuthError(err error) error {
	if osinErr, ok := err.(*osincli.Error); ok {
		return createOAuthError(osinErr.Id, osinErr.Description)
	}
	return err
}

func oauthErrFromValues(values url.Values) error {
	if errorCode := values.Get("error"); len(errorCode) > 0 {
		errorDescription := values.Get("error_description")
		return createOAuthError(errorCode, errorDescription)
	}
	return nil
}

func createOAuthError(errorCode, errorDescription string) error {
	return fmt.Errorf("%s %s", errorCode, errorDescription)
}

func request(rt http.RoundTripper, requestURL string, requestHeaders http.Header) (*http.Response, error) {
	// Build the request
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range requestHeaders {
		req.Header[k] = v
	}
	req.Header.Set(csrfTokenHeader, "1")

	// Make the request
	return rt.RoundTrip(req)
}

func clientConfigWithSystemRoots(in *restclient.Config) (ret *restclient.Config, retErr error) {
	defer runtime.HandleCrash(func(i interface{}) { // attempt to prevent oc from crashing
		glog.V(4).Infof("clientConfigWithSystemRoots failed: %#v", i)
		ret, retErr = in, nil // fallback to our input config
	})

	// best effort loading of the system roots
	pool, err := x509.SystemCertPool()
	if err != nil { // system has no built in certs
		glog.V(4).Infof("failed to load system roots: %v", err)
		return in, nil // fallback to our input config
	}

	// copy the config so we can freely mutate it
	out := restclient.CopyConfig(in)

	caData, err := dataFromSliceOrFile(out.CAData, out.CAFile)
	if err != nil {
		return nil, err
	}

	// caData could be empty so ignore the returned bool
	_ = pool.AppendCertsFromPEM(caData)

	// these reflect operations are safe and cannot panic
	// assume the pool has a "certs" field of type []*x509.Certificate
	// this assumption is verified via unit tests
	certsField := reflect.ValueOf(pool).Elem().FieldByName("certs")

	// we want to forcibly extract the certs from the pool into this slice
	var certs []*x509.Certificate

	// avoid operations that we know will fail
	if !certsField.IsValid() || certsField.Kind() != reflect.Slice || certsField.Type() != reflect.TypeOf(certs) {
		glog.V(4).Infof("failed to extract certs from pool: %#v", pool)
		return in, nil // fallback to our input config
	}

	// at this point we know that certsField is a []*x509.Certificate
	// thus the below operations cannot fail since the shape of x509.Certificate is stable
	for i := 0; i < certsField.Len(); i++ {
		cert := certsField.Index(i)
		raw := cert.Elem().FieldByName("Raw").Bytes()
		certs = append(certs, &x509.Certificate{Raw: raw})
	}

	// if we have no certs, fallback to our input config
	if len(certs) == 0 {
		return in, nil
	}

	// re-encode them as PEM, this should never fail as the pool only has valid certs
	allCerts, err := crypto.EncodeCertificates(certs...)
	if err != nil {
		return nil, err
	}

	// explicitly set our combined PEM encoded certs
	out.CAFile = ""
	out.CAData = allCerts

	return out, nil
}

// copied from k8s.io/client-go/transport/transport.go
// dataFromSliceOrFile returns data from the slice (if non-empty), or from the file,
// or an error if an error occurred reading the file
func dataFromSliceOrFile(data []byte, file string) ([]byte, error) {
	if len(data) > 0 {
		return data, nil
	}
	if len(file) > 0 {
		fileData, err := ioutil.ReadFile(file)
		if err != nil {
			return []byte{}, err
		}
		return fileData, nil
	}
	return nil, nil
}
