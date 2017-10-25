package tokencmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/util/diff"
	restclient "k8s.io/client-go/rest"

	"github.com/openshift/origin/pkg/oauth/util"

	"github.com/RangelReale/osincli"
)

type unloadableNegotiator struct {
	releaseCalls int
}

func (n *unloadableNegotiator) Load() error {
	return errors.New("Load failed")
}
func (n *unloadableNegotiator) InitSecContext(requestURL string, challengeToken []byte) (tokenToSend []byte, err error) {
	return nil, errors.New("InitSecContext failed")
}
func (n *unloadableNegotiator) IsComplete() bool {
	return false
}
func (n *unloadableNegotiator) Release() error {
	n.releaseCalls++
	return errors.New("Release failed")
}

type failingNegotiator struct {
	releaseCalls int
}

func (n *failingNegotiator) Load() error {
	return nil
}
func (n *failingNegotiator) InitSecContext(requestURL string, challengeToken []byte) (tokenToSend []byte, err error) {
	return nil, errors.New("InitSecContext failed")
}
func (n *failingNegotiator) IsComplete() bool {
	return false
}
func (n *failingNegotiator) Release() error {
	n.releaseCalls++
	return errors.New("Release failed")
}

type successfulNegotiator struct {
	rounds              int
	initSecContextCalls int
	loadCalls           int
	releaseCalls        int
}

func (n *successfulNegotiator) Load() error {
	n.loadCalls++
	return nil
}
func (n *successfulNegotiator) InitSecContext(requestURL string, challengeToken []byte) (tokenToSend []byte, err error) {
	n.initSecContextCalls++

	if n.initSecContextCalls > n.rounds {
		return nil, fmt.Errorf("InitSecContext: expected %d calls, saw %d", n.rounds, n.initSecContextCalls)
	}

	if n.initSecContextCalls == 1 {
		if len(challengeToken) > 0 {
			return nil, errors.New("expected empty token for first challenge")
		}
	} else {
		expectedChallengeToken := fmt.Sprintf("challenge%d", n.initSecContextCalls)
		if string(challengeToken) != expectedChallengeToken {
			return nil, fmt.Errorf("expected challenge token '%s', got '%s'", expectedChallengeToken, string(challengeToken))
		}
	}

	return []byte(fmt.Sprintf("response%d", n.initSecContextCalls)), nil
}
func (n *successfulNegotiator) IsComplete() bool {
	return n.initSecContextCalls == n.rounds
}
func (n *successfulNegotiator) Release() error {
	n.releaseCalls++
	return nil
}

func TestRequestToken(t *testing.T) {
	type req struct {
		authorization string
	}
	type resp struct {
		status          int
		location        string
		wwwAuthenticate []string
	}

	type requestResponse struct {
		expectedRequest req
		serverResponse  resp
	}

	var verifyReleased func(test string, handler ChallengeHandler)
	verifyReleased = func(test string, handler ChallengeHandler) {
		switch handler := handler.(type) {
		case *MultiHandler:
			for _, subhandler := range handler.allHandlers {
				verifyReleased(test, subhandler)
			}
		case *BasicChallengeHandler:
			// we don't care
		case *NegotiateChallengeHandler:
			switch negotiator := handler.negotiater.(type) {
			case *successfulNegotiator:
				if negotiator.releaseCalls != 1 {
					t.Errorf("%s: expected one call to Release(), saw %d", test, negotiator.releaseCalls)
				}
			case *failingNegotiator:
				if negotiator.releaseCalls != 1 {
					t.Errorf("%s: expected one call to Release(), saw %d", test, negotiator.releaseCalls)
				}
			case *unloadableNegotiator:
				if negotiator.releaseCalls != 1 {
					t.Errorf("%s: expected one call to Release(), saw %d", test, negotiator.releaseCalls)
				}
			default:
				t.Errorf("%s: unrecognized negotiator: %#v", test, handler)
			}
		default:
			t.Errorf("%s: unrecognized handler: %#v", test, handler)
		}
	}

	initialRequest := req{}

	basicChallenge1 := resp{401, "", []string{"Basic realm=foo"}}
	basicRequest1 := req{"Basic bXl1c2VyOm15cGFzc3dvcmQ="} // base64("myuser:mypassword")
	basicChallenge2 := resp{401, "", []string{"Basic realm=seriously...foo"}}

	negotiateChallenge1 := resp{401, "", []string{"Negotiate"}}
	negotiateRequest1 := req{"Negotiate cmVzcG9uc2Ux"}                           // base64("response1")
	negotiateChallenge2 := resp{401, "", []string{"Negotiate Y2hhbGxlbmdlMg=="}} // base64("challenge2")
	negotiateRequest2 := req{"Negotiate cmVzcG9uc2Uy"}                           // base64("response2")

	doubleChallenge := resp{401, "", []string{"Negotiate", "Basic realm=foo"}}

	successfulToken := "12345"
	successfulLocation := fmt.Sprintf("/#access_token=%s", successfulToken)
	success := resp{302, successfulLocation, nil}
	successWithNegotiate := resp{302, successfulLocation, []string{"Negotiate Y2hhbGxlbmdlMg=="}}

	testcases := map[string]struct {
		Handler       ChallengeHandler
		Requests      []requestResponse
		ExpectedToken string
		ExpectedError string
	}{
		// Defaulting basic handler
		"defaulted basic handler, no challenge, success": {
			Handler: &BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"defaulted basic handler, basic challenge, success": {
			Handler: &BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialRequest, basicChallenge1},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"defaulted basic handler, basic+negotiate challenge, success": {
			Handler: &BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialRequest, doubleChallenge},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"defaulted basic handler, basic challenge, failure": {
			Handler: &BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialRequest, basicChallenge1},
				{basicRequest1, basicChallenge2},
			},
			ExpectedError: "challenger chose not to retry the request",
		},
		"defaulted basic handler, negotiate challenge, failure": {
			Handler: &BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialRequest, negotiateChallenge1},
			},
			ExpectedError: "unhandled challenge",
		},
		"failing basic handler, basic challenge, failure": {
			Handler: &BasicChallengeHandler{},
			Requests: []requestResponse{
				{initialRequest, basicChallenge1},
			},
			ExpectedError: "challenger chose not to retry the request",
		},

		// Prompting basic handler
		"prompting basic handler, no challenge, success": {
			Handler: &BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			Requests: []requestResponse{
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic challenge, success": {
			Handler: &BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			Requests: []requestResponse{
				{initialRequest, basicChallenge1},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic+negotiate challenge, success": {
			Handler: &BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			Requests: []requestResponse{
				{initialRequest, doubleChallenge},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic challenge, failure": {
			Handler: &BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			Requests: []requestResponse{
				{initialRequest, basicChallenge1},
				{basicRequest1, basicChallenge2},
			},
			ExpectedError: "challenger chose not to retry the request",
		},
		"prompting basic handler, negotiate challenge, failure": {
			Handler: &BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			Requests: []requestResponse{
				{initialRequest, negotiateChallenge1},
			},
			ExpectedError: "unhandled challenge",
		},

		// negotiate handler
		"negotiate handler, no challenge, success": {
			Handler: &NegotiateChallengeHandler{negotiater: &successfulNegotiator{rounds: 1}},
			Requests: []requestResponse{
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"negotiate handler, negotiate challenge, success": {
			Handler: &NegotiateChallengeHandler{negotiater: &successfulNegotiator{rounds: 1}},
			Requests: []requestResponse{
				{initialRequest, negotiateChallenge1},
				{negotiateRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"negotiate handler, negotiate challenge, 2 rounds, success": {
			Handler: &NegotiateChallengeHandler{negotiater: &successfulNegotiator{rounds: 2}},
			Requests: []requestResponse{
				{initialRequest, negotiateChallenge1},
				{negotiateRequest1, negotiateChallenge2},
				{negotiateRequest2, success},
			},
			ExpectedToken: successfulToken,
		},
		"negotiate handler, negotiate challenge, 2 rounds, success with mutual auth": {
			Handler: &NegotiateChallengeHandler{negotiater: &successfulNegotiator{rounds: 2}},
			Requests: []requestResponse{
				{initialRequest, negotiateChallenge1},
				{negotiateRequest1, successWithNegotiate},
			},
			ExpectedToken: successfulToken,
		},
		"negotiate handler, negotiate challenge, 2 rounds expected, server success without client completion": {
			Handler: &NegotiateChallengeHandler{negotiater: &successfulNegotiator{rounds: 2}},
			Requests: []requestResponse{
				{initialRequest, negotiateChallenge1},
				{negotiateRequest1, success},
			},
			ExpectedError: "client requires final negotiate token, none provided",
		},

		// Unloadable negotiate handler
		"unloadable negotiate handler, no challenge, success": {
			Handler: &NegotiateChallengeHandler{negotiater: &unloadableNegotiator{}},
			Requests: []requestResponse{
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"unloadable negotiate handler, negotiate challenge, failure": {
			Handler: &NegotiateChallengeHandler{negotiater: &unloadableNegotiator{}},
			Requests: []requestResponse{
				{initialRequest, negotiateChallenge1},
			},
			ExpectedError: "unhandled challenge",
		},
		"unloadable negotiate handler, basic challenge, failure": {
			Handler: &NegotiateChallengeHandler{negotiater: &unloadableNegotiator{}},
			Requests: []requestResponse{
				{initialRequest, basicChallenge1},
			},
			ExpectedError: "unhandled challenge",
		},

		// Failing negotiate handler
		"failing negotiate handler, no challenge, success": {
			Handler: &NegotiateChallengeHandler{negotiater: &failingNegotiator{}},
			Requests: []requestResponse{
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"failing negotiate handler, negotiate challenge, failure": {
			Handler: &NegotiateChallengeHandler{negotiater: &failingNegotiator{}},
			Requests: []requestResponse{
				{initialRequest, negotiateChallenge1},
			},
			ExpectedError: "InitSecContext failed",
		},
		"failing negotiate handler, basic challenge, failure": {
			Handler: &NegotiateChallengeHandler{negotiater: &failingNegotiator{}},
			Requests: []requestResponse{
				{initialRequest, basicChallenge1},
			},
			ExpectedError: "unhandled challenge",
		},

		// Negotiate+Basic fallback cases
		"failing negotiate+prompting basic handler, no challenge, success": {
			Handler: NewMultiHandler(
				&NegotiateChallengeHandler{negotiater: &failingNegotiator{}},
				&BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			),
			Requests: []requestResponse{
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"failing negotiate+prompting basic handler, negotiate+basic challenge, success": {
			Handler: NewMultiHandler(
				&NegotiateChallengeHandler{negotiater: &failingNegotiator{}},
				&BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			),
			Requests: []requestResponse{
				{initialRequest, doubleChallenge},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"negotiate+failing basic handler, negotiate+basic challenge, success": {
			Handler: NewMultiHandler(
				&NegotiateChallengeHandler{negotiater: &successfulNegotiator{rounds: 2}},
				&BasicChallengeHandler{},
			),
			Requests: []requestResponse{
				{initialRequest, doubleChallenge},
				{negotiateRequest1, negotiateChallenge2},
				{negotiateRequest2, success},
			},
			ExpectedToken: successfulToken,
		},
		"negotiate+basic handler, negotiate+basic challenge, prefers negotiation, success": {
			Handler: NewMultiHandler(
				&NegotiateChallengeHandler{negotiater: &successfulNegotiator{rounds: 2}},
				&BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			),
			Requests: []requestResponse{
				{initialRequest, doubleChallenge},
				{negotiateRequest1, negotiateChallenge2},
				{negotiateRequest2, success},
			},
			ExpectedToken: successfulToken,
		},
		"negotiate+basic handler, negotiate+basic challenge, prefers negotiation, sticks with selected handler on failure": {
			Handler: NewMultiHandler(
				&NegotiateChallengeHandler{negotiater: &successfulNegotiator{rounds: 2}},
				&BasicChallengeHandler{Reader: bytes.NewBufferString("myuser\nmypassword\n")},
			),
			Requests: []requestResponse{
				{initialRequest, doubleChallenge},
				{negotiateRequest1, negotiateChallenge2},
				{negotiateRequest2, doubleChallenge},
			},
			ExpectedError: "InitSecContext: expected 2 calls, saw 3",
		},
	}

	for k, tc := range testcases {
		i := 0
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if i >= len(tc.Requests) {
				t.Errorf("%s: %d: more requests received than expected: %#v", k, i, req)
				return
			}
			rr := tc.Requests[i]
			i++
			if req.Method != "GET" {
				t.Errorf("%s: %d: Expected GET, got %s", k, i, req.Method)
				return
			}
			if req.URL.Path != "/oauth/authorize" {
				t.Errorf("%s: %d: Expected /oauth/authorize, got %s", k, i, req.URL.Path)
				return
			}
			if e, a := rr.expectedRequest.authorization, req.Header.Get("Authorization"); e != a {
				t.Errorf("%s: %d: expected 'Authorization: %s', got 'Authorization: %s'", k, i, e, a)
				return
			}
			if len(rr.serverResponse.location) > 0 {
				w.Header().Add("Location", rr.serverResponse.location)
			}
			for _, v := range rr.serverResponse.wwwAuthenticate {
				w.Header().Add("WWW-Authenticate", v)
			}
			w.WriteHeader(rr.serverResponse.status)
		}))
		defer s.Close()

		opts := &RequestTokenOptions{
			ClientConfig: &restclient.Config{Host: s.URL},
			Handler:      tc.Handler,
			OsinConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: util.OpenShiftOAuthAuthorizeURL(s.URL),
				TokenUrl:     util.OpenShiftOAuthTokenURL(s.URL),
				RedirectUrl:  util.OpenShiftOAuthTokenImplicitURL(s.URL),
			},
			TokenFlow: true,
		}
		token, err := opts.RequestToken()
		if token != tc.ExpectedToken {
			t.Errorf("%s: expected token '%s', got '%s'", k, tc.ExpectedToken, token)
		}
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		if errStr != tc.ExpectedError {
			t.Errorf("%s: expected error '%s', got '%s'", k, tc.ExpectedError, errStr)
		}
		if i != len(tc.Requests) {
			t.Errorf("%s: expected %d requests, saw %d", k, len(tc.Requests), i)
		}
		verifyReleased(k, tc.Handler)
	}
}

func TestSetDefaultOsinConfig(t *testing.T) {
	noHostChange := func(host string) string { return host }
	for _, tc := range []struct {
		name        string
		metadata    *util.OauthAuthorizationServerMetadata
		hostWrapper func(host string) (newHost string)
		tokenFlow   bool

		expectPKCE     bool
		expectedConfig *osincli.ClientConfig
	}{
		{
			name: "code with PKCE support from server",
			metadata: &util.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIClientID,
				AuthorizeUrl:        "b",
				TokenUrl:            "c",
				RedirectUrl:         "a/oauth/token/implicit",
				CodeChallengeMethod: pkce_s256,
			},
		},
		{
			name: "code without PKCE support from server",
			metadata: &util.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{"someotherstuff"},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,

			expectPKCE: false,
			expectedConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: "b",
				TokenUrl:     "c",
				RedirectUrl:  "a/oauth/token/implicit",
			},
		},
		{
			name: "token with PKCE support from server",
			metadata: &util.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   true,

			expectPKCE: false,
			expectedConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: "b",
				TokenUrl:     "c",
				RedirectUrl:  "a/oauth/token/implicit",
			},
		},
		{
			name: "code with PKCE support from server, but wrong case",
			metadata: &util.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{"s256"}, // we are case sensitive so this is not valid
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,

			expectPKCE: false,
			expectedConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: "b",
				TokenUrl:     "c",
				RedirectUrl:  "a/oauth/token/implicit",
			},
		},
		{
			name: "token without PKCE support from server",
			metadata: &util.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{"random"},
			},
			hostWrapper: noHostChange,
			tokenFlow:   true,

			expectPKCE: false,
			expectedConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: "b",
				TokenUrl:     "c",
				RedirectUrl:  "a/oauth/token/implicit",
			},
		},
		{
			name: "host with extra slashes",
			metadata: &util.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: func(host string) string { return host + "/////" },
			tokenFlow:   false,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIClientID,
				AuthorizeUrl:        "b",
				TokenUrl:            "c",
				RedirectUrl:         "a/oauth/token/implicit",
				CodeChallengeMethod: pkce_s256,
			},
		},
		{
			name: "issuer with extra slashes",
			metadata: &util.OauthAuthorizationServerMetadata{
				Issuer:                        "a/////",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIClientID,
				AuthorizeUrl:        "b",
				TokenUrl:            "c",
				RedirectUrl:         "a/oauth/token/implicit",
				CodeChallengeMethod: pkce_s256,
			},
		},
		{
			name: "code with PKCE support from server, more complex JSON",
			metadata: &util.OauthAuthorizationServerMetadata{
				Issuer:                        "arandomissuerthatisfun123!!!///",
				AuthorizationEndpoint:         "44authzisanawesomeendpoint",
				TokenEndpoint:                 "&&buttokenendpointisprettygoodtoo",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIClientID,
				AuthorizeUrl:        "44authzisanawesomeendpoint",
				TokenUrl:            "&&buttokenendpointisprettygoodtoo",
				RedirectUrl:         "arandomissuerthatisfun123!!!/oauth/token/implicit",
				CodeChallengeMethod: pkce_s256,
			},
		},
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != "GET" {
				t.Errorf("%s: Expected GET, got %s", tc.name, req.Method)
				return
			}
			if req.URL.Path != oauthMetadataEndpoint {
				t.Errorf("%s: Expected metadata endpoint, got %s", tc.name, req.URL.Path)
				return
			}
			data, err := json.Marshal(tc.metadata)
			if err != nil {
				t.Errorf("%s: unexpected json error: %v", tc.name, err)
				return
			}
			w.Write(data)
		}))
		defer s.Close()

		opts := &RequestTokenOptions{
			ClientConfig: &restclient.Config{Host: tc.hostWrapper(s.URL)},
			TokenFlow:    tc.tokenFlow,
		}
		if err := opts.SetDefaultOsinConfig(); err != nil {
			t.Errorf("%s: unexpected SetDefaultOsinConfig error: %v", tc.name, err)
			continue
		}

		// check PKCE data
		if tc.expectPKCE {
			if len(opts.OsinConfig.CodeChallenge) == 0 || len(opts.OsinConfig.CodeChallengeMethod) == 0 || len(opts.OsinConfig.CodeVerifier) == 0 {
				t.Errorf("%s: did not set PKCE", tc.name)
				continue
			}
		} else {
			if len(opts.OsinConfig.CodeChallenge) != 0 || len(opts.OsinConfig.CodeChallengeMethod) != 0 || len(opts.OsinConfig.CodeVerifier) != 0 {
				t.Errorf("%s: incorrectly set PKCE", tc.name)
				continue
			}
		}

		// blindly unset random PKCE data since we already checked for it
		opts.OsinConfig.CodeChallenge = ""
		opts.OsinConfig.CodeVerifier = ""

		// compare the configs to see if they match
		if !reflect.DeepEqual(*tc.expectedConfig, *opts.OsinConfig) {
			t.Errorf("%s: expected osin config does not match, %s", tc.name, diff.ObjectDiff(*tc.expectedConfig, *opts.OsinConfig))
		}
	}
}

func TestRequestTokenCodeFlow(t *testing.T) {
	type req struct {
		authorization string
		path          string
		method        string
		query         url.Values
		body          string
	}
	type resp struct {
		status          int
		location        string
		query           url.Values
		wwwAuthenticate []string
		body            string
	}

	type requestResponse struct {
		expectedRequest req
		serverResponse  resp
	}

	var verifyReleased func(test string, handler ChallengeHandler)
	verifyReleased = func(test string, handler ChallengeHandler) {
		switch handler := handler.(type) {
		case *MultiHandler:
			for _, subhandler := range handler.allHandlers {
				verifyReleased(test, subhandler)
			}
		case *BasicChallengeHandler:
			// we don't care
		case *NegotiateChallengeHandler:
			switch negotiator := handler.negotiater.(type) {
			case *successfulNegotiator:
				if negotiator.releaseCalls != 1 {
					t.Errorf("%s: expected one call to Release(), saw %d", test, negotiator.releaseCalls)
				}
			case *failingNegotiator:
				if negotiator.releaseCalls != 1 {
					t.Errorf("%s: expected one call to Release(), saw %d", test, negotiator.releaseCalls)
				}
			case *unloadableNegotiator:
				if negotiator.releaseCalls != 1 {
					t.Errorf("%s: expected one call to Release(), saw %d", test, negotiator.releaseCalls)
				}
			default:
				t.Errorf("%s: unrecognized negotiator: %#v", test, handler)
			}
		default:
			t.Errorf("%s: unrecognized handler: %#v", test, handler)
		}
	}

	initialRequest := req{path: "/oauth/authorize", method: "GET",
		query: url.Values{
			"client_id":     []string{"openshift-challenging-client"},
			"redirect_uri":  []string{"http://127.0.0.1:41933/oauth/token/implicit"},
			"response_type": []string{"code"},
		},
	}

	basicChallenge1 := resp{status: 401, wwwAuthenticate: []string{"Basic realm=foo"}}
	basicRequest1 := req{path: "/oauth/authorize", authorization: "Basic bXl1c2VyOm15cGFzc3dvcmQ=", method: "GET",
		query: url.Values{
			"client_id":     []string{"openshift-challenging-client"},
			"redirect_uri":  []string{"http://127.0.0.1:41933/oauth/token/implicit"},
			"response_type": []string{"code"},
		},
	} // base64("myuser:mypassword")

	//basicChallenge2 := resp{401, "", []string{"Basic realm=seriously...foo"}}
	//
	//negotiateChallenge1 := resp{401, "", []string{"Negotiate"}}
	//negotiateRequest1 := req{"Negotiate cmVzcG9uc2Ux"}                           // base64("response1")
	//negotiateChallenge2 := resp{401, "", []string{"Negotiate Y2hhbGxlbmdlMg=="}} // base64("challenge2")
	//negotiateRequest2 := req{"Negotiate cmVzcG9uc2Uy"}                           // base64("response2")
	//
	//doubleChallenge := resp{401, "", []string{"Negotiate", "Basic realm=foo"}}

	successfulToken := "12345"
	//successfulLocation := fmt.Sprintf("/#access_token=%s", successfulToken)

	response1 := resp{status: 302, location: "/redir1"}
	response2 := resp{status: 302, location: "/redir2"}
	response3 := resp{status: 302, location: "/redir3"}
	response4 := resp{status: 302, location: "/valuedoesnotmatter", query: url.Values{
		"code": []string{"fancycode"},
	}}
	response5 := resp{status: 200, body: `{"token_type": "code", "access_token": "12345"}`}

	request1 := req{path: "/redir1", method: "GET"}
	request2 := req{path: "/redir2", method: "GET"}
	request3 := req{path: "/redir3", method: "GET"}
	request4 := req{path: "/oauth/token", method: "POST", body: `code=fancycode&grant_type=authorization_code&redirect_uri=http%3A%2F%2F127.0.0.1%3A34645%2Foauth%2Ftoken%2Fimplicit`,
		authorization: "Basic b3BlbnNoaWZ0LWNoYWxsZW5naW5nLWNsaWVudDo=", // base64 openshift-challenging-client:
	}

	//success := resp{status: 302, location: successfulLocation}
	//successWithNegotiate := resp{302, successfulLocation, []string{"Negotiate Y2hhbGxlbmdlMg=="}}

	for k, tc := range map[string]struct {
		handler       ChallengeHandler
		requests      []requestResponse
		expectedToken string
		expectedError string
	}{
		// Defaulting basic handler
		"defaulted basic handler, no challenge, success": {
			handler: &BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			requests: []requestResponse{
				{expectedRequest: initialRequest, serverResponse: basicChallenge1},
				{expectedRequest: basicRequest1, serverResponse: response1},
				{expectedRequest: request1, serverResponse: response2},
				{expectedRequest: request2, serverResponse: response3},
				{expectedRequest: request3, serverResponse: response4},
				{expectedRequest: request4, serverResponse: response5},
			},
			expectedToken: successfulToken,
		},
	} {
		i := 0
		var s *httptest.Server
		s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if i >= len(tc.requests) {
				t.Errorf("%s: %d: more requests received than expected: %#v", k, i, req)
				return
			}
			rr := tc.requests[i]
			i++
			if e, a := rr.expectedRequest.method, req.Method; e != a {
				t.Errorf("%s: %d: Expected method %s, got %s", k, i, e, a)
				return
			}
			if e, a := rr.expectedRequest.path, req.URL.Path; e != a {
				t.Errorf("%s: %d: Expected path %s, got %s", k, i, e, a)
				return
			}
			if e, a := getQuery(rr.expectedRequest.query), req.URL.Query().Encode(); e != a {
				t.Logf("%s: %d: Expected query %s, got %s", k, i, e, a)
				//return
			}
			if e, a := rr.expectedRequest.body, getBody(req.Body); e != a {
				t.Logf("%s: %d: Expected body %s, got %s", k, i, e, a)
				//return
			}
			if e, a := rr.expectedRequest.authorization, req.Header.Get("Authorization"); e != a { // TODO check all headers
				t.Errorf("%s: %d: expected 'Authorization: %s', got 'Authorization: %s'", k, i, e, a)
				return
			}
			if location, query := rr.serverResponse.location, getQuery(rr.serverResponse.query); len(location) > 0 {
				if len(query) > 0 {
					query = "?" + query
				}
				w.Header().Add("Location", s.URL+location+query)
			}
			for _, v := range rr.serverResponse.wwwAuthenticate {
				w.Header().Add("WWW-Authenticate", v)
			}
			w.WriteHeader(rr.serverResponse.status)
			w.Write([]byte(rr.serverResponse.body))
		}))
		defer s.Close()

		opts := &RequestTokenOptions{
			ClientConfig: &restclient.Config{Host: s.URL},
			Handler:      tc.handler,
			OsinConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: util.OpenShiftOAuthAuthorizeURL(s.URL),
				TokenUrl:     util.OpenShiftOAuthTokenURL(s.URL),
				RedirectUrl:  util.OpenShiftOAuthTokenImplicitURL(s.URL),
			},
			TokenFlow: false,
		}
		token, err := opts.RequestToken()
		if e, a := tc.expectedToken, token; e != a {
			t.Errorf("%s: expected token %q, got %q", k, e, a)
		}
		if e, a := tc.expectedError, getErrorStr(err); e != a {
			t.Errorf("%s: expected error '%s', got '%s'", k, e, a)
		}
		if e, a := len(tc.requests), i; e != a {
			t.Errorf("%s: expected %d requests, saw %d", k, e, a)
		}
		verifyReleased(k, tc.handler)
	}
}

func getQuery(values url.Values) string {
	if values == nil {
		return ""
	}
	return values.Encode()
}

func getBody(closer io.ReadCloser) string {
	if closer == nil {
		return ""
	}
	defer closer.Close()
	data, err := ioutil.ReadAll(closer)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func getErrorStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
