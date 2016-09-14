package oauthclient

import (
	"reflect"
	"strings"
	"testing"

	kapi "k8s.io/kubernetes/pkg/api"
	ktestclient "k8s.io/kubernetes/pkg/client/unversioned/testclient"
	"k8s.io/kubernetes/pkg/types"

	ostestclient "github.com/openshift/origin/pkg/client/testclient"
	oauthapi "github.com/openshift/origin/pkg/oauth/api"
	routeapi "github.com/openshift/origin/pkg/route/api"
	"k8s.io/kubernetes/pkg/util/intstr"
)

func TestGetClient(t *testing.T) {
	testCases := []struct {
		name       string
		clientName string
		kubeClient *ktestclient.Fake
		osClient   *ostestclient.Fake

		expectedDelegation  bool
		expectedErr         string
		expectedClient      *oauthapi.OAuthClient
		expectedKubeActions []ktestclient.Action
		expectedOSActions   []ktestclient.Action
	}{
		{
			name:                "delegate",
			clientName:          "not:serviceaccount",
			kubeClient:          ktestclient.NewSimpleFake(),
			osClient:            ostestclient.NewSimpleFake(),
			expectedDelegation:  true,
			expectedKubeActions: []ktestclient.Action{},
			expectedOSActions:   []ktestclient.Action{},
		},
		{
			name:                "missing sa",
			clientName:          "system:serviceaccount:ns-01:missing-sa",
			kubeClient:          ktestclient.NewSimpleFake(),
			osClient:            ostestclient.NewSimpleFake(),
			expectedErr:         `ServiceAccount "missing-sa" not found`,
			expectedKubeActions: []ktestclient.Action{ktestclient.NewGetAction("serviceaccounts", "ns-01", "missing-sa")},
			expectedOSActions:   []ktestclient.Action{},
		},
		{
			name:       "sa no redirects",
			clientName: "system:serviceaccount:ns-01:default",
			kubeClient: ktestclient.NewSimpleFake(
				&kapi.ServiceAccount{
					ObjectMeta: kapi.ObjectMeta{
						Namespace:   "ns-01",
						Name:        "default",
						Annotations: map[string]string{},
					},
				}),
			osClient:            ostestclient.NewSimpleFake(),
			expectedErr:         `system:serviceaccount:ns-01:default has no redirectURIs; set serviceaccounts.openshift.io/oauth-redirecturi.<some-value>`,
			expectedKubeActions: []ktestclient.Action{ktestclient.NewGetAction("serviceaccounts", "ns-01", "default")},
			expectedOSActions:   []ktestclient.Action{},
		},
		{
			name:       "sa no tokens",
			clientName: "system:serviceaccount:ns-01:default",
			kubeClient: ktestclient.NewSimpleFake(
				&kapi.ServiceAccount{
					ObjectMeta: kapi.ObjectMeta{
						Namespace:   "ns-01",
						Name:        "default",
						Annotations: map[string]string{OAuthRedirectURISecretAnnotationPrefix + "one": "anywhere"},
					},
				}),
			osClient:    ostestclient.NewSimpleFake(),
			expectedErr: `system:serviceaccount:ns-01:default has no tokens`,
			expectedKubeActions: []ktestclient.Action{
				ktestclient.NewGetAction("serviceaccounts", "ns-01", "default"),
				ktestclient.NewListAction("secrets", "ns-01", kapi.ListOptions{}),
			},
			expectedOSActions: []ktestclient.Action{},
		},
		{
			name:       "good SA",
			clientName: "system:serviceaccount:ns-01:default",
			kubeClient: ktestclient.NewSimpleFake(
				&kapi.ServiceAccount{
					ObjectMeta: kapi.ObjectMeta{
						Namespace:   "ns-01",
						Name:        "default",
						UID:         types.UID("any"),
						Annotations: map[string]string{OAuthRedirectURISecretAnnotationPrefix + "one": "anywhere"},
					},
				},
				&kapi.Secret{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						Annotations: map[string]string{
							kapi.ServiceAccountNameKey: "default",
							kapi.ServiceAccountUIDKey:  "any",
						},
					},
					Type: kapi.SecretTypeServiceAccountToken,
					Data: map[string][]byte{kapi.ServiceAccountTokenKey: []byte("foo")},
				}),
			osClient: ostestclient.NewSimpleFake(),
			expectedClient: &oauthapi.OAuthClient{
				ObjectMeta:        kapi.ObjectMeta{Name: "system:serviceaccount:ns-01:default"},
				ScopeRestrictions: getScopeRestrictionsFor("ns-01", "default"),
				AdditionalSecrets: []string{"foo"},
				RedirectURIs:      []string{"anywhere"},
				GrantMethod:       oauthapi.GrantHandlerPrompt,
			},
			expectedKubeActions: []ktestclient.Action{
				ktestclient.NewGetAction("serviceaccounts", "ns-01", "default"),
				ktestclient.NewListAction("secrets", "ns-01", kapi.ListOptions{}),
			},
			expectedOSActions: []ktestclient.Action{},
		},
		{
			name:       "good SA with valid, simple route redirects",
			clientName: "system:serviceaccount:ns-01:default",
			kubeClient: ktestclient.NewSimpleFake(
				&kapi.ServiceAccount{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						UID:       types.UID("any"),
						Annotations: map[string]string{
							OAuthRedirectURISecretAnnotationPrefix + "one":        "anywhere",
							OAuthRedirectModelAnnotationResourceKindPrefix + "1":  RouteKind,
							OAuthRedirectModelAnnotationResourceNamePrefix + "1":  "route1",
							OAuthRedirectModelAnnotationResourceGroupPrefix + "1": routeapi.FutureGroupName,
						},
					},
				},
				&kapi.Secret{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						Annotations: map[string]string{
							kapi.ServiceAccountNameKey: "default",
							kapi.ServiceAccountUIDKey:  "any",
						},
					},
					Type: kapi.SecretTypeServiceAccountToken,
					Data: map[string][]byte{kapi.ServiceAccountTokenKey: []byte("foo")},
				}),
			osClient: ostestclient.NewSimpleFake(
				&routeapi.Route{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "route1",
						UID:       types.UID("route1"),
					},
					Spec: routeapi.RouteSpec{
						Path: "/defaultpath",
						TLS:  &routeapi.TLSConfig{},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "example1.com"},
						},
					},
				},
			),
			expectedClient: &oauthapi.OAuthClient{
				ObjectMeta:        kapi.ObjectMeta{Name: "system:serviceaccount:ns-01:default"},
				ScopeRestrictions: getScopeRestrictionsFor("ns-01", "default"),
				AdditionalSecrets: []string{"foo"},
				RedirectURIs:      []string{"anywhere", "https://example1.com/defaultpath"},
				GrantMethod:       oauthapi.GrantHandlerPrompt,
			},
			expectedKubeActions: []ktestclient.Action{
				ktestclient.NewGetAction("serviceaccounts", "ns-01", "default"),
				ktestclient.NewListAction("secrets", "ns-01", kapi.ListOptions{}),
			},
			expectedOSActions: []ktestclient.Action{
				ktestclient.NewGetAction("routes", "ns-01", "route1"),
			},
		},
		{
			name:       "good SA with invalid route redirects",
			clientName: "system:serviceaccount:ns-01:default",
			kubeClient: ktestclient.NewSimpleFake(
				&kapi.ServiceAccount{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						UID:       types.UID("any"),
						Annotations: map[string]string{
							OAuthRedirectURISecretAnnotationPrefix + "one":        "anywhere",
							OAuthRedirectModelAnnotationResourceKindPrefix + "1":  RouteKind,
							OAuthRedirectModelAnnotationResourceNamePrefix + "1":  "route1",
							OAuthRedirectModelAnnotationResourceGroupPrefix + "1": "wronggroup",
							OAuthRedirectModelAnnotationResourceKindPrefix + "2":  "wrongkind",
							OAuthRedirectModelAnnotationResourceNamePrefix + "2":  "route1",
							OAuthRedirectModelAnnotationResourceGroupPrefix + "2": routeapi.FutureGroupName,
						},
					},
				},
				&kapi.Secret{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						Annotations: map[string]string{
							kapi.ServiceAccountNameKey: "default",
							kapi.ServiceAccountUIDKey:  "any",
						},
					},
					Type: kapi.SecretTypeServiceAccountToken,
					Data: map[string][]byte{kapi.ServiceAccountTokenKey: []byte("foo")},
				}),
			osClient: ostestclient.NewSimpleFake(
				&routeapi.Route{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "route1",
						UID:       types.UID("route1"),
					},
					Spec: routeapi.RouteSpec{
						Path: "/defaultpath",
						TLS:  &routeapi.TLSConfig{},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "example1.com"},
							{Host: "example2.com"},
							{Host: "example3.com"},
						},
					},
				},
			),
			expectedClient: &oauthapi.OAuthClient{
				ObjectMeta:        kapi.ObjectMeta{Name: "system:serviceaccount:ns-01:default"},
				ScopeRestrictions: getScopeRestrictionsFor("ns-01", "default"),
				AdditionalSecrets: []string{"foo"},
				RedirectURIs:      []string{"anywhere"},
				GrantMethod:       oauthapi.GrantHandlerPrompt,
			},
			expectedKubeActions: []ktestclient.Action{
				ktestclient.NewGetAction("serviceaccounts", "ns-01", "default"),
				ktestclient.NewListAction("secrets", "ns-01", kapi.ListOptions{}),
			},
			expectedOSActions: []ktestclient.Action{},
		},
		{
			name:       "good SA with a route that don't have a host",
			clientName: "system:serviceaccount:ns-01:default",
			kubeClient: ktestclient.NewSimpleFake(
				&kapi.ServiceAccount{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						UID:       types.UID("any"),
						Annotations: map[string]string{
							OAuthRedirectURISecretAnnotationPrefix + "one":        "anywhere",
							OAuthRedirectModelAnnotationResourceKindPrefix + "1":  RouteKind,
							OAuthRedirectModelAnnotationResourceNamePrefix + "1":  "route1",
							OAuthRedirectModelAnnotationResourceGroupPrefix + "1": routeapi.FutureGroupName,
						},
					},
				},
				&kapi.Secret{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						Annotations: map[string]string{
							kapi.ServiceAccountNameKey: "default",
							kapi.ServiceAccountUIDKey:  "any",
						},
					},
					Type: kapi.SecretTypeServiceAccountToken,
					Data: map[string][]byte{kapi.ServiceAccountTokenKey: []byte("foo")},
				}),
			osClient: ostestclient.NewSimpleFake(
				&routeapi.Route{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "route1",
						UID:       types.UID("route1"),
					},
					Spec: routeapi.RouteSpec{
						Path: "/defaultpath",
						TLS:  &routeapi.TLSConfig{},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: ""},
						},
					},
				},
			),
			expectedClient: &oauthapi.OAuthClient{
				ObjectMeta:        kapi.ObjectMeta{Name: "system:serviceaccount:ns-01:default"},
				ScopeRestrictions: getScopeRestrictionsFor("ns-01", "default"),
				AdditionalSecrets: []string{"foo"},
				RedirectURIs:      []string{"anywhere"},
				GrantMethod:       oauthapi.GrantHandlerPrompt,
			},
			expectedKubeActions: []ktestclient.Action{
				ktestclient.NewGetAction("serviceaccounts", "ns-01", "default"),
				ktestclient.NewListAction("secrets", "ns-01", kapi.ListOptions{}),
			},
			expectedOSActions: []ktestclient.Action{
				ktestclient.NewGetAction("routes", "ns-01", "route1"),
			},
		},
		{
			name:       "good SA with routes that don't have hosts, some of which are empty or duplicates",
			clientName: "system:serviceaccount:ns-01:default",
			kubeClient: ktestclient.NewSimpleFake(
				&kapi.ServiceAccount{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						UID:       types.UID("any"),
						Annotations: map[string]string{
							OAuthRedirectURISecretAnnotationPrefix + "one":        "anywhere",
							OAuthRedirectModelAnnotationResourceKindPrefix + "1":  RouteKind,
							OAuthRedirectModelAnnotationResourceNamePrefix + "1":  "route1",
							OAuthRedirectModelAnnotationResourceGroupPrefix + "1": routeapi.FutureGroupName,
							OAuthRedirectModelAnnotationResourceKindPrefix + "2":  RouteKind,
							OAuthRedirectModelAnnotationResourceNamePrefix + "2":  "route2",
							OAuthRedirectModelAnnotationResourceGroupPrefix + "2": routeapi.FutureGroupName,
							OAuthRedirectModelAnnotationResourceKindPrefix + "3":  RouteKind,
							OAuthRedirectModelAnnotationResourceNamePrefix + "3":  "missingroute",
							OAuthRedirectModelAnnotationResourceGroupPrefix + "3": routeapi.FutureGroupName,
						},
					},
				},
				&kapi.Secret{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "default",
						Annotations: map[string]string{
							kapi.ServiceAccountNameKey: "default",
							kapi.ServiceAccountUIDKey:  "any",
						},
					},
					Type: kapi.SecretTypeServiceAccountToken,
					Data: map[string][]byte{kapi.ServiceAccountTokenKey: []byte("foo")},
				}),
			osClient: ostestclient.NewSimpleFake(
				&routeapi.Route{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "route1",
						UID:       types.UID("route1"),
					},
					Spec: routeapi.RouteSpec{
						Path: "/defaultpath",
						TLS:  &routeapi.TLSConfig{},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: ""},
							{Host: "a.com"},
							{Host: ""},
							{Host: "a.com"},
							{Host: "b.com"},
						},
					},
				},
				&routeapi.Route{
					ObjectMeta: kapi.ObjectMeta{
						Namespace: "ns-01",
						Name:      "route2",
						UID:       types.UID("route2"),
					},
					Spec: routeapi.RouteSpec{
						Path: "/path2",
						TLS:  &routeapi.TLSConfig{},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "a.com"},
							{Host: ""},
							{Host: "b.com"},
							{Host: "b.com"},
							{Host: ""},
						},
					},
				},
			),
			expectedClient: &oauthapi.OAuthClient{
				ObjectMeta:        kapi.ObjectMeta{Name: "system:serviceaccount:ns-01:default"},
				ScopeRestrictions: getScopeRestrictionsFor("ns-01", "default"),
				AdditionalSecrets: []string{"foo"},
				RedirectURIs:      []string{"anywhere", "https://a.com/defaultpath", "https://a.com/path2", "https://b.com/defaultpath", "https://b.com/path2"},
				GrantMethod:       oauthapi.GrantHandlerPrompt,
			},
			expectedKubeActions: []ktestclient.Action{
				ktestclient.NewGetAction("serviceaccounts", "ns-01", "default"),
				ktestclient.NewListAction("secrets", "ns-01", kapi.ListOptions{}),
			},
			expectedOSActions: []ktestclient.Action{
				ktestclient.NewListAction("routes", "ns-01", kapi.ListOptions{}),
			},
		},
	}

	for _, tc := range testCases {
		delegate := &fakeDelegate{}
		getter := NewServiceAccountOAuthClientGetter(tc.kubeClient, tc.kubeClient, tc.osClient, delegate, oauthapi.GrantHandlerPrompt)
		client, err := getter.GetClient(kapi.NewContext(), tc.clientName)
		switch {
		case len(tc.expectedErr) == 0 && err == nil:
		case len(tc.expectedErr) == 0 && err != nil,
			len(tc.expectedErr) > 0 && err == nil,
			len(tc.expectedErr) > 0 && err != nil && !strings.Contains(err.Error(), tc.expectedErr):
			t.Errorf("%s: expected %#v, got %#v", tc.name, tc.expectedErr, err)
			continue
		}

		if tc.expectedDelegation != delegate.called {
			t.Errorf("%s: expected %#v, got %#v", tc.name, tc.expectedDelegation, delegate.called)
			continue
		}

		if !kapi.Semantic.DeepEqual(tc.expectedClient, client) {
			t.Errorf("%s: expected %#v, got %#v", tc.name, tc.expectedClient, client)
			continue
		}

		if !reflect.DeepEqual(tc.expectedKubeActions, tc.kubeClient.Actions()) {
			t.Errorf("%s: expected %#v, got %#v", tc.name, tc.expectedKubeActions, tc.kubeClient.Actions())
			continue
		}

		if !reflect.DeepEqual(tc.expectedOSActions, tc.osClient.Actions()) {
			t.Errorf("%s: expected %#v, got %#v", tc.name, tc.expectedOSActions, tc.osClient.Actions())
			continue
		}
	}

}

type fakeDelegate struct {
	called bool
}

func (d *fakeDelegate) GetClient(ctx kapi.Context, name string) (*oauthapi.OAuthClient, error) {
	d.called = true
	return nil, nil
}

func TestRedirectURIString(t *testing.T) {
	for _, test := range []struct {
		name     string
		uri      redirectURI
		expected string
	}{
		{
			name: "host with no port",
			uri: redirectURI{
				scheme: "http",
				host:   "example1.com",
				port:   "",
				path:   "/test1",
			},
			expected: "http://example1.com/test1",
		},
		{
			name: "host with port",
			uri: redirectURI{
				scheme: "https",
				host:   "example2.com",
				port:   "8000",
				path:   "/test2",
			},
			expected: "https://example2.com:8000/test2",
		},
	} {
		if test.expected != test.uri.String() {
			t.Errorf("%s: expected %s, got %s", test.name, test.expected, test.uri.String())
		}
	}
}

func TestMerge(t *testing.T) {
	for _, test := range []struct {
		name     string
		uri      redirectURI
		m        model
		expected redirectURI
	}{
		{
			name: "empty model",
			uri: redirectURI{
				scheme: "http",
				host:   "example1.com",
				port:   "9000",
				path:   "/test1",
			},
			m: model{
				scheme: "",
				port:   "",
				path:   "",
			},
			expected: redirectURI{
				scheme: "http",
				host:   "example1.com",
				port:   "9000",
				path:   "/test1",
			},
		},
		{
			name: "full model",
			uri: redirectURI{
				scheme: "http",
				host:   "example1.com",
				port:   "9000",
				path:   "/test1",
			},
			m: model{
				scheme: "https",
				port:   "8000",
				path:   "/ello",
			},
			expected: redirectURI{
				scheme: "https",
				host:   "example1.com",
				port:   "8000",
				path:   "/ello",
			},
		},
		{
			name: "only path",
			uri: redirectURI{
				scheme: "http",
				host:   "example1.com",
				port:   "9000",
				path:   "/test1",
			},
			m: model{
				scheme: "",
				port:   "",
				path:   "/newpath",
			},
			expected: redirectURI{
				scheme: "http",
				host:   "example1.com",
				port:   "9000",
				path:   "/newpath",
			},
		},
	} {
		test.uri.merge(test.m)
		if test.expected != test.uri {
			t.Errorf("%s: expected %#v, got %#v", test.name, test.expected, test.uri)
		}
	}
}

func TestParseModels(t *testing.T) {
	for _, test := range []struct {
		name        string
		annotations map[string]string
		expected    map[string]model
	}{
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			expected:    map[string]model{},
		},
		{
			name:        "no model annotations",
			annotations: map[string]string{OAuthRedirectURISecretAnnotationPrefix + "one": "anywhere"},
			expected:    map[string]model{},
		},
		{
			name: "simple model",
			annotations: map[string]string{
				OAuthRedirectModelAnnotationResourceKindPrefix + "one":  RouteKind,
				OAuthRedirectModelAnnotationResourceNamePrefix + "one":  "route1",
				OAuthRedirectModelAnnotationResourceGroupPrefix + "one": routeapi.FutureGroupName,
			},
			expected: map[string]model{
				"one": {
					scheme: "",
					port:   "",
					path:   "",
					group:  routeapi.FutureGroupName,
					kind:   RouteKind,
					name:   "route1",
				},
			},
		},
		{
			name: "multiple full models",
			annotations: map[string]string{
				OAuthRedirectModelAnnotationResourceKindPrefix + "one":  RouteKind,
				OAuthRedirectModelAnnotationResourceNamePrefix + "one":  "route1",
				OAuthRedirectModelAnnotationResourceGroupPrefix + "one": routeapi.FutureGroupName,
				OAuthRedirectModelAnnotationURIPathPrefix + "one":       "/path1",
				OAuthRedirectModelAnnotationURIPortPrefix + "one":       "8000",
				OAuthRedirectModelAnnotationURISchemePrefix + "one":     "https",

				OAuthRedirectModelAnnotationResourceKindPrefix + "two":  RouteKind,
				OAuthRedirectModelAnnotationResourceNamePrefix + "two":  "route2",
				OAuthRedirectModelAnnotationResourceGroupPrefix + "two": routeapi.FutureGroupName,
				OAuthRedirectModelAnnotationURIPathPrefix + "two":       "/path2",
				OAuthRedirectModelAnnotationURIPortPrefix + "two":       "9000",
				OAuthRedirectModelAnnotationURISchemePrefix + "two":     "http",
			},
			expected: map[string]model{
				"one": {
					scheme: "https",
					port:   "8000",
					path:   "/path1",
					group:  routeapi.FutureGroupName,
					kind:   RouteKind,
					name:   "route1",
				},
				"two": {
					scheme: "http",
					port:   "9000",
					path:   "/path2",
					group:  routeapi.FutureGroupName,
					kind:   RouteKind,
					name:   "route2",
				},
			},
		},
	} {
		if !reflect.DeepEqual(test.expected, parseModels(test.annotations)) {
			t.Errorf("%s: expected %#v, got %#v", test.name, test.expected, parseModels(test.annotations))
		}
	}
}

func TestGetOSRoutesRedirectURIs(t *testing.T) {
	for _, test := range []struct {
		name      string
		modelList []model
		routes    []routeapi.Route
		expected  []redirectURI
	}{
		{
			name: "single ingress routes",
			modelList: []model{
				{
					scheme: "https",
					port:   "8000",
					path:   "/path1",
					group:  routeapi.FutureGroupName,
					kind:   RouteKind,
					name:   "route1",
				},
				{
					scheme: "http",
					port:   "9000",
					path:   "",
					group:  routeapi.FutureGroupName,
					kind:   RouteKind,
					name:   "route2",
				},
			},
			routes: []routeapi.Route{
				{
					ObjectMeta: kapi.ObjectMeta{
						Name: "route1",
					},
					Spec: routeapi.RouteSpec{
						Path: "/pathA",
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "exampleA.com"},
						},
					},
				},
				{
					ObjectMeta: kapi.ObjectMeta{
						Name: "route2",
					},
					Spec: routeapi.RouteSpec{
						Path: "/pathB",
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "exampleB.com"},
						},
					},
				},
			},
			expected: []redirectURI{
				{
					scheme: "https",
					host:   "exampleA.com",
					port:   "8000",
					path:   "/path1",
				},
				{
					scheme: "http",
					host:   "exampleB.com",
					port:   "9000",
					path:   "/pathB",
				},
			},
		},
		{
			name: "multiple ingress routes",
			modelList: []model{
				{
					scheme: "https",
					port:   "8000",
					path:   "/path1",
					group:  routeapi.FutureGroupName,
					kind:   RouteKind,
					name:   "route1",
				},
				{
					scheme: "http",
					port:   "9000",
					path:   "",
					group:  routeapi.FutureGroupName,
					kind:   RouteKind,
					name:   "route2",
				},
				{
					scheme: "http",
					port:   "",
					path:   "/secondroute2path",
					group:  routeapi.FutureGroupName,
					kind:   RouteKind,
					name:   "route2",
				},
			},
			routes: []routeapi.Route{
				{
					ObjectMeta: kapi.ObjectMeta{
						Name: "route1",
					},
					Spec: routeapi.RouteSpec{
						Path: "/pathA",
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "A.com"},
							{Host: "B.com"},
							{Host: "C.com"},
						},
					},
				},
				{
					ObjectMeta: kapi.ObjectMeta{
						Name: "route2",
					},
					Spec: routeapi.RouteSpec{
						Path: "/pathB",
						Port: &routeapi.RoutePort{
							TargetPort: intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "3000",
							},
						},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "0.com"},
							{Host: "1.com"},
						},
					},
				},
			},
			expected: []redirectURI{
				{
					scheme: "https",
					host:   "A.com",
					port:   "8000",
					path:   "/path1",
				},
				{
					scheme: "https",
					host:   "B.com",
					port:   "8000",
					path:   "/path1",
				},
				{
					scheme: "https",
					host:   "C.com",
					port:   "8000",
					path:   "/path1",
				},
				{
					scheme: "http",
					host:   "0.com",
					port:   "9000",
					path:   "/pathB",
				},
				{
					scheme: "http",
					host:   "1.com",
					port:   "9000",
					path:   "/pathB",
				},
				{
					scheme: "http",
					host:   "0.com",
					port:   "3000",
					path:   "/secondroute2path",
				},
				{
					scheme: "http",
					host:   "1.com",
					port:   "3000",
					path:   "/secondroute2path",
				},
			},
		},
	} {
		if !reflect.DeepEqual(test.expected, getOSRoutesRedirectURIs(test.modelList, test.routes)) {
			t.Errorf("%s: expected %#v, got %#v", test.name, test.expected, getOSRoutesRedirectURIs(test.modelList, test.routes))
		}
	}
}

func TestGetRouteMap(t *testing.T) {
	for _, test := range []struct {
		name     string
		routes   []routeapi.Route
		expected map[string][]redirectURI
	}{
		{
			name: "single route with single ingress",
			routes: []routeapi.Route{
				{
					ObjectMeta: kapi.ObjectMeta{
						Name: "routeA",
					},
					Spec: routeapi.RouteSpec{
						Path: "/pathA",
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "exampleA.com"},
						},
					},
				},
			},
			expected: map[string][]redirectURI{
				"routeA": {
					{
						scheme: "http",
						host:   "exampleA.com",
						port:   "",
						path:   "/pathA",
					},
				},
			},
		},
		{
			name: "multiple routes with multiple ingresses",
			routes: []routeapi.Route{
				{
					ObjectMeta: kapi.ObjectMeta{
						Name: "route0",
					},
					Spec: routeapi.RouteSpec{
						Path: "/path0",
						Port: &routeapi.RoutePort{
							TargetPort: intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "8000",
							},
						},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "example0A.com"},
							{Host: "example0B.com"},
							{Host: "example0C.com"},
						},
					},
				},
				{
					ObjectMeta: kapi.ObjectMeta{
						Name: "route1",
					},
					Spec: routeapi.RouteSpec{
						Path: "/path1",
						TLS:  &routeapi.TLSConfig{},
						Port: &routeapi.RoutePort{
							TargetPort: intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "7000",
							},
						},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "redhat.com"},
							{Host: "coreos.com"},
							{Host: "github.com"},
						},
					},
				},
				{
					ObjectMeta: kapi.ObjectMeta{
						Name: "route2",
					},
					Spec: routeapi.RouteSpec{
						Path: "/path2",
						TLS:  &routeapi.TLSConfig{},
						Port: &routeapi.RoutePort{
							TargetPort: intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "6000",
							},
						},
					},
					Status: routeapi.RouteStatus{
						Ingress: []routeapi.RouteIngress{
							{Host: "google.com"},
							{Host: "yahoo.com"},
							{Host: "bing.com"},
						},
					},
				},
			},
			expected: map[string][]redirectURI{
				"route0": {
					{
						scheme: "http",
						host:   "example0A.com",
						port:   "8000",
						path:   "/path0",
					},
					{
						scheme: "http",
						host:   "example0B.com",
						port:   "8000",
						path:   "/path0",
					},
					{
						scheme: "http",
						host:   "example0C.com",
						port:   "8000",
						path:   "/path0",
					},
				},
				"route1": {
					{
						scheme: "https",
						host:   "redhat.com",
						port:   "7000",
						path:   "/path1",
					},
					{
						scheme: "https",
						host:   "coreos.com",
						port:   "7000",
						path:   "/path1",
					},
					{
						scheme: "https",
						host:   "github.com",
						port:   "7000",
						path:   "/path1",
					},
				},
				"route2": {
					{
						scheme: "https",
						host:   "google.com",
						port:   "6000",
						path:   "/path2",
					},
					{
						scheme: "https",
						host:   "yahoo.com",
						port:   "6000",
						path:   "/path2",
					},
					{
						scheme: "https",
						host:   "bing.com",
						port:   "6000",
						path:   "/path2",
					},
				},
			},
		},
	} {
		if !reflect.DeepEqual(test.expected, getRouteMap(test.routes)) {
			t.Errorf("%s: expected %#v, got %#v", test.name, test.expected, getRouteMap(test.routes))
		}
	}
}
