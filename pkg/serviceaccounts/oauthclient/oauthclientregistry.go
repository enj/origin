package oauthclient

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	kapi "k8s.io/kubernetes/pkg/api"
	kclient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/serviceaccount"

	scopeauthorizer "github.com/openshift/origin/pkg/authorization/authorizer/scope"
	osclient "github.com/openshift/origin/pkg/client"
	oauthapi "github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclient"
	routeapi "github.com/openshift/origin/pkg/route/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/util/sets"
)

const (
	OAuthRedirectURISecretAnnotationPrefix = "serviceaccounts.openshift.io/oauth-redirecturi."
	OAuthWantChallengesAnnotationPrefix    = "serviceaccounts.openshift.io/oauth-want-challenges"

	OAuthRedirectModelAnnotationPrefix              = "serviceaccounts.openshift.io/oauth-redirectmodel."
	OAuthRedirectModelAnnotationURIPrefix           = OAuthRedirectModelAnnotationPrefix + "uri."
	OAuthRedirectModelAnnotationResourcePrefix      = OAuthRedirectModelAnnotationPrefix + "resource."
	OAuthRedirectModelAnnotationURISchemePrefix     = OAuthRedirectModelAnnotationURIPrefix + "scheme."
	OAuthRedirectModelAnnotationURIPortPrefix       = OAuthRedirectModelAnnotationURIPrefix + "port."
	OAuthRedirectModelAnnotationURIPathPrefix       = OAuthRedirectModelAnnotationURIPrefix + "path."
	OAuthRedirectModelAnnotationURIHostPrefix       = OAuthRedirectModelAnnotationURIPrefix + "host."
	OAuthRedirectModelAnnotationResourceKindPrefix  = OAuthRedirectModelAnnotationResourcePrefix + "kind."
	OAuthRedirectModelAnnotationResourceNamePrefix  = OAuthRedirectModelAnnotationResourcePrefix + "name."
	OAuthRedirectModelAnnotationResourceGroupPrefix = OAuthRedirectModelAnnotationResourcePrefix + "group."

	RouteKind = "Route"
)

var modelPrefixes = []string{
	OAuthRedirectModelAnnotationURISchemePrefix,
	OAuthRedirectModelAnnotationURIPortPrefix,
	OAuthRedirectModelAnnotationURIPathPrefix,
	OAuthRedirectModelAnnotationURIHostPrefix,
	OAuthRedirectModelAnnotationResourceKindPrefix,
	OAuthRedirectModelAnnotationResourceNamePrefix,
	OAuthRedirectModelAnnotationResourceGroupPrefix,
}

type modelsToURIsFunc func(modelList []model) []redirectURI

var routeGroupKind = unversioned.GroupKind{Group: routeapi.FutureGroupName, Kind: RouteKind}

type saOAuthClientAdapter struct {
	saClient     kclient.ServiceAccountsNamespacer
	secretClient kclient.SecretsNamespacer
	routeClient  osclient.RoutesNamespacer

	delegate    oauthclient.Getter
	grantMethod oauthapi.GrantHandlerType
}

type model struct {
	scheme string
	port   string
	path   string
	host   string

	group string
	kind  string
	name  string
}

func (m *model) getGroupKind() unversioned.GroupKind {
	return unversioned.GroupKind{Group: m.group, Kind: m.kind}
}

type redirectURI struct {
	scheme string
	host   string
	port   string
	path   string
}

func (uri *redirectURI) String() string {
	host := uri.host
	if len(uri.port) > 0 {
		host = net.JoinHostPort(host, uri.port)
	}
	return (&url.URL{Scheme: uri.scheme, Host: host, Path: uri.path}).String()
}

func (uri *redirectURI) isValid() bool {
	return len(uri.scheme) != 0 && len(uri.host) != 0
}

func newDefaultRedirectURI() redirectURI {
	return redirectURI{scheme: "https"}
}

func (uri *redirectURI) merge(m model) {
	if len(m.scheme) != 0 {
		uri.scheme = m.scheme
	}
	if len(m.path) != 0 {
		uri.path = m.path
	}
	if len(m.port) != 0 {
		uri.port = m.port
	}
	if len(m.host) != 0 {
		uri.host = m.host
	}
}

var _ oauthclient.Getter = &saOAuthClientAdapter{}

func NewServiceAccountOAuthClientGetter(saClient kclient.ServiceAccountsNamespacer, secretClient kclient.SecretsNamespacer, routeClient osclient.RoutesNamespacer, delegate oauthclient.Getter, grantMethod oauthapi.GrantHandlerType) oauthclient.Getter {
	return &saOAuthClientAdapter{saClient: saClient, secretClient: secretClient, routeClient: routeClient, delegate: delegate, grantMethod: grantMethod}
}

func (a *saOAuthClientAdapter) GetClient(ctx kapi.Context, name string) (*oauthapi.OAuthClient, error) {
	saNamespace, saName, err := serviceaccount.SplitUsername(name)
	if err != nil {
		return a.delegate.GetClient(ctx, name)
	}

	sa, err := a.saClient.ServiceAccounts(saNamespace).Get(saName)
	if err != nil {
		return nil, err
	}

	redirectURIs := []string{}
	for key, value := range sa.Annotations {
		if strings.HasPrefix(key, OAuthRedirectURISecretAnnotationPrefix) {
			redirectURIs = append(redirectURIs, value)
		}
	}
	models := parseModels(sa.Annotations)
	if len(models) > 0 {
		ri := a.routeClient.Routes(saNamespace)
		redirectURIData := extractRedirectURIs(models, ri)
		if len(redirectURIData) > 0 {
			redirectURIs = append(redirectURIs, extractValidRedirectURIStrings(redirectURIData)...)
		}
	}
	if len(redirectURIs) == 0 {
		return nil, fmt.Errorf("%v has no redirectURIs; set %v<some-value>=<redirect>", name, OAuthRedirectURISecretAnnotationPrefix)
	}

	tokens, err := a.getServiceAccountTokens(sa)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("%v has no tokens", name)
	}

	saWantsChallenges, _ := strconv.ParseBool(sa.Annotations[OAuthWantChallengesAnnotationPrefix])

	saClient := &oauthapi.OAuthClient{
		ObjectMeta:            kapi.ObjectMeta{Name: name},
		ScopeRestrictions:     getScopeRestrictionsFor(saNamespace, saName),
		AdditionalSecrets:     tokens,
		RespondWithChallenges: saWantsChallenges,

		// TODO update this to allow https redirection to any
		// 1. service IP (useless in general)
		// 2. service DNS (useless in general)
		// 3. loopback? (useful, but maybe a bit weird)
		RedirectURIs: sets.NewString(redirectURIs...).List(),
		GrantMethod:  a.grantMethod,
	}
	return saClient, nil
}

func parseModels(annotations map[string]string) map[string]model {
	models := map[string]model{}
	for key, value := range annotations {
		if prefix, name, ok := parseModelPrefixName(key); ok {
			m := models[name]
			switch prefix {
			case OAuthRedirectModelAnnotationURISchemePrefix:
				m.scheme = value
			case OAuthRedirectModelAnnotationURIPortPrefix:
				m.port = value
			case OAuthRedirectModelAnnotationURIPathPrefix:
				m.path = value
			case OAuthRedirectModelAnnotationURIHostPrefix:
				m.host = value
			case OAuthRedirectModelAnnotationResourceKindPrefix:
				m.kind = value
			case OAuthRedirectModelAnnotationResourceNamePrefix:
				m.name = value
			case OAuthRedirectModelAnnotationResourceGroupPrefix:
				m.group = value
			}
			models[name] = m
		}
	}
	return models
}

func parseModelPrefixName(key string) (string, string, bool) {
	for _, prefix := range modelPrefixes {
		if strings.HasPrefix(key, prefix) {
			return prefix, key[len(prefix):], true
		}
	}
	return "", "", false
}

func extractRedirectURIs(models map[string]model, routeInterface osclient.RouteInterface) []redirectURI {
	var data []redirectURI
	groupKindModelListMapper := map[unversioned.GroupKind][]model{}

	groupKindModelToURI := map[unversioned.GroupKind]modelsToURIsFunc{
		routeGroupKind: func(osRouteModels []model) []redirectURI {
			routes := getOSRoutes(osRouteModels, routeInterface)
			return getOSRoutesRedirectURIs(osRouteModels, routes)
		},
	}

	for _, model := range models {
		gk := model.getGroupKind()
		if _, ok := groupKindModelToURI[gk]; ok {
			groupKindModelListMapper[gk] = append(groupKindModelListMapper[gk], model)
		}
	}

	for gk, modelList := range groupKindModelListMapper {
		if len(modelList) > 0 {
			data = append(data, groupKindModelToURI[gk](modelList)...)
		}
	}

	return data
}

func getOSRoutes(modelList []model, routeInterface osclient.RouteInterface) []routeapi.Route {
	var routes []routeapi.Route
	if len(modelList) > 1 {
		r, err := routeInterface.List(kapi.ListOptions{})
		if err == nil {
			routes = r.Items
		}
	} else {
		r, err := routeInterface.Get(modelList[0].name)
		if err == nil {
			routes = append(routes, *r)
		}
	}
	return routes
}

func getOSRoutesRedirectURIs(modelList []model, routes []routeapi.Route) []redirectURI {
	var data []redirectURI
	if rm := getRouteMap(routes); len(rm) > 0 {
		for _, m := range modelList {
			if r, ok := rm[m.name]; ok {
				for _, rURI := range r {
					u := rURI
					u.merge(m)
					data = append(data, u)
				}
			}
		}
	}
	return data
}

func getRouteMap(routes []routeapi.Route) map[string][]redirectURI {
	rm := map[string][]redirectURI{}
	for _, r := range routes {
		for _, i := range r.Status.Ingress {
			u := newDefaultRedirectURI()
			u.host = i.Host
			u.path = r.Spec.Path
			if r.Spec.Port != nil {
				u.port = r.Spec.Port.TargetPort.String()
			}
			if r.Spec.TLS == nil {
				u.scheme = "http"
			}
			rm[r.Name] = append(rm[r.Name], u)
		}
	}
	return rm
}

func extractValidRedirectURIStrings(redirectURIData []redirectURI) []string {
	var data []string
	for _, u := range redirectURIData {
		if u.isValid() {
			data = append(data, u.String())
		}
	}
	return data
}

func getScopeRestrictionsFor(namespace, name string) []oauthapi.ScopeRestriction {
	return []oauthapi.ScopeRestriction{
		{ExactValues: []string{
			scopeauthorizer.UserInfo,
			scopeauthorizer.UserAccessCheck,
			scopeauthorizer.UserListScopedProjects,
			scopeauthorizer.UserListAllProjects,
		}},
		{ClusterRole: &oauthapi.ClusterRoleScopeRestriction{RoleNames: []string{"*"}, Namespaces: []string{namespace}, AllowEscalation: true}},
	}
}

// getServiceAccountTokens returns all ServiceAccountToken secrets for the given ServiceAccount
func (a *saOAuthClientAdapter) getServiceAccountTokens(sa *kapi.ServiceAccount) ([]string, error) {
	allSecrets, err := a.secretClient.Secrets(sa.Namespace).List(kapi.ListOptions{})
	if err != nil {
		return nil, err
	}

	tokens := []string{}
	for i := range allSecrets.Items {
		secret := allSecrets.Items[i]
		if serviceaccount.IsServiceAccountToken(&secret, sa) {
			tokens = append(tokens, string(secret.Data[kapi.ServiceAccountTokenKey]))
		}
	}
	return tokens, nil
}
