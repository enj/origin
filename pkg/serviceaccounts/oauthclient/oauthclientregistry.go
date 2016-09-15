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

type namesToObjMapperFunc func(namespace string, names sets.String) map[string]redirectURIList

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

type modelList []model

func (ml modelList) getNames() sets.String {
	var data []string
	for _, model := range ml {
		if len(model.name) > 0 {
			data = append(data, model.name)
		}
	}
	return sets.NewString(data...)
}

func (ml modelList) getRedirectURIs(objMapper map[string]redirectURIList) redirectURIList {
	var data redirectURIList
	for _, m := range ml {
		if uris, ok := objMapper[m.name]; ok {
			for _, uri := range uris {
				u := uri
				u.merge(m)
				data = append(data, u)
			}
		}
	}
	return data
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
	return len(uri.scheme) > 0 && len(uri.host) > 0
}

type redirectURIList []redirectURI

func (rl redirectURIList) extractValidRedirectURIStrings() []string {
	var data []string
	for _, u := range rl {
		if u.isValid() {
			data = append(data, u.String())
		}
	}
	return data
}

func (uri *redirectURI) merge(m model) {
	if len(m.scheme) > 0 {
		uri.scheme = m.scheme
	}
	if len(m.path) > 0 {
		uri.path = m.path
	}
	if len(m.port) > 0 {
		uri.port = m.port
	}
	if len(m.host) > 0 {
		uri.host = m.host
	}
}

func newDefaultRedirectURI() redirectURI {
	return redirectURI{scheme: "https"}
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
	if modelsMap := parseModelsMap(sa.Annotations); len(modelsMap) > 0 {
		if uris := a.extractRedirectURIs(modelsMap, saNamespace); len(uris) > 0 {
			redirectURIs = append(redirectURIs, uris.extractValidRedirectURIStrings()...)
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

func parseModelsMap(annotations map[string]string) map[string]model {
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

func (a *saOAuthClientAdapter) extractRedirectURIs(modelsMap map[string]model, namespace string) redirectURIList {
	var data redirectURIList
	groupKindModelListMapper := map[unversioned.GroupKind]modelList{}
	groupKindModelToURI := map[unversioned.GroupKind]namesToObjMapperFunc{
		routeGroupKind: a.redirectURIsFromRoutes,
	}

	for _, model := range modelsMap {
		gk := model.getGroupKind()
		if _, ok := groupKindModelToURI[gk]; ok {
			groupKindModelListMapper[gk] = append(groupKindModelListMapper[gk], model)
		}
	}

	for gk, models := range groupKindModelListMapper {
		if len(models) > 0 {
			if names := models.getNames(); names.Len() > 0 {
				if objMapper := groupKindModelToURI[gk](namespace, names); len(objMapper) > 0 {
					data = append(data, models.getRedirectURIs(objMapper)...)
				}
			}
		}
	}

	return data
}

func (a *saOAuthClientAdapter) redirectURIsFromRoutes(namespace string, osRouteNames sets.String) map[string]redirectURIList {
	var routes []routeapi.Route
	routeInterface := a.routeClient.Routes(namespace)
	if osRouteNames.Len() > 1 {
		r, err := routeInterface.List(kapi.ListOptions{})
		if err == nil {
			routes = r.Items
		}
	} else {
		r, err := routeInterface.Get(osRouteNames.List()[0])
		if err == nil {
			routes = append(routes, *r)
		}
	}
	routeMap := map[string]redirectURIList{}
	for _, route := range routes {
		if osRouteNames.Has(route.Name) {
			routeMap[route.Name] = redirectURIsFromRoute(route)
		}
	}
	return routeMap
}

func redirectURIsFromRoute(route routeapi.Route) redirectURIList {
	var uris redirectURIList
	uri := newDefaultRedirectURI()
	uri.path = route.Spec.Path
	if route.Spec.Port != nil {
		uri.port = route.Spec.Port.TargetPort.String()
	}
	if route.Spec.TLS == nil {
		uri.scheme = "http"
	}
	for _, ingress := range route.Status.Ingress {
		u := uri
		u.host = ingress.Host
		uris = append(uris, u)
	}
	return uris
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
