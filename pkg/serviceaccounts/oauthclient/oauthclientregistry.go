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
	// Prefix used for directly specifying redirect URIs for a service account via annotations
	OAuthRedirectURISecretAnnotationPrefix = "serviceaccounts.openshift.io/oauth-redirecturi."
	OAuthWantChallengesAnnotationPrefix    = "serviceaccounts.openshift.io/oauth-want-challenges"

	// Prefix used for indirectly specifying redirect URIs using resources for a service account via annotations
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
	// TODO add ingress support
	// IngressKind = "Ingress"
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

// namesToObjMapperFunc is linked to a given GroupKind.
// Based on the namespace and names provided, it builds a map of resource name to redirect URIs.
// The redirect URIs represent the default values as specified by the resource.
// These values can be overridden by user specified data.
type namesToObjMapperFunc func(namespace string, names sets.String) map[string]redirectURIList

var routeGroupKind = unversioned.GroupKind{Group: routeapi.FutureGroupName, Kind: RouteKind}

// TODO add ingress support
// var ingressGroupKind = unversioned.GroupKind{Group: ??, Kind: IngressKind}

type saOAuthClientAdapter struct {
	saClient     kclient.ServiceAccountsNamespacer
	secretClient kclient.SecretsNamespacer
	routeClient  osclient.RoutesNamespacer
	// TODO add ingress support
	//ingressClient ??

	delegate    oauthclient.Getter
	grantMethod oauthapi.GrantHandlerType
}

// model holds fields that could be used to build redirect URI(s).
// The resource components define where to get the default redirect data from.
// If specified, the uri components are used to override the default data.
// As long as the resulting URI(s) have a scheme and a host, they are considered valid.
type model struct {
	scheme string
	port   string
	path   string
	host   string

	group string
	kind  string
	name  string
}

// getGroupKind is used to determine if a group and kind combination is supported.
func (m *model) getGroupKind() unversioned.GroupKind {
	return unversioned.GroupKind{Group: m.group, Kind: m.kind}
}

type modelList []model

// getNames determines the unique, non-empty resource names specified by the models.
func (ml modelList) getNames() sets.String {
	data := sets.NewString()
	for _, model := range ml {
		if len(model.name) > 0 {
			data.Insert(model.name)
		}
	}
	return data
}

// getRedirectURIs uses the mapping provided by a namesToObjMapperFunc to enumerate all of the redirect URIs
// based on the name of each resource.  The user provided data in the model overrides the data in the mapping.
// The returned redirect URIs may contain duplicate and invalid entries.
func (ml modelList) getRedirectURIs(objMapper map[string]redirectURIList) redirectURIList {
	var data redirectURIList
	for _, m := range ml {
		if uris, ok := objMapper[m.name]; ok {
			for _, uri := range uris {
				u := uri
				u.merge(&m)
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

// isValid returns true when both scheme and host are non-empty.
func (uri *redirectURI) isValid() bool {
	return len(uri.scheme) > 0 && len(uri.host) > 0
}

type redirectURIList []redirectURI

// extractValidRedirectURIStrings returns the redirect URIs that are valid per `isValid` as strings.
func (rl redirectURIList) extractValidRedirectURIStrings() []string {
	var data []string
	for _, u := range rl {
		if u.isValid() {
			data = append(data, u.String())
		}
	}
	return data
}

// merge overrides the default data in the uri with the user provided data in the model.
func (uri *redirectURI) merge(m *model) {
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
	// parse annotations for directly specified redirect URI(s)
	for key, value := range sa.Annotations {
		if strings.HasPrefix(key, OAuthRedirectURISecretAnnotationPrefix) {
			redirectURIs = append(redirectURIs, value)
		}
	}
	// parse annotations for indirectly specified redirect URI(s)
	if modelsMap := parseModelsMap(sa.Annotations); len(modelsMap) > 0 {
		if uris := a.extractRedirectURIs(modelsMap, saNamespace); len(uris) > 0 {
			redirectURIs = append(redirectURIs, uris.extractValidRedirectURIStrings()...)
		}
	}
	if len(redirectURIs) == 0 {
		return nil, fmt.Errorf("%v has no redirectURIs; set %v<some-value>=<redirect> or create a model using %v",
			name, OAuthRedirectURISecretAnnotationPrefix, OAuthRedirectModelAnnotationPrefix)
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

// parseModelsMap builds a map of model name to model using a service account's annotations.
// The model name is only used for building the map and serves no functional purpose other than making testing easier.
func parseModelsMap(annotations map[string]string) map[string]model {
	models := map[string]model{}
	for key, value := range annotations {
		prefix, name, ok := parseModelPrefixName(key)
		if !ok {
			continue
		}
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
	return models
}

// parseModelPrefixName determines if the given key is a model prefix.
// Returns what prefix was used, the name of the model, and true if a model prefix was actually used.
func parseModelPrefixName(key string) (string, string, bool) {
	for _, prefix := range modelPrefixes {
		if strings.HasPrefix(key, prefix) {
			return prefix, key[len(prefix):], true
		}
	}
	return "", "", false
}

// extractRedirectURIs builds redirect URIs using the given models and namespace.
// The returned redirect URIs may contain duplicates and invalid entries.
func (a *saOAuthClientAdapter) extractRedirectURIs(modelsMap map[string]model, namespace string) redirectURIList {
	var data redirectURIList
	groupKindModelListMapper := map[unversioned.GroupKind]modelList{} // map of GroupKind to all models belonging to it
	groupKindModelToURI := map[unversioned.GroupKind]namesToObjMapperFunc{
		routeGroupKind: a.redirectURIsFromRoutes,
		// TODO add support for ingresses by creating the appropriate GroupKind and namesToObjMapperFunc
		// ingressGroupKind: a.redirectURIsFromIngresses,
	}

	for _, model := range modelsMap {
		gk := model.getGroupKind()
		if _, ok := groupKindModelToURI[gk]; ok { // a GroupKind is valid if we have a namesToObjMapperFunc to handle it
			groupKindModelListMapper[gk] = append(groupKindModelListMapper[gk], model)
		}
	}

	for gk, models := range groupKindModelListMapper {
		if names := models.getNames(); names.Len() > 0 {
			if objMapper := groupKindModelToURI[gk](namespace, names); len(objMapper) > 0 {
				data = append(data, models.getRedirectURIs(objMapper)...)
			}
		}
	}

	return data
}

// redirectURIsFromRoutes is the namesToObjMapperFunc specific to Routes.
// Returns a map of route name to redirect URIs that contain the default data as specified by the route's ingresses.
func (a *saOAuthClientAdapter) redirectURIsFromRoutes(namespace string, osRouteNames sets.String) map[string]redirectURIList {
	var routes []routeapi.Route
	routeInterface := a.routeClient.Routes(namespace)
	if osRouteNames.Len() > 1 {
		if r, err := routeInterface.List(kapi.ListOptions{}); err == nil {
			routes = r.Items
		}
	} else {
		if r, err := routeInterface.Get(osRouteNames.List()[0]); err == nil {
			routes = append(routes, *r)
		}
	}
	routeMap := map[string]redirectURIList{}
	for _, route := range routes {
		if osRouteNames.Has(route.Name) {
			routeMap[route.Name] = redirectURIsFromRoute(&route)
		}
	}
	return routeMap
}

// redirectURIsFromRoute returns a list of redirect URIs that contain the default data as specified by the given route's ingresses.
func redirectURIsFromRoute(route *routeapi.Route) redirectURIList {
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
