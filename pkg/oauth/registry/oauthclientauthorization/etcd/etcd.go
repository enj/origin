package etcd

import (
	"fmt"
	"strings"

	kapi "k8s.io/kubernetes/pkg/api"
	kubeerr "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/registry/generic/registry"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/storage"

	"github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclient"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclientauthorization"
	oauthclientauthorizationhelpers "github.com/openshift/origin/pkg/oauth/registry/oauthclientauthorization/helpers"
	"github.com/openshift/origin/pkg/util/restoptions"
)

// rest implements a RESTStorage for oauth client authorizations against etcd
type REST struct {
	registry.Store
}

// NewREST returns a RESTStorage object that will work against oauth clients
func NewREST(optsGetter restoptions.Getter, clientGetter oauthclient.Getter) (*REST, error) {
	resource, prefix, err := oauthclientauthorizationhelpers.GetResourceAndPrefix(optsGetter, "oauthclientauthorizations")
	if err != nil {
		return nil, fmt.Errorf("error building RESTOptions for %s store: %v", resource.String(), err)
	}

	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &api.OAuthClientAuthorization{} },
		NewListFunc: func() runtime.Object { return &api.OAuthClientAuthorizationList{} },
		KeyFunc: func(ctx kapi.Context, name string) (string, error) {
			username := oauthclientauthorizationhelpers.UserNameFromClientAuthorizationName(name)
			if len(username) == 0 {
				return "", kubeerr.NewBadRequest(fmt.Sprintf("Name parameter invalid: %q", name))
			}
			return registry.NoNamespaceKeyFunc(ctx, prefix+"/"+username, name)
		},
	}

	return applyOAuthClientAuthorizationOptions(optsGetter, clientGetter, store, resource)
}

func NewSelfREST(optsGetter restoptions.Getter, clientGetter oauthclient.Getter) (*REST, error) {
	resource, prefix, err := oauthclientauthorizationhelpers.GetResourceAndPrefix(optsGetter, "selfoauthclientauthorizations")
	if err != nil {
		return nil, fmt.Errorf("error building RESTOptions for %s store: %v", resource.String(), err)
	}

	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &api.SelfOAuthClientAuthorization{} },
		NewListFunc: func() runtime.Object { return &api.SelfOAuthClientAuthorizationList{} },
		KeyRootFunc: func(ctx kapi.Context) string {
			user, ok := kapi.UserFrom(ctx)
			if !ok {
				return prefix + "/" + "%invalid%" // Something invalid
			}
			return prefix + "/" + user.GetName()
		},
		KeyFunc: func(ctx kapi.Context, name string) (string, error) {
			user, ok := kapi.UserFrom(ctx)
			if !ok {
				return "", kubeerr.NewBadRequest("User parameter required.")
			}
			username := user.GetName()
			namePrefix := username + oauthclientauthorizationhelpers.UserSpaceSeparator
			if !strings.HasPrefix(name, namePrefix) {
				return "", kubeerr.NewForbidden(*resource, name, fmt.Errorf("Name parameter invalid: %q: must start with %s", name, namePrefix))
			}
			return registry.NoNamespaceKeyFunc(ctx, prefix+"/"+username, name)
		},
	}

	return applyOAuthClientAuthorizationOptions(optsGetter, clientGetter, store, resource)
}

func applyOAuthClientAuthorizationOptions(optsGetter restoptions.Getter, clientGetter oauthclient.Getter, store *registry.Store, resource *unversioned.GroupResource) (*REST, error) {
	store.ObjectNameFunc = func(obj runtime.Object) (string, error) {
		return oauthclientauthorizationhelpers.ObjectToOAuthClientAuthorization(obj).Name, nil
	}
	store.PredicateFunc = func(label labels.Selector, field fields.Selector) *generic.SelectionPredicate {
		return oauthclientauthorization.Matcher(label, field)
	}
	store.QualifiedResource = *resource
	store.CreateStrategy = oauthclientauthorization.NewStrategy(clientGetter)
	store.UpdateStrategy = oauthclientauthorization.NewStrategy(clientGetter)

	if err := restoptions.ApplyOptions(optsGetter, store, false, storage.NoTriggerPublisher); err != nil {
		return nil, err
	}

	return &REST{*store}, nil
}
