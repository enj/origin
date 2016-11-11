package etcd

import (
	"fmt"
	"strings"

	kapi "k8s.io/kubernetes/pkg/api"
	kubeerr "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/registry/generic/registry"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/storage"

	"github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclient"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclientauthorization"
	"github.com/openshift/origin/pkg/util/restoptions"
)

// rest implements a RESTStorage for oauth client authorizations against etcd
type REST struct {
	registry.Store
}

// NewREST returns a RESTStorage object that will work against oauth clients
func NewREST(optsGetter restoptions.Getter, clientGetter oauthclient.Getter) (*REST, error) {
	resource := api.Resource("oauthclientauthorizations")
	opts, err := optsGetter.GetRESTOptions(resource)
	if err != nil {
		return nil, fmt.Errorf("error building RESTOptions for %s store: %v", resource.String(), err)
	}
	prefix := "/" + opts.ResourcePrefix

	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &api.OAuthClientAuthorization{} },
		NewListFunc: func() runtime.Object { return &api.OAuthClientAuthorizationList{} },
		KeyFunc: func(ctx kapi.Context, name string) (string, error) {
			username := userNameFromName(name)
			if len(username) == 0 {
				return "", kubeerr.NewBadRequest(fmt.Sprintf("Name parameter invalid: %q", name))
			}
			return registry.NoNamespaceKeyFunc(ctx, prefix+"/"+username, name)
		},
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*api.OAuthClientAuthorization).Name, nil
		},
		PredicateFunc: func(label labels.Selector, field fields.Selector) *generic.SelectionPredicate {
			return oauthclientauthorization.Matcher(label, field)
		},
		QualifiedResource: resource,

		CreateStrategy: oauthclientauthorization.NewStrategy(clientGetter),
		UpdateStrategy: oauthclientauthorization.NewStrategy(clientGetter),
	}

	if err := restoptions.ApplyOptions(optsGetter, store, false, storage.NoTriggerPublisher); err != nil {
		return nil, err
	}

	return &REST{*store}, nil
}

func userNameFromName(name string) string {
	if !strings.Contains(name, oauthclientauthorization.NameSeparator) {
		return ""
	}
	return strings.SplitN(name, oauthclientauthorization.NameSeparator, 2)[0]
}

func NewSelfREST(optsGetter restoptions.Getter, clientGetter oauthclient.Getter) (*REST, error) {
	resource := api.Resource("selfoauthclientauthorizations")
	opts, err := optsGetter.GetRESTOptions(resource)
	if err != nil {
		return nil, fmt.Errorf("error building RESTOptions for %s store: %v", resource.String(), err)
	}
	prefix := "/" + opts.ResourcePrefix

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
			namePrefix := username + oauthclientauthorization.NameSeparator
			if !strings.HasPrefix(name, namePrefix) {
				return "", kubeerr.NewForbidden(resource, name, fmt.Errorf("Name parameter invalid: %q: must start with %s", name, namePrefix))
			}
			return registry.NoNamespaceKeyFunc(ctx, prefix+"/"+username, name)
		},
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*api.SelfOAuthClientAuthorization).Name, nil
		},
		PredicateFunc: func(label labels.Selector, field fields.Selector) *generic.SelectionPredicate {
			return oauthclientauthorization.Matcher(label, field)
		},
		QualifiedResource: resource,

		CreateStrategy: oauthclientauthorization.NewStrategy(clientGetter),
		UpdateStrategy: oauthclientauthorization.NewStrategy(clientGetter),
	}

	if err := restoptions.ApplyOptions(optsGetter, store, false, storage.NoTriggerPublisher); err != nil {
		return nil, err
	}

	return &REST{*store}, nil
}
