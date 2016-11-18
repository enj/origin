package etcd

import (
	"fmt"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/registry/generic/registry"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/storage"

	"github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/oauth/registry/helpers"
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
	resource, prefix, err := helpers.GetResourceAndPrefix(optsGetter, "oauthclientauthorizations")
	if err != nil {
		return nil, fmt.Errorf("error building RESTOptions for %s store: %v", resource.String(), err)
	}

	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &api.OAuthClientAuthorization{} },
		NewListFunc: func() runtime.Object { return &api.OAuthClientAuthorizationList{} },
		KeyFunc: func(ctx kapi.Context, name string) (string, error) {
			base := prefix
			// Check to see if the name has the new format and thus is stored per user instead of a flat list
			if username := helpers.UserNameFromClientAuthorizationName(name); len(username) > 0 {
				base = base + "/" + username
			}
			return registry.NoNamespaceKeyFunc(ctx, base, name)
		},
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*api.OAuthClientAuthorization).Name, nil
		},
		PredicateFunc: func(label labels.Selector, field fields.Selector) *generic.SelectionPredicate {
			return oauthclientauthorization.Matcher(label, field)
		},
		QualifiedResource: *resource,

		CreateStrategy: oauthclientauthorization.NewStrategy(clientGetter),
		UpdateStrategy: oauthclientauthorization.NewStrategy(clientGetter),
	}

	if err := restoptions.ApplyOptions(optsGetter, store, false, storage.NoTriggerPublisher); err != nil {
		return nil, err
	}

	return &REST{*store}, nil
}
