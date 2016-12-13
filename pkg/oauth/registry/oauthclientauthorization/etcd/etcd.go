package etcd

import (
	"fmt"
	"strings"

	kapi "k8s.io/kubernetes/pkg/api"
	kubeerr "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
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

type SelfREST struct {
	helpers.ReadAndDeleteStorage
}

// NewREST returns a RESTStorage object that will work against oauth clients authorizations
func NewREST(optsGetter restoptions.Getter, clientGetter oauthclient.Getter) (*REST, *SelfREST, error) {
	resource, prefix, err := helpers.GetResourceAndPrefix(optsGetter, "oauthclientauthorizations")
	if err != nil {
		return nil, nil, fmt.Errorf("error building RESTOptions for %s store: %v", resource.String(), err)
	}
	strategy := oauthclientauthorization.NewStrategy(clientGetter)

	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &api.OAuthClientAuthorization{} },
		NewListFunc: func() runtime.Object { return &api.OAuthClientAuthorizationList{} },
		KeyFunc: func(ctx kapi.Context, name string) (string, error) {
			// Check to see if the name has the new format and thus is stored per user instead of a flat list
			if username, clientname, err := helpers.SplitClientAuthorizationName(name); err == nil {
				return registry.NoNamespaceKeyFunc(ctx, helpers.GetKeyWithUsername(prefix, username), clientname)
			}
			return registry.NoNamespaceKeyFunc(ctx, prefix, name)
		},
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*api.OAuthClientAuthorization).Name, nil
		},
		PredicateFunc:     oauthclientauthorization.Matcher,
		QualifiedResource: *resource,

		CreateStrategy: strategy,
		UpdateStrategy: strategy,
	}

	if err := restoptions.ApplyOptions(optsGetter, store, false, storage.NoTriggerPublisher); err != nil {
		return nil, nil, err
	}

	selfStore := *store
	selfStore.PredicateFunc = oauthclientauthorization.SelfMatcher
	selfStore.QualifiedResource = api.Resource("selfoauthclientauthorizations")
	selfStore.CreateStrategy = helpers.CannotCreateStrategy
	selfStore.UpdateStrategy = nil

	// We cannot override KeyFunc because the cacher does not provide the user in the context
	// The cacher does not use the KeyRootFunc so it is safe to override
	selfStore.KeyRootFunc = func(ctx kapi.Context) string { // This makes watches more efficient
		user, ok := kapi.UserFrom(ctx)
		if !ok {
			panic("User parameter required.")
		}
		return helpers.GetKeyWithUsername(prefix, user.GetName())
	}

	toSelfObject := func(obj runtime.Object) runtime.Object { // TODO fix
		return (*api.SelfOAuthClientAuthorization)(obj.(*api.OAuthClientAuthorization))
	}

	toSelfList := func(obj runtime.Object) runtime.Object {
		list := obj.(*api.OAuthClientAuthorizationList)
		newlist := &api.SelfOAuthClientAuthorizationList{Items: make([]api.SelfOAuthClientAuthorization, len(list.Items))}
		newlist.ResourceVersion = list.ResourceVersion
		for _, item := range list.Items {
			newlist.Items = append(newlist.Items, *(toSelfObject(&item).(*api.SelfOAuthClientAuthorization)))
		}
		return newlist
	}

	selfObjectUIDFilter := func(ctx kapi.Context, obj runtime.Object) error {
		user, ok := kapi.UserFrom(ctx)
		if !ok {
			return kubeerr.NewBadRequest("User parameter required.")
		}
		uid := user.GetUID()
		if len(uid) != 0 {
			if matched, err := store.PredicateFunc(labels.Everything(), fields.OneTermEqualSelector("userUID", uid)).Matches(obj); !matched || err != nil {
				name, _ := store.ObjectNameFunc(obj)
				return kubeerr.NewNotFound(selfStore.QualifiedResource, name)
			}
		}
		return nil
	}

	selfListUIDFilter := func(ctx kapi.Context, options *kapi.ListOptions) error {
		user, ok := kapi.UserFrom(ctx)
		if !ok {
			return kubeerr.NewBadRequest("User parameter required.")
		}
		uid := user.GetUID()
		if len(uid) == 0 {
			return nil
		}
		if options == nil {
			options = &kapi.ListOptions{}
		}
		if options.FieldSelector == nil {
			options.FieldSelector = fields.OneTermEqualSelector("userUID", uid)
		} else {
			options.FieldSelector, _ = options.FieldSelector.Transform(func(string, string) (string, string, error) {
				return "userUID", uid, nil
			})
		}
		return nil
	}

	// This simulates overriding the KeyFunc
	selfNamer := func(ctx kapi.Context, name string) (string, error) {
		if strings.Contains(name, helpers.UserSpaceSeparator) {
			return "", kubeerr.NewBadRequest("Invalid name: " + name)
		}
		user, ok := kapi.UserFrom(ctx)
		if !ok {
			return "", kubeerr.NewBadRequest("User parameter required.")
		}
		return helpers.MakeClientAuthorizationName(user.GetName(), name), nil
	}

	selfFilterConverter := helpers.NewFilterConverter(
		&selfStore,
		toSelfObject,
		selfObjectUIDFilter,
		toSelfList,
		selfListUIDFilter,
		selfNamer,
	)

	return &REST{*store}, &SelfREST{selfFilterConverter}, nil
}

// Implement rest.Storage
func (s *SelfREST) New() runtime.Object {
	return &api.SelfOAuthClientAuthorization{} // Hack for apiserver.APIInstaller.getResourceKind
}
