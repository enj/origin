package etcd

import (
	"errors"
	"fmt"

	kapi "k8s.io/kubernetes/pkg/api"
	kubeerr "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/registry/generic/registry"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/storage"

	"github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/oauth/registry/helpers"
	"github.com/openshift/origin/pkg/util/restoptions"
)

// rest implements a RESTStorage for self oauth client authorizations against etcd
type REST struct {
	helpers.UIDEnforcer
}

// NewREST returns a RESTStorage object that will work against self oauth client authorizations
func NewREST(optsGetter restoptions.Getter) (*REST, error) {
	resource, prefix, err := helpers.GetResourceAndPrefix(optsGetter, "selfoauthclientauthorizations")
	if err != nil {
		return nil, fmt.Errorf("error building RESTOptions for %s store: %v", resource.String(), err)
	}

	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &api.SelfOAuthClientAuthorization{} },
		NewListFunc: func() runtime.Object { return &api.OAuthClientAuthorizationList{} },
		KeyRootFunc: func(ctx kapi.Context) string {
			user, ok := kapi.UserFrom(ctx)
			if !ok {
				panic("User parameter required.")
			}
			return helpers.GetKeyWithUsername(prefix, user.GetName())
		},
		KeyFunc: func(ctx kapi.Context, name string) (string, error) {
			user, ok := kapi.UserFrom(ctx)
			if !ok {
				return "", kubeerr.NewBadRequest("User parameter required.")
			}
			return registry.NoNamespaceKeyFunc(ctx, helpers.GetKeyWithUsername(prefix, user.GetName()), name)
		},
		PredicateFunc: func(label labels.Selector, field fields.Selector) *generic.SelectionPredicate {
			return &generic.SelectionPredicate{
				Label: label,
				Field: field,
				GetAttrs: func(o runtime.Object) (labels.Set, fields.Set, error) {
					obj, ok := safeObjectToSelfOAuthClientAuthorization(o)
					if !ok { // TODO do I need this check?
						return nil, nil, errors.New("not a SelfOAuthClientAuthorization")
					}
					return labels.Set(obj.Labels), api.SelfOAuthClientAuthorizationToSelectableFields(obj), nil
				},
			}
		},
		QualifiedResource: *resource,
		Decorator: func(obj runtime.Object) error {
			auth := objectToSelfOAuthClientAuthorization(obj)
			auth.UserName = ""
			auth.Name = auth.ClientName
			return nil
		},

		CreateStrategy: helpers.CannotCreateStrategy,
	}

	if err := restoptions.ApplyOptions(optsGetter, store, false, storage.NoTriggerPublisher); err != nil {
		return nil, err
	}

	return &REST{helpers.UIDEnforcer{Store: *store, ObjFn: toSelfObject, ListFn: toSelfList, UserUIDField: "userUID"}}, nil
}
