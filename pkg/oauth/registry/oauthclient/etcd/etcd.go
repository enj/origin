package etcd

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"

	oauthapi "github.com/openshift/origin/pkg/oauth/apis/oauth"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclient"
	"github.com/openshift/origin/pkg/util/restoptions"
)

// rest implements a RESTStorage for oauth clients against etcd
type REST struct {
	*registry.Store
	saGetter oauthclient.Getter
}

var _ rest.StandardStorage = &REST{}

// NewREST returns a RESTStorage object that will work against oauth clients
func NewREST(optsGetter restoptions.Getter, saGetter oauthclient.Getter) (*REST, error) {
	store := &registry.Store{
		NewFunc:                  func() runtime.Object { return &oauthapi.OAuthClient{} },
		NewListFunc:              func() runtime.Object { return &oauthapi.OAuthClientList{} },
		DefaultQualifiedResource: oauthapi.Resource("oauthclients"),

		CreateStrategy: oauthclient.Strategy,
		UpdateStrategy: oauthclient.Strategy,
		DeleteStrategy: oauthclient.Strategy,
	}

	options := &generic.StoreOptions{RESTOptions: optsGetter}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, err
	}

	return &REST{store, saGetter}, nil
}

func (r *REST) Get(ctx request.Context, name string, options *v1.GetOptions) (runtime.Object, error) {
	if _, _, err := serviceaccount.SplitUsername(name); err != nil {
		return r.Store.Get(ctx, name, options)
	}
	saOAuthClient, err := r.saGetter.Get(name, v1.GetOptions{})
	if err != nil {
		return nil, err // TODO: do we need to mask this error?
	}
	// copy the client and strip secrets
	// TODO maybe perform a SAR to make this stripping conditional?
	saOAuthClient = saOAuthClient.DeepCopy()
	saOAuthClient.Secret = ""
	saOAuthClient.AdditionalSecrets = nil
	return saOAuthClient, nil
}
