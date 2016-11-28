package etcd

import (
	"k8s.io/kubernetes/pkg/runtime"

	"github.com/openshift/origin/pkg/oauth/api"
)

func objectToSelfOAuthClientAuthorization(obj runtime.Object) *api.SelfOAuthClientAuthorization {
	if auth, ok := safeObjectToSelfOAuthClientAuthorization(obj); ok {
		return auth
	}
	panic("not a SelfOAuthClientAuthorization")
}

func safeObjectToSelfOAuthClientAuthorization(obj runtime.Object) (*api.SelfOAuthClientAuthorization, bool) {
	switch auth := obj.(type) {
	case *api.SelfOAuthClientAuthorization:
		return auth, true
	case *api.OAuthClientAuthorization:
		return (*api.SelfOAuthClientAuthorization)(auth), true
	default:
		return nil, false
	}
}

func toSelfObject(obj runtime.Object) runtime.Object {
	return (*api.SelfOAuthClientAuthorization)(obj.(*api.OAuthClientAuthorization))
}

func toSelfList(obj runtime.Object) runtime.Object {
	list := obj.(*api.OAuthClientAuthorizationList)
	newlist := &api.SelfOAuthClientAuthorizationList{Items: make([]api.SelfOAuthClientAuthorization, len(list.Items))}
	newlist.ResourceVersion = list.ResourceVersion
	for _, item := range list.Items {
		newlist.Items = append(newlist.Items, api.SelfOAuthClientAuthorization(item))
	}
	return newlist
}
