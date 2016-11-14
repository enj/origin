package helpers

import (
	"strings"

	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/runtime"

	"github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/util/restoptions"
)

const UserSpaceSeparator = "::"

func GetClientAuthorizationName(userName, clientName string) string {
	return userName + UserSpaceSeparator + clientName
}

func UserNameFromClientAuthorizationName(clientAuthorizationName string) string {
	if !strings.Contains(clientAuthorizationName, UserSpaceSeparator) {
		return ""
	}
	return strings.SplitN(clientAuthorizationName, UserSpaceSeparator, 2)[0]
}

func GetResourceAndPrefix(optsGetter restoptions.Getter, resourceName string) (*unversioned.GroupResource, string, error) {
	resource := api.Resource(resourceName)
	opts, err := optsGetter.GetRESTOptions(resource)
	if err != nil {
		return nil, "", err
	}
	return &resource, "/" + opts.ResourcePrefix, nil
}

func ObjectToOAuthClientAuthorization(obj runtime.Object) *api.OAuthClientAuthorization {
	if auth, ok := SafeObjectToOAuthClientAuthorization(obj); ok {
		return auth
	}
	panic("not an OAuthClientAuthorization")
}

func SafeObjectToOAuthClientAuthorization(obj runtime.Object) (*api.OAuthClientAuthorization, bool) {
	switch auth := obj.(type) {
	case *api.OAuthClientAuthorization:
		return auth, true
	case *api.SelfOAuthClientAuthorization:
		return (*api.OAuthClientAuthorization)(auth), true
	default:
		return nil, false
	}
}
