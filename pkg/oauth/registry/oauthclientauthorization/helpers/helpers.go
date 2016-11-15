package helpers

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/runtime"

	"github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/util/restoptions"
)

const UserSpaceSeparator = "::"

func GetClientAuthorizationName(userName, clientName string) string {
	return getHash(userName) + UserSpaceSeparator + getHash(clientName)
}

func UserNameHashFromClientAuthorizationName(clientAuthorizationName string) string {
	if !strings.Contains(clientAuthorizationName, UserSpaceSeparator) {
		return ""
	}
	return strings.SplitN(clientAuthorizationName, UserSpaceSeparator, 2)[0]
}

func UserNameHashFromContext(ctx kapi.Context) string {
	user, ok := kapi.UserFrom(ctx)
	if !ok {
		return ""
	}
	return getHash(user.GetName())
}

func getHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash[:])
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
