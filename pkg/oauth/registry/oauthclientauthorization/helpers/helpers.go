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

func GetClientAuthorizationName(userUID, clientName string) string {
	return getHash(userUID) + UserSpaceSeparator + getHash(clientName)
}

func UserUIDHashFromClientAuthorizationName(clientAuthorizationName string) string {
	// Check for the regex equivalent to `.+::.+` if `::` is the separator
	firstUserSpaceSeperatorIdx := strings.Index(clientAuthorizationName, UserSpaceSeparator)
	if firstUserSpaceSeperatorIdx <= 0 || firstUserSpaceSeperatorIdx >= len(clientAuthorizationName)-len(UserSpaceSeparator) {
		return ""
	}
	return clientAuthorizationName[:firstUserSpaceSeperatorIdx]
}

func UserUIDHashFromContext(ctx kapi.Context) string {
	user, ok := kapi.UserFrom(ctx)
	if !ok {
		return ""
	}
	return getHash(user.GetUID())
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
