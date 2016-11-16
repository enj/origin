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

func GetClientAuthorizationName(userName, userUID, clientName string) string {
	return getUserHash(userName, userUID) + UserSpaceSeparator + getHash(clientName)
}

func UserHashFromClientAuthorizationName(clientAuthorizationName string) string {
	data := strings.Split(clientAuthorizationName, UserSpaceSeparator)
	if len(data) != 2 {
		return ""
	}
	return data[0]
}

func UserHashFromContext(ctx kapi.Context) string {
	user, ok := kapi.UserFrom(ctx)
	if !ok {
		return ""
	}
	return getUserHash(user.GetName(), user.GetUID())
}

func getHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func getUserHash(userName, userUID string) string {
	return getHash(userName + "/" + userUID)
}

func GetPrefixWithHash(prefix, hash string) string {
	return prefix + "/" + hash
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
