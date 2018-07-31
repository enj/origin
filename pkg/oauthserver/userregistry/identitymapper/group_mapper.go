package identitymapper

import (
	"crypto/sha256"
	"encoding/hex"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	hashutil "k8s.io/kubernetes/pkg/util/hash"

	"github.com/openshift/api/user/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	authapi "github.com/openshift/origin/pkg/oauthserver/api"
)

type groupsMapper struct {
	delegate authapi.UserIdentityMapper
	// TODO add identity metadata API client
	hack userclient.UserInterface
}

func (p *groupsMapper) UserFor(identityInfo authapi.UserIdentityInfo) (kuser.Info, error) {
	user, err := p.delegate.UserFor(identityInfo)
	if err != nil {
		return nil, err
	}
	// if there are no groups we do not need to waste resources on identity metadata objects
	// this does mean that flows that use the cookie session must always store the user and UID
	// in the cookie as they cannot rely on there always being an identity metadata object
	groups := identityInfo.GetProviderGroups()
	if len(groups) == 0 {
		return user, nil
	}
	// TODO use identity metadata API client to store groups, needs to handle conflicts/already exists like provision.go
	identityMetadataName := hash(groups)
	_, err = p.hack.Create(&v1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:        identityMetadataName,
			Annotations: mapH(groups),
		},
	})
	runtime.HandleError(err)
	return authapi.NewDefaultUserIdentityMetadata(user, identityMetadataName), nil
}

func hash(groups []string) string {
	groups = sets.NewString(groups...).List()
	hasher := sha256.New()
	hashutil.DeepHashObject(hasher, groups)
	return hex.EncodeToString(hasher.Sum(nil))
}

func mapH(groups []string) map[string]string {
	out := map[string]string{}
	for _, group := range groups {
		out[group] = ""
	}
	return out
}
