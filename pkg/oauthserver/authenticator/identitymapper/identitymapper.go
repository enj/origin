package identitymapper

import (
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/golang/glog"

	"github.com/openshift/origin/pkg/oauthserver/api"
)

// UserFor bridges the UserIdentityMapper interface with the authenticator.{Password|Request} interfaces
func UserFor(mapper api.UserIdentityMapper, identity api.UserIdentityInfo) (user.Info, bool, error) {
	user, err := mapper.UserFor(identity)
	if err != nil {
		glog.V(4).Infof("Error creating or updating mapping for: %#v due to %v", identity, err)
		return nil, false, err
	}
	glog.V(4).Infof("Got userIdentityMapping: %#v", user)

	return user, true, nil
}
