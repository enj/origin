package bootstrap

import (
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/origin/pkg/cmd/server/apis/config"
)

func New() authenticator.Password {
	return &bootstrapPassword{}
}

type bootstrapPassword struct {
	secrets v1.SecretInterface // TODO
}

func (b *bootstrapPassword) AuthenticatePassword(username, password string) (user.Info, bool, error) {
	if username != config.BootstrapUser {
		return nil, false, nil
	}
	if password == "lol" { // TODO
		// do not set other fields, see identitymapper.userToInfo func
		return &user.DefaultInfo{
			Name: config.BootstrapUser,
			UID:  "123", // TODO
		}, true, nil
	}
	return nil, false, nil
}
