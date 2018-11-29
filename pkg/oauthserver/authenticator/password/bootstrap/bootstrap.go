package bootstrap

import (
	"crypto/sha512"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/origin/pkg/cmd/server/apis/config"
)

func New(secrets v1.SecretInterface) authenticator.Password {
	return &bootstrapPassword{
		secrets: secrets,
		names:   sets.NewString(config.BootstrapUser, config.BootstrapUserBasicAuth),
	}
}

type bootstrapPassword struct {
	secrets v1.SecretInterface
	names   sets.String
}

func (b *bootstrapPassword) AuthenticatePassword(username, password string) (user.Info, bool, error) {
	if !b.names.Has(username) {
		return nil, false, nil
	}

	hashedPassword, uid, ok, err := HashAndUID(b.secrets)
	if err != nil || !ok {
		return nil, ok, err
	}

	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, false, nil
		}
		return nil, false, err
	}

	// do not set other fields, see identitymapper.userToInfo func
	return &user.DefaultInfo{
		Name: config.BootstrapUser,
		UID:  uid,
	}, true, nil
}

func HashAndUID(secrets v1.SecretInterface) ([]byte, string, bool, error) {
	secret, err := secrets.Get(config.BootstrapUserBasicAuth, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}

	hashedPassword := secret.Data[config.BootstrapUserBasicAuth]
	if len(hashedPassword) == 0 {
		return nil, "", false, nil
	}

	exactSecret := string(secret.UID) + secret.ResourceVersion
	both := append([]byte(exactSecret), hashedPassword...)

	uidBytes := sha512.Sum512(both)

	return hashedPassword, base64.RawURLEncoding.EncodeToString(uidBytes[:]), true, nil
}
