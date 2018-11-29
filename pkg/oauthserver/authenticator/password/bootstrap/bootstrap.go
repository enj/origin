package bootstrap

import (
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/openshift/origin/pkg/cmd/server/apis/config"
)

func New(getter v1.SecretsGetter) authenticator.Password {
	return &bootstrapPassword{
		secrets: getter.Secrets(metav1.NamespaceSystem),
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

	secret, err := b.secrets.Get(config.BootstrapUserBasicAuth, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	hashedPassword := secret.Data[config.BootstrapUserBasicAuth]
	if len(hashedPassword) == 0 {
		return nil, false, nil
	}

	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, false, nil
		}
		return nil, false, err
	}

	uid, err := SecretToUID(secret)
	if err != nil {
		return nil, false, err
	}

	// do not set other fields, see identitymapper.userToInfo func
	return &user.DefaultInfo{
		Name: config.BootstrapUser,
		UID:  uid,
	}, true, nil
}

func SecretToUID(secret *corev1.Secret) (string, error) {
	hashedPassword := secret.Data[config.BootstrapUserBasicAuth]
	exactSecret := string(secret.UID) + secret.ResourceVersion
	both := append([]byte(exactSecret), hashedPassword...)
	uid, err := bcrypt.GenerateFromPassword(both, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(uid), nil
}
