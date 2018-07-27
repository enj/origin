package session

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"

	authapi "github.com/openshift/origin/pkg/oauthserver/api"
)

const (
	UserNameKey = "user.name"
	UserUIDKey  = "user.uid"

	ExpiresKey = "expires"

	IdentityMetadataNameKey = "identity.metadata.name" // TODO maybe use a smaller name to make cookie smaller?
)

type Authenticator struct {
	store  Store
	name   string
	maxAge int
}

func NewAuthenticator(store Store, name string, maxAge int) *Authenticator {
	return &Authenticator{
		store:  store,
		name:   name,
		maxAge: maxAge,
	}
}

func (a *Authenticator) AuthenticateRequest(req *http.Request) (user.Info, bool, error) {
	session, err := a.store.Get(req, a.name)
	if err != nil {
		return nil, false, err
	}

	values := session.Values()

	expiresString, ok, err := getString(ExpiresKey, values)
	if !ok || err != nil {
		return nil, false, err
	}
	expires, err := strconv.ParseInt(expiresString, 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("error parsing expires timestamp: %v", err)
	}
	if expires < time.Now().Unix() {
		return nil, false, nil
	}

	// check if we reference an identity metadata object
	identityMetadataName, ok, err := getString(IdentityMetadataNameKey, values)
	if err != nil {
		return nil, false, err
	}

	// if we reference an identity metadata object, use it as the
	// source of truth and ignore the remaining fields of the cookie
	if ok {
		// TODO use client to get identity metadata to fill this object
		user := &user.DefaultInfo{
			Name: "name", // TODO fix
			UID:  "uid",  // TODO fix
		}
		return authapi.NewDefaultUserIdentityMetadata(user, identityMetadataName), true, nil
	}

	// otherwise fallback to name and UID
	name, ok, err := getString(UserNameKey, values)
	if !ok || err != nil {
		return nil, false, err
	}

	uid, _, err := getString(UserUIDKey, values)
	// Ignore ok to tolerate empty string UIDs in the session
	// TODO in what valid flow is UID empty?
	if err != nil {
		return nil, false, err
	}

	return &user.DefaultInfo{
		Name: name,
		UID:  uid,
	}, true, nil
}

func (a *Authenticator) AuthenticationSucceeded(user user.Info, state string, w http.ResponseWriter, req *http.Request) (bool, error) {
	session, err := a.store.Get(req, a.name)
	if err != nil {
		return false, err
	}

	values := session.Values()

	// we always need to store an expiration time for the cookie
	values[ExpiresKey] = strconv.FormatInt(time.Now().Add(time.Duration(a.maxAge)*time.Second).Unix(), 10)

	// store name and UID to handle the case where we have no identity metadata
	// or when we may have old masters that do not know about identity metadata
	values[UserNameKey] = user.GetName()
	values[UserUIDKey] = user.GetUID()

	// check if we need have optional identity metadata (for storing a reference to group information)
	if userIdentityMetadata, ok := user.(authapi.UserIdentityMetadata); ok {
		values[IdentityMetadataNameKey] = userIdentityMetadata.GetIdentityMetadataName()
		// TODO maybe do this once we no longer have mixed master scenarios to worry about
		// unset name and UID since identity metadata is authoritative
		// values[UserNameKey] = ""
		// values[UserUIDKey] = ""
	}

	return false, a.store.Save(w, req)
}

func (a *Authenticator) InvalidateAuthentication(w http.ResponseWriter, req *http.Request) error {
	session, err := a.store.Get(req, a.name)
	if err != nil {
		return err
	}

	values := session.Values()
	values[UserNameKey] = ""
	values[UserUIDKey] = ""
	values[ExpiresKey] = ""
	values[IdentityMetadataNameKey] = ""

	return a.store.Save(w, req)
}

func getString(key string, values map[interface{}]interface{}) (string, bool, error) {
	obj, ok := values[key]
	if !ok {
		return "", false, nil
	}
	str, ok := obj.(string)
	if !ok {
		return "", false, fmt.Errorf("%s on session is not a string", key)
	}
	return str, len(str) != 0, nil
}
