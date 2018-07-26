package session

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"

	authapi "github.com/openshift/origin/pkg/oauthserver/api"
)

const (
	// TODO drop the the two user key fields in a later release
	// once we no longer need to worry about mixed master scenarios
	UserNameKey = "user.name"
	UserUIDKey  = "user.uid"

	ExpiresKey = "expires"

	IdentityMetadataNameKey = "identity.metadata.name"
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

	expiresObj, ok := values[ExpiresKey]
	if !ok {
		return nil, false, nil
	}
	expiresString, ok := expiresObj.(string)
	if !ok {
		return nil, false, errors.New("expires on session is not a string")
	}
	if len(expiresString) == 0 {
		return nil, false, nil
	}
	expires, err := strconv.ParseInt(expiresString, 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("error parsing expires timestamp: %v", err)
	}
	if expires < time.Now().Unix() {
		return nil, false, nil
	}

	// if we reference an identity metadata object, use it as the
	// source of truth and ignore the remaining fields of the cookie
	if identityMetadataNameObj, ok := values[IdentityMetadataNameKey]; ok {
		identityMetadataName, ok := identityMetadataNameObj.(string)
		if !ok {
			return nil, false, errors.New("identity.metadata.name on session is not a string")
		}
		if len(identityMetadataName) == 0 {
			return nil, false, nil
		}
		// TODO use client to get identity metadata to fill this object
		user := &user.DefaultInfo{
			Name: "name", // TODO fix
			UID:  "uid",  // TODO fix
		}
		return authapi.NewDefaultUserIdentityMetadata(user, identityMetadataName), true, nil
	}

	nameObj, ok := values[UserNameKey]
	if !ok {
		return nil, false, nil
	}
	name, ok := nameObj.(string)
	if !ok {
		return nil, false, errors.New("user.name on session is not a string")
	}
	if len(name) == 0 {
		return nil, false, nil
	}

	uidObj, ok := values[UserUIDKey]
	if !ok {
		return nil, false, nil
	}
	uid, ok := uidObj.(string)
	if !ok {
		return nil, false, errors.New("user.uid on session is not a string")
	}
	// Tolerate empty string UIDs in the session

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
	values[UserNameKey] = user.GetName()
	values[UserUIDKey] = user.GetUID()
	values[ExpiresKey] = strconv.FormatInt(time.Now().Add(time.Duration(a.maxAge)*time.Second).Unix(), 10)

	// TODO when the user keys are dropped, this interface check will become required
	if userIdentityMetadata, ok := user.(authapi.UserIdentityMetadata); ok {
		values[IdentityMetadataNameKey] = userIdentityMetadata.GetIdentityMetadataName()
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
