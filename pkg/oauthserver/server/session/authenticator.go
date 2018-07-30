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
	userNameKey = "user.name"
	userUIDKey  = "user.uid"

	// expKey is stored as an int64 unix time
	expKey = "exp"
	// expiresKey is the string representation of expKey
	// TODO drop in a release when mixed masters are no longer an issue
	expiresKey = "expires"

	identityMetadataNameKey = "identity.metadata.name" // TODO maybe use a smaller name to make cookie smaller?
)

type Authenticator struct {
	store  Store
	maxAge time.Duration
}

func NewAuthenticator(store Store, maxAge int32) *Authenticator {
	return &Authenticator{
		store:  store,
		maxAge: time.Duration(maxAge) * time.Second,
	}
}

func (a *Authenticator) AuthenticateRequest(req *http.Request) (user.Info, bool, error) {
	values, err := a.store.Get(req)
	if err != nil {
		return nil, false, err
	}

	expires, ok, err := values.GetInt64(expKey)
	// TODO in a release when mixed masters are no longer an issue, replace with:
	// if !ok || err != nil {
	if err != nil {
		return nil, false, err
	}

	// TODO drop this logic in a release when mixed masters are no longer an issue
	if !ok {
		expiresString, ok, err := values.GetString(expiresKey)
		if !ok || err != nil {
			return nil, false, err
		}
		expires, err = strconv.ParseInt(expiresString, 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("error parsing expires timestamp: %v", err)
		}
	}

	if expires < time.Now().Unix() {
		return nil, false, nil
	}

	// check if we reference an identity metadata object
	identityMetadataName, ok, err := values.GetString(identityMetadataNameKey)
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
	name, ok, err := values.GetString(userNameKey)
	if !ok || err != nil {
		return nil, false, err
	}

	uid, _, err := values.GetString(userUIDKey)
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
	// we always need to store an expiration time for the cookie
	expires := time.Now().Add(a.maxAge).Unix()

	// store name and UID to handle the case where we have no identity metadata
	// or when we may have old masters that do not know about identity metadata
	name := user.GetName()
	uid := user.GetUID()

	// assume not identity metadata by default
	identityMetadata := ""
	// check if we need have optional identity metadata (for storing a reference to group information)
	if userIdentityMetadata, ok := user.(authapi.UserIdentityMetadata); ok {
		identityMetadata = userIdentityMetadata.GetIdentityMetadataName()
		// TODO maybe do this once we no longer have mixed master scenarios to worry about
		// unset name and UID since identity metadata is authoritative
		// name = ""
		// uid = ""
	}

	return false, a.put(w, name, uid, identityMetadata, expires)
}

func (a *Authenticator) InvalidateAuthentication(w http.ResponseWriter, req *http.Request) error {
	// zero out all fields
	return a.put(w, "", "", "", 0)
}

func (a *Authenticator) put(w http.ResponseWriter, name, uid, identityMetadata string, expires int64) error {
	values := Values{}

	values[userNameKey] = name
	values[userUIDKey] = uid

	values[expKey] = expires

	// TODO drop this logic in a release when mixed masters are no longer an issue
	if expires == 0 {
		values[expiresKey] = ""
	} else {
		values[expiresKey] = strconv.FormatInt(expires, 10)
	}

	values[identityMetadataNameKey] = identityMetadata

	return a.store.Put(w, values)
}
