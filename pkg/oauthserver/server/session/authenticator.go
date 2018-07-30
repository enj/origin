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
	values := a.store.Get(req)

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

	u := &user.DefaultInfo{
		Name: name,
		UID:  uid,
	}

	// check if we reference an identity metadata object
	identityMetadataName, ok, err := values.GetString(identityMetadataNameKey)
	if err != nil {
		return nil, false, err
	}

	// just use the name and uid when we do not reference an identity metadata object
	if !ok {
		return u, true, nil
	}

	// use the identity metadata object that we reference
	return authapi.NewDefaultUserIdentityMetadata(u, identityMetadataName), true, nil
}

func (a *Authenticator) AuthenticationSucceeded(user user.Info, state string, w http.ResponseWriter, req *http.Request) (bool, error) {
	// assume no identity metadata by default
	identityMetadata := ""
	// check if we have optional identity metadata (for storing a reference to group information)
	if userIdentityMetadata, ok := user.(authapi.UserIdentityMetadata); ok {
		identityMetadata = userIdentityMetadata.GetIdentityMetadataName()
	}

	return false, a.put(w, user.GetName(), user.GetUID(), identityMetadata, time.Now().Add(a.maxAge).Unix())
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
