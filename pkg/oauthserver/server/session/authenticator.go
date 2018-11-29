package session

import (
	"net/http"
	"time"

	"github.com/openshift/origin/pkg/cmd/server/apis/config"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	userNameKey = "user.name"
	userUIDKey  = "user.uid"

	// expKey is stored as an int64 unix time
	expKey = "exp"
)

type Authenticator struct {
	store  Store
	maxAge time.Duration
}

func NewAuthenticator(store Store, maxAge time.Duration) *Authenticator {
	return &Authenticator{
		store:  store,
		maxAge: maxAge,
	}
}

func (a *Authenticator) AuthenticateRequest(req *http.Request) (user.Info, bool, error) {
	values := a.store.Get(req)

	expires, ok := values.GetInt64(expKey)
	if !ok {
		return nil, false, nil
	}

	if expires < time.Now().Unix() {
		return nil, false, nil
	}

	name, ok := values.GetString(userNameKey)
	if !ok {
		return nil, false, nil
	}

	uid, ok := values.GetString(userUIDKey)
	if !ok {
		return nil, false, nil
	}

	return &user.DefaultInfo{
		Name: name,
		UID:  uid,
	}, true, nil
}

func (a *Authenticator) AuthenticationSucceeded(user user.Info, state string, w http.ResponseWriter, req *http.Request) (bool, error) {
	return false, a.put(w, user.GetName(), user.GetUID(), time.Now().Add(a.getMaxAge(user)).Unix())
}

func (a *Authenticator) getMaxAge(user user.Info) time.Duration {
	// since osin is the IDP for this user, we increase the length
	// of the session to allow for transitions between components
	if user.GetName() == config.BootstrapUser {
		// this means the user could stay authenticated for one hour + OAuth access token lifetime
		return time.Hour
	}

	return a.maxAge
}

func (a *Authenticator) InvalidateAuthentication(w http.ResponseWriter, user user.Info) error {
	// the IDP is responsible for maintaining the user's session
	// since osin is the IDP for this user, we do not invalidate its session
	if user.GetName() == config.BootstrapUser {
		return nil
	}

	// zero out all fields
	return a.put(w, "", "", 0)
}

func (a *Authenticator) put(w http.ResponseWriter, name, uid string, expires int64) error {
	values := Values{}

	values[userNameKey] = name
	values[userUIDKey] = uid

	values[expKey] = expires

	return a.store.Put(w, values)
}
