package session

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	UserNameKey = "user.name"
	UserUIDKey  = "user.uid"

	ExpiresKey = "expires"
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

	expiresString, ok, err := values.Get(ExpiresKey)
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

	name, ok, err := values.Get(UserNameKey)
	if !ok || err != nil {
		return nil, false, err
	}

	uid, _, err := values.Get(UserUIDKey)
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
	values, err := a.store.Get(req)
	if err != nil {
		return false, err
	}

	values[UserNameKey] = user.GetName()
	values[UserUIDKey] = user.GetUID()
	values[ExpiresKey] = strconv.FormatInt(time.Now().Add(a.maxAge).Unix(), 10)

	// TODO: should we save groups, scope, and extra in the session as well?
	return false, a.store.Save(w, req)
}

func (a *Authenticator) InvalidateAuthentication(w http.ResponseWriter, req *http.Request) error {
	values, err := a.store.Get(req)
	if err != nil {
		return err
	}

	values[UserNameKey] = ""
	values[UserUIDKey] = ""
	values[ExpiresKey] = ""

	return a.store.Save(w, req)
}

func (a *Authenticator) Clear(req *http.Request) {
	a.store.Clear(req)
}
