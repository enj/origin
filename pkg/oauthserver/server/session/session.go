package session

import (
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type store struct {
	// name of the cookie used for session data
	name string
	// do not use store's Get method, it mucks with global state for caching purposes
	// decoding a single small cookie multiple times is not the end of the world
	// currently we do not have any single request paths that decode the cookie multiple times
	store sessions.Store
}

func NewStore(name string, secure bool, secrets ...[]byte) Store {
	cookie := sessions.NewCookieStore(secrets...)
	cookie.Options.MaxAge = 0 // we encode expiration information into the cookie data to avoid browser bugs
	cookie.Options.HttpOnly = true
	cookie.Options.Secure = secure
	return &store{name: name, store: cookie}
}

func (s *store) Get(r *http.Request) (Values, error) {
	// always use New to avoid global state
	session, err := s.store.New(r, s.name)
	// ignore cookie decoding errors (this could occur from poorly handling key rotation)
	if err != nil && err.Error() != securecookie.ErrMacInvalid.Error() {
		return nil, err
	}
	// session and Values are guaranteed to never be nil per the interface and underlying code
	return session.Values, nil
}

func (s *store) Put(w http.ResponseWriter, v Values) error {
	// build a session from an empty request to avoid any decoding overhead
	// always use New to avoid global state
	r := &http.Request{}
	session, err := s.store.New(r, s.name)
	if err != nil {
		return err
	}

	// override the values for the session
	session.Values = v

	// write the encoded cookie, the request parameter is ignored
	return s.store.Save(r, w, session)
}
