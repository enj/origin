package session

import (
	"errors"
	"net/http"

	"github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type store struct {
	store sessions.Store
	name  string
}

func NewStore(secure bool, name string, secrets ...string) Store {
	values := make([][]byte, 0, len(secrets))
	for _, secret := range secrets {
		values = append(values, []byte(secret))
	}
	cookie := sessions.NewCookieStore(values...)
	cookie.Options.MaxAge = 0
	cookie.Options.HttpOnly = true
	cookie.Options.Secure = secure
	return &store{store: cookie, name: name}
}

func (s *store) Get(req *http.Request) (Values, error) {
	session, err := s.store.Get(req, s.name)
	if err != nil && err.Error() != securecookie.ErrMacInvalid.Error() {
		return nil, err
	}
	if session == nil || session.Values == nil {
		return nil, errors.New("unable to get cookie session")
	}
	return session.Values, nil
}

func (s *store) Save(w http.ResponseWriter, req *http.Request) error {
	return sessions.Save(req, w)
}

func (s *store) Clear(req *http.Request) {
	context.Clear(req)
}
