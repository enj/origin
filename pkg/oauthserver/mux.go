package oauthserver

import (
	"net/http"

	"github.com/openshift/origin/pkg/oauthserver/server/headers"
)

type Mux interface {
	http.Handler

	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

func NewMuxWithStandardHeaders() Mux {
	return &muxWrapper{
		mux: http.NewServeMux(),
		wrapper: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			headers.SetStandardHeaders(w)
		}),
	}
}

type muxWrapper struct {
	mux     Mux
	wrapper http.Handler
}

func (m *muxWrapper) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.mux.ServeHTTP(w, req)
}

func (m *muxWrapper) Handle(pattern string, handler http.Handler) {
	m.mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		m.wrapper.ServeHTTP(w, req)
		handler.ServeHTTP(w, req)
	}))
}

func (m *muxWrapper) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(handler))
}
