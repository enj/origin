package oauthserver

import (
	"net/http"

	"github.com/golang/glog"

	"github.com/openshift/origin/pkg/oauthserver/server/headers"
)

type Mux interface {
	http.Handler

	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

type Endpoints interface {
	// Install registers one or more http.Handlers into the given mux.
	// It is expected that the provided prefix will serve all operations.
	// prefix MUST NOT end in a slash.
	Install(mux Mux, prefix string)
}

func NewMuxWithStandardHeaders() Mux {
	return &muxWrapper{
		mux: http.NewServeMux(),
		wrapper: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headers.SetStandardHeaders(w)

			tlsServerName := "<no_tls>"
			if r.TLS != nil {
				tlsServerName = r.TLS.ServerName
				if len(tlsServerName) == 0 {
					tlsServerName = "<empty_name>"
				}
			}

			glog.Infof("%s FROM %s TO %s %s%s LEN %d TLS_NAME %s",
				r.Proto, r.RemoteAddr, r.Method, r.Host, r.URL.String(), r.ContentLength, tlsServerName)
			glog.Infof("Request Headers:")
			for key, values := range r.Header {
				for _, value := range values {
					glog.Infof("    %s: %s", key, value)
				}
			}

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
