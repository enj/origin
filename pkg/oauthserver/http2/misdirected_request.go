package http2

import (
	"net/http"

	"github.com/golang/glog"
)

const (
	// Explicitly limit to a single concurrent open stream per client in
	// an attempt to reduce the chance that we get misdirected requests.
	MaxStreamsPerConnection = 1

	// TODO replace with Go std lib constant when we upgrade
	statusMisdirectedRequest = 421 // RFC 7540, 9.1.2
)

func WithMisdirectedRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMisdirectedRequest(r) {
			// log only the safe metadata for this misdirected request
			glog.Infof("misdirected request detected from %s to %s %s %d instead of %s",
				r.RemoteAddr, r.Method, r.Host, r.ContentLength, r.TLS.ServerName)
			w.WriteHeader(statusMisdirectedRequest)
			_, _ = w.Write([]byte("misdirected request"))
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func isMisdirectedRequest(r *http.Request) bool {
	if r.ProtoMajor != 2 {
		return false
	}

	host := r.Host
	if len(host) == 0 {
		return false
	}

	tls := r.TLS
	if tls == nil {
		return false
	}

	serverName := tls.ServerName
	if len(serverName) == 0 {
		return false
	}

	return host != serverName
}
