package server

import (
	"net/http"
	"time"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/time/rate"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog"
)

var (
	config = spew.ConfigState{Indent: "\t", MaxDepth: 5, DisableMethods: true}
	rl     = rate.NewLimiter(rate.Every(time.Second), 10)
)

func withContextLog(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)

		if !rl.Allow() {
			return
		}

		ctx := r.Context()

		info, _ := request.RequestInfoFrom(ctx)
		auds, _ := authenticator.AudiencesFrom(ctx)
		user, _ := request.UserFrom(ctx)
		ae := request.AuditEventFrom(ctx)

		klog.Errorf("ENJ:\n%s", config.Sdump(info, auds, user, ae))
	})
}
