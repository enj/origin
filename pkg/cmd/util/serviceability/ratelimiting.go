package serviceability

import (
	"sync"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"
	"github.com/golang/groupcache/lru"
)

const cacheSize = 1000

type rateLimitedErrorHandler struct {
	handlers []func(error)
	cache    *lru.Cache
	mutex    sync.Mutex
}

func (r *rateLimitedErrorHandler) handle(err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	key := errKey{caller: utilruntime.GetCaller(), errorMessage: err.Error()}
	// only call r.handlers if this key is not in the cache
	if _, ok := r.cache.Get(key); !ok {
		r.cache.Add(key, err)
		for _, fn := range r.handlers {
			fn(err)
		}
	}
}

type errKey struct {
	caller, errorMessage string
}

func BehaviorOnPanicWithRateLimitedErrors(mode string) func() {
	// globally unset all default error handlers, they are useless to us
	utilruntime.ErrorHandlers = nil
	// let BehaviorOnPanic set its own utilruntime.ErrorHandlers if it wants to
	fn := BehaviorOnPanic(mode)
	// save a copy
	origErrorHandlers := utilruntime.ErrorHandlers
	// override with our rate limited error handler that throttles calls to origErrorHandlers
	utilruntime.ErrorHandlers = []func(error){newRateLimitedErrorHandler(origErrorHandlers)}
	// return BehaviorOnPanic defer func so we can be used to replace it easily
	return fn
}

func newRateLimitedErrorHandler(funcs []func(error)) func(error) {
	// create a slice with our error logger and the given funcs
	handlers := append([]func(error){logError}, funcs...)
	// wrap the slice with our rate limiter
	errorHandler := &rateLimitedErrorHandler{handlers: handlers, cache: lru.New(cacheSize)}
	return errorHandler.handle
}

func logError(err error) {
	glog.ErrorDepth(3, err)
}
