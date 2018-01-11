package serviceability

import (
	"runtime/debug"
	"strings"
	"sync"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"
	"github.com/golang/groupcache/lru"
)

const (
	cacheSize = 1000
	// logError in utilruntime has a dept of 2, which does not work with our extra indirection
	// we add 1 for rateLimitedErrorHandler.handleErr
	// and we add 1 more for its pointer that is stored in utilruntime.ErrorHandlers
	depth = 4
)

type rateLimitedErrorHandler struct {
	handlers []func(error)
	cache    *lru.Cache
	mutex    sync.Mutex
}

func (r *rateLimitedErrorHandler) handleErr(err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	stack := strings.Join(strings.Split(string(debug.Stack()), "\n")[depth*2:], "\n")
	key := errKey{stack: stack, errorMessage: err.Error()}
	// only call r.handlers if this key is not in the cache
	if _, ok := r.cache.Get(key); !ok {
		r.cache.Add(key, err)
		for _, fn := range r.handlers {
			fn(err)
		}
	}
}

type errKey struct {
	stack, errorMessage string
}

func BehaviorOnPanicWithRateLimitedErrors(mode string) func() {
	// globally unset all default error handlers, they are useless to us
	utilruntime.ErrorHandlers = nil
	// let BehaviorOnPanic set its own utilruntime.ErrorHandlers if it wants to
	fn := BehaviorOnPanic(mode)
	// save a copy
	origErrorHandlers := utilruntime.ErrorHandlers
	// override with our rate limited error handler that throttles calls to origErrorHandlers
	utilruntime.ErrorHandlers = []func(error){newRateLimitedErrorHandler(origErrorHandlers).handleErr}
	// return BehaviorOnPanic defer func so we can be used to replace it easily
	return fn
}

func newRateLimitedErrorHandler(funcs []func(error)) *rateLimitedErrorHandler {
	// create a slice with our error logger and the given funcs
	handlers := append([]func(error){logError}, funcs...)
	// wrap the slice with our rate limiter
	return &rateLimitedErrorHandler{handlers: handlers, cache: lru.New(cacheSize)}
}

func logError(err error) {
	glog.ErrorDepth(depth, err)
}
