package internalversion

import (
	"fmt"
	"runtime"
	"strings"
)

var replacer = strings.NewReplacer("/home/mkhan/aos/origin/src/github.com/openshift/origin/_output/local/go/src/github.com/openshift/origin/", "")

func PrintCallers() string {
	stack := make([]uintptr, 1024)
	total := runtime.Callers(2, stack)
	stack = stack[:total]
	frames := runtime.CallersFrames(stack)
	data := make([]string, 0, total)
	for frame, more := frames.Next(); more; frame, more = frames.Next() {
		data = append(data, fmt.Sprintf("%s:%d#%s", replacer.Replace(frame.File), frame.Line, frame.Function))
	}
	return strings.Join(data, " -> ")
}
