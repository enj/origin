/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package responsewriters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"strconv"

	"github.com/davecgh/go-spew/spew"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/endpoints/handlers/negotiation"
	"k8s.io/apiserver/pkg/endpoints/metrics"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/util/flushwriter"
	"k8s.io/apiserver/pkg/util/wsstream"
	"k8s.io/klog"
)

// httpResponseWriterWithInit wraps http.ResponseWriter, and implements the io.Writer interface to be used
// with encoding. The purpose is to allow for encoding to a stream, while accommodating a custom HTTP status code
// if encoding fails, and meeting the encoder's io.Writer interface requirement.
type httpResponseWriterWithInit struct {
	hasWritten bool
	mediaType  string
	statusCode int
	innerW     http.ResponseWriter
}

func (w httpResponseWriterWithInit) Write(b []byte) (n int, err error) {
	if !w.hasWritten {
		w.innerW.Header().Set("Content-Type", w.mediaType)
		w.innerW.WriteHeader(w.statusCode)
		w.hasWritten = true
	}

	if w.statusCode == http.StatusUnauthorized || bytes.Contains(b, unauthorizedMsg1) || bytes.Contains(b, unauthorizedMsg2) {
		log(string(b), w)
	}

	return w.innerW.Write(b)
}

// WriteObject renders a returned runtime.Object to the response as a stream or an encoded object. If the object
// returned by the response implements rest.ResourceStreamer that interface will be used to render the
// response. The Accept header and current API version will be passed in, and the output will be copied
// directly to the response body. If content type is returned it is used, otherwise the content type will
// be "application/octet-stream". All other objects are sent to standard JSON serialization.
func WriteObject(statusCode int, gv schema.GroupVersion, s runtime.NegotiatedSerializer, object runtime.Object, w http.ResponseWriter, req *http.Request) {
	stream, ok := object.(rest.ResourceStreamer)
	if ok {
		requestInfo, _ := request.RequestInfoFrom(req.Context())
		metrics.RecordLongRunning(req, requestInfo, func() {
			StreamObject(statusCode, gv, s, stream, w, req)
		})
		return
	}
	WriteObjectNegotiated(s, gv, w, req, statusCode, object)
}

// StreamObject performs input stream negotiation from a ResourceStreamer and writes that to the response.
// If the client requests a websocket upgrade, negotiate for a websocket reader protocol (because many
// browser clients cannot easily handle binary streaming protocols).
func StreamObject(statusCode int, gv schema.GroupVersion, s runtime.NegotiatedSerializer, stream rest.ResourceStreamer, w http.ResponseWriter, req *http.Request) {
	out, flush, contentType, err := stream.InputStream(req.Context(), gv.String(), req.Header.Get("Accept"))
	if err != nil {
		ErrorNegotiated(err, s, gv, w, req)
		return
	}
	if out == nil {
		// No output provided - return StatusNoContent
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer out.Close()

	buf := &bytes.Buffer{}
	defer func() {
		if statusCode == http.StatusUnauthorized || bytes.Contains(buf.Bytes(), unauthorizedMsg1) || bytes.Contains(buf.Bytes(), unauthorizedMsg2) {
			log(gv, w, req, string(buf.Bytes()))
		}
	}()

	if wsstream.IsWebSocketRequest(req) {
		r := wsstream.NewReader(out, true, wsstream.NewDefaultReaderProtocols())
		if err := r.Copy(w, req); err != nil {
			utilruntime.HandleError(fmt.Errorf("error encountered while streaming results via websocket: %v", err))
		}
		return
	}

	if len(contentType) == 0 {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(statusCode)
	writer := w.(io.Writer)

	if flush {
		writer = flushwriter.Wrap(w)
	} else {
		writer = io.MultiWriter(writer, buf)
	}
	io.Copy(writer, out)
}

// SerializeObject renders an object in the content type negotiated by the client using the provided encoder.
// The context is optional and can be nil.
func SerializeObject(mediaType string, encoder runtime.Encoder, innerW http.ResponseWriter, req *http.Request, statusCode int, object runtime.Object) {
	w := httpResponseWriterWithInit{mediaType: mediaType, innerW: innerW, statusCode: statusCode}

	if err := encoder.Encode(object, w); err != nil {
		errSerializationFatal(err, encoder, w)
	}
}

// WriteObjectNegotiated renders an object in the content type negotiated by the client.
// The context is optional and can be nil.
func WriteObjectNegotiated(s runtime.NegotiatedSerializer, gv schema.GroupVersion, w http.ResponseWriter, req *http.Request, statusCode int, object runtime.Object) {
	serializer, err := negotiation.NegotiateOutputSerializer(req, s)
	if err != nil {
		// if original statusCode was not successful we need to return the original error
		// we cannot hide it behind negotiation problems
		if statusCode < http.StatusOK || statusCode >= http.StatusBadRequest {
			WriteRawJSON(int(statusCode), object, w)
			return
		}
		status := ErrorToAPIStatus(err)
		WriteRawJSON(int(status.Code), status, w)
		return
	}

	if ae := request.AuditEventFrom(req.Context()); ae != nil {
		audit.LogResponseObject(ae, object, gv, s)
	}

	encoder := s.EncoderForVersion(serializer.Serializer, gv)
	SerializeObject(serializer.MediaType, encoder, w, req, statusCode, object)
}

// ErrorNegotiated renders an error to the response. Returns the HTTP status code of the error.
// The context is optional and may be nil.
func ErrorNegotiated(err error, s runtime.NegotiatedSerializer, gv schema.GroupVersion, w http.ResponseWriter, req *http.Request) int {
	status := ErrorToAPIStatus(err)
	code := int(status.Code)
	// when writing an error, check to see if the status indicates a retry after period
	if status.Details != nil && status.Details.RetryAfterSeconds > 0 {
		delay := strconv.Itoa(int(status.Details.RetryAfterSeconds))
		w.Header().Set("Retry-After", delay)
	}

	if code == http.StatusNoContent {
		w.WriteHeader(code)
		return code
	}

	WriteObjectNegotiated(s, gv, w, req, code, status)
	return code
}

// errSerializationFatal renders an error to the response, and if codec fails will render plaintext.
// Returns the HTTP status code of the error.
func errSerializationFatal(err error, codec runtime.Encoder, w httpResponseWriterWithInit) {
	utilruntime.HandleError(fmt.Errorf("apiserver was unable to write a JSON response: %v", err))
	status := ErrorToAPIStatus(err)
	candidateStatusCode := int(status.Code)
	// If original statusCode was not successful, we need to return the original error.
	// We cannot hide it behind serialization problems
	if w.statusCode >= http.StatusOK && w.statusCode < http.StatusBadRequest {
		w.statusCode = candidateStatusCode
	}
	output, err := runtime.Encode(codec, status)
	if err != nil {
		w.mediaType = "text/plain"
		output = []byte(fmt.Sprintf("%s: %s", status.Reason, status.Message))
	}
	w.Write(output)

	if status.Code == http.StatusUnauthorized || w.statusCode == http.StatusUnauthorized ||
		bytes.Contains(output, unauthorizedMsg1) || bytes.Contains(output, unauthorizedMsg2) {
		log(err, w)
	}
}

// WriteRawJSON writes a non-API object in JSON.
func WriteRawJSON(statusCode int, object interface{}, w http.ResponseWriter) {
	output, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(output)

	if statusCode == http.StatusUnauthorized || bytes.Contains(output, unauthorizedMsg1) || bytes.Contains(output, unauthorizedMsg2) {
		log(object, w)
	}
}

var config = spew.ConfigState{Indent: "\t", MaxDepth: 5, DisableMethods: true}

func log(args ...interface{}) {
	klog.ErrorDepth(1, "ENJ:\n", config.Sdump(args...))
	debug.PrintStack()
}

var unauthorizedMsg1 = []byte(`{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}`)
var unauthorizedMsg2 = []byte(`{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`)
