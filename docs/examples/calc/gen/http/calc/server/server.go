// Code generated by goa v3.14.5, DO NOT EDIT.
//
// calc HTTP server
//
// Command:
// $ goa gen goa.design/plugins/v3/docs/examples/calc/design -o
// $(GOPATH)/src/goa.design/plugins/docs/examples/calc

package server

import (
	"context"
	"net/http"

	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
	calc "goa.design/plugins/v3/docs/examples/calc/gen/calc"
)

// Server lists the calc service endpoint HTTP handlers.
type Server struct {
	Mounts             []*MountPoint
	Add                http.Handler
	GenHTTPOpenapiJSON http.Handler
}

// MountPoint holds information about the mounted endpoints.
type MountPoint struct {
	// Method is the name of the service method served by the mounted HTTP handler.
	Method string
	// Verb is the HTTP method used to match requests to the mounted handler.
	Verb string
	// Pattern is the HTTP request path pattern used to match requests to the
	// mounted handler.
	Pattern string
}

// New instantiates HTTP handlers for all the calc service endpoints using the
// provided encoder and decoder. The handlers are mounted on the given mux
// using the HTTP verb and path defined in the design. errhandler is called
// whenever a response fails to be encoded. formatter is used to format errors
// returned by the service methods prior to encoding. Both errhandler and
// formatter are optional and can be nil.
func New(
	e *calc.Endpoints,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
	upgrader goahttp.Upgrader,
	configurer *ConnConfigurer,
	fileSystemGenHTTPOpenapiJSON http.FileSystem,
) *Server {
	if configurer == nil {
		configurer = &ConnConfigurer{}
	}
	if fileSystemGenHTTPOpenapiJSON == nil {
		fileSystemGenHTTPOpenapiJSON = http.Dir(".")
	}
	return &Server{
		Mounts: []*MountPoint{
			{"Add", "GET", "/add/{left}/{right}"},
			{"../../gen/http/openapi.json", "GET", "/swagger.json"},
		},
		Add:                NewAddHandler(e.Add, mux, decoder, encoder, errhandler, formatter, upgrader, configurer.AddFn),
		GenHTTPOpenapiJSON: http.FileServer(fileSystemGenHTTPOpenapiJSON),
	}
}

// Service returns the name of the service served.
func (s *Server) Service() string { return "calc" }

// Use wraps the server handlers with the given middleware.
func (s *Server) Use(m func(http.Handler) http.Handler) {
	s.Add = m(s.Add)
}

// MethodNames returns the methods served.
func (s *Server) MethodNames() []string { return calc.MethodNames[:] }

// Mount configures the mux to serve the calc endpoints.
func Mount(mux goahttp.Muxer, h *Server) {
	MountAddHandler(mux, h.Add)
	MountGenHTTPOpenapiJSON(mux, goahttp.Replace("", "/../../gen/http/openapi.json", h.GenHTTPOpenapiJSON))
}

// Mount configures the mux to serve the calc endpoints.
func (s *Server) Mount(mux goahttp.Muxer) {
	Mount(mux, s)
}

// MountAddHandler configures the mux to serve the "calc" service "add"
// endpoint.
func MountAddHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := h.(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("GET", "/add/{left}/{right}", f)
}

// NewAddHandler creates a HTTP handler which loads the HTTP request and calls
// the "calc" service "add" endpoint.
func NewAddHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
	upgrader goahttp.Upgrader,
	configurer goahttp.ConnConfigureFunc,
) http.Handler {
	var (
		decodeRequest = DecodeAddRequest(mux, decoder)
		encodeError   = goahttp.ErrorEncoder(encoder, formatter)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "add")
		ctx = context.WithValue(ctx, goa.ServiceKey, "calc")
		payload, err := decodeRequest(r)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				errhandler(ctx, w, err)
			}
			return
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		v := &calc.AddEndpointInput{
			Stream: &AddServerStream{
				upgrader:   upgrader,
				configurer: configurer,
				cancel:     cancel,
				w:          w,
				r:          r,
			},
			Payload: payload.(*calc.AddPayload),
		}
		_, err = endpoint(ctx, v)
		if err != nil {
			if v.Stream.(*AddServerStream).conn != nil {
				// Response writer has been hijacked, do not encode the error
				errhandler(ctx, w, err)
				return
			}
			if err := encodeError(ctx, w, err); err != nil {
				errhandler(ctx, w, err)
			}
			return
		}
	})
}

// MountGenHTTPOpenapiJSON configures the mux to serve GET request made to
// "/swagger.json".
func MountGenHTTPOpenapiJSON(mux goahttp.Muxer, h http.Handler) {
	mux.Handle("GET", "/swagger.json", h.ServeHTTP)
}
