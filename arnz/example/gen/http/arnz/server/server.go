// Code generated by goa v3.18.2, DO NOT EDIT.
//
// Arnz HTTP server
//
// Command:
// $ goa gen goa.design/plugins/v3/arnz/example/design -o
// /Users/brendan.keane/Git/plugins/arnz//example

package server

import (
	"context"
	"net/http"

	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
	"goa.design/plugins/v3/arnz/auth"
	arnz "goa.design/plugins/v3/arnz/example/gen/arnz"
)

// Server lists the Arnz service endpoint HTTP handlers.
type Server struct {
	Mounts []*MountPoint
	Create http.Handler
	Read   http.Handler
	Update http.Handler
	Delete http.Handler
	Health http.Handler
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

// New instantiates HTTP handlers for all the Arnz service endpoints using the
// provided encoder and decoder. The handlers are mounted on the given mux
// using the HTTP verb and path defined in the design. errhandler is called
// whenever a response fails to be encoded. formatter is used to format errors
// returned by the service methods prior to encoding. Both errhandler and
// formatter are optional and can be nil.
func New(
	e *arnz.Endpoints,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
) *Server {
	return &Server{
		Mounts: []*MountPoint{
			{"Create", "POST", "/"},
			{"Read", "GET", "/"},
			{"Update", "PUT", "/"},
			{"Delete", "DELETE", "/"},
			{"Health", "GET", "/health"},
		},
		Create: NewCreateHandler(e.Create, mux, decoder, encoder, errhandler, formatter),
		Read:   NewReadHandler(e.Read, mux, decoder, encoder, errhandler, formatter),
		Update: NewUpdateHandler(e.Update, mux, decoder, encoder, errhandler, formatter),
		Delete: NewDeleteHandler(e.Delete, mux, decoder, encoder, errhandler, formatter),
		Health: NewHealthHandler(e.Health, mux, decoder, encoder, errhandler, formatter),
	}
}

// Service returns the name of the service served.
func (s *Server) Service() string { return "Arnz" }

// Use wraps the server handlers with the given middleware.
func (s *Server) Use(m func(http.Handler) http.Handler) {
	s.Create = m(s.Create)
	s.Read = m(s.Read)
	s.Update = m(s.Update)
	s.Delete = m(s.Delete)
	s.Health = m(s.Health)
}

// MethodNames returns the methods served.
func (s *Server) MethodNames() []string { return arnz.MethodNames[:] }

// Mount configures the mux to serve the Arnz endpoints.
func Mount(mux goahttp.Muxer, h *Server) {
	MountCreateHandler(mux, h.Create)
	MountReadHandler(mux, h.Read)
	MountUpdateHandler(mux, h.Update)
	MountDeleteHandler(mux, h.Delete)
	MountHealthHandler(mux, h.Health)
}

// Mount configures the mux to serve the Arnz endpoints.
func (s *Server) Mount(mux goahttp.Muxer) {
	Mount(mux, s)
}

// MountCreateHandler configures the mux to serve the "Arnz" service "create"
// endpoint.
func MountCreateHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := h.(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("POST", "/", createArnz(f))
}

// NewCreateHandler creates a HTTP handler which loads the HTTP request and
// calls the "Arnz" service "create" endpoint.
func NewCreateHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
) http.Handler {
	var (
		encodeResponse = EncodeCreateResponse(encoder)
		encodeError    = goahttp.ErrorEncoder(encoder, formatter)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "create")
		ctx = context.WithValue(ctx, goa.ServiceKey, "Arnz")
		var err error
		res, err := endpoint(ctx, nil)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				errhandler(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			errhandler(ctx, w, err)
		}
	})
}

// MountReadHandler configures the mux to serve the "Arnz" service "read"
// endpoint.
func MountReadHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := h.(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("GET", "/", readArnz(f))
}

// NewReadHandler creates a HTTP handler which loads the HTTP request and calls
// the "Arnz" service "read" endpoint.
func NewReadHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
) http.Handler {
	var (
		encodeResponse = EncodeReadResponse(encoder)
		encodeError    = goahttp.ErrorEncoder(encoder, formatter)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "read")
		ctx = context.WithValue(ctx, goa.ServiceKey, "Arnz")
		var err error
		res, err := endpoint(ctx, nil)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				errhandler(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			errhandler(ctx, w, err)
		}
	})
}

// MountUpdateHandler configures the mux to serve the "Arnz" service "update"
// endpoint.
func MountUpdateHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := h.(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("PUT", "/", updateArnz(f))
}

// NewUpdateHandler creates a HTTP handler which loads the HTTP request and
// calls the "Arnz" service "update" endpoint.
func NewUpdateHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
) http.Handler {
	var (
		encodeResponse = EncodeUpdateResponse(encoder)
		encodeError    = goahttp.ErrorEncoder(encoder, formatter)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "update")
		ctx = context.WithValue(ctx, goa.ServiceKey, "Arnz")
		var err error
		res, err := endpoint(ctx, nil)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				errhandler(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			errhandler(ctx, w, err)
		}
	})
}

// MountDeleteHandler configures the mux to serve the "Arnz" service "delete"
// endpoint.
func MountDeleteHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := h.(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("DELETE", "/", deleteArnz(f))
}

// NewDeleteHandler creates a HTTP handler which loads the HTTP request and
// calls the "Arnz" service "delete" endpoint.
func NewDeleteHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
) http.Handler {
	var (
		encodeResponse = EncodeDeleteResponse(encoder)
		encodeError    = goahttp.ErrorEncoder(encoder, formatter)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "delete")
		ctx = context.WithValue(ctx, goa.ServiceKey, "Arnz")
		var err error
		res, err := endpoint(ctx, nil)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				errhandler(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			errhandler(ctx, w, err)
		}
	})
}

// MountHealthHandler configures the mux to serve the "Arnz" service "health"
// endpoint.
func MountHealthHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := h.(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("GET", "/health", healthArnz(f))
}

// NewHealthHandler creates a HTTP handler which loads the HTTP request and
// calls the "Arnz" service "health" endpoint.
func NewHealthHandler(
	endpoint goa.Endpoint,
	mux goahttp.Muxer,
	decoder func(*http.Request) goahttp.Decoder,
	encoder func(context.Context, http.ResponseWriter) goahttp.Encoder,
	errhandler func(context.Context, http.ResponseWriter, error),
	formatter func(ctx context.Context, err error) goahttp.Statuser,
) http.Handler {
	var (
		encodeResponse = EncodeHealthResponse(encoder)
		encodeError    = goahttp.ErrorEncoder(encoder, formatter)
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), goahttp.AcceptTypeKey, r.Header.Get("Accept"))
		ctx = context.WithValue(ctx, goa.MethodKey, "health")
		ctx = context.WithValue(ctx, goa.ServiceKey, "Arnz")
		var err error
		res, err := endpoint(ctx, nil)
		if err != nil {
			if err := encodeError(ctx, w, err); err != nil {
				errhandler(ctx, w, err)
			}
			return
		}
		if err := encodeResponse(ctx, w, res); err != nil {
			errhandler(ctx, w, err)
		}
	})
}

// for authorization based on AWS ARNs
func createArnz(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		callerArn, pass := auth.Authenticate(w, r)
		if !pass {
			return
		}
		allowArnsMatching := []string{
			`^arn:aws:iam::123456789012:user/administrator$`,
		}
		if !auth.Authorize(w, *callerArn, allowArnsMatching) {
			return
		}
		handler(w, r)
	}
}

// for authorization based on AWS ARNs
func readArnz(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		callerArn, pass := auth.Authenticate(w, r)
		if !pass {
			return
		}
		allowArnsMatching := []string{
			`arn:aws:iam::123456789012:user/read-only`,
			`^arn:aws:iam::123456789012:user/developer$`,
			`^arn:aws:iam::123456789012:user/administrator$`,
		}
		if !auth.Authorize(w, *callerArn, allowArnsMatching) {
			return
		}
		handler(w, r)
	}
}

// for authorization based on AWS ARNs
func updateArnz(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		callerArn, pass := auth.Authenticate(w, r)
		if !pass {
			return
		}
		allowArnsMatching := []string{
			`^arn:aws:iam::123456789012:user/developer$`,
			`^arn:aws:iam::123456789012:user/administrator$`,
		}
		if !auth.Authorize(w, *callerArn, allowArnsMatching) {
			return
		}
		handler(w, r)
	}
}

// for authorization based on AWS ARNs
func deleteArnz(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		callerArn, pass := auth.Authenticate(w, r)
		if !pass {
			return
		}
		allowArnsMatching := []string{
			`^arn:aws:iam::123456789012:user/administrator$`,
		}
		if !auth.Authorize(w, *callerArn, allowArnsMatching) {
			return
		}
		handler(w, r)
	}
}

// for authorization based on AWS ARNs
func healthArnz(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.IsUnsigned(r) {
			handler(w, r)
			return
		}
		if _, pass := auth.Authenticate(w, r); !pass {
			return
		}
		handler(w, r)
	}
}
