// Code generated by goa v3.3.1, DO NOT EDIT.
//
// fetcher go-kit HTTP server encoders and decoders
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/fetcher/fetcher/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/fetcher/fetcher

package server

import (
	"net/http"

	goahttp "goa.design/goa/v3/http"
)

// MountFetchHandler configures the mux to serve the "fetcher" service "fetch"
// endpoint.
func MountFetchHandler(mux goahttp.Muxer, h http.Handler) {
	f, ok := h.(http.HandlerFunc)
	if !ok {
		f = func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}
	}
	mux.Handle("GET", "/fetch/{*url}", f)
}
