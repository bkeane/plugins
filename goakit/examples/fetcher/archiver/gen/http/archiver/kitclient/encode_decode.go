// Code generated by goa v3.15.0, DO NOT EDIT.
//
// archiver go-kit HTTP client encoders and decoders
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/fetcher/archiver/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/fetcher/archiver

package client

import (
	"context"
	"net/http"

	kithttp "github.com/go-kit/kit/transport/http"
	goahttp "goa.design/goa/v3/http"
	"goa.design/plugins/v3/goakit/examples/fetcher/archiver/gen/http/archiver/client"
)

// EncodeArchiveRequest returns a go-kit EncodeRequestFunc suitable for
// encoding archiver archive requests.
func EncodeArchiveRequest(encoder func(*http.Request) goahttp.Encoder) kithttp.EncodeRequestFunc {
	enc := client.EncodeArchiveRequest(encoder)
	return func(_ context.Context, r *http.Request, v interface{}) error {
		return enc(r, v)
	}
}

// DecodeArchiveResponse returns a go-kit DecodeResponseFunc suitable for
// decoding archiver archive responses.
func DecodeArchiveResponse(decoder func(*http.Response) goahttp.Decoder) kithttp.DecodeResponseFunc {
	dec := client.DecodeArchiveResponse(decoder, false)
	return func(ctx context.Context, resp *http.Response) (interface{}, error) {
		return dec(resp)
	}
}

// DecodeReadResponse returns a go-kit DecodeResponseFunc suitable for decoding
// archiver read responses.
func DecodeReadResponse(decoder func(*http.Response) goahttp.Decoder) kithttp.DecodeResponseFunc {
	dec := client.DecodeReadResponse(decoder, false)
	return func(ctx context.Context, resp *http.Response) (interface{}, error) {
		return dec(resp)
	}
}
