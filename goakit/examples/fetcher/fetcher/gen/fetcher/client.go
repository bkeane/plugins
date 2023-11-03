// Code generated by goa v3.14.0, DO NOT EDIT.
//
// fetcher client
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/fetcher/fetcher/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/fetcher/fetcher

package fetcher

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

// Client is the "fetcher" service client.
type Client struct {
	FetchEndpoint endpoint.Endpoint
}

// NewClient initializes a "fetcher" service client given the endpoints.
func NewClient(fetch endpoint.Endpoint) *Client {
	return &Client{
		FetchEndpoint: fetch,
	}
}

// Fetch calls the "fetch" endpoint of the "fetcher" service.
// Fetch may return the following errors:
//   - "bad_request" (type *goa.ServiceError)
//   - "internal_error" (type *goa.ServiceError)
//   - error: internal error
func (c *Client) Fetch(ctx context.Context, p *FetchPayload) (res *FetchMedia, err error) {
	var ires any
	ires, err = c.FetchEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(*FetchMedia), nil
}
