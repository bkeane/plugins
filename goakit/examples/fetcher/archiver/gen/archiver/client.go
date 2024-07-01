// Code generated by goa v3.17.0, DO NOT EDIT.
//
// archiver client
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/fetcher/archiver/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/fetcher/archiver

package archiver

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

// Client is the "archiver" service client.
type Client struct {
	ArchiveEndpoint endpoint.Endpoint
	ReadEndpoint    endpoint.Endpoint
}

// NewClient initializes a "archiver" service client given the endpoints.
func NewClient(archive, read endpoint.Endpoint) *Client {
	return &Client{
		ArchiveEndpoint: archive,
		ReadEndpoint:    read,
	}
}

// Archive calls the "archive" endpoint of the "archiver" service.
func (c *Client) Archive(ctx context.Context, p *ArchivePayload) (res *ArchiveMedia, err error) {
	var ires any
	ires, err = c.ArchiveEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(*ArchiveMedia), nil
}

// Read calls the "read" endpoint of the "archiver" service.
// Read may return the following errors:
//   - "not_found" (type *goa.ServiceError)
//   - "bad_request" (type *goa.ServiceError)
//   - error: internal error
func (c *Client) Read(ctx context.Context, p *ReadPayload) (res *ArchiveMedia, err error) {
	var ires any
	ires, err = c.ReadEndpoint(ctx, p)
	if err != nil {
		return
	}
	return ires.(*ArchiveMedia), nil
}
