// Code generated by goa v3.15.2, DO NOT EDIT.
//
// calc endpoints
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/calc/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/calc

package calc

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps the "calc" service endpoints.
type Endpoints struct {
	Add endpoint.Endpoint
}

// NewEndpoints wraps the methods of the "calc" service with endpoints.
func NewEndpoints(s Service) *Endpoints {
	return &Endpoints{
		Add: NewAddEndpoint(s),
	}
}

// Use applies the given middleware to all the "calc" service endpoints.
func (e *Endpoints) Use(m func(endpoint.Endpoint) endpoint.Endpoint) {
	e.Add = m(e.Add)
}

// NewAddEndpoint returns an endpoint function that calls the method "add" of
// service "calc".
func NewAddEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		p := req.(*AddPayload)
		return s.Add(ctx, p)
	}
}
