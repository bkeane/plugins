// Code generated by goa v2.0.0-wip, DO NOT EDIT.
//
// adder service security
//
// Command:
// $ goa gen goa.design/plugins/security/examples/calc/adder/design

package addersvc

import (
	"context"

	"goa.design/goa"
	"goa.design/plugins/security"
)

// NewSecureEndpoints wraps the methods of a adder service with security scheme
// aware endpoints.
func NewSecureEndpoints(s Service, authAPIKeyFn security.AuthAPIKeyFunc) *Endpoints {
	return &Endpoints{
		Add: SecureAdd(NewAddEndpoint(s), authAPIKeyFn),
	}
}

// SecureAdd returns an endpoint function which initializes the context with
// the security requirements for the method "add" of service "adder".
func SecureAdd(ep goa.Endpoint, authAPIKeyFn security.AuthAPIKeyFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*AddPayload)
		var err error
		ctx, err = authAPIKeyFn(ctx, p.Key, &security.APIKeyScheme{
			Name: "api_key",
		})
		if err != nil {
			return nil, err
		}
		return ep(ctx, req)
	}
}