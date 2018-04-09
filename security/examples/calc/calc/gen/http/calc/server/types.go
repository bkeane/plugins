// Code generated by goa v2.0.0-wip, DO NOT EDIT.
//
// calc HTTP server types
//
// Command:
// $ goa gen goa.design/plugins/security/examples/calc/calc/design

package server

import (
	goa "goa.design/goa"
	calcsvc "goa.design/plugins/security/examples/calc/calc/gen/calc"
)

// LoginUnauthorizedResponseBody is the type of the "calc" service "login"
// endpoint HTTP response body for the "unauthorized" error.
type LoginUnauthorizedResponseBody string

// AddForbiddenResponseBody is the type of the "calc" service "add" endpoint
// HTTP response body for the "forbidden" error.
type AddForbiddenResponseBody struct {
	// Name is the name of this class of errors.
	Name string `form:"name" json:"name" xml:"name"`
	// ID is a unique identifier for this particular occurrence of the problem.
	ID string `form:"id" json:"id" xml:"id"`
	// Message is a human-readable explanation specific to this occurrence of the
	// problem.
	Message string `form:"message" json:"message" xml:"message"`
	// Is the error temporary?
	Temporary bool `form:"temporary" json:"temporary" xml:"temporary"`
	// Is the error a timeout?
	Timeout bool `form:"timeout" json:"timeout" xml:"timeout"`
}

// NewLoginUnauthorizedResponseBody builds the HTTP response body from the
// result of the "login" endpoint of the "calc" service.
func NewLoginUnauthorizedResponseBody(res calcsvc.Unauthorized) LoginUnauthorizedResponseBody {
	body := LoginUnauthorizedResponseBody(res)
	return body
}

// NewAddForbiddenResponseBody builds the HTTP response body from the result of
// the "add" endpoint of the "calc" service.
func NewAddForbiddenResponseBody(res *goa.ServiceError) *AddForbiddenResponseBody {
	body := &AddForbiddenResponseBody{
		Name:      res.Name,
		ID:        res.ID,
		Message:   res.Message,
		Temporary: res.Temporary,
		Timeout:   res.Timeout,
	}
	return body
}

// NewLoginLoginPayload builds a calc service login endpoint payload.
func NewLoginLoginPayload() *calcsvc.LoginPayload {
	return &calcsvc.LoginPayload{}
}

// NewAddAddPayload builds a calc service add endpoint payload.
func NewAddAddPayload(a int, b int, token string) *calcsvc.AddPayload {
	return &calcsvc.AddPayload{
		A:     a,
		B:     b,
		Token: token,
	}
}