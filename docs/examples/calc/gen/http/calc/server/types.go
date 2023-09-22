// Code generated by goa v3.13.1, DO NOT EDIT.
//
// calc HTTP server types
//
// Command:
// $ goa gen goa.design/plugins/v3/docs/examples/calc/design -o
// $(GOPATH)/src/goa.design/plugins/docs/examples/calc

package server

import (
	goa "goa.design/goa/v3/pkg"
	calc "goa.design/plugins/v3/docs/examples/calc/gen/calc"
)

// AddStreamingBody is the type of the "calc" service "add" endpoint HTTP
// request body.
type AddStreamingBody struct {
	// Left operand
	A *int `form:"a,omitempty" json:"a,omitempty" xml:"a,omitempty"`
	// Right operand
	B *int `form:"b,omitempty" json:"b,omitempty" xml:"b,omitempty"`
}

// NewAddPayload builds a calc service add endpoint payload.
func NewAddPayload(left int, right int) *calc.AddPayload {
	v := &calc.AddPayload{}
	v.Left = left
	v.Right = right

	return v
}

// NewAddStreamingBody builds a calc service add endpoint payload.
func NewAddStreamingBody(body *AddStreamingBody) *calc.AddStreamingPayload {
	v := &calc.AddStreamingPayload{
		A: *body.A,
		B: *body.B,
	}

	return v
}

// ValidateAddStreamingBody runs the validations defined on AddStreamingBody
func ValidateAddStreamingBody(body *AddStreamingBody) (err error) {
	if body.A == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("a", "body"))
	}
	if body.B == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("b", "body"))
	}
	return
}
