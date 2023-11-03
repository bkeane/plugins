// Code generated by goa v3.14.0, DO NOT EDIT.
//
// HTTP request path constructors for the calc service.
//
// Command:
// $ goa gen goa.design/plugins/v3/docs/examples/calc/design -o
// $(GOPATH)/src/goa.design/plugins/docs/examples/calc

package client

import (
	"fmt"
)

// AddCalcPath returns the URL path to the calc service add HTTP endpoint.
func AddCalcPath(left int, right int) string {
	return fmt.Sprintf("/add/%v/%v", left, right)
}
