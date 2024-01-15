// Code generated by goa v3.14.6, DO NOT EDIT.
//
// calc HTTP client CLI support package
//
// Command:
// $ goa gen goa.design/plugins/v3/docs/examples/calc/design -o
// $(GOPATH)/src/goa.design/plugins/docs/examples/calc

package client

import (
	"fmt"
	"strconv"

	calc "goa.design/plugins/v3/docs/examples/calc/gen/calc"
)

// BuildAddPayload builds the payload for the calc add endpoint from CLI flags.
func BuildAddPayload(calcAddLeft string, calcAddRight string) (*calc.AddPayload, error) {
	var err error
	var left int
	{
		var v int64
		v, err = strconv.ParseInt(calcAddLeft, 10, strconv.IntSize)
		left = int(v)
		if err != nil {
			return nil, fmt.Errorf("invalid value for left, must be INT")
		}
	}
	var right int
	{
		var v int64
		v, err = strconv.ParseInt(calcAddRight, 10, strconv.IntSize)
		right = int(v)
		if err != nil {
			return nil, fmt.Errorf("invalid value for right, must be INT")
		}
	}
	v := &calc.AddPayload{}
	v.Left = left
	v.Right = right

	return v, nil
}
