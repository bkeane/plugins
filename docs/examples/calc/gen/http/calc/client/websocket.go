// Code generated by goa v3.14.5, DO NOT EDIT.
//
// calc WebSocket client streaming
//
// Command:
// $ goa gen goa.design/plugins/v3/docs/examples/calc/design -o
// $(GOPATH)/src/goa.design/plugins/docs/examples/calc

package client

import (
	"io"

	"github.com/gorilla/websocket"
	goahttp "goa.design/goa/v3/http"
	calc "goa.design/plugins/v3/docs/examples/calc/gen/calc"
)

// ConnConfigurer holds the websocket connection configurer functions for the
// streaming endpoints in "calc" service.
type ConnConfigurer struct {
	AddFn goahttp.ConnConfigureFunc
}

// AddClientStream implements the calc.AddClientStream interface.
type AddClientStream struct {
	// conn is the underlying websocket connection.
	conn *websocket.Conn
}

// NewConnConfigurer initializes the websocket connection configurer function
// with fn for all the streaming endpoints in "calc" service.
func NewConnConfigurer(fn goahttp.ConnConfigureFunc) *ConnConfigurer {
	return &ConnConfigurer{
		AddFn: fn,
	}
}

// Recv reads instances of "int" from the "add" endpoint websocket connection.
func (s *AddClientStream) Recv() (int, error) {
	var (
		rv   int
		body int
		err  error
	)
	err = s.conn.ReadJSON(&body)
	if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		return rv, io.EOF
	}
	if err != nil {
		return rv, err
	}
	return body, nil
}

// Send streams instances of "calc.AddStreamingPayload" to the "add" endpoint
// websocket connection.
func (s *AddClientStream) Send(v *calc.AddStreamingPayload) error {
	body := NewAddStreamingBody(v)
	return s.conn.WriteJSON(body)
}

// Close closes the "add" endpoint websocket connection.
func (s *AddClientStream) Close() error {
	var err error
	// Send a nil payload to the server implying client closing connection.
	if err = s.conn.WriteJSON(nil); err != nil {
		return err
	}
	return s.conn.Close()
}
