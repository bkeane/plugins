// Code generated by goa v3.15.2, DO NOT EDIT.
//
// calc WebSocket server streaming
//
// Command:
// $ goa gen goa.design/plugins/v3/docs/examples/calc/design -o
// $(GOPATH)/src/goa.design/plugins/docs/examples/calc

package server

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	goahttp "goa.design/goa/v3/http"
	calc "goa.design/plugins/v3/docs/examples/calc/gen/calc"
)

// ConnConfigurer holds the websocket connection configurer functions for the
// streaming endpoints in "calc" service.
type ConnConfigurer struct {
	AddFn goahttp.ConnConfigureFunc
}

// AddServerStream implements the calc.AddServerStream interface.
type AddServerStream struct {
	once sync.Once
	// upgrader is the websocket connection upgrader.
	upgrader goahttp.Upgrader
	// configurer is the websocket connection configurer.
	configurer goahttp.ConnConfigureFunc
	// cancel is the context cancellation function which cancels the request
	// context when invoked.
	cancel context.CancelFunc
	// w is the HTTP response writer used in upgrading the connection.
	w http.ResponseWriter
	// r is the HTTP request.
	r *http.Request
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

// Send streams instances of "int" to the "add" endpoint websocket connection.
func (s *AddServerStream) Send(v int) error {
	var err error
	// Upgrade the HTTP connection to a websocket connection only once. Connection
	// upgrade is done here so that authorization logic in the endpoint is executed
	// before calling the actual service method which may call Send().
	s.once.Do(func() {
		var conn *websocket.Conn
		conn, err = s.upgrader.Upgrade(s.w, s.r, nil)
		if err != nil {
			return
		}
		if s.configurer != nil {
			conn = s.configurer(conn, s.cancel)
		}
		s.conn = conn
	})
	if err != nil {
		return err
	}
	res := v
	return s.conn.WriteJSON(res)
}

// Recv reads instances of "calc.AddStreamingPayload" from the "add" endpoint
// websocket connection.
func (s *AddServerStream) Recv() (*calc.AddStreamingPayload, error) {
	var (
		rv  *calc.AddStreamingPayload
		msg *AddStreamingBody
		err error
	)
	// Upgrade the HTTP connection to a websocket connection only once. Connection
	// upgrade is done here so that authorization logic in the endpoint is executed
	// before calling the actual service method which may call Recv().
	s.once.Do(func() {
		var conn *websocket.Conn
		conn, err = s.upgrader.Upgrade(s.w, s.r, nil)
		if err != nil {
			return
		}
		if s.configurer != nil {
			conn = s.configurer(conn, s.cancel)
		}
		s.conn = conn
	})
	if err != nil {
		return rv, err
	}
	if err = s.conn.ReadJSON(&msg); err != nil {
		return rv, err
	}
	if msg == nil {
		return rv, io.EOF
	}
	body := *msg
	err = ValidateAddStreamingBody(&body)
	if err != nil {
		return rv, err
	}
	return NewAddStreamingBody(msg), nil
}

// Close closes the "add" endpoint websocket connection.
func (s *AddServerStream) Close() error {
	var err error
	if s.conn == nil {
		return nil
	}
	if err = s.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "server closing connection"),
		time.Now().Add(time.Second),
	); err != nil {
		return err
	}
	return s.conn.Close()
}
