// Code generated by goa v3.15.1, DO NOT EDIT.
//
// Zap logger implementation
//
// Command:
// $ goa gen goa.design/plugins/v3/zaplogger/examples/calc/design -o
// $(GOPATH)/src/goa.design/plugins/zaplogger/examples/calc

package log

import (
	"go.uber.org/zap"
)

// Logger is an adapted zap logger
type Logger struct {
	*zap.SugaredLogger
}

// New creates a new zap logger
func New(serviceName string, production bool) *Logger {

	if production {
		l, _ := zap.NewProduction()
		return &Logger{l.Sugar().With(zap.String("service", serviceName))}
	} else {
		l, _ := zap.NewDevelopment()
		return &Logger{l.Sugar().With(zap.String("service", serviceName))}
	}
}

// Log is called by the log middleware to log HTTP requests key values
func (logger *Logger) Log(keyvals ...interface{}) error {
	logger.Infow("HTTP Request", keyvals...)
	return nil
}
