package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/aws/aws-lambda-go/events"
)

const (
	Header = "X-Amzn-Request-Context"
)

// contextKeyType is an unexported type for context keys to avoid collisions
type contextKeyType struct{}

// ContextKey is the key used to store API Gateway context in the context.Context
var ContextKey = contextKeyType{}

type Gate struct {
	MethodName        string
	AllowUnsigned     bool
	AllowArnsMatching []string
}

// FromContext extracts the API Gateway context from the provided context.
func FromContext(ctx context.Context) (events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription, bool) {
	if ctx == nil {
		return events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{}, false
	}

	value := ctx.Value(ContextKey)
	if value == nil {
		return events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{}, false
	}

	amznCtx, ok := value.(events.APIGatewayV2HTTPRequestContext)

	return *amznCtx.Authorizer.IAM, ok
}

// IntoContext returns a new context with the API Gateway HTTP request context injected
func IntoContext(ctx context.Context, r *http.Request) context.Context {
	amzReqCtxHeader := r.Header.Get(Header)
	if amzReqCtxHeader == "" || amzReqCtxHeader == "null" {
		return ctx
	}

	var amznCtx events.APIGatewayV2HTTPRequestContext
	err := json.Unmarshal([]byte(amzReqCtxHeader), &amznCtx)
	if err != nil {
		return ctx
	}

	return context.WithValue(ctx, ContextKey, amznCtx)
}

func IsUnsigned(r *http.Request) (pass bool) {
	return r.Header.Get(Header) == "" || r.Header.Get(Header) == "null"
}

func Authenticate(w http.ResponseWriter, r *http.Request) (caller *string, pass bool) {
	var amznCtx events.APIGatewayV2HTTPRequestContext
	amzReqCtxHeader := r.Header.Get(Header)

	if IsUnsigned(r) {
		WriteUnauthenticated(w, "caller not authenticated")
		return
	}

	err := json.Unmarshal([]byte(amzReqCtxHeader), &amznCtx)
	if err != nil {
		WriteUnauthenticated(w, "failed to unmarshal X-Amzn-Request-Context header")
		return
	}

	if amznCtx.Authorizer == nil {
		WriteUnauthenticated(w, "no Authorizer defined in X-Amzn-Request-Context")
		return
	}

	if amznCtx.Authorizer.IAM == nil {
		WriteUnauthenticated(w, "no IAM defined in X-Amzn-Request-Context")
		return
	}

	if amznCtx.Authorizer.IAM.UserARN == "" {
		WriteUnauthenticated(w, "no UserARN defined in X-Amzn-Request-Context")
		return
	}

	return &amznCtx.Authorizer.IAM.UserARN, true
}

func Authorize(w http.ResponseWriter, callerArn string, matchers []string) (pass bool) {
	for _, pattern := range matchers {
		re := regexp.MustCompile(pattern)
		if re.MatchString(callerArn) {
			return true
		}
	}
	WriteUnauthorized(w, "caller not authorized")
	return false
}

func WriteUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": message,
	})
}

func WriteUnauthenticated(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthenticated",
		"message": message,
	})
}
