package example

import (
	"context"

	"goa.design/plugins/v3/arnz/auth"
	genarnz "goa.design/plugins/v3/arnz/example/gen/arnz"
)

type Service struct{}

func (s *Service) Create(ctx context.Context) (res *genarnz.ResponseBody, err error) {
	return &genarnz.ResponseBody{Action: "created!"}, nil
}

func (s *Service) Read(ctx context.Context) (res *genarnz.ResponseBody, err error) {
	return &genarnz.ResponseBody{Action: "read!"}, nil
}

func (s *Service) Update(ctx context.Context) (res *genarnz.ResponseBody, err error) {
	return &genarnz.ResponseBody{Action: "updated!"}, nil
}

func (s *Service) Delete(ctx context.Context) (res *genarnz.ResponseBody, err error) {
	return &genarnz.ResponseBody{Action: "deleted!"}, nil
}

func (s *Service) Health(ctx context.Context) (res *genarnz.ResponseBody, err error) {
	return &genarnz.ResponseBody{Action: "healthy!"}, nil
}

func (s *Service) Caller(ctx context.Context) (res *genarnz.IntrospectResponse, err error) {
	amznCtx, ok := auth.FromContext(ctx)
	if !ok {
		return &genarnz.IntrospectResponse{Caller: "unsigned"}, nil
	}
	return &genarnz.IntrospectResponse{Caller: amznCtx.Authorizer.IAM.UserARN}, nil
}
