// Code generated by goa v3.14.6, DO NOT EDIT.
//
// fetcher HTTP client encoders and decoders
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/fetcher/fetcher/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/fetcher/fetcher

package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"

	goahttp "goa.design/goa/v3/http"
	fetcher "goa.design/plugins/v3/goakit/examples/fetcher/fetcher/gen/fetcher"
	fetcherviews "goa.design/plugins/v3/goakit/examples/fetcher/fetcher/gen/fetcher/views"
)

// BuildFetchRequest instantiates a HTTP request object with method and path
// set to call the "fetcher" service "fetch" endpoint
func (c *Client) BuildFetchRequest(ctx context.Context, v any) (*http.Request, error) {
	var (
		url_ string
	)
	{
		p, ok := v.(*fetcher.FetchPayload)
		if !ok {
			return nil, goahttp.ErrInvalidType("fetcher", "fetch", "*fetcher.FetchPayload", v)
		}
		url_ = p.URL
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: FetchFetcherPath(url_)}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("fetcher", "fetch", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// DecodeFetchResponse returns a decoder for responses returned by the fetcher
// fetch endpoint. restoreBody controls whether the response body should be
// restored after having been read.
// DecodeFetchResponse may return the following errors:
//   - "bad_request" (type *goa.ServiceError): http.StatusBadRequest
//   - "internal_error" (type *goa.ServiceError): http.StatusInternalServerError
//   - error: internal error
func DecodeFetchResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (any, error) {
	return func(resp *http.Response) (any, error) {
		if restoreBody {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = io.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var (
				body FetchResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("fetcher", "fetch", err)
			}
			p := NewFetchMediaViewOK(&body)
			view := "default"
			vres := &fetcherviews.FetchMedia{Projected: p, View: view}
			if err = fetcherviews.ValidateFetchMedia(vres); err != nil {
				return nil, goahttp.ErrValidationError("fetcher", "fetch", err)
			}
			res := fetcher.NewFetchMedia(vres)
			return res, nil
		case http.StatusBadRequest:
			var (
				body FetchBadRequestResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("fetcher", "fetch", err)
			}
			err = ValidateFetchBadRequestResponseBody(&body)
			if err != nil {
				return nil, goahttp.ErrValidationError("fetcher", "fetch", err)
			}
			return nil, NewFetchBadRequest(&body)
		case http.StatusInternalServerError:
			var (
				body FetchInternalErrorResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("fetcher", "fetch", err)
			}
			err = ValidateFetchInternalErrorResponseBody(&body)
			if err != nil {
				return nil, goahttp.ErrValidationError("fetcher", "fetch", err)
			}
			return nil, NewFetchInternalError(&body)
		default:
			body, _ := io.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("fetcher", "fetch", resp.StatusCode, string(body))
		}
	}
}
