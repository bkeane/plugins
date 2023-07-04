// Code generated by goa v3.12.1, DO NOT EDIT.
//
// archiver service
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/fetcher/archiver/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/fetcher/archiver

package archiver

import (
	"context"

	goa "goa.design/goa/v3/pkg"
	archiverviews "goa.design/plugins/v3/goakit/examples/fetcher/archiver/gen/archiver/views"
)

// Service is the archiver service interface.
type Service interface {
	// Archive HTTP response
	Archive(context.Context, *ArchivePayload) (res *ArchiveMedia, err error)
	// Read HTTP response from archive
	Read(context.Context, *ReadPayload) (res *ArchiveMedia, err error)
}

// ServiceName is the name of the service as defined in the design. This is the
// same value that is set in the endpoint request contexts under the ServiceKey
// key.
const ServiceName = "archiver"

// MethodNames lists the service method names as defined in the design. These
// are the same values that are set in the endpoint request contexts under the
// MethodKey key.
var MethodNames = [2]string{"archive", "read"}

// ArchiveMedia is the result type of the archiver service archive method.
type ArchiveMedia struct {
	// The archive resouce href
	Href string
	// HTTP status
	Status int
	// HTTP response body content
	Body string
}

// ArchivePayload is the payload type of the archiver service archive method.
type ArchivePayload struct {
	// HTTP status
	Status int
	// HTTP response body content
	Body string
}

// ReadPayload is the payload type of the archiver service read method.
type ReadPayload struct {
	// ID of archive
	ID int
}

// MakeNotFound builds a goa.ServiceError from an error.
func MakeNotFound(err error) *goa.ServiceError {
	return goa.NewServiceError(err, "not_found", false, false, false)
}

// MakeBadRequest builds a goa.ServiceError from an error.
func MakeBadRequest(err error) *goa.ServiceError {
	return goa.NewServiceError(err, "bad_request", false, false, false)
}

// NewArchiveMedia initializes result type ArchiveMedia from viewed result type
// ArchiveMedia.
func NewArchiveMedia(vres *archiverviews.ArchiveMedia) *ArchiveMedia {
	return newArchiveMedia(vres.Projected)
}

// NewViewedArchiveMedia initializes viewed result type ArchiveMedia from
// result type ArchiveMedia using the given view.
func NewViewedArchiveMedia(res *ArchiveMedia, view string) *archiverviews.ArchiveMedia {
	p := newArchiveMediaView(res)
	return &archiverviews.ArchiveMedia{Projected: p, View: "default"}
}

// newArchiveMedia converts projected type ArchiveMedia to service type
// ArchiveMedia.
func newArchiveMedia(vres *archiverviews.ArchiveMediaView) *ArchiveMedia {
	res := &ArchiveMedia{}
	if vres.Href != nil {
		res.Href = *vres.Href
	}
	if vres.Status != nil {
		res.Status = *vres.Status
	}
	if vres.Body != nil {
		res.Body = *vres.Body
	}
	return res
}

// newArchiveMediaView projects result type ArchiveMedia to projected type
// ArchiveMediaView using the "default" view.
func newArchiveMediaView(res *ArchiveMedia) *archiverviews.ArchiveMediaView {
	vres := &archiverviews.ArchiveMediaView{
		Href:   &res.Href,
		Status: &res.Status,
		Body:   &res.Body,
	}
	return vres
}
