// Code generated by goa v3.12.1, DO NOT EDIT.
//
// fetcher views
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/fetcher/fetcher/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/fetcher/fetcher

package views

import (
	goa "goa.design/goa/v3/pkg"
)

// FetchMedia is the viewed result type that is projected based on a view.
type FetchMedia struct {
	// Type to project
	Projected *FetchMediaView
	// View to render
	View string
}

// FetchMediaView is a type that runs validations on a projected type.
type FetchMediaView struct {
	// HTTP status code returned by fetched service
	Status *int
	// The href to the corresponding archive in the archiver service
	ArchiveHref *string
}

var (
	// FetchMediaMap is a map indexing the attribute names of FetchMedia by view
	// name.
	FetchMediaMap = map[string][]string{
		"default": {
			"status",
			"archive_href",
		},
	}
)

// ValidateFetchMedia runs the validations defined on the viewed result type
// FetchMedia.
func ValidateFetchMedia(result *FetchMedia) (err error) {
	switch result.View {
	case "default", "":
		err = ValidateFetchMediaView(result.Projected)
	default:
		err = goa.InvalidEnumValueError("view", result.View, []any{"default"})
	}
	return
}

// ValidateFetchMediaView runs the validations defined on FetchMediaView using
// the "default" view.
func ValidateFetchMediaView(result *FetchMediaView) (err error) {
	if result.Status == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("status", "result"))
	}
	if result.ArchiveHref == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("archive_href", "result"))
	}
	if result.Status != nil {
		if *result.Status < 0 {
			err = goa.MergeErrors(err, goa.InvalidRangeError("result.status", *result.Status, 0, true))
		}
	}
	if result.ArchiveHref != nil {
		err = goa.MergeErrors(err, goa.ValidatePattern("result.archive_href", *result.ArchiveHref, "^/archive/[0-9]+$"))
	}
	return
}
