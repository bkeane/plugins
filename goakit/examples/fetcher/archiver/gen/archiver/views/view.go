// Code generated by goa v3.2.1, DO NOT EDIT.
//
// archiver views
//
// Command:
// $ goa gen goa.design/plugins/v3/goakit/examples/fetcher/archiver/design -o
// $(GOPATH)/src/goa.design/plugins/goakit/examples/fetcher/archiver

package views

import (
	goa "goa.design/goa/v3/pkg"
)

// ArchiveMedia is the viewed result type that is projected based on a view.
type ArchiveMedia struct {
	// Type to project
	Projected *ArchiveMediaView
	// View to render
	View string
}

// ArchiveMediaView is a type that runs validations on a projected type.
type ArchiveMediaView struct {
	// The archive resouce href
	Href *string
	// HTTP status
	Status *int
	// HTTP response body content
	Body *string
}

var (
	// ArchiveMediaMap is a map of attribute names in result type ArchiveMedia
	// indexed by view name.
	ArchiveMediaMap = map[string][]string{
		"default": []string{
			"href",
			"status",
			"body",
		},
	}
)

// ValidateArchiveMedia runs the validations defined on the viewed result type
// ArchiveMedia.
func ValidateArchiveMedia(result *ArchiveMedia) (err error) {
	switch result.View {
	case "default", "":
		err = ValidateArchiveMediaView(result.Projected)
	default:
		err = goa.InvalidEnumValueError("view", result.View, []interface{}{"default"})
	}
	return
}

// ValidateArchiveMediaView runs the validations defined on ArchiveMediaView
// using the "default" view.
func ValidateArchiveMediaView(result *ArchiveMediaView) (err error) {
	if result.Href == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("href", "result"))
	}
	if result.Status == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("status", "result"))
	}
	if result.Body == nil {
		err = goa.MergeErrors(err, goa.MissingFieldError("body", "result"))
	}
	if result.Href != nil {
		err = goa.MergeErrors(err, goa.ValidatePattern("result.href", *result.Href, "^/archive/[0-9]+$"))
	}
	if result.Status != nil {
		if *result.Status < 0 {
			err = goa.MergeErrors(err, goa.InvalidRangeError("result.status", *result.Status, 0, true))
		}
	}
	return
}
