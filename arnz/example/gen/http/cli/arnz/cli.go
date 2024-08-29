// Code generated by goa v3.18.2, DO NOT EDIT.
//
// Arnz HTTP client CLI support package
//
// Command:
// $ goa gen goa.design/plugins/v3/arnz/example/design -o
// /Users/brendan.keane/Git/plugins/arnz//example

package cli

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
	arnzc "goa.design/plugins/v3/arnz/example/gen/http/arnz/client"
)

// UsageCommands returns the set of commands and sub-commands using the format
//
//	command (subcommand1|subcommand2|...)
func UsageCommands() string {
	return `arnz (create|read|update|delete|health)
`
}

// UsageExamples produces an example of a valid invocation of the CLI tool.
func UsageExamples() string {
	return os.Args[0] + ` arnz create` + "\n" +
		""
}

// ParseEndpoint returns the endpoint and payload as specified on the command
// line.
func ParseEndpoint(
	scheme, host string,
	doer goahttp.Doer,
	enc func(*http.Request) goahttp.Encoder,
	dec func(*http.Response) goahttp.Decoder,
	restore bool,
) (goa.Endpoint, any, error) {
	var (
		arnzFlags = flag.NewFlagSet("arnz", flag.ContinueOnError)

		arnzCreateFlags = flag.NewFlagSet("create", flag.ExitOnError)

		arnzReadFlags = flag.NewFlagSet("read", flag.ExitOnError)

		arnzUpdateFlags = flag.NewFlagSet("update", flag.ExitOnError)

		arnzDeleteFlags = flag.NewFlagSet("delete", flag.ExitOnError)

		arnzHealthFlags = flag.NewFlagSet("health", flag.ExitOnError)
	)
	arnzFlags.Usage = arnzUsage
	arnzCreateFlags.Usage = arnzCreateUsage
	arnzReadFlags.Usage = arnzReadUsage
	arnzUpdateFlags.Usage = arnzUpdateUsage
	arnzDeleteFlags.Usage = arnzDeleteUsage
	arnzHealthFlags.Usage = arnzHealthUsage

	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		return nil, nil, err
	}

	if flag.NArg() < 2 { // two non flag args are required: SERVICE and ENDPOINT (aka COMMAND)
		return nil, nil, fmt.Errorf("not enough arguments")
	}

	var (
		svcn string
		svcf *flag.FlagSet
	)
	{
		svcn = flag.Arg(0)
		switch svcn {
		case "arnz":
			svcf = arnzFlags
		default:
			return nil, nil, fmt.Errorf("unknown service %q", svcn)
		}
	}
	if err := svcf.Parse(flag.Args()[1:]); err != nil {
		return nil, nil, err
	}

	var (
		epn string
		epf *flag.FlagSet
	)
	{
		epn = svcf.Arg(0)
		switch svcn {
		case "arnz":
			switch epn {
			case "create":
				epf = arnzCreateFlags

			case "read":
				epf = arnzReadFlags

			case "update":
				epf = arnzUpdateFlags

			case "delete":
				epf = arnzDeleteFlags

			case "health":
				epf = arnzHealthFlags

			}

		}
	}
	if epf == nil {
		return nil, nil, fmt.Errorf("unknown %q endpoint %q", svcn, epn)
	}

	// Parse endpoint flags if any
	if svcf.NArg() > 1 {
		if err := epf.Parse(svcf.Args()[1:]); err != nil {
			return nil, nil, err
		}
	}

	var (
		data     any
		endpoint goa.Endpoint
		err      error
	)
	{
		switch svcn {
		case "arnz":
			c := arnzc.NewClient(scheme, host, doer, enc, dec, restore)
			switch epn {
			case "create":
				endpoint = c.Create()
			case "read":
				endpoint = c.Read()
			case "update":
				endpoint = c.Update()
			case "delete":
				endpoint = c.Delete()
			case "health":
				endpoint = c.Health()
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}

	return endpoint, data, nil
}

// arnzUsage displays the usage of the arnz command and its subcommands.
func arnzUsage() {
	fmt.Fprintf(os.Stderr, `Service is the Arnz service interface.
Usage:
    %[1]s [globalflags] arnz COMMAND [flags]

COMMAND:
    create: Create implements create.
    read: Read implements read.
    update: Update implements update.
    delete: Delete implements delete.
    health: Health implements health.

Additional help:
    %[1]s arnz COMMAND --help
`, os.Args[0])
}
func arnzCreateUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] arnz create

Create implements create.

Example:
    %[1]s arnz create
`, os.Args[0])
}

func arnzReadUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] arnz read

Read implements read.

Example:
    %[1]s arnz read
`, os.Args[0])
}

func arnzUpdateUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] arnz update

Update implements update.

Example:
    %[1]s arnz update
`, os.Args[0])
}

func arnzDeleteUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] arnz delete

Delete implements delete.

Example:
    %[1]s arnz delete
`, os.Args[0])
}

func arnzHealthUsage() {
	fmt.Fprintf(os.Stderr, `%[1]s [flags] arnz health

Health implements health.

Example:
    %[1]s arnz health
`, os.Args[0])
}