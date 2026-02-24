package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/provider"
)

var (
	version string = "dev"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/smithjw/jamfprotect",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)

	if err != nil {
		slog.Error("failed to serve provider", "error", err)
		os.Exit(1)
	}
}
