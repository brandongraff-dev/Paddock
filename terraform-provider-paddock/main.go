// Command terraform-provider-paddock is the Terraform provider for Paddock.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/brandongraff-dev/paddock/terraform-provider-paddock/internal/provider"
)

// version is set by the release build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/paddock/paddock",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
