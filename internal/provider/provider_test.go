// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories is used to instantiate a provider during acceptance testing.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"jamfprotect": providerserver.NewProtocol6WithError(New("test")()),
}

func testAccPreCheck(t *testing.T) {
	t.Helper()

	required := []string{"JAMFPROTECT_URL", "JAMFPROTECT_CLIENT_ID", "JAMFPROTECT_CLIENT_SECRET"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			t.Fatalf("environment variable %s must be set for acceptance tests", env)
		}
	}

	if testAccEnumValues == nil {
		values, err := testAccProbeEnumValues(t)
		if err != nil {
			t.Fatalf("failed to probe enum values: %v", err)
		}
		testAccEnumValues = values
	}
}

var testAccEnumValues map[string][]string
