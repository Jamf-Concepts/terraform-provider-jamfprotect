// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetryv2_test

import (
	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccTelemetryV2Resource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			// Create and Read.
			{
				Config: `
resource "jamfprotect_telemetry_v2" "test" {
  name               = "tf-acc-test-telemetry"
  description        = "Acceptance test telemetry v2"
  log_files          = []
  log_file_collection = false
  performance_metrics = false
  file_hashing       = false
  events             = ["exec", "sudo"]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("jamfprotect_telemetry_v2.test", "id"),
					resource.TestCheckResourceAttr("jamfprotect_telemetry_v2.test", "name", "tf-acc-test-telemetry"),
					resource.TestCheckResourceAttr("jamfprotect_telemetry_v2.test", "events.#", "2"),
				),
			},
			// Import.
			{
				ResourceName:      "jamfprotect_telemetry_v2.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update.
			{
				Config: `
resource "jamfprotect_telemetry_v2" "test" {
  name                = "tf-acc-test-telemetry-updated"
  description         = "Updated telemetry v2"
  log_files           = ["/var/log/system.log"]
  log_file_collection = true
  performance_metrics = true
  file_hashing        = true
  events              = ["exec", "sudo", "mount", "authentication"]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("jamfprotect_telemetry_v2.test", "name", "tf-acc-test-telemetry-updated"),
					resource.TestCheckResourceAttr("jamfprotect_telemetry_v2.test", "log_file_collection", "true"),
					resource.TestCheckResourceAttr("jamfprotect_telemetry_v2.test", "events.#", "4"),
				),
			},
		},
	})
}
