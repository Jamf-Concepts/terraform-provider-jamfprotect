// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetry_test

import (
	"testing"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"

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
resource "jamfprotect_telemetry" "test" {
  name               = "tf-acc-test-telemetry"
  description        = "Acceptance test telemetry v2"
	log_file_path       = []
	collect_diagnostic_and_crash_reports = false
	collect_performance_metrics = false
	file_hashes         = false
	log_access_and_authentication = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("jamfprotect_telemetry.test", "id"),
					resource.TestCheckResourceAttr("jamfprotect_telemetry.test", "name", "tf-acc-test-telemetry"),
					resource.TestCheckResourceAttr("jamfprotect_telemetry.test", "log_access_and_authentication", "true"),
				),
			},
			// Import.
			{
				ResourceName:      "jamfprotect_telemetry.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update.
			{
				Config: `
resource "jamfprotect_telemetry" "test" {
  name                = "tf-acc-test-telemetry-updated"
  description         = "Updated telemetry v2"
	log_file_path        = ["/var/log/system.log"]
	collect_diagnostic_and_crash_reports = true
	collect_performance_metrics = true
	file_hashes          = true
	log_access_and_authentication = true
	log_hardware_and_software     = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("jamfprotect_telemetry.test", "name", "tf-acc-test-telemetry-updated"),
					resource.TestCheckResourceAttr("jamfprotect_telemetry.test", "collect_diagnostic_and_crash_reports", "true"),
					resource.TestCheckResourceAttr("jamfprotect_telemetry.test", "log_hardware_and_software", "true"),
				),
			},
		},
	})
}
