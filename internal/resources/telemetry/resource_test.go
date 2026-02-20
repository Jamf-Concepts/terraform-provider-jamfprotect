// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetry_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

func TestAccTelemetryV2Resource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-telemetry")
	resourceName := "jamfprotect_telemetry.test"

	if testing.Short() {
		t.Skip("skipping acceptance test")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			// Create and Read.
			{
				Config: testAccTelemetryV2ResourceConfig(rName, "Acceptance test telemetry v2", false, false, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Acceptance test telemetry v2"),
					resource.TestCheckResourceAttr(resourceName, "log_access_and_authentication", "true"),
				),
			},
			// Import.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update.
			{
				Config: testAccTelemetryV2ResourceConfig(rName, "Updated telemetry v2", true, true, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated telemetry v2"),
					resource.TestCheckResourceAttr(resourceName, "collect_diagnostic_and_crash_reports", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_hardware_and_software", "true"),
				),
			},
		},
	})
}

func testAccTelemetryV2ResourceConfig(name, description string, diagnostics, performance, hardware bool) string {
	logFilePath := "[]"
	fileHashes := "false"

	if diagnostics {
		logFilePath = `["/var/log/system.log"]`
		fileHashes = "true"
	}

	config := fmt.Sprintf(`
resource "jamfprotect_telemetry" "test" {
  name               = %[1]q
  description        = %[2]q
	log_file_path       = %[5]s
	collect_diagnostic_and_crash_reports = %[3]t
	collect_performance_metrics = %[4]t
	file_hashes         = %[6]s
	log_access_and_authentication = true
`, name, description, diagnostics, performance, logFilePath, fileHashes)

	if hardware {
		config += `	log_hardware_and_software = true
`
	}

	config += "}\n"
	return config
}
