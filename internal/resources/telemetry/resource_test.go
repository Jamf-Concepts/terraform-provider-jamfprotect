// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

// testAccTelemetryV2CheckDestroy verifies the telemetry config has been deleted.
func testAccTelemetryV2CheckDestroy(s *terraform.State) error {
	c := testutil.TestAccClient()
	if c == nil {
		return fmt.Errorf("client not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_telemetry" {
			continue
		}
		result, err := c.GetTelemetryV2(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("telemetry v2 %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

// TestAccTelemetryV2Resource_basic validates create, read, update, and import behavior.
func TestAccTelemetryV2Resource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-telemetry")
	resourceName := "jamfprotect_telemetry.test"

	if testing.Short() {
		t.Skip("skipping acceptance test")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccTelemetryV2CheckDestroy,
		Steps: []resource.TestStep{
			// Create with a single event category.
			{
				Config: testAccTelemetryV2ResourceConfig(rName, "Acceptance test telemetry v2", telemetryConfigOpts{
					LogAccessAuth: true,
				}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Acceptance test telemetry v2"),
					resource.TestCheckResourceAttr(resourceName, "log_access_and_authentication", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_applications_and_processes", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_users_and_groups", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_persistence", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_hardware_and_software", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_apple_security", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_system", "false"),
					resource.TestCheckResourceAttr(resourceName, "collect_diagnostic_and_crash_reports", "false"),
					resource.TestCheckResourceAttr(resourceName, "collect_performance_metrics", "false"),
					resource.TestCheckResourceAttr(resourceName, "file_hashes", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
				),
			},
			// Import.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update: enable all categories, diagnostics, performance, file hashes, and log files.
			{
				Config: testAccTelemetryV2ResourceConfig(rName, "Updated telemetry v2", telemetryConfigOpts{
					LogAccessAuth:       true,
					LogAppsProcesses:    true,
					LogUsersGroups:      true,
					LogPersistence:      true,
					LogHardwareSoftware: true,
					LogAppleSecurity:    true,
					LogSystem:           true,
					Diagnostics:         true,
					Performance:         true,
					FileHashes:          true,
					LogFiles:            []string{"/var/log/system.log", "/var/log/install.log", "/var/log/apache2/access_log", "/var/log/apache2/error_log", "/var/log/wifi.log"},
				}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated telemetry v2"),
					resource.TestCheckResourceAttr(resourceName, "log_access_and_authentication", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_applications_and_processes", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_users_and_groups", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_persistence", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_hardware_and_software", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_apple_security", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_system", "true"),
					resource.TestCheckResourceAttr(resourceName, "collect_diagnostic_and_crash_reports", "true"),
					resource.TestCheckResourceAttr(resourceName, "collect_performance_metrics", "true"),
					resource.TestCheckResourceAttr(resourceName, "file_hashes", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_file_path.#", "5"),
				),
			},
			// Update: disable most categories, verify they revert to false.
			{
				Config: testAccTelemetryV2ResourceConfig(rName, "Updated telemetry v2", telemetryConfigOpts{
					LogAppsProcesses: true,
				}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "log_applications_and_processes", "true"),
					resource.TestCheckResourceAttr(resourceName, "log_access_and_authentication", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_users_and_groups", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_persistence", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_hardware_and_software", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_apple_security", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_system", "false"),
					resource.TestCheckResourceAttr(resourceName, "collect_diagnostic_and_crash_reports", "false"),
					resource.TestCheckResourceAttr(resourceName, "collect_performance_metrics", "false"),
					resource.TestCheckResourceAttr(resourceName, "file_hashes", "false"),
					resource.TestCheckResourceAttr(resourceName, "log_file_path.#", "0"),
				),
			},
		},
	})
}

// TestAccTelemetriesV2DataSource_basic validates the data source lists telemetry configurations.
func TestAccTelemetriesV2DataSource_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccTelemetriesV2DataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.jamfprotect_telemetries.test", "telemetries.#"),
				),
			},
		},
	})
}

// telemetryConfigOpts controls which attributes are set in the test config.
type telemetryConfigOpts struct {
	LogAccessAuth       bool
	LogAppsProcesses    bool
	LogUsersGroups      bool
	LogPersistence      bool
	LogHardwareSoftware bool
	LogAppleSecurity    bool
	LogSystem           bool
	Diagnostics         bool
	Performance         bool
	FileHashes          bool
	LogFiles            []string
}

// testAccTelemetryV2ResourceConfig builds Terraform configuration for a telemetry v2 resource.
func testAccTelemetryV2ResourceConfig(name, description string, opts telemetryConfigOpts) string {
	logFilePath := "[]"
	if len(opts.LogFiles) > 0 {
		logFilePath = "["
		for i, f := range opts.LogFiles {
			if i > 0 {
				logFilePath += ", "
			}
			logFilePath += fmt.Sprintf("%q", f)
		}
		logFilePath += "]"
	}

	return fmt.Sprintf(`
resource "jamfprotect_telemetry" "test" {
  name                                 = %[1]q
  description                          = %[2]q
  log_file_path                        = %[3]s
  collect_diagnostic_and_crash_reports  = %[4]t
  collect_performance_metrics           = %[5]t
  file_hashes                           = %[6]t
  log_access_and_authentication         = %[7]t
  log_applications_and_processes        = %[8]t
  log_users_and_groups                  = %[9]t
  log_persistence                       = %[10]t
  log_hardware_and_software             = %[11]t
  log_apple_security                    = %[12]t
  log_system                            = %[13]t
}
`, name, description, logFilePath,
		opts.Diagnostics, opts.Performance, opts.FileHashes,
		opts.LogAccessAuth, opts.LogAppsProcesses, opts.LogUsersGroups,
		opts.LogPersistence, opts.LogHardwareSoftware, opts.LogAppleSecurity,
		opts.LogSystem)
}

// testAccTelemetriesV2DataSourceConfig builds Terraform configuration for the telemetries data source.
func testAccTelemetriesV2DataSourceConfig() string {
	return `
data "jamfprotect_telemetries" "test" {}
`
}
