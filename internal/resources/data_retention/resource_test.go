package data_retention_test

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

// TestAccDataRetentionResource_basic validates update and import behavior.
//
// IMPORTANT: This test is SKIPPED by default due to the API's 24-hour rate limit on updates.
// Data retention settings can only be modified once every 24 hours per tenant.
//
// To run this test, set the environment variable:
//
//	TF_ACC_DATA_RETENTION_TEST=1
//
// The test will fail if the tenant's data retention was updated within the last 24 hours.
// This is expected API behavior, not a provider bug.
func TestAccDataRetentionResource_basic(t *testing.T) {
	// Skip by default unless explicitly enabled
	if os.Getenv("TF_ACC_DATA_RETENTION_TEST") != "1" {
		t.Skip("Skipping data_retention test due to 24-hour API rate limit. " +
			"Set TF_ACC_DATA_RETENTION_TEST=1 to run (may fail if recently updated).")
	}

	resourceName := "jamfprotect_data_retention.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccDataRetentionResourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "informational_alert_days", "90"),
					resource.TestCheckResourceAttr(resourceName, "low_medium_high_severity_alert_days", "365"),
					resource.TestCheckResourceAttr(resourceName, "archived_data_days", "365"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// testAccDataRetentionResourceConfig builds Terraform configuration for data retention.
func testAccDataRetentionResourceConfig() string {
	return `
resource "jamfprotect_data_retention" "test" {
	informational_alert_days            = 90
	low_medium_high_severity_alert_days = 365
	archived_data_days                  = 365
}
`
}
