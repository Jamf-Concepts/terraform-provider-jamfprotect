// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package data_retention_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

// TestAccDataRetentionResource_basic validates update and import behavior.
//
// IMPORTANT: This test may fail with "Data retention settings can only be updated once every 24 hours"
// if the test tenant has recently modified retention settings. This is a Jamf Protect API business rule,
// not a provider bug. To resolve:
//   - Wait 24 hours before re-running, OR
//   - Use a fresh test tenant that hasn't had retention settings modified recently
func TestAccDataRetentionResource_basic(t *testing.T) {
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
