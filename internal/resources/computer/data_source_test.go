package computer_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

// TestAccComputersDataSource_basic validates the plural data source lists computers.
func TestAccComputersDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccComputersDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify computers list exists (may be empty in test environment)
					resource.TestCheckResourceAttrSet("data.jamfprotect_computers.test", "computers.#"),
				),
			},
		},
	})
}

// testAccComputersDataSourceConfig returns the config for the plural data source test.
func testAccComputersDataSourceConfig() string {
	return `
data "jamfprotect_computers" "test" {}
`
}
