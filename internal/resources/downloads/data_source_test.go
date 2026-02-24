package downloads_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

// TestAccDownloadsDataSource_basic validates download metadata is returned.
func TestAccDownloadsDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccDownloadsDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.jamfprotect_downloads.test", "installer_package.version"),
				),
			},
		},
	})
}

// testAccDownloadsDataSourceConfig builds Terraform configuration for downloads.
func testAccDownloadsDataSourceConfig() string {
	return `
data "jamfprotect_downloads" "test" {}
`
}
