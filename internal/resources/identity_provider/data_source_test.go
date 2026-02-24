package identity_provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

// TestAccIdentityProvidersDataSource_basic validates the data source lists identity provider connections.
func TestAccIdentityProvidersDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityProvidersDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.jamfprotect_identity_providers.test", "identity_providers.#"),
				),
			},
		},
	})
}

// testAccIdentityProvidersDataSourceConfig builds Terraform configuration for identity providers.
func testAccIdentityProvidersDataSourceConfig() string {
	return `
data "jamfprotect_identity_providers" "test" {}
`
}
