package unified_logging_filter_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/testutil"
)

func testAccUnifiedLoggingFilterCheckDestroy(s *terraform.State) error {
	svc := testutil.TestAccService()
	if svc == nil {
		return fmt.Errorf("service not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_unified_logging_filter" {
			continue
		}
		result, err := svc.GetUnifiedLoggingFilter(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("unified logging filter %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccUnifiedLoggingFilterResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-ulf")
	resourceName := "jamfprotect_unified_logging_filter.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccUnifiedLoggingFilterCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccUnifiedLoggingFilterResourceConfig(rName, "Test filter description", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test filter description"),
					resource.TestCheckResourceAttr(resourceName, "filter", `subsystem == "com.apple.securityd"`),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "tags.#", "5"),
					resource.TestCheckResourceAttr(resourceName, "tags.0", "alpha"),
					resource.TestCheckResourceAttr(resourceName, "tags.1", "beta"),
					resource.TestCheckResourceAttr(resourceName, "tags.2", "delta"),
					resource.TestCheckResourceAttr(resourceName, "tags.3", "gamma"),
					resource.TestCheckResourceAttr(resourceName, "tags.4", "terraform-test"),
					resource.TestCheckResourceAttrSet(resourceName, "created"),
					resource.TestCheckResourceAttrSet(resourceName, "updated"),
				),
			},
			// ImportState testing.
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update: disable the filter.
			{
				Config: testAccUnifiedLoggingFilterResourceConfig(rName, "Updated description", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
					resource.TestCheckResourceAttr(resourceName, "enabled", "false"),
				),
			},
		},
	})
}

func testAccUnifiedLoggingFilterResourceConfig(name, description string, enabled bool) string {
	return fmt.Sprintf(`
resource "jamfprotect_unified_logging_filter" "test" {
  name        = %[1]q
  description = %[2]q
  filter      = "subsystem == \"com.apple.securityd\""
  enabled     = %[3]t
  tags        = ["alpha", "beta", "gamma", "delta", "terraform-test"]
}
`, name, description, enabled)
}
