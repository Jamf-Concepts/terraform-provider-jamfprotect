package analytic_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

func testAccAnalyticCheckDestroy(s *terraform.State) error {
	svc := testutil.TestAccService()
	if svc == nil {
		return fmt.Errorf("service not configured")
	}
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "jamfprotect_analytic" {
			continue
		}
		result, err := svc.GetAnalytic(context.Background(), rs.Primary.ID)
		if err == nil && result != nil {
			return fmt.Errorf("analytic %s still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestAccAnalyticResource_basic(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccAnalyticCheckDestroy,
		Steps: []resource.TestStep{
			// Create and Read testing.
			{
				Config: testAccAnalyticResourceConfig(rName, "Test analytic description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test analytic description"),
					resource.TestCheckResourceAttr(resourceName, "sensor_type", "File System Event"),
					resource.TestCheckResourceAttr(resourceName, "severity", "Informational"),
					resource.TestCheckResourceAttr(resourceName, "level", "0"),
					resource.TestCheckResourceAttr(resourceName, "tags.#", "5"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "alpha"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "beta"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "gamma"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "delta"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tags.*", "terraform-test"),
					resource.TestCheckResourceAttr(resourceName, "categories.#", "5"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "DefenseEvasion"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "Execution"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "Persistence"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "PrivilegeEscalation"),
					resource.TestCheckTypeSetElemAttr(resourceName, "categories.*", "Testing"),
					resource.TestCheckResourceAttr(resourceName, "snapshot_files.#", "5"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/a.log"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/b.log"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/c.log"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/d.log"),
					resource.TestCheckTypeSetElemAttr(resourceName, "snapshot_files.*", "/tmp/e.log"),
					resource.TestCheckResourceAttr(resourceName, "add_to_jamf_pro_smart_group", "false"),
					resource.TestCheckResourceAttr(resourceName, "context_item.#", "0"),
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
			// Update and Read testing.
			{
				Config: testAccAnalyticResourceConfig(rName, "Updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Updated description"),
				),
			},
		},
	})
}

func TestAccAnalyticResource_withSmartGroup(t *testing.T) {
	rName := acctest.RandomWithPrefix("tf-acc-analytic")
	resourceName := "jamfprotect_analytic.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		CheckDestroy:             testAccAnalyticCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAnalyticResourceConfigWithSmartGroup(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "add_to_jamf_pro_smart_group", "true"),
					resource.TestCheckResourceAttr(resourceName, "jamf_pro_smart_group_identifier", "smartgroup"),
					resource.TestCheckResourceAttr(resourceName, "context_item.#", "5"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_alpha",
						"type": "String",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_beta",
						"type": "String",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_gamma",
						"type": "String",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_delta",
						"type": "String",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "context_item.*", map[string]string{
						"name": "context_epsilon",
						"type": "String",
					}),
				),
			},
		},
	})
}

func testAccAnalyticResourceConfig(name, description string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
	sensor_type  = "File System Event"
  description = %[2]q
	filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Informational"

  tags           = ["alpha", "beta", "gamma", "delta", "terraform-test"]
  categories     = ["DefenseEvasion", "Execution", "Persistence", "PrivilegeEscalation", "Testing"]
  snapshot_files = ["/tmp/a.log", "/tmp/b.log", "/tmp/c.log", "/tmp/d.log", "/tmp/e.log"]

	add_to_jamf_pro_smart_group = false
	context_item                 = []
}
`, name, description)
}

func testAccAnalyticResourceConfigWithSmartGroup(name string) string {
	return fmt.Sprintf(`
resource "jamfprotect_analytic" "test" {
  name        = %[1]q
	sensor_type  = "File System Event"
	description = "Analytic with Smart Group"
	filter      = "( $event.type == Filter )"
  level       = 0
  severity    = "Low"

  tags           = ["alpha", "beta", "gamma", "delta", "terraform-test"]
  categories     = ["DefenseEvasion", "Execution", "Persistence", "PrivilegeEscalation", "Testing"]
  snapshot_files = ["/tmp/a.log", "/tmp/b.log", "/tmp/c.log", "/tmp/d.log", "/tmp/e.log"]

	add_to_jamf_pro_smart_group   = true
	jamf_pro_smart_group_identifier = "smartgroup"

	context_item = [
		{
			name        = "context_alpha"
			type        = "String"
			expressions = [""]
		},
		{
			name        = "context_beta"
			type        = "String"
			expressions = [""]
		},
		{
			name        = "context_gamma"
			type        = "String"
			expressions = [""]
		},
		{
			name        = "context_delta"
			type        = "String"
			expressions = [""]
		},
		{
			name        = "context_epsilon"
			type        = "String"
			expressions = [""]
		},
	]
}
`, name)
}
