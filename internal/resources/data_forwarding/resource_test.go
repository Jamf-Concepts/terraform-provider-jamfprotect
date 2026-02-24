// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_forwarding_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/testutil"
)

// Environment variable keys for data forwarding acceptance tests.
const (
	dataForwardingAccEnvFlag     = "TF_ACC_DATA_FORWARDING_TEST"
	dataForwardingS3BucketEnv    = "TF_ACC_DATA_FORWARDING_S3_BUCKET"
	dataForwardingS3PrefixEnv    = "TF_ACC_DATA_FORWARDING_S3_PREFIX"
	dataForwardingAzureTenantEnv = "TF_ACC_DATA_FORWARDING_AZURE_TENANT_ID"
	dataForwardingAzureClientEnv = "TF_ACC_DATA_FORWARDING_AZURE_CLIENT_ID"
	dataForwardingDceEnv         = "TF_ACC_DATA_FORWARDING_DCE"
)

// TestAccDataForwardingResource_basic validates update and import behavior.
func TestAccDataForwardingResource_basic(t *testing.T) {
	if os.Getenv(dataForwardingAccEnvFlag) != "1" {
		t.Skip("Skipping data_forwarding acceptance test. Set TF_ACC_DATA_FORWARDING_TEST=1 to run.")
	}

	bucket := testAccDataForwardingRequiredEnv(t, dataForwardingS3BucketEnv)
	prefix := testAccDataForwardingRequiredEnv(t, dataForwardingS3PrefixEnv)
	directoryID := testAccDataForwardingRequiredEnv(t, dataForwardingAzureTenantEnv)
	applicationID := testAccDataForwardingRequiredEnv(t, dataForwardingAzureClientEnv)
	endpoint := testAccDataForwardingRequiredEnv(t, dataForwardingDceEnv)

	resourceName := "jamfprotect_data_forwarding.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV6ProviderFactories: testutil.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: testAccDataForwardingResourceConfig(bucket, prefix, directoryID, applicationID, endpoint),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "amazon_s3.bucket_name", bucket),
					resource.TestCheckResourceAttr(resourceName, "amazon_s3.prefix", prefix),
					resource.TestCheckResourceAttr(resourceName, "microsoft_sentinel.directory_id", directoryID),
					resource.TestCheckResourceAttr(resourceName, "microsoft_sentinel.application_id", applicationID),
					resource.TestCheckResourceAttr(resourceName, "microsoft_sentinel.data_collection_endpoint", endpoint),
					resource.TestCheckResourceAttr(resourceName, "microsoft_sentinel.alerts.enabled", "false"),
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

// testAccDataForwardingRequiredEnv returns a required environment variable value.
func testAccDataForwardingRequiredEnv(t *testing.T, key string) string {
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("environment variable %s must be set for data_forwarding acceptance tests", key)
	}
	return value
}

// testAccDataForwardingResourceConfig builds Terraform configuration for data forwarding.
func testAccDataForwardingResourceConfig(bucket, prefix, directoryID, applicationID, endpoint string) string {
	return fmt.Sprintf(`
resource "jamfprotect_data_forwarding" "test" {
  amazon_s3 = {
    bucket_name = %q
    prefix      = %q
    enabled     = false
  }

  microsoft_sentinel = {
    enabled                  = false
    directory_id             = %q
    application_id           = %q
    data_collection_endpoint = %q

    alerts = {
      enabled = false
    }

    unified_logs = {
      enabled = false
    }

    telemetry_deprecated = {
      enabled = false
    }

    telemetry = {
      enabled = false
    }
  }
}
`, bucket, prefix, directoryID, applicationID, endpoint)
}
