# Manage Jamf Protect data forwarding settings.
resource "jamfprotect_data_forwarding" "example" {
  amazon_s3 = {
    enabled                 = true
    encrypt_forwarding_data = true
    bucket_name             = "example-bucket"
    prefix                  = "jamfprotect"
    iam_role                = "example-iam-role"
  }

  microsoft_sentinel = {
    enabled                  = true
    directory_id             = "example"
    application_id           = "example"
    data_collection_endpoint = "https://endpoint.azure.com"

    # Supply the Azure client secret as a write-only attribute (Terraform 1.11+):
    # it is sent to Jamf Protect but never stored in state. Bump
    # application_secret_value_wo_version to rotate the secret.
    application_secret_value_wo         = "example-secret"
    application_secret_value_wo_version = "1"

    alerts = {
      enabled                           = true
      data_collection_rule_immutable_id = "example-alerts-rule-id"
      stream_name                       = "example-alerts-stream"
    }

    unified_logs = {
      enabled                           = true
      data_collection_rule_immutable_id = "example-unified-logs-rule-id"
      stream_name                       = "example-unified-logs-stream"
    }

    telemetry_deprecated = {
      enabled = false
    }

    telemetry = {
      enabled                           = true
      data_collection_rule_immutable_id = "example-telemetry-rule-id"
      stream_name                       = "example-telemetry-stream"
    }
  }
}

# Output the CloudFormation template for the Amazon S3 data forwarding configuration.
output "cloud_formation_template" {
  value = jamfprotect_data_forwarding.imported.amazon_s3.cloudformation_template
}

# Export the CloudFormation template for the Amazon S3 data forwarding configuration to a local file.
resource "local_file" "cloud_formation_template" {
  content  = jamfprotect_data_forwarding.imported.amazon_s3.cloudformation_template
  filename = "cloudformation_template.yml"
}
