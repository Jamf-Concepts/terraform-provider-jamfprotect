// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package data_forwarding

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// DataForwardingResourceModel maps the resource schema data.
type DataForwardingResourceModel struct {
	ID                types.String   `tfsdk:"id"`
	AmazonS3          types.Object   `tfsdk:"amazon_s3"`
	MicrosoftSentinel types.Object   `tfsdk:"microsoft_sentinel"`
	Timeouts          timeouts.Value `tfsdk:"timeouts"`
}

// amazonS3ForwardingModel maps the amazon_s3 nested attributes.
type amazonS3ForwardingModel struct {
	BucketName            types.String `tfsdk:"bucket_name"`
	Enabled               types.Bool   `tfsdk:"enabled"`
	EncryptForwardingData types.Bool   `tfsdk:"encrypt_forwarding_data"`
	Prefix                types.String `tfsdk:"prefix"`
	IAMRole               types.String `tfsdk:"iam_role"`
	CloudFormation        types.String `tfsdk:"cloudformation_template"`
	ExternalID            types.String `tfsdk:"external_id"`
}

// microsoftSentinelForwardingModel maps the microsoft_sentinel nested attributes.
type microsoftSentinelForwardingModel struct {
	Enabled                types.Bool   `tfsdk:"enabled"`
	SecretExists           types.Bool   `tfsdk:"secret_exists"`
	DirectoryID            types.String `tfsdk:"directory_id"`
	ApplicationID          types.String `tfsdk:"application_id"`
	DataCollectionEndpoint types.String `tfsdk:"data_collection_endpoint"`
	ApplicationSecretValue types.String `tfsdk:"application_secret_value"`
	Alerts                 types.Object `tfsdk:"alerts"`
	UnifiedLogs            types.Object `tfsdk:"unified_logs"`
	TelemetryDeprecated    types.Object `tfsdk:"telemetry_deprecated"`
	Telemetry              types.Object `tfsdk:"telemetry"`
}

// dataStreamModel maps nested data stream attributes.
type dataStreamModel struct {
	Enabled                       types.Bool   `tfsdk:"enabled"`
	DataCollectionRuleImmutableID types.String `tfsdk:"data_collection_rule_immutable_id"`
	StreamName                    types.String `tfsdk:"stream_name"`
}
