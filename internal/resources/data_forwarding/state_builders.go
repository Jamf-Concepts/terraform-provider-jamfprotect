// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_forwarding

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// apiToState maps the API response into the Terraform state model.
func (r *DataForwardingResource) apiToState(ctx context.Context, data *DataForwardingResourceModel, api jamfprotect.DataForwardingSettings, externalID string, diags *diag.Diagnostics) {
	data.ID = types.StringValue(dataForwardingResourceID)
	data.AmazonS3 = buildAmazonS3Object(api.S3, externalID, diags)
	data.MicrosoftSentinel = buildMicrosoftSentinelObject(ctx, data.MicrosoftSentinel, api.SentinelV2, diags)
}

// buildAmazonS3Object maps the S3 response to a Terraform object.
func buildAmazonS3Object(api jamfprotect.ForwardS3, externalID string, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"bucket_name":             types.StringValue(api.Bucket),
		"enabled":                 types.BoolValue(api.Enabled),
		"encrypt_forwarding_data": types.BoolValue(api.Encrypted),
		"prefix":                  types.StringValue(api.Prefix),
		"iam_role":                types.StringValue(api.Role),
		"cloudformation_template": common.StringValueOrNullValue(api.CloudFormation),
		"external_id":             common.StringValueOrNullValue(externalID),
	}
	obj, d := types.ObjectValue(amazonS3ForwardingAttrTypes, attrs)
	diags.Append(d...)
	if diags.HasError() {
		return types.ObjectNull(amazonS3ForwardingAttrTypes)
	}
	return obj
}

// buildMicrosoftSentinelObject maps the Sentinel v2 response to a Terraform object.
func buildMicrosoftSentinelObject(ctx context.Context, current types.Object, api jamfprotect.ForwardSentinelV2, diags *diag.Diagnostics) types.Object {
	alerts := buildDataStreamObject(api.Alerts, diags)
	unifiedLogs := buildDataStreamObject(api.ULogs, diags)
	telemetryDeprecated := buildDataStreamObject(api.Telemetries, diags)
	telemetry := buildDataStreamObject(api.TelemetriesV2, diags)
	if diags.HasError() {
		return types.ObjectNull(microsoftSentinelForwardingAttrTypes)
	}

	attrs := map[string]attr.Value{
		"enabled":                  types.BoolValue(api.Enabled),
		"secret_exists":            types.BoolValue(api.SecretExists),
		"directory_id":             types.StringValue(api.AzureTenantID),
		"application_id":           types.StringValue(api.AzureClientID),
		"data_collection_endpoint": types.StringValue(api.Endpoint),
		"application_secret_value": applicationSecretStateValue(ctx, current, diags),
		"alerts":                   alerts,
		"unified_logs":             unifiedLogs,
		"telemetry_deprecated":     telemetryDeprecated,
		"telemetry":                telemetry,
	}
	obj, d := types.ObjectValue(microsoftSentinelForwardingAttrTypes, attrs)
	diags.Append(d...)
	if diags.HasError() {
		return types.ObjectNull(microsoftSentinelForwardingAttrTypes)
	}
	return obj
}

// buildDataStreamObject maps a data stream response to a Terraform object.
func buildDataStreamObject(api jamfprotect.DataStream, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"enabled":                           types.BoolValue(api.Enabled),
		"data_collection_rule_immutable_id": stringPointerValueOrNull(api.DcrImmutableID),
		"stream_name":                       stringPointerValueOrNull(api.StreamName),
	}
	obj, d := types.ObjectValue(dataStreamAttrTypes, attrs)
	diags.Append(d...)
	if diags.HasError() {
		return types.ObjectNull(dataStreamAttrTypes)
	}
	return obj
}

// applicationSecretStateValue preserves the current secret when the API omits it.
func applicationSecretStateValue(ctx context.Context, current types.Object, diags *diag.Diagnostics) types.String {
	if current.IsNull() || current.IsUnknown() {
		return types.StringNull()
	}
	var model microsoftSentinelForwardingModel
	diags.Append(current.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return types.StringNull()
	}
	if common.IsKnownString(model.ApplicationSecretValue) {
		return model.ApplicationSecretValue
	}
	return types.StringNull()
}

// stringPointerValueOrNull maps string pointers into Terraform values.
func stringPointerValueOrNull(value *string) attr.Value {
	if value == nil || *value == "" {
		return types.StringNull()
	}
	return types.StringValue(*value)
}
