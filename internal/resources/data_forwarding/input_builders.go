// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_forwarding

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// buildDataForwardingInput builds the API input from the Terraform model.
func buildDataForwardingInput(ctx context.Context, data DataForwardingResourceModel, currentSentinel jamfprotect.ForwardSentinel, diags *diag.Diagnostics) jamfprotect.DataForwardingInput {
	var s3 amazonS3ForwardingModel
	var microsoftSentinel microsoftSentinelForwardingModel

	diags.Append(data.AmazonS3.As(ctx, &s3, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return jamfprotect.DataForwardingInput{}
	}
	diags.Append(data.MicrosoftSentinel.As(ctx, &microsoftSentinel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return jamfprotect.DataForwardingInput{}
	}

	alerts := buildDataStreamInput(ctx, microsoftSentinel.Alerts, diags)
	unifiedLogs := buildDataStreamInput(ctx, microsoftSentinel.UnifiedLogs, diags)
	telemetryDeprecated := buildDataStreamInput(ctx, microsoftSentinel.TelemetryDeprecated, diags)
	telemetry := buildDataStreamInput(ctx, microsoftSentinel.Telemetry, diags)
	if diags.HasError() {
		return jamfprotect.DataForwardingInput{}
	}
	secretValue := stringPointerOrNil(microsoftSentinel.ApplicationSecretValue)

	input := jamfprotect.DataForwardingInput{
		S3: jamfprotect.ForwardS3Input{
			Bucket:    common.StringValue(s3.BucketName),
			Enabled:   s3.Enabled.ValueBool(),
			Encrypted: s3.EncryptForwardingData.ValueBool(),
			Prefix:    common.StringValue(s3.Prefix),
			Role:      common.StringValue(s3.IAMRole),
		},
		Sentinel: jamfprotect.ForwardSentinelInput(currentSentinel),
		SentinelV2: jamfprotect.ForwardSentinelV2Input{
			Enabled:       microsoftSentinel.Enabled.ValueBool(),
			AzureTenantID: common.StringValue(microsoftSentinel.DirectoryID),
			AzureClientID: common.StringValue(microsoftSentinel.ApplicationID),
			Endpoint:      common.StringValue(microsoftSentinel.DataCollectionEndpoint),
			Alerts:        alerts,
			ULogs:         unifiedLogs,
			Telemetries:   telemetryDeprecated,
			TelemetriesV2: telemetry,
		},
	}
	if secretValue != nil {
		input.SentinelV2.AzureClientSecret = secretValue
	}
	return input
}

// buildDataStreamInput builds a data stream input from the Terraform object.
func buildDataStreamInput(ctx context.Context, obj types.Object, diags *diag.Diagnostics) jamfprotect.DataStreamInput {
	var stream dataStreamModel
	diags.Append(obj.As(ctx, &stream, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return jamfprotect.DataStreamInput{}
	}

	return jamfprotect.DataStreamInput{
		Enabled:        stream.Enabled.ValueBool(),
		DcrImmutableID: stringPointerOrNil(stream.DataCollectionRuleImmutableID),
		StreamName:     stringPointerOrNil(stream.StreamName),
	}
}

// stringPointerOrNil returns a string pointer for non-empty values.
func stringPointerOrNil(value basetypes.StringValue) *string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	trimmed := strings.TrimSpace(value.ValueString())
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
