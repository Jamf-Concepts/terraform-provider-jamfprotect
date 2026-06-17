// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_forwarding

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// sentinelWriteOnlySecretPath locates the write-only secret within the config.
var sentinelWriteOnlySecretPath = path.Root("microsoft_sentinel").AtName("application_secret_value_wo")

// sentinelWriteOnlySecret reads the write-only Azure client secret from the
// request config. Write-only values exist only in config (never plan or state),
// so this must be sourced from the config on every create and update. Returns
// nil when unset.
func sentinelWriteOnlySecret(ctx context.Context, config tfsdk.Config, diags *diag.Diagnostics) *string {
	var wo types.String
	diags.Append(config.GetAttribute(ctx, sentinelWriteOnlySecretPath, &wo)...)
	if diags.HasError() {
		return nil
	}
	return stringPointerOrNil(wo)
}

// buildDataForwardingInput builds the API input from the Terraform model.
//
// woSecret is the write-only application secret read from the request config
// (nil when unset). When present it takes precedence over the deprecated
// plaintext application_secret_value attribute.
func buildDataForwardingInput(ctx context.Context, data DataForwardingResourceModel, currentSentinel *jamfprotect.ForwardSentinel, woSecret *string, diags *diag.Diagnostics) jamfprotect.DataForwardingInput {
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
	secretValue := woSecret
	if secretValue == nil {
		secretValue = stringPointerOrNil(microsoftSentinel.ApplicationSecretValue)
	}

	input := jamfprotect.DataForwardingInput{
		S3: jamfprotect.ForwardS3Input{
			Bucket:    common.StringValue(s3.BucketName),
			Enabled:   s3.Enabled.ValueBool(),
			Encrypted: s3.EncryptForwardingData.ValueBool(),
			Prefix:    common.StringValue(s3.Prefix),
			Role:      common.StringValue(s3.IAMRole),
		},
		Sentinel: sentinelInputFromCurrent(currentSentinel),
		SentinelV2: jamfprotect.ForwardSentinelV2Input{
			Enabled:       microsoftSentinel.Enabled.ValueBool(),
			AzureTenantID: common.StringValue(microsoftSentinel.DirectoryID),
			AzureClientID: common.StringValue(microsoftSentinel.ApplicationID),
			Endpoint:      common.StringValue(microsoftSentinel.DataCollectionEndpoint),
			Alerts:        alerts,
			Ulogs:         unifiedLogs,
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

// sentinelInputFromCurrent preserves the existing Sentinel v1 config on update.
func sentinelInputFromCurrent(s *jamfprotect.ForwardSentinel) jamfprotect.ForwardSentinelInput {
	if s == nil {
		return jamfprotect.ForwardSentinelInput{}
	}
	return jamfprotect.ForwardSentinelInput(*s)
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
