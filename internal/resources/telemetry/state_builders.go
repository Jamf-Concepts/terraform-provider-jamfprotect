// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// apiToState maps the API response into the resource state.
func (r *TelemetryV2Resource) apiToState(_ context.Context, data *TelemetryV2ResourceModel, api jamfprotect.TelemetryV2) {
	flags := flagsFromEvents(api.Events)

	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.DiagnosticReports = types.BoolValue(api.LogFileCollection)
	data.PerformanceMetrics = types.BoolValue(api.PerformanceMetrics)
	data.FileHashes = types.BoolValue(api.FileHashing)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.LogFilePath = common.StringsToSet(api.LogFiles)
	data.LogAppsProcesses = types.BoolValue(flags.LogAppsProcesses)
	data.LogAccessAuth = types.BoolValue(flags.LogAccessAuth)
	data.LogUsersGroups = types.BoolValue(flags.LogUsersGroups)
	data.LogPersistence = types.BoolValue(flags.LogPersistence)
	data.LogHardwareSoftware = types.BoolValue(flags.LogHardwareSoftware)
	data.LogAppleSecurity = types.BoolValue(flags.LogAppleSecurity)
	data.LogSystem = types.BoolValue(flags.LogSystem)

	data.Description = types.StringValue(api.Description)
}
