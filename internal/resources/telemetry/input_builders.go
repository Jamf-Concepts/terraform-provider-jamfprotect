// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// buildInput builds the API input from the resource model.
func (r *TelemetryV2Resource) buildInput(ctx context.Context, data TelemetryV2ResourceModel, diags *diag.Diagnostics) *jamfprotect.TelemetryV2Input {
	flags := telemetryEventFlags{
		LogAppsProcesses:    data.LogAppsProcesses.ValueBool(),
		LogAccessAuth:       data.LogAccessAuth.ValueBool(),
		LogUsersGroups:      data.LogUsersGroups.ValueBool(),
		LogPersistence:      data.LogPersistence.ValueBool(),
		LogHardwareSoftware: data.LogHardwareSoftware.ValueBool(),
		LogAppleSecurity:    data.LogAppleSecurity.ValueBool(),
		LogSystem:           data.LogSystem.ValueBool(),
	}

	input := &jamfprotect.TelemetryV2Input{
		Name:               data.Name.ValueString(),
		LogFileCollection:  data.DiagnosticReports.ValueBool(),
		PerformanceMetrics: data.PerformanceMetrics.ValueBool(),
		FileHashing:        data.FileHashes.ValueBool(),
		LogFiles:           common.SetToStrings(ctx, data.LogFilePath, diags),
		Events:             eventsFromFlags(flags),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	return input
}
