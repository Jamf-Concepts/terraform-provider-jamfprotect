// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package telemetry

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TelemetryV2ResourceModel maps the resource schema data.
type TelemetryV2ResourceModel struct {
	ID                  types.String   `tfsdk:"id"`
	Name                types.String   `tfsdk:"name"`
	Description         types.String   `tfsdk:"description"`
	LogFilePath         types.List     `tfsdk:"log_file_path"`
	DiagnosticReports   types.Bool     `tfsdk:"collect_diagnostic_and_crash_reports"`
	PerformanceMetrics  types.Bool     `tfsdk:"collect_performance_metrics"`
	FileHashes          types.Bool     `tfsdk:"file_hashes"`
	LogAppsProcesses    types.Bool     `tfsdk:"log_applications_and_processes"`
	LogAccessAuth       types.Bool     `tfsdk:"log_access_and_authentication"`
	LogUsersGroups      types.Bool     `tfsdk:"log_users_and_groups"`
	LogPersistence      types.Bool     `tfsdk:"log_persistence"`
	LogHardwareSoftware types.Bool     `tfsdk:"log_hardware_and_software"`
	LogAppleSecurity    types.Bool     `tfsdk:"log_apple_security"`
	LogSystem           types.Bool     `tfsdk:"log_system"`
	Created             types.String   `tfsdk:"created"`
	Updated             types.String   `tfsdk:"updated"`
	Timeouts            timeouts.Value `tfsdk:"timeouts"`
}
