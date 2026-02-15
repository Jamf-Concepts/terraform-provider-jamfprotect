// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// PlanResourceModel maps the resource schema data.
type PlanResourceModel struct {
	ID                       types.String   `tfsdk:"id"`
	Hash                     types.String   `tfsdk:"hash"`
	Name                     types.String   `tfsdk:"name"`
	Description              types.String   `tfsdk:"description"`
	LogLevel                 types.String   `tfsdk:"log_level"`
	AutoUpdate               types.Bool     `tfsdk:"auto_update"`
	ActionConfigs            types.String   `tfsdk:"action_configs"`
	ExceptionSets            types.List     `tfsdk:"exception_sets"`
	Telemetry                types.String   `tfsdk:"telemetry"`
	TelemetryV2              types.String   `tfsdk:"telemetry_v2"`
	USBControlSet            types.String   `tfsdk:"removable_storage_control_set"`
	AnalyticSets             types.Set      `tfsdk:"analytic_sets"`
	CommsConfig              types.Object   `tfsdk:"comms_config"`
	InfoSync                 types.Object   `tfsdk:"info_sync"`
	EndpointThreatPrevention types.String   `tfsdk:"endpoint_threat_prevention"`
	AdvancedThreatControls   types.String   `tfsdk:"advanced_threat_controls"`
	TamperPrevention         types.String   `tfsdk:"tamper_prevention"`
	Created                  types.String   `tfsdk:"created"`
	Updated                  types.String   `tfsdk:"updated"`
	Timeouts                 timeouts.Value `tfsdk:"timeouts"`
}
