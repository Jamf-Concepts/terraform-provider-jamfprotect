// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AnalyticResourceModel maps the resource schema data.
type AnalyticResourceModel struct {
	ID                          types.String   `tfsdk:"id"`
	Name                        types.String   `tfsdk:"name"`
	SensorType                  types.String   `tfsdk:"sensor_type"`
	Description                 types.String   `tfsdk:"description"`
	Label                       types.String   `tfsdk:"label"`
	LongDescription             types.String   `tfsdk:"long_description"`
	Filter                      types.String   `tfsdk:"filter"`
	Level                       types.Int64    `tfsdk:"level"`
	Severity                    types.String   `tfsdk:"severity"`
	Tags                        types.Set      `tfsdk:"tags"`
	Categories                  types.Set      `tfsdk:"categories"`
	SnapshotFiles               types.Set      `tfsdk:"snapshot_files"`
	AddToJamfProSmartGroup      types.Bool     `tfsdk:"add_to_jamf_pro_smart_group"`
	JamfProSmartGroupIdentifier types.String   `tfsdk:"jamf_pro_smart_group_identifier"`
	AnalyticActions             types.List     `tfsdk:"analytic_actions"`
	TenantActions               types.Set      `tfsdk:"tenant_actions"`
	TenantSeverity              types.String   `tfsdk:"tenant_severity"`
	ContextItem                 types.Set      `tfsdk:"context_item"`
	Created                     types.String   `tfsdk:"created"`
	Jamf                        types.Bool     `tfsdk:"jamf"`
	Remediation                 types.String   `tfsdk:"remediation"`
	Timeouts                    timeouts.Value `tfsdk:"timeouts"`
}

// analyticActionModel maps an analytic action as stored in analytic_actions.
type analyticActionModel struct {
	Name       types.String `tfsdk:"name"`
	Parameters types.Map    `tfsdk:"parameters"`
}

// analyticContextModel maps AnalyticContextInput / response.
type analyticContextModel struct {
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Expressions types.Set    `tfsdk:"expressions"`
}
