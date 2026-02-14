// Copyright (c) James Smith 2025
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
	Predicate                   types.String   `tfsdk:"predicate"`
	Level                       types.Int64    `tfsdk:"level"`
	Severity                    types.String   `tfsdk:"severity"`
	Tags                        types.List     `tfsdk:"tags"`
	Categories                  types.List     `tfsdk:"categories"`
	SnapshotFiles               types.List     `tfsdk:"snapshot_files"`
	Actions                     types.List     `tfsdk:"actions"`
	AddToJamfProSmartGroup      types.Bool     `tfsdk:"add_to_jamf_pro_smart_group"`
	JamfProSmartGroupIdentifier types.String   `tfsdk:"jamf_pro_smart_group_identifier"`
	TenantActions               types.List     `tfsdk:"tenant_actions"`
	TenantSeverity              types.String   `tfsdk:"tenant_severity"`
	ContextItem                 types.List     `tfsdk:"context_item"`
	Created                     types.String   `tfsdk:"created"`
	Updated                     types.String   `tfsdk:"updated"`
	Jamf                        types.Bool     `tfsdk:"jamf"`
	Remediation                 types.String   `tfsdk:"remediation"`
	Timeouts                    timeouts.Value `tfsdk:"timeouts"`
}

// analyticContextModel maps AnalyticContextInput / response.
type analyticContextModel struct {
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Expressions types.List   `tfsdk:"expressions"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type analyticAPIModel struct {
	UUID            string                    `json:"uuid"`
	Name            string                    `json:"name"`
	Label           string                    `json:"label"`
	InputType       string                    `json:"inputType"`
	Filter          string                    `json:"filter"`
	Description     string                    `json:"description"`
	LongDescription string                    `json:"longDescription"`
	Created         string                    `json:"created"`
	Updated         string                    `json:"updated"`
	Actions         []string                  `json:"actions"`
	AnalyticActions []analyticActionAPIModel  `json:"analyticActions"`
	TenantActions   []analyticActionAPIModel  `json:"tenantActions"`
	Tags            []string                  `json:"tags"`
	Level           int64                     `json:"level"`
	Severity        string                    `json:"severity"`
	TenantSeverity  string                    `json:"tenantSeverity"`
	SnapshotFiles   []string                  `json:"snapshotFiles"`
	Context         []analyticContextAPIModel `json:"context"`
	Categories      []string                  `json:"categories"`
	Jamf            bool                      `json:"jamf"`
	Remediation     string                    `json:"remediation"`
}

type analyticActionAPIModel struct {
	Name       string `json:"name"`
	Parameters string `json:"parameters"`
}

type analyticContextAPIModel struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Exprs []string `json:"exprs"`
}
