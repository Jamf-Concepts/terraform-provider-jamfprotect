// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AnalyticResourceModel maps the resource schema data.
type AnalyticResourceModel struct {
	ID              types.String   `tfsdk:"id"`
	Name            types.String   `tfsdk:"name"`
	InputType       types.String   `tfsdk:"input_type"`
	Description     types.String   `tfsdk:"description"`
	Filter          types.String   `tfsdk:"filter"`
	Level           types.Int64    `tfsdk:"level"`
	Severity        types.String   `tfsdk:"severity"`
	Tags            types.List     `tfsdk:"tags"`
	Categories      types.List     `tfsdk:"categories"`
	SnapshotFiles   types.List     `tfsdk:"snapshot_files"`
	Actions         types.List     `tfsdk:"actions"`
	AnalyticActions types.List     `tfsdk:"analytic_actions"`
	Context         types.List     `tfsdk:"context"`
	Created         types.String   `tfsdk:"created"`
	Updated         types.String   `tfsdk:"updated"`
	Timeouts        timeouts.Value `tfsdk:"timeouts"`
}

// analyticActionModel maps AnalyticActionsInput / response.
type analyticActionModel struct {
	Name       types.String `tfsdk:"name"`
	Parameters types.Map    `tfsdk:"parameters"`
}

// analyticContextModel maps AnalyticContextInput / response.
type analyticContextModel struct {
	Name  types.String `tfsdk:"name"`
	Type  types.String `tfsdk:"type"`
	Exprs types.List   `tfsdk:"exprs"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type analyticAPIModel struct {
	UUID            string                    `json:"uuid"`
	Name            string                    `json:"name"`
	InputType       string                    `json:"inputType"`
	Filter          string                    `json:"filter"`
	Description     string                    `json:"description"`
	Created         string                    `json:"created"`
	Updated         string                    `json:"updated"`
	Actions         []string                  `json:"actions"`
	AnalyticActions []analyticActionAPIModel  `json:"analyticActions"`
	Tags            []string                  `json:"tags"`
	Level           int64                     `json:"level"`
	Severity        string                    `json:"severity"`
	SnapshotFiles   []string                  `json:"snapshotFiles"`
	Context         []analyticContextAPIModel `json:"context"`
	Categories      []string                  `json:"categories"`
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
