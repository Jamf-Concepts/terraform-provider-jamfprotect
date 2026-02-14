// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic_set

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AnalyticSetResourceModel maps the resource schema data.
type AnalyticSetResourceModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Analytics   types.Set      `tfsdk:"analytics"`
	Created     types.String   `tfsdk:"created"`
	Updated     types.String   `tfsdk:"updated"`
	Managed     types.Bool     `tfsdk:"managed"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

// analyticSetResourceAPIModel matches the structure returned by CRUD mutations.
type analyticSetResourceAPIModel struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Types       []string `json:"types"`
	Analytics   []struct {
		UUID string `json:"uuid"`
		Name string `json:"name"`
		Jamf bool   `json:"jamf"`
	} `json:"analytics"`
	Plans []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"plans"`
	Created string `json:"created"`
	Updated string `json:"updated"`
	Managed bool   `json:"managed"`
}
