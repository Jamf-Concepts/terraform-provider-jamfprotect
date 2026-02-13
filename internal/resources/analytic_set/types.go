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
	Types       types.List     `tfsdk:"types"`
	Analytics   types.List     `tfsdk:"analytics"`
	Created     types.String   `tfsdk:"created"`
	Updated     types.String   `tfsdk:"updated"`
	Managed     types.Bool     `tfsdk:"managed"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

// analyticSetResourceAPIModel matches the simpler structure returned by CRUD mutations.
// The analytics field returns just UUIDs as an array of objects with a single uuid field.
type analyticSetResourceAPIModel struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Types       []string `json:"types"`
	Analytics   []struct {
		UUID string `json:"uuid"`
	} `json:"analytics"`
	Created string `json:"created"`
	Updated string `json:"updated"`
	Managed bool   `json:"managed"`
}
