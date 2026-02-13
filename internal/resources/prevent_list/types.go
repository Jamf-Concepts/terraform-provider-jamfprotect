// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package prevent_list

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// PreventListResourceModel maps the resource schema data.
type PreventListResourceModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Type        types.String   `tfsdk:"type"`
	Tags        types.List     `tfsdk:"tags"`
	List        types.List     `tfsdk:"list"`
	EntryCount  types.Int64    `tfsdk:"entry_count"`
	Created     types.String   `tfsdk:"created"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// API model (matches the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type preventListAPIModel struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Count       int64    `json:"count"`
	List        []string `json:"list"`
	Created     string   `json:"created"`
	Description string   `json:"description"`
}
