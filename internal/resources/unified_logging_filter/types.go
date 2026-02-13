// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package unified_logging_filter

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// UnifiedLoggingFilterResourceModel maps the resource schema data.
type UnifiedLoggingFilterResourceModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Filter      types.String   `tfsdk:"filter"`
	Level       types.String   `tfsdk:"level"`
	Enabled     types.Bool     `tfsdk:"enabled"`
	Tags        types.List     `tfsdk:"tags"`
	Created     types.String   `tfsdk:"created"`
	Updated     types.String   `tfsdk:"updated"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

// ---------------------------------------------------------------------------
// API model (matches the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type unifiedLoggingFilterAPIModel struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Created     string   `json:"created"`
	Updated     string   `json:"updated"`
	Filter      string   `json:"filter"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
	Level       string   `json:"level"`
}
