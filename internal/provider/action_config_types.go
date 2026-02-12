// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ActionConfigResourceModel maps the resource schema data.
type ActionConfigResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Hash        types.String `tfsdk:"hash"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	AlertConfig types.String `tfsdk:"alert_config"`
	Created     types.String `tfsdk:"created"`
	Updated     types.String `tfsdk:"updated"`
}

// ---------------------------------------------------------------------------
// API model (matches the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type actionConfigAPIModel struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Hash        string          `json:"hash"`
	Created     string          `json:"created"`
	Updated     string          `json:"updated"`
	AlertConfig json.RawMessage `json:"alertConfig"`
}
