// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ExceptionSetResourceModel maps the resource schema data.
type ExceptionSetResourceModel struct {
	ID          types.String   `tfsdk:"id"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	Exceptions  types.Set      `tfsdk:"exceptions"`
	Created     types.String   `tfsdk:"created"`
	Updated     types.String   `tfsdk:"updated"`
	Managed     types.Bool     `tfsdk:"managed"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

// exceptionModel maps exception entries.
type exceptionModel struct {
	Type    types.String `tfsdk:"type"`
	SubType types.String `tfsdk:"sub_type"`
	Rules   types.List   `tfsdk:"rules"`
}

// exceptionRuleModel maps exception rule entries.
type exceptionRuleModel struct {
	RuleType types.String `tfsdk:"rule_type"`
	Value    types.String `tfsdk:"value"`
	AppID    types.String `tfsdk:"app_id"`
	TeamID   types.String `tfsdk:"team_id"`
}
