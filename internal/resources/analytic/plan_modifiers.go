// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// analyticActionsPlanModifier plans analytic_actions as the actions the next create or update
// will send: the prior actions with the SmartGroup entry following the Smart Group attributes.
type analyticActionsPlanModifier struct{}

// Description returns a plain-text description of the modifier.
func (m analyticActionsPlanModifier) Description(_ context.Context) string {
	return "Plans analytic_actions from prior state, with the SmartGroup action following add_to_jamf_pro_smart_group and jamf_pro_smart_group_identifier."
}

// MarkdownDescription returns a Markdown description of the modifier.
func (m analyticActionsPlanModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

// PlanModifyList computes analytic_actions when the framework has marked it unknown and the
// Smart Group attributes are known; otherwise the planned value is left as it is.
func (m analyticActionsPlanModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if req.Plan.Raw.IsNull() || !req.PlanValue.IsUnknown() {
		return
	}

	var addToSmartGroup types.Bool
	var identifier types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("add_to_jamf_pro_smart_group"), &addToSmartGroup)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("jamf_pro_smart_group_identifier"), &identifier)...)
	if resp.Diagnostics.HasError() || addToSmartGroup.IsUnknown() || identifier.IsUnknown() {
		return
	}

	actions := mergeSmartGroupAction(ctx, req.StateValue, smartGroupAction(addToSmartGroup, identifier), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.PlanValue = analyticActionsToList(actions, &resp.Diagnostics)
}
