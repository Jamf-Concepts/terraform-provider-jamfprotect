// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ resource.ResourceWithModifyPlan = &PlanResource{}

// ModifyPlan gates non-Legacy threat_prevention_strategy values behind the NGTP beta check.
func (r *PlanResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan PlanResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ThreatPreventionStrategy.IsNull() || plan.ThreatPreventionStrategy.IsUnknown() {
		return
	}

	if plan.ThreatPreventionStrategy.ValueString() != "Legacy" {
		r.checkNGTPBetaEnrollment(ctx, plan.ThreatPreventionStrategy.ValueString(), &resp.Diagnostics)
	}
}
