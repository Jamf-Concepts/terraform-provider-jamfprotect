// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var _ resource.ResourceWithModifyPlan = &PlanResource{}

// ModifyPlan reconciles threat_prevention_strategy with strategy-specific fields:
//  1. Custom: carry custom_engine_config from state when not in config (UseStateForUnknown
//     does not fire on SingleNestedAttribute when plan is null), error if no prior state.
//  2. Custom: validate all sub-fields are non-null/unknown so failures surface at plan time.
//  3. Legacy: promote null legacy fields to unknown so apiToState can populate them after
//     a strategy switch without producing a plan/state inconsistency.
//  4. Non-Legacy: error if legacy-only fields are explicitly set in config; null any
//     state carry-overs from a previous Legacy run.
//  5. Verify NGTP beta enrollment at plan time when strategy is non-Legacy.
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
	strategy := plan.ThreatPreventionStrategy.ValueString()

	if strategy != "Legacy" {
		r.checkNGTPBetaEnrollment(ctx, strategy, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	modified := false

	if strategy == "Custom" && (plan.CustomEngineConfig.IsNull() || plan.CustomEngineConfig.IsUnknown()) {
		carriedFromState := false
		if !req.State.Raw.IsNull() {
			var state PlanResourceModel
			stateDiags := req.State.Get(ctx, &state)
			if !stateDiags.HasError() && !state.CustomEngineConfig.IsNull() && !state.CustomEngineConfig.IsUnknown() {
				plan.CustomEngineConfig = state.CustomEngineConfig
				modified = true
				carriedFromState = true
			}
		}
		if !carriedFromState {
			resp.Diagnostics.AddAttributeError(
				path.Root("custom_engine_config"),
				"custom_engine_config required",
				"custom_engine_config must be set when threat_prevention_strategy is Custom.",
			)
			return
		}
	}

	if strategy == "Custom" && !plan.CustomEngineConfig.IsNull() && !plan.CustomEngineConfig.IsUnknown() {
		var cfg CustomEngineConfigModel
		resp.Diagnostics.Append(plan.CustomEngineConfig.As(ctx, &cfg, basetypes.ObjectAsOptions{})...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, f := range []struct {
			name string
			val  types.String
		}{
			{"malware_riskware", cfg.MalwareRiskware},
			{"adversary_tactics", cfg.AdversaryTactics},
			{"system_tampering", cfg.SystemTampering},
			{"fileless_threats", cfg.FilelessThreats},
		} {
			if f.val.IsNull() || f.val.IsUnknown() {
				resp.Diagnostics.AddAttributeError(
					path.Root("custom_engine_config").AtName(f.name),
					f.name+" must be set",
					"All custom_engine_config fields must be specified when threat_prevention_strategy is Custom.",
				)
			}
		}
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if strategy == "Legacy" {
		if plan.EndpointThreatPrevention.IsNull() {
			plan.EndpointThreatPrevention = types.StringUnknown()
			modified = true
		}
		if plan.AdvancedThreatControls.IsNull() {
			plan.AdvancedThreatControls = types.StringUnknown()
			modified = true
		}
		if plan.TamperPrevention.IsNull() {
			plan.TamperPrevention = types.StringUnknown()
			modified = true
		}
		if plan.AnalyticSets.IsNull() {
			plan.AnalyticSets = types.SetUnknown(types.StringType)
			modified = true
		}
		if modified {
			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		}
		return
	}

	var config PlanResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.EndpointThreatPrevention.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("endpoint_threat_prevention"),
			"endpoint_threat_prevention not allowed with this threat prevention strategy",
			"endpoint_threat_prevention can only be set when threat_prevention_strategy is Legacy.",
		)
	}
	if !config.AdvancedThreatControls.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("advanced_threat_controls"),
			"advanced_threat_controls not allowed with this threat prevention strategy",
			"advanced_threat_controls can only be set when threat_prevention_strategy is Legacy.",
		)
	}
	if !config.TamperPrevention.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("tamper_prevention"),
			"tamper_prevention not allowed with this threat prevention strategy",
			"tamper_prevention can only be set when threat_prevention_strategy is Legacy.",
		)
	}
	if !config.AnalyticSets.IsNull() && len(config.AnalyticSets.Elements()) > 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("analytic_sets"),
			"analytic_sets not allowed with this threat prevention strategy",
			"analytic_sets can only be set when threat_prevention_strategy is Legacy.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.EndpointThreatPrevention.IsNull() {
		plan.EndpointThreatPrevention = types.StringNull()
		modified = true
	}
	if !plan.AdvancedThreatControls.IsNull() {
		plan.AdvancedThreatControls = types.StringNull()
		modified = true
	}
	if !plan.TamperPrevention.IsNull() {
		plan.TamperPrevention = types.StringNull()
		modified = true
	}

	if modified {
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}
}
