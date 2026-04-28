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

// ModifyPlan handles two concerns:
//  1. For Custom strategy: carries custom_engine_config forward from state when not
//     set in config (SingleNestedAttribute does not trigger UseStateForUnknown for
//     null plan values), and errors at plan-time if no prior state exists.
//  2. For non-Legacy strategies: errors if legacy-only fields are explicitly set in
//     config, and nulls out any values carried forward from state.
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

	modified := false

	// For Custom strategy, carry custom_engine_config from state when not configured.
	// UseStateForUnknown does not fire for SingleNestedAttribute when plan is null
	// (rather than unknown), so we handle it here explicitly.
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

	// Validate all sub-fields are explicitly set for Custom strategy.
	if strategy == "Custom" && !plan.CustomEngineConfig.IsNull() && !plan.CustomEngineConfig.IsUnknown() {
		var cfg CustomEngineConfigModel
		if d := plan.CustomEngineConfig.As(ctx, &cfg, basetypes.ObjectAsOptions{}); !d.HasError() {
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
		}
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if strategy == "Legacy" {
		// When legacy fields are null (e.g. transitioning from non-Legacy where apiToState
		// set them null), UseStateForUnknown won't fire. Mark them unknown so apiToState
		// can populate them without causing a plan/state inconsistency.
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

	// Null out any state carry-overs for legacy-only fields.
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
