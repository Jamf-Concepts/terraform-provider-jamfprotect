// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

const (
	advancedThreatControlsName = "Advanced Threat Controls"
	tamperPreventionName       = "Tamper Prevention"
	commsFQDNPlaceholder       = "placeholder - will be updated by resolver on create"
)

// endpointThreatPreventionToMode maps UI endpoint threat prevention values to API modes.
func endpointThreatPreventionToMode(value string) (string, bool) {
	switch value {
	case "Block and report":
		return "blocking", true
	case "Report only":
		return "reportOnly", true
	case "Disable":
		return "disabled", true
	default:
		return "", false
	}
}

// modeToEndpointThreatPrevention maps API modes to UI endpoint threat prevention values.
func modeToEndpointThreatPrevention(mode string) (string, bool) {
	switch mode {
	case "blocking":
		return "Block and report", true
	case "reportOnly", "monitoring":
		return "Report only", true
	case "disabled", "off":
		return "Disable", true
	default:
		return "", false
	}
}

// resolveManagedAnalyticSetUUIDs loads managed analytic set UUIDs by name.
func (r *PlanResource) resolveManagedAnalyticSetUUIDs(ctx context.Context, diags *diag.Diagnostics) map[string]string {
	sets, err := r.client.ListAnalyticSets(ctx)
	if err != nil {
		diags.AddError("Error listing analytic sets", err.Error())
		return nil
	}

	uuids := map[string]string{}
	for _, set := range sets {
		switch set.Name {
		case advancedThreatControlsName:
			uuids[advancedThreatControlsName] = set.UUID
		case tamperPreventionName:
			uuids[tamperPreventionName] = set.UUID
		}
	}

	for _, name := range []string{advancedThreatControlsName, tamperPreventionName} {
		if uuids[name] == "" {
			diags.AddError("Managed analytic set not found", fmt.Sprintf("Expected analytic set named %q.", name))
		}
	}

	if diags.HasError() {
		return nil
	}

	return uuids
}

// filterManagedAnalyticSets removes managed analytic sets from the plan input.
func filterManagedAnalyticSets(sets []jamfprotect.PlanAnalyticSetInput, managedUUIDs map[string]string, diags *diag.Diagnostics) []jamfprotect.PlanAnalyticSetInput {
	if len(sets) == 0 {
		return sets
	}

	filtered := make([]jamfprotect.PlanAnalyticSetInput, 0, len(sets))
	var removed []string
	for _, set := range sets {
		if set.UUID == managedUUIDs[advancedThreatControlsName] || set.UUID == managedUUIDs[tamperPreventionName] {
			removed = append(removed, set.UUID)
			continue
		}
		filtered = append(filtered, set)
	}

	if len(removed) > 0 {
		diags.AddError(
			"Managed analytic sets are not configurable via analytic_sets",
			"Use advanced_threat_controls and tamper_prevention instead of adding managed analytic sets to analytic_sets.",
		)
		return nil
	}

	return filtered
}

// advancedThreatControlsToType maps UI advanced threat controls values to analytic set types.
func advancedThreatControlsToType(value string) (string, bool) {
	switch value {
	case "Block and report":
		return "Prevent", true
	case "Report only":
		return "Report", true
	case "Disable":
		return "", true
	default:
		return "", false
	}
}

// tamperPreventionToType maps UI tamper prevention values to analytic set types.
func tamperPreventionToType(value string) (string, bool) {
	switch value {
	case "Block and report":
		return "Prevent", true
	case "Disable":
		return "", true
	default:
		return "", false
	}
}

// resolveManagedAnalyticSetState maps managed analytic sets to UI values.
func resolveManagedAnalyticSetState(sets []jamfprotect.PlanAnalyticSet, name string, allowReport bool, diags *diag.Diagnostics) types.String {
	for _, set := range sets {
		if set.AnalyticSet.Name != name {
			continue
		}
		switch set.Type {
		case "Prevent":
			return types.StringValue("Block and report")
		case "Report":
			if allowReport {
				return types.StringValue("Report only")
			}
			if diags != nil {
				diags.AddError("Unsupported analytic set type", fmt.Sprintf("%s must be Prevent, but was Report.", name))
			}
			return types.StringNull()
		default:
			if diags != nil {
				diags.AddError("Unsupported analytic set type", fmt.Sprintf("%s has unexpected type %q.", name, set.Type))
			}
			return types.StringNull()
		}
	}

	return types.StringValue("Disable")
}

// filterManagedAnalyticSetEntries drops managed sets from the API list.
func filterManagedAnalyticSetEntries(sets []jamfprotect.PlanAnalyticSet) []jamfprotect.PlanAnalyticSet {
	if len(sets) == 0 {
		return nil
	}

	filtered := make([]jamfprotect.PlanAnalyticSet, 0, len(sets))
	for _, set := range sets {
		if set.AnalyticSet.Name == advancedThreatControlsName || set.AnalyticSet.Name == tamperPreventionName {
			continue
		}
		filtered = append(filtered, set)
	}

	return filtered
}
