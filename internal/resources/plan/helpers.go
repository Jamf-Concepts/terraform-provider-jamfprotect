// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

// checkNGTPBetaEnrollment returns an error diagnostic when the requested
// strategy requires the NGTP beta but the tenant has not opted in. Result is
// cached per-resource-instance to avoid redundant API calls across multiple
// plan blocks in a single Terraform run.
func (r *PlanResource) checkNGTPBetaEnrollment(ctx context.Context, strategy string, diags *diag.Diagnostics) {
	if strategy == "Legacy" || strategy == "" {
		return
	}
	r.ngtpBetaOnce.Do(func() {
		statuses, err := r.client.GetBetaAcceptanceStatus(ctx)
		if err != nil {
			r.ngtpBetaErr = err
			return
		}
		for _, s := range statuses {
			if s.BetaName == string(jamfprotect.BetaNameNGTP) && s.AcceptedTimestamp != "" {
				r.ngtpBetaEnrolled = true
				return
			}
		}
	})
	if r.ngtpBetaErr != nil {
		diags.AddError("Error checking Threat Prevention beta status", r.ngtpBetaErr.Error())
		return
	}
	if r.ngtpBetaEnrolled {
		return
	}
	diags.AddError(
		"Threat Prevention beta not enabled",
		fmt.Sprintf(
			"threat_prevention_strategy %q requires the Threat Prevention beta. "+
				"Opt in via the Threat Prevention section in the Jamf Protect UI before applying.",
			strategy,
		),
	)
}

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

// resolveManagedAnalyticSetUUIDs loads the UUIDs of the Jamf-managed Advanced Threat
// Controls and Tamper Prevention analytic sets.
func (r *PlanResource) resolveManagedAnalyticSetUUIDs(ctx context.Context, diags *diag.Diagnostics) map[string]string {
	sets, err := r.client.ListAnalyticSets(ctx)
	if err != nil {
		diags.AddError("Error listing analytic sets", err.Error())
		return nil
	}

	return managedAnalyticSetUUIDs(sets, diags)
}

// managedAnalyticSetUUIDs picks the UUID of each Jamf-managed analytic set by name.
// Only sets the API flags as managed are candidates, so a custom set that shares a
// managed set's name is never selected. Zero or several candidates for a name is an
// error.
func managedAnalyticSetUUIDs(sets []jamfprotect.AnalyticSet, diags *diag.Diagnostics) map[string]string {
	candidates := map[string][]string{}
	for _, set := range sets {
		if set.Managed && isManagedAnalyticSetName(set.Name) {
			candidates[set.Name] = append(candidates[set.Name], set.UUID)
		}
	}

	uuids := map[string]string{}
	for _, name := range []string{advancedThreatControlsName, tamperPreventionName} {
		switch len(candidates[name]) {
		case 0:
			diags.AddError("Managed analytic set not found", fmt.Sprintf("Expected a Jamf-managed analytic set named %q.", name))
		case 1:
			uuids[name] = candidates[name][0]
		default:
			diags.AddError(
				"Ambiguous managed analytic set",
				fmt.Sprintf("Found %d Jamf-managed analytic sets named %q: %s.", len(candidates[name]), name, strings.Join(candidates[name], ", ")),
			)
		}
	}

	if diags.HasError() {
		return nil
	}

	return uuids
}

// isManagedAnalyticSetName reports whether name is the name of one of the Jamf-managed
// analytic sets exposed through advanced_threat_controls and tamper_prevention.
func isManagedAnalyticSetName(name string) bool {
	return name == advancedThreatControlsName || name == tamperPreventionName
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

// resolveManagedAnalyticSetState maps the Jamf-managed analytic set with the given name
// to its UI value. Custom sets that share the name are ignored.
func resolveManagedAnalyticSetState(sets []jamfprotect.PlanAnalyticSet, name string, allowReport bool, diags *diag.Diagnostics) types.String {
	for _, set := range sets {
		if !set.AnalyticSet.Managed || set.AnalyticSet.Name != name {
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

// filterManagedAnalyticSetEntries drops the Jamf-managed Advanced Threat Controls and
// Tamper Prevention sets from the API list. Custom sets that share their names are kept.
func filterManagedAnalyticSetEntries(sets []jamfprotect.PlanAnalyticSet) []jamfprotect.PlanAnalyticSet {
	if len(sets) == 0 {
		return nil
	}

	filtered := make([]jamfprotect.PlanAnalyticSet, 0, len(sets))
	for _, set := range sets {
		if set.AnalyticSet.Managed && isManagedAnalyticSetName(set.AnalyticSet.Name) {
			continue
		}
		filtered = append(filtered, set)
	}

	return filtered
}
