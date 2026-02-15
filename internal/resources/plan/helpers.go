// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const (
	advancedThreatControlsName = "Advanced Threat Controls"
	tamperPreventionName       = "Tamper Prevention"
	commsFQDNPlaceholder       = "placeholder - will be updated by resolver on create"
)

// buildVariables converts the Terraform model into a plan input.
func (r *PlanResource) buildVariables(ctx context.Context, data PlanResourceModel, commsFQDN string, diags *diag.Diagnostics) *jamfprotect.PlanInput {
	input := &jamfprotect.PlanInput{
		Name:          data.Name.ValueString(),
		ActionConfigs: data.ActionConfigs.ValueString(),
		AutoUpdate:    data.AutoUpdate.ValueBool(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	if !data.LogLevel.IsNull() {
		logLevel := data.LogLevel.ValueString()
		input.LogLevel = &logLevel
	}

	if !data.Telemetry.IsNull() {
		telemetry := data.Telemetry.ValueString()
		input.Telemetry = &telemetry
	}

	if !data.TelemetryV2.IsNull() {
		telemetryV2 := data.TelemetryV2.ValueString()
		input.TelemetryV2 = &telemetryV2
	}

	if !data.USBControlSet.IsNull() {
		usbControlSet := data.USBControlSet.ValueString()
		input.USBControlSet = &usbControlSet
	}

	// Exception sets.
	if !data.ExceptionSets.IsNull() {
		input.ExceptionSets = common.ListToStrings(ctx, data.ExceptionSets, diags)
	}

	// Analytic sets (Report type only).
	var analyticSets []jamfprotect.PlanAnalyticSetInput
	if !data.AnalyticSets.IsNull() {
		uuids := common.SetToStrings(ctx, data.AnalyticSets, diags)
		for _, uuid := range uuids {
			analyticSets = append(analyticSets, jamfprotect.PlanAnalyticSetInput{
				Type: "Report",
				UUID: uuid,
			})
		}
	}

	managedSetUUIDs := map[string]string{}
	shouldResolveManagedSets := len(analyticSets) > 0 || isKnownString(data.AdvancedThreatControls) || isKnownString(data.TamperPrevention)
	if shouldResolveManagedSets {
		managedSetUUIDs = r.resolveManagedAnalyticSetUUIDs(ctx, diags)
		if diags.HasError() {
			return nil
		}
		analyticSets = filterManagedAnalyticSets(analyticSets, managedSetUUIDs, diags)
		if diags.HasError() {
			return nil
		}
	}

	if isKnownString(data.AdvancedThreatControls) {
		advancedValue := data.AdvancedThreatControls.ValueString()
		if advancedValue != "Disable" {
			uuid := managedSetUUIDs[advancedThreatControlsName]
			if uuid == "" {
				diags.AddError("Managed analytic set not found", fmt.Sprintf("Expected analytic set named %q.", advancedThreatControlsName))
				return nil
			}
			setType, ok := advancedThreatControlsToType(advancedValue)
			if !ok {
				diags.AddError("Invalid advanced threat controls value", "advanced_threat_controls must be one of: BlockAndReport, ReportOnly, Disable.")
				return nil
			}
			analyticSets = append(analyticSets, jamfprotect.PlanAnalyticSetInput{
				Type: setType,
				UUID: uuid,
			})
		}
	}

	if isKnownString(data.TamperPrevention) {
		tamperValue := data.TamperPrevention.ValueString()
		if tamperValue != "Disable" {
			uuid := managedSetUUIDs[tamperPreventionName]
			if uuid == "" {
				diags.AddError("Managed analytic set not found", fmt.Sprintf("Expected analytic set named %q.", tamperPreventionName))
				return nil
			}
			setType, ok := tamperPreventionToType(tamperValue)
			if !ok {
				diags.AddError("Invalid tamper prevention value", "tamper_prevention must be one of: BlockAndReport, Disable.")
				return nil
			}
			analyticSets = append(analyticSets, jamfprotect.PlanAnalyticSetInput{
				Type: setType,
				UUID: uuid,
			})
		}
	}

	if analyticSets != nil {
		input.AnalyticSets = analyticSets
	}

	// Comms config (required).
	protocol := "mqtt"
	if isKnownString(data.CommunicationsProtocol) {
		protocol = data.CommunicationsProtocol.ValueString()
	}
	input.CommsConfig = jamfprotect.PlanCommsConfigInput{
		FQDN:     commsFQDN,
		Protocol: protocol,
	}

	// Info sync (required).
	if !data.InfoSync.IsNull() {
		infoAttrs := data.InfoSync.Attributes()
		attrsList, ok := infoAttrs["attrs"].(types.List)
		if !ok {
			diags.AddError("Type assertion failed", "attrs is not a types.List")
			return nil
		}
		syncInterval, ok := infoAttrs["insights_sync_interval"].(types.Int64)
		if !ok {
			diags.AddError("Type assertion failed", "insights_sync_interval is not a types.Int64")
			return nil
		}
		input.InfoSync = jamfprotect.PlanInfoSyncInput{
			Attrs:                common.ListToStrings(ctx, attrsList, diags),
			InsightsSyncInterval: syncInterval.ValueInt64(),
		}
	} else {
		input.InfoSync = jamfprotect.PlanInfoSyncInput{
			Attrs:                []string{},
			InsightsSyncInterval: 0,
		}
	}

	// Endpoint threat prevention setting (required).
	if data.EndpointThreatPrevention.IsNull() {
		input.SignaturesFeedConfig = jamfprotect.PlanSignaturesFeedConfigInput{
			Mode: "blocking",
		}
	} else {
		mode, ok := endpointThreatPreventionToMode(data.EndpointThreatPrevention.ValueString())
		if !ok {
			diags.AddError(
				"Invalid endpoint threat prevention value",
				"endpoint_threat_prevention must be one of: BlockAndReport, Report, Disable.",
			)
			return nil
		}
		input.SignaturesFeedConfig = jamfprotect.PlanSignaturesFeedConfigInput{
			Mode: mode,
		}
	}

	return input
}

// apiToState maps the API response into the Terraform state model.
func (r *PlanResource) apiToState(_ context.Context, data *PlanResourceModel, api jamfprotect.Plan, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Hash = types.StringValue(api.Hash)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.AutoUpdate = types.BoolValue(api.AutoUpdate)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}

	if api.LogLevel != "" {
		data.LogLevel = types.StringValue(api.LogLevel)
	} else {
		data.LogLevel = types.StringNull()
	}

	// Action configs — the API returns an object with id+name; we store just the ID.
	if api.ActionConfigs != nil {
		data.ActionConfigs = types.StringValue(api.ActionConfigs.ID)
	}

	// Exception sets — extract UUIDs.
	if len(api.ExceptionSets) > 0 {
		uuids := make([]string, len(api.ExceptionSets))
		for i, es := range api.ExceptionSets {
			uuids[i] = es.UUID
		}
		data.ExceptionSets = common.StringsToList(uuids)
	} else {
		data.ExceptionSets = types.ListNull(types.StringType)
	}

	// Telemetry references.
	if api.Telemetry != nil && api.Telemetry.ID != "" {
		data.Telemetry = types.StringValue(api.Telemetry.ID)
	} else {
		data.Telemetry = types.StringNull()
	}

	if api.TelemetryV2 != nil && api.TelemetryV2.ID != "" {
		data.TelemetryV2 = types.StringValue(api.TelemetryV2.ID)
	} else {
		data.TelemetryV2 = types.StringNull()
	}

	// USB control set.
	if api.USBControlSet != nil && api.USBControlSet.ID != "" {
		data.USBControlSet = types.StringValue(api.USBControlSet.ID)
	} else {
		data.USBControlSet = types.StringNull()
	}

	// Analytic sets (exclude managed ones with dedicated attributes).
	filteredAnalyticSets := filterManagedAnalyticSetEntries(api.AnalyticSets)
	if len(filteredAnalyticSets) > 0 {
		uuids := make([]string, len(filteredAnalyticSets))
		for i, as := range filteredAnalyticSets {
			uuids[i] = as.AnalyticSet.UUID
		}
		data.AnalyticSets = common.StringsToSet(uuids)
	} else {
		data.AnalyticSets = types.SetNull(types.StringType)
	}

	// Communications protocol.
	if api.CommsConfig != nil && api.CommsConfig.Protocol != "" {
		data.CommunicationsProtocol = types.StringValue(api.CommsConfig.Protocol)
	} else {
		data.CommunicationsProtocol = types.StringNull()
	}

	// Info sync.
	infoSyncAttrTypes := map[string]attr.Type{
		"attrs":                  types.ListType{ElemType: types.StringType},
		"insights_sync_interval": types.Int64Type,
	}
	if api.InfoSync != nil {
		data.InfoSync = types.ObjectValueMust(infoSyncAttrTypes, map[string]attr.Value{
			"attrs":                  common.StringsToList(api.InfoSync.Attrs),
			"insights_sync_interval": types.Int64Value(api.InfoSync.InsightsSyncInterval),
		})
	} else {
		data.InfoSync = types.ObjectNull(infoSyncAttrTypes)
	}

	// Endpoint threat prevention setting.
	if api.SignaturesFeedConfig != nil {
		if endpointThreatPrevention, ok := modeToEndpointThreatPrevention(api.SignaturesFeedConfig.Mode); ok {
			data.EndpointThreatPrevention = types.StringValue(endpointThreatPrevention)
		} else {
			diags.AddError(
				"Unsupported signatures feed mode",
				"signaturesFeedConfig.mode was not recognized.",
			)
			data.EndpointThreatPrevention = types.StringNull()
		}
	} else {
		data.EndpointThreatPrevention = types.StringNull()
	}

	data.AdvancedThreatControls = resolveManagedAnalyticSetState(api.AnalyticSets, advancedThreatControlsName, true, diags)
	data.TamperPrevention = resolveManagedAnalyticSetState(api.AnalyticSets, tamperPreventionName, false, diags)
}

func endpointThreatPreventionToMode(value string) (string, bool) {
	switch value {
	case "BlockAndReport":
		return "blocking", true
	case "Report":
		return "reportOnly", true
	case "Disable":
		return "disabled", true
	default:
		return "", false
	}
}

func modeToEndpointThreatPrevention(mode string) (string, bool) {
	switch mode {
	case "blocking":
		return "BlockAndReport", true
	case "reportOnly", "monitoring":
		return "Report", true
	case "disabled", "off":
		return "Disable", true
	default:
		return "", false
	}
}

func isKnownString(value types.String) bool {
	return !value.IsNull() && !value.IsUnknown()
}

func (r *PlanResource) resolveManagedAnalyticSetUUIDs(ctx context.Context, diags *diag.Diagnostics) map[string]string {
	sets, err := r.service.ListAnalyticSets(ctx)
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

func advancedThreatControlsToType(value string) (string, bool) {
	switch value {
	case "BlockAndReport":
		return "Prevent", true
	case "ReportOnly":
		return "Report", true
	case "Disable":
		return "", true
	default:
		return "", false
	}
}

func tamperPreventionToType(value string) (string, bool) {
	switch value {
	case "BlockAndReport":
		return "Prevent", true
	case "Disable":
		return "", true
	default:
		return "", false
	}
}

func resolveManagedAnalyticSetState(sets []jamfprotect.PlanAnalyticSet, name string, allowReport bool, diags *diag.Diagnostics) types.String {
	for _, set := range sets {
		if set.AnalyticSet.Name != name {
			continue
		}
		switch set.Type {
		case "Prevent":
			return types.StringValue("BlockAndReport")
		case "Report":
			if allowReport {
				return types.StringValue("ReportOnly")
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
