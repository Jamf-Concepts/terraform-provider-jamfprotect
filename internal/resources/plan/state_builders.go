// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// apiToState maps the API response into the resource state model.
func (r *PlanResource) apiToState(ctx context.Context, data *PlanResourceModel, api jamfprotect.Plan, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Hash = types.StringValue(api.Hash)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.AutoUpdate = types.BoolValue(api.AutoUpdate)

	data.Description = types.StringValue(api.Description)

	if api.LogLevel != "" {
		data.LogLevel = types.StringValue(logLevelFromAPI(api.LogLevel))
	} else {
		data.LogLevel = types.StringNull()
	}

	if api.ActionConfigs != nil {
		data.ActionConfiguration = types.StringValue(api.ActionConfigs.ID)
	} else {
		data.ActionConfiguration = types.StringNull()
	}

	if len(api.ExceptionSets) > 0 {
		uuids := make([]string, len(api.ExceptionSets))
		for i, es := range api.ExceptionSets {
			uuids[i] = es.UUID
		}
		data.ExceptionSets = common.StringsToSet(uuids)
	} else {
		data.ExceptionSets = types.SetNull(types.StringType)
	}

	if api.TelemetryV2 != nil && api.TelemetryV2.ID != "" {
		data.Telemetry = types.StringValue(api.TelemetryV2.ID)
	} else {
		data.Telemetry = types.StringNull()
	}

	if api.USBControlSet != nil && api.USBControlSet.ID != "" {
		data.USBControlSet = types.StringValue(api.USBControlSet.ID)
	} else {
		data.USBControlSet = types.StringNull()
	}

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

	if api.CommsConfig != nil && api.CommsConfig.Protocol != "" {
		data.CommunicationsProtocol = types.StringValue(communicationsProtocolFromAPI(api.CommsConfig.Protocol))
	} else {
		data.CommunicationsProtocol = types.StringNull()
	}

	setReportingFlags(data, api.InfoSync)

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

	if api.ThreatPreventionStrategy != "" {
		data.ThreatPreventionStrategy = types.StringValue(threatPreventionStrategyFromAPI(api.ThreatPreventionStrategy))
	} else {
		data.ThreatPreventionStrategy = types.StringValue("Legacy")
	}

	data.CustomEngineConfig = customEngineConfigToObject(ctx, api.CustomEngineConfig, diags)
}

// planAPIToDataSourceItem maps a plan to PlanDataSourceItemModel.
func planAPIToDataSourceItem(api jamfprotect.Plan, diags *diag.Diagnostics) PlanDataSourceItemModel {
	item := PlanDataSourceItemModel{
		ID:         types.StringValue(api.ID),
		Hash:       types.StringValue(api.Hash),
		Name:       types.StringValue(api.Name),
		AutoUpdate: types.BoolValue(api.AutoUpdate),
		Created:    types.StringValue(api.Created),
		Updated:    types.StringValue(api.Updated),
	}

	item.Description = types.StringValue(api.Description)

	if api.LogLevel != "" {
		item.LogLevel = types.StringValue(logLevelFromAPI(api.LogLevel))
	} else {
		item.LogLevel = types.StringNull()
	}

	if api.ActionConfigs != nil {
		item.ActionConfiguration = types.StringValue(api.ActionConfigs.ID)
	} else {
		item.ActionConfiguration = types.StringNull()
	}

	if len(api.ExceptionSets) > 0 {
		uuids := make([]string, len(api.ExceptionSets))
		for i, es := range api.ExceptionSets {
			uuids[i] = es.UUID
		}
		item.ExceptionSets = common.StringsToSet(uuids)
	} else {
		item.ExceptionSets = types.SetNull(types.StringType)
	}

	if api.TelemetryV2 != nil && api.TelemetryV2.ID != "" {
		item.Telemetry = types.StringValue(api.TelemetryV2.ID)
	} else {
		item.Telemetry = types.StringNull()
	}

	if api.USBControlSet != nil && api.USBControlSet.ID != "" {
		item.USBControlSet = types.StringValue(api.USBControlSet.ID)
	} else {
		item.USBControlSet = types.StringNull()
	}

	filteredAnalyticSets := filterManagedAnalyticSetEntries(api.AnalyticSets)
	if len(filteredAnalyticSets) > 0 {
		uuids := make([]string, len(filteredAnalyticSets))
		for i, as := range filteredAnalyticSets {
			uuids[i] = as.AnalyticSet.UUID
		}
		item.AnalyticSets = common.SortedStringsToList(uuids)
	} else {
		item.AnalyticSets = types.ListNull(types.StringType)
	}

	if api.CommsConfig != nil && api.CommsConfig.Protocol != "" {
		item.CommunicationsProtocol = types.StringValue(communicationsProtocolFromAPI(api.CommsConfig.Protocol))
	} else {
		item.CommunicationsProtocol = types.StringNull()
	}

	setReportingFlagsDataSource(&item, api.InfoSync)

	if api.SignaturesFeedConfig != nil {
		if endpointThreatPrevention, ok := modeToEndpointThreatPrevention(api.SignaturesFeedConfig.Mode); ok {
			item.EndpointThreatPrevention = types.StringValue(endpointThreatPrevention)
		} else {
			item.EndpointThreatPrevention = types.StringNull()
		}
	} else {
		item.EndpointThreatPrevention = types.StringNull()
	}

	item.AdvancedThreatControls = resolveManagedAnalyticSetState(api.AnalyticSets, advancedThreatControlsName, true, nil)
	item.TamperPrevention = resolveManagedAnalyticSetState(api.AnalyticSets, tamperPreventionName, false, nil)

	if api.ThreatPreventionStrategy != "" {
		item.ThreatPreventionStrategy = types.StringValue(threatPreventionStrategyFromAPI(api.ThreatPreventionStrategy))
	} else {
		item.ThreatPreventionStrategy = types.StringValue("Legacy")
	}

	item.CustomEngineConfig = customEngineConfigToObject(context.Background(), api.CustomEngineConfig, diags)

	return item
}

// customEngineConfigToObject converts an API CustomEngineConfig to a types.Object.
func customEngineConfigToObject(ctx context.Context, cfg *jamfprotect.CustomEngineConfig, diags *diag.Diagnostics) types.Object {
	if cfg == nil {
		return types.ObjectNull(customEngineConfigAttrTypes)
	}
	malwareUI, ok := customEngineConfigModeFromAPI(cfg.MalwareRiskware)
	if !ok {
		malwareUI = cfg.MalwareRiskware
	}
	adversaryUI, ok := customEngineConfigModeFromAPI(cfg.AdversaryTactics)
	if !ok {
		adversaryUI = cfg.AdversaryTactics
	}
	systemUI, ok := customEngineConfigModeFromAPI(cfg.SystemTampering)
	if !ok {
		systemUI = cfg.SystemTampering
	}
	filelessUI, ok := customEngineConfigModeFromAPI(cfg.FilelessThreats)
	if !ok {
		filelessUI = cfg.FilelessThreats
	}
	experimentalUI, ok := customEngineConfigModeFromAPI(cfg.Experimental)
	if !ok {
		experimentalUI = cfg.Experimental
	}
	obj, d := types.ObjectValueFrom(ctx, customEngineConfigAttrTypes, CustomEngineConfigModel{
		MalwareRiskware:  types.StringValue(malwareUI),
		AdversaryTactics: types.StringValue(adversaryUI),
		SystemTampering:  types.StringValue(systemUI),
		FilelessThreats:  types.StringValue(filelessUI),
		Experimental:     types.StringValue(experimentalUI),
	})
	diags.Append(d...)
	return obj
}

// setReportingFlags maps info sync settings into the resource model.
func setReportingFlags(data *PlanResourceModel, infoSync *jamfprotect.PlanInfoSync) {
	if infoSync == nil {
		data.ReportingInterval = types.Int64Null()
		data.ReportArchitecture = types.BoolValue(false)
		data.ReportHostname = types.BoolValue(false)
		data.ReportKernelVersion = types.BoolValue(false)
		data.ReportMemorySize = types.BoolValue(false)
		data.ReportModelName = types.BoolValue(false)
		data.ReportSerialNumber = types.BoolValue(false)
		data.ComplianceBaseline = types.BoolValue(false)
		data.ReportOSVersion = types.BoolValue(false)
		return
	}

	data.ReportingInterval = types.Int64Value(infoSync.InsightsSyncInterval / 60)

	attrSet := map[string]struct{}{}
	for _, attr := range infoSync.Attrs {
		attrSet[attr] = struct{}{}
	}

	data.ReportArchitecture = types.BoolValue(hasAttr(attrSet, "arch"))
	data.ReportHostname = types.BoolValue(hasAttr(attrSet, "hostName"))
	data.ReportKernelVersion = types.BoolValue(hasAttr(attrSet, "kernelVersion"))
	data.ReportMemorySize = types.BoolValue(hasAttr(attrSet, "memorySize"))
	data.ReportModelName = types.BoolValue(hasAttr(attrSet, "modelName"))
	data.ReportSerialNumber = types.BoolValue(hasAttr(attrSet, "serial"))
	data.ComplianceBaseline = types.BoolValue(hasAttr(attrSet, "insights"))
	data.ReportOSVersion = types.BoolValue(
		hasAttr(attrSet, "osMajor") || hasAttr(attrSet, "osMinor") || hasAttr(attrSet, "osPatch") || hasAttr(attrSet, "osString"),
	)
}

// setReportingFlagsDataSource maps info sync settings into the data source model.
func setReportingFlagsDataSource(item *PlanDataSourceItemModel, infoSync *jamfprotect.PlanInfoSync) {
	if infoSync == nil {
		item.ReportingInterval = types.Int64Null()
		item.ReportArchitecture = types.BoolValue(false)
		item.ReportHostname = types.BoolValue(false)
		item.ReportKernelVersion = types.BoolValue(false)
		item.ReportMemorySize = types.BoolValue(false)
		item.ReportModelName = types.BoolValue(false)
		item.ReportSerialNumber = types.BoolValue(false)
		item.ComplianceBaseline = types.BoolValue(false)
		item.ReportOSVersion = types.BoolValue(false)
		return
	}

	item.ReportingInterval = types.Int64Value(infoSync.InsightsSyncInterval / 60)

	attrSet := map[string]struct{}{}
	for _, attr := range infoSync.Attrs {
		attrSet[attr] = struct{}{}
	}

	item.ReportArchitecture = types.BoolValue(hasAttr(attrSet, "arch"))
	item.ReportHostname = types.BoolValue(hasAttr(attrSet, "hostName"))
	item.ReportKernelVersion = types.BoolValue(hasAttr(attrSet, "kernelVersion"))
	item.ReportMemorySize = types.BoolValue(hasAttr(attrSet, "memorySize"))
	item.ReportModelName = types.BoolValue(hasAttr(attrSet, "modelName"))
	item.ReportSerialNumber = types.BoolValue(hasAttr(attrSet, "serial"))
	item.ComplianceBaseline = types.BoolValue(hasAttr(attrSet, "insights"))
	item.ReportOSVersion = types.BoolValue(
		hasAttr(attrSet, "osMajor") || hasAttr(attrSet, "osMinor") || hasAttr(attrSet, "osPatch") || hasAttr(attrSet, "osString"),
	)
}

// hasAttr reports whether an attribute is present in the set.
func hasAttr(attrs map[string]struct{}, key string) bool {
	_, ok := attrs[key]
	return ok
}
