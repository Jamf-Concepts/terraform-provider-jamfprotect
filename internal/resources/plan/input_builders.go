package plan

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// buildVariables converts the Terraform model into a plan input.
func (r *PlanResource) buildVariables(ctx context.Context, data PlanResourceModel, commsFQDN string, diags *diag.Diagnostics) *jamfprotect.PlanInput {
	input := &jamfprotect.PlanInput{
		Name:          data.Name.ValueString(),
		ActionConfigs: data.ActionConfiguration.ValueString(),
		AutoUpdate:    data.AutoUpdate.ValueBool(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	if !data.LogLevel.IsNull() {
		input.LogLevel = new(logLevelToAPI(data.LogLevel.ValueString()))
	}

	if data.Telemetry.IsNull() {
		input.TelemetryV2Null = true
	} else if !data.Telemetry.IsUnknown() {
		input.TelemetryV2 = new(data.Telemetry.ValueString())
	}

	if !data.USBControlSet.IsNull() {
		input.USBControlSet = new(data.USBControlSet.ValueString())
	}

	if !data.ExceptionSets.IsNull() {
		input.ExceptionSets = common.SetToStrings(ctx, data.ExceptionSets, diags)
	}

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
	shouldResolveManagedSets := len(analyticSets) > 0 || common.IsKnownString(data.AdvancedThreatControls) || common.IsKnownString(data.TamperPrevention)
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

	if common.IsKnownString(data.AdvancedThreatControls) {
		advancedValue := data.AdvancedThreatControls.ValueString()
		if advancedValue != "Disable" {
			uuid := managedSetUUIDs[advancedThreatControlsName]
			if uuid == "" {
				diags.AddError("Managed analytic set not found", fmt.Sprintf("Expected analytic set named %q.", advancedThreatControlsName))
				return nil
			}
			setType, ok := advancedThreatControlsToType(advancedValue)
			if !ok {
				diags.AddError("Invalid advanced threat controls value", "advanced_threat_controls must be one of: Block and report, Report only, Disable.")
				return nil
			}
			analyticSets = append(analyticSets, jamfprotect.PlanAnalyticSetInput{
				Type: setType,
				UUID: uuid,
			})
		}
	}

	if common.IsKnownString(data.TamperPrevention) {
		tamperValue := data.TamperPrevention.ValueString()
		if tamperValue != "Disable" {
			uuid := managedSetUUIDs[tamperPreventionName]
			if uuid == "" {
				diags.AddError("Managed analytic set not found", fmt.Sprintf("Expected analytic set named %q.", tamperPreventionName))
				return nil
			}
			setType, ok := tamperPreventionToType(tamperValue)
			if !ok {
				diags.AddError("Invalid tamper prevention value", "tamper_prevention must be one of: Block and report, Disable.")
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

	protocol := communicationsProtocolToAPI("MQTT:443")
	if common.IsKnownString(data.CommunicationsProtocol) {
		protocol = communicationsProtocolToAPI(data.CommunicationsProtocol.ValueString())
	}
	input.CommsConfig = jamfprotect.PlanCommsConfigInput{
		FQDN:     commsFQDN,
		Protocol: protocol,
	}

	if data.ReportingInterval.IsNull() {
		diags.AddError("Missing reporting interval", "reporting_interval must be set.")
		return nil
	}
	input.InfoSync = jamfprotect.PlanInfoSyncInput{
		Attrs:                buildInfoSyncAttrs(data),
		InsightsSyncInterval: data.ReportingInterval.ValueInt64() * 60,
	}

	if data.EndpointThreatPrevention.IsNull() {
		input.SignaturesFeedConfig = jamfprotect.PlanSignaturesFeedConfigInput{
			Mode: "blocking",
		}
	} else {
		mode, ok := endpointThreatPreventionToMode(data.EndpointThreatPrevention.ValueString())
		if !ok {
			diags.AddError(
				"Invalid endpoint threat prevention value",
				"endpoint_threat_prevention must be one of: Block and report, Report only, Disable.",
			)
			return nil
		}
		input.SignaturesFeedConfig = jamfprotect.PlanSignaturesFeedConfigInput{
			Mode: mode,
		}
	}

	return input
}

// buildInfoSyncAttrs builds info sync attributes from the plan model.
func buildInfoSyncAttrs(data PlanResourceModel) []string {
	attrs := make([]string, 0, 10)
	if data.ReportArchitecture.ValueBool() {
		attrs = append(attrs, "arch")
	}
	if data.ReportHostname.ValueBool() {
		attrs = append(attrs, "hostName")
	}
	if data.ReportKernelVersion.ValueBool() {
		attrs = append(attrs, "kernelVersion")
	}
	if data.ReportMemorySize.ValueBool() {
		attrs = append(attrs, "memorySize")
	}
	if data.ReportModelName.ValueBool() {
		attrs = append(attrs, "modelName")
	}
	if data.ReportSerialNumber.ValueBool() {
		attrs = append(attrs, "serial")
	}
	if data.ComplianceBaseline.ValueBool() {
		attrs = append(attrs, "insights")
	}
	if data.ReportOSVersion.ValueBool() {
		attrs = append(attrs, "osMajor", "osMinor", "osPatch", "osString")
	}
	return attrs
}
