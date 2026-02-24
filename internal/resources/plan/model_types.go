// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// PlanResourceModel maps the resource schema data.
type PlanResourceModel struct {
	ID                       types.String   `tfsdk:"id"`
	Hash                     types.String   `tfsdk:"hash"`
	Name                     types.String   `tfsdk:"name"`
	Description              types.String   `tfsdk:"description"`
	LogLevel                 types.String   `tfsdk:"log_level"`
	AutoUpdate               types.Bool     `tfsdk:"auto_update"`
	ActionConfiguration      types.String   `tfsdk:"action_configuration"`
	ExceptionSets            types.Set      `tfsdk:"exception_sets"`
	Telemetry                types.String   `tfsdk:"telemetry"`
	USBControlSet            types.String   `tfsdk:"removable_storage_control_set"`
	AnalyticSets             types.Set      `tfsdk:"analytic_sets"`
	CommunicationsProtocol   types.String   `tfsdk:"communications_protocol"`
	ReportingInterval        types.Int64    `tfsdk:"reporting_interval"`
	ReportArchitecture       types.Bool     `tfsdk:"report_architecture"`
	ReportHostname           types.Bool     `tfsdk:"report_hostname"`
	ReportKernelVersion      types.Bool     `tfsdk:"report_kernel_version"`
	ReportMemorySize         types.Bool     `tfsdk:"report_memory_size"`
	ReportModelName          types.Bool     `tfsdk:"report_model_name"`
	ReportSerialNumber       types.Bool     `tfsdk:"report_serial_number"`
	ComplianceBaseline       types.Bool     `tfsdk:"compliance_baseline_reporting"`
	ReportOSVersion          types.Bool     `tfsdk:"report_os_version"`
	EndpointThreatPrevention types.String   `tfsdk:"endpoint_threat_prevention"`
	AdvancedThreatControls   types.String   `tfsdk:"advanced_threat_controls"`
	TamperPrevention         types.String   `tfsdk:"tamper_prevention"`
	Created                  types.String   `tfsdk:"created"`
	Updated                  types.String   `tfsdk:"updated"`
	Timeouts                 timeouts.Value `tfsdk:"timeouts"`
}
