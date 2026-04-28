// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package computer

import "github.com/hashicorp/terraform-plugin-framework/types"

// ComputerModel maps the computer data for data sources and list resources.
type ComputerModel struct {
	UUID                    types.String  `tfsdk:"uuid"`
	Serial                  types.String  `tfsdk:"serial"`
	HostName                types.String  `tfsdk:"host_name"`
	ModelName               types.String  `tfsdk:"model_name"`
	OSMajor                 types.Int64   `tfsdk:"os_major"`
	OSMinor                 types.Int64   `tfsdk:"os_minor"`
	OSPatch                 types.Int64   `tfsdk:"os_patch"`
	Arch                    types.String  `tfsdk:"arch"`
	CertID                  types.String  `tfsdk:"cert_id"`
	MemorySize              types.Float64 `tfsdk:"memory_size"`
	OSString                types.String  `tfsdk:"os_string"`
	KernelVersion           types.String  `tfsdk:"kernel_version"`
	InstallType             types.String  `tfsdk:"install_type"`
	Label                   types.String  `tfsdk:"label"`
	Created                 types.String  `tfsdk:"created"`
	Updated                 types.String  `tfsdk:"updated"`
	Version                 types.String  `tfsdk:"version"`
	Checkin                 types.String  `tfsdk:"checkin"`
	ConfigHash              types.String  `tfsdk:"config_hash"`
	Tags                    types.List    `tfsdk:"tags"`
	SignaturesVersion       types.Int64   `tfsdk:"signatures_version"`
	Plan                    types.Object  `tfsdk:"plan"`
	InsightsStatsFail       types.Int64   `tfsdk:"insights_stats_fail"`
	InsightsUpdated         types.String  `tfsdk:"insights_updated"`
	ConnectionStatus        types.String  `tfsdk:"connection_status"`
	LastConnection          types.String  `tfsdk:"last_connection"`
	LastConnectionIP        types.String  `tfsdk:"last_connection_ip"`
	LastDisconnection       types.String  `tfsdk:"last_disconnection"`
	LastDisconnectionReason types.String  `tfsdk:"last_disconnection_reason"`
	WebProtectionActive     types.Bool    `tfsdk:"web_protection_active"`
	FullDiskAccess          types.String  `tfsdk:"full_disk_access"`
	PendingPlan             types.Int64   `tfsdk:"pending_plan"`
}

// ComputerPlanModel maps the nested plan object.
type ComputerPlanModel struct {
	ID   types.String `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
	Hash types.String `tfsdk:"hash"`
}

// ComputersDataSourceModel maps the plural data source schema.
type ComputersDataSourceModel struct {
	Computers []ComputerModel `tfsdk:"computers"`
}
