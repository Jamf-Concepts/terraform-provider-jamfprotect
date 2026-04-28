// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// AnalyticManagedResourceModel maps the resource schema for a Jamf-managed analytic.
// Most fields are server-owned (Computed) — only TenantActions and TenantSeverity are user-writable
// via the UpdateInternalAnalytic mutation.
type AnalyticManagedResourceModel struct {
	ID              types.String   `tfsdk:"id"`
	Name            types.String   `tfsdk:"name"`
	SensorType      types.String   `tfsdk:"sensor_type"`
	Description     types.String   `tfsdk:"description"`
	Label           types.String   `tfsdk:"label"`
	LongDescription types.String   `tfsdk:"long_description"`
	Filter          types.String   `tfsdk:"filter"`
	Level           types.Int64    `tfsdk:"level"`
	Severity        types.String   `tfsdk:"severity"`
	Tags            types.Set      `tfsdk:"tags"`
	Categories      types.Set      `tfsdk:"categories"`
	SnapshotFiles   types.Set      `tfsdk:"snapshot_files"`
	ContextItem     types.Set      `tfsdk:"context_item"`
	TenantActions   types.Set      `tfsdk:"tenant_actions"`
	TenantSeverity  types.String   `tfsdk:"tenant_severity"`
	Created         types.String   `tfsdk:"created"`
	Updated         types.String   `tfsdk:"updated"`
	Jamf            types.Bool     `tfsdk:"jamf"`
	Remediation     types.String   `tfsdk:"remediation"`
	Timeouts        timeouts.Value `tfsdk:"timeouts"`
}

// tenantActionModel maps a single tenant action entry for ElementsAs decoding.
type tenantActionModel struct {
	Name       types.String `tfsdk:"name"`
	Parameters types.Map    `tfsdk:"parameters"`
}
