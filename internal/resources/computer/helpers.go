package computer

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"
)

// computerPlanAttrTypes defines the attribute types for the plan object.
var computerPlanAttrTypes = map[string]attr.Type{
	"id":   types.StringType,
	"name": types.StringType,
	"hash": types.StringType,
}

// computerDataSourceAttributes returns the schema attributes for a computer data source.
func computerDataSourceAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"uuid": schema.StringAttribute{
			MarkdownDescription: "The unique identifier of the computer.",
			Computed:            true,
		},
		"serial": schema.StringAttribute{
			MarkdownDescription: "The serial number of the computer.",
			Computed:            true,
		},
		"host_name": schema.StringAttribute{
			MarkdownDescription: "The hostname of the computer.",
			Computed:            true,
		},
		"model_name": schema.StringAttribute{
			MarkdownDescription: "The model name of the computer.",
			Computed:            true,
		},
		"os_major": schema.Int64Attribute{
			MarkdownDescription: "The major version of the operating system.",
			Computed:            true,
		},
		"os_minor": schema.Int64Attribute{
			MarkdownDescription: "The minor version of the operating system.",
			Computed:            true,
		},
		"os_patch": schema.Int64Attribute{
			MarkdownDescription: "The patch version of the operating system.",
			Computed:            true,
		},
		"arch": schema.StringAttribute{
			MarkdownDescription: "The architecture of the computer (e.g., arm64, x86_64).",
			Computed:            true,
		},
		"cert_id": schema.StringAttribute{
			MarkdownDescription: "The certificate ID of the computer.",
			Computed:            true,
		},
		"memory_size": schema.Int64Attribute{
			MarkdownDescription: "The memory size of the computer in bytes.",
			Computed:            true,
		},
		"os_string": schema.StringAttribute{
			MarkdownDescription: "The full operating system version string.",
			Computed:            true,
		},
		"kernel_version": schema.StringAttribute{
			MarkdownDescription: "The kernel version of the operating system.",
			Computed:            true,
		},
		"install_type": schema.StringAttribute{
			MarkdownDescription: "The installation type of Jamf Protect on the computer.",
			Computed:            true,
		},
		"label": schema.StringAttribute{
			MarkdownDescription: "A custom label for the computer.",
			Computed:            true,
		},
		"created": schema.StringAttribute{
			MarkdownDescription: "The timestamp when the computer was enrolled.",
			Computed:            true,
		},
		"updated": schema.StringAttribute{
			MarkdownDescription: "The timestamp when the computer record was last updated.",
			Computed:            true,
		},
		"version": schema.StringAttribute{
			MarkdownDescription: "The version of Jamf Protect installed on the computer.",
			Computed:            true,
		},
		"checkin": schema.StringAttribute{
			MarkdownDescription: "The timestamp of the last check-in.",
			Computed:            true,
		},
		"config_hash": schema.StringAttribute{
			MarkdownDescription: "The hash of the current configuration.",
			Computed:            true,
		},
		"tags": schema.SetAttribute{
			MarkdownDescription: "Tags associated with the computer.",
			Computed:            true,
			ElementType:         types.StringType,
		},
		"signatures_version": schema.Int64Attribute{
			MarkdownDescription: "The version of threat prevention signatures.",
			Computed:            true,
		},
		"plan": schema.SingleNestedAttribute{
			MarkdownDescription: "The plan assigned to the computer.",
			Computed:            true,
			Attributes: map[string]schema.Attribute{
				"id": schema.StringAttribute{
					MarkdownDescription: "The ID of the plan.",
					Computed:            true,
				},
				"name": schema.StringAttribute{
					MarkdownDescription: "The name of the plan.",
					Computed:            true,
				},
				"hash": schema.StringAttribute{
					MarkdownDescription: "The hash of the plan configuration.",
					Computed:            true,
				},
			},
		},
		"insights_stats_fail": schema.Int64Attribute{
			MarkdownDescription: "The number of failed insights checks.",
			Computed:            true,
		},
		"insights_updated": schema.StringAttribute{
			MarkdownDescription: "The timestamp when insights were last updated.",
			Computed:            true,
		},
		"connection_status": schema.StringAttribute{
			MarkdownDescription: "The current connection status (CONNECTED, DISCONNECTED).",
			Computed:            true,
		},
		"last_connection": schema.StringAttribute{
			MarkdownDescription: "The timestamp of the last connection.",
			Computed:            true,
		},
		"last_connection_ip": schema.StringAttribute{
			MarkdownDescription: "The IP address from the last connection.",
			Computed:            true,
		},
		"last_disconnection": schema.StringAttribute{
			MarkdownDescription: "The timestamp of the last disconnection.",
			Computed:            true,
		},
		"last_disconnection_reason": schema.StringAttribute{
			MarkdownDescription: "The reason for the last disconnection.",
			Computed:            true,
		},
		"web_protection_active": schema.BoolAttribute{
			MarkdownDescription: "Whether web protection is active on the computer.",
			Computed:            true,
		},
		"full_disk_access": schema.StringAttribute{
			MarkdownDescription: "Whether Jamf Protect has Full Disk Access on the computer.",
			Computed:            true,
		},
		"pending_plan": schema.Int64Attribute{
			MarkdownDescription: "Whether there is a pending plan update for the computer.",
			Computed:            true,
		},
	}
}

// buildComputerModel builds a ComputerModel from a Computer API response.
func buildComputerModel(computer jamfprotect.Computer) ComputerModel {
	model := ComputerModel{
		UUID:                    types.StringPointerValue(computer.UUID),
		Serial:                  types.StringPointerValue(computer.Serial),
		HostName:                types.StringPointerValue(computer.HostName),
		ModelName:               types.StringPointerValue(computer.ModelName),
		OSMajor:                 types.Int64PointerValue(computer.OSMajor),
		OSMinor:                 types.Int64PointerValue(computer.OSMinor),
		OSPatch:                 types.Int64PointerValue(computer.OSPatch),
		Arch:                    types.StringPointerValue(computer.Arch),
		CertID:                  types.StringPointerValue(computer.CertID),
		MemorySize:              types.Int64PointerValue(computer.MemorySize),
		OSString:                types.StringPointerValue(computer.OSString),
		KernelVersion:           types.StringPointerValue(computer.KernelVersion),
		InstallType:             types.StringPointerValue(computer.InstallType),
		Label:                   types.StringPointerValue(computer.Label),
		Created:                 types.StringPointerValue(computer.Created),
		Updated:                 types.StringPointerValue(computer.Updated),
		Version:                 types.StringPointerValue(computer.Version),
		Checkin:                 types.StringPointerValue(computer.Checkin),
		ConfigHash:              types.StringPointerValue(computer.ConfigHash),
		SignaturesVersion:       types.Int64PointerValue(computer.SignaturesVersion),
		InsightsStatsFail:       types.Int64PointerValue(computer.InsightsStatsFail),
		InsightsUpdated:         types.StringPointerValue(computer.InsightsUpdated),
		ConnectionStatus:        types.StringPointerValue(computer.ConnectionStatus),
		LastConnection:          types.StringPointerValue(computer.LastConnection),
		LastConnectionIP:        types.StringPointerValue(computer.LastConnectionIP),
		LastDisconnection:       types.StringPointerValue(computer.LastDisconnection),
		LastDisconnectionReason: types.StringPointerValue(computer.LastDisconnectionReason),
		WebProtectionActive:     types.BoolPointerValue(computer.WebProtectionActive),
		FullDiskAccess:          types.StringPointerValue(computer.FullDiskAccess),
		PendingPlan:             types.Int64PointerValue(computer.PendingPlan),
	}

	// Handle tags
	if computer.Tags != nil && len(*computer.Tags) > 0 {
		tagElements := make([]attr.Value, len(*computer.Tags))
		for i, tag := range *computer.Tags {
			tagElements[i] = types.StringValue(tag)
		}
		model.Tags = types.SetValueMust(types.StringType, tagElements)
	} else {
		model.Tags = types.SetNull(types.StringType)
	}

	// Handle plan
	if computer.Plan != nil {
		planAttrs := map[string]attr.Value{
			"id":   types.StringPointerValue(computer.Plan.ID),
			"name": types.StringPointerValue(computer.Plan.Name),
			"hash": types.StringPointerValue(computer.Plan.Hash),
		}
		model.Plan = types.ObjectValueMust(computerPlanAttrTypes, planAttrs)
	} else {
		model.Plan = types.ObjectNull(computerPlanAttrTypes)
	}

	return model
}
