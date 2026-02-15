// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// RemovableStorageControlSetResourceModel maps the resource schema data.
type RemovableStorageControlSetResourceModel struct {
	ID                   types.String                `tfsdk:"id"`
	Name                 types.String                `tfsdk:"name"`
	Description          types.String                `tfsdk:"description"`
	DefaultMountAction   types.String                `tfsdk:"default_mount_action"`
	DefaultMessageAction types.String                `tfsdk:"default_message_action"`
	Rules                []RemovableStorageRuleModel `tfsdk:"rules"`
	Created              types.String                `tfsdk:"created"`
	Updated              types.String                `tfsdk:"updated"`
	Timeouts             timeouts.Value              `tfsdk:"timeouts"`
}

// RemovableStorageRuleModel represents a single rule in the removable storage control set.
// Uses a discriminator field "type" with optional fields per rule variant.
type RemovableStorageRuleModel struct {
	Type          types.String                   `tfsdk:"type"`
	MountAction   types.String                   `tfsdk:"mount_action"`
	MessageAction types.String                   `tfsdk:"message_action"`
	ApplyTo       types.String                   `tfsdk:"apply_to"`
	Vendors       types.List                     `tfsdk:"vendors"`
	Serials       types.List                     `tfsdk:"serials"`
	Products      []RemovableStorageProductModel `tfsdk:"products"`
}

// RemovableStorageProductModel represents a vendor+product pair in a ProductRule.
type RemovableStorageProductModel struct {
	Vendor  types.String `tfsdk:"vendor"`
	Product types.String `tfsdk:"product"`
}
