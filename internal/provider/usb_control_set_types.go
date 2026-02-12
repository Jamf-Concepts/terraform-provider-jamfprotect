// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// USBControlSetResourceModel maps the resource schema data.
type USBControlSetResourceModel struct {
	ID                   types.String   `tfsdk:"id"`
	Name                 types.String   `tfsdk:"name"`
	Description          types.String   `tfsdk:"description"`
	DefaultMountAction   types.String   `tfsdk:"default_mount_action"`
	DefaultMessageAction types.String   `tfsdk:"default_message_action"`
	Rules                []USBRuleModel `tfsdk:"rules"`
	Created              types.String   `tfsdk:"created"`
	Updated              types.String   `tfsdk:"updated"`
	Timeouts             timeouts.Value `tfsdk:"timeouts"`
}

// USBRuleModel represents a single rule in the USB control set.
// Uses a discriminator field "type" with optional fields per rule variant.
type USBRuleModel struct {
	Type          types.String      `tfsdk:"type"`
	MountAction   types.String      `tfsdk:"mount_action"`
	MessageAction types.String      `tfsdk:"message_action"`
	ApplyTo       types.String      `tfsdk:"apply_to"`
	Vendors       types.List        `tfsdk:"vendors"`
	Serials       types.List        `tfsdk:"serials"`
	Products      []USBProductModel `tfsdk:"products"`
}

// USBProductModel represents a vendor+product pair in a ProductRule.
type USBProductModel struct {
	Vendor  types.String `tfsdk:"vendor"`
	Product types.String `tfsdk:"product"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type usbControlSetAPIModel struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	Description          string            `json:"description"`
	DefaultMountAction   string            `json:"defaultMountAction"`
	DefaultMessageAction string            `json:"defaultMessageAction"`
	Rules                []usbRuleAPIModel `json:"rules"`
	Created              string            `json:"created"`
	Updated              string            `json:"updated"`
}

type usbRuleAPIModel struct {
	Type          string               `json:"type"`
	MountAction   string               `json:"mountAction"`
	MessageAction string               `json:"messageAction"`
	ApplyTo       string               `json:"applyTo"`
	Vendors       []string             `json:"vendors"`
	Serials       []string             `json:"serials"`
	Products      []usbProductAPIModel `json:"products"`
}

type usbProductAPIModel struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}
