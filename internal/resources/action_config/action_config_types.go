// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package actionconfig

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ActionConfigResourceModel maps the resource schema data.
type ActionConfigResourceModel struct {
	ID          types.String   `tfsdk:"id"`
	Hash        types.String   `tfsdk:"hash"`
	Name        types.String   `tfsdk:"name"`
	Description types.String   `tfsdk:"description"`
	AlertConfig types.Object   `tfsdk:"alert_config"`
	Created     types.String   `tfsdk:"created"`
	Updated     types.String   `tfsdk:"updated"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

// alertConfigModel maps the top-level alert_config attribute.
type alertConfigModel struct {
	Data types.Object `tfsdk:"data"`
}

// alertDataModel maps the alert_config.data nested attribute containing all 14 event types.
type alertDataModel struct {
	Binary              types.Object `tfsdk:"binary"`
	ClickEvent          types.Object `tfsdk:"click_event"`
	DownloadEvent       types.Object `tfsdk:"download_event"`
	File                types.Object `tfsdk:"file"`
	FsEvent             types.Object `tfsdk:"fs_event"`
	Group               types.Object `tfsdk:"group"`
	ProcEvent           types.Object `tfsdk:"proc_event"`
	Process             types.Object `tfsdk:"process"`
	ScreenshotEvent     types.Object `tfsdk:"screenshot_event"`
	UsbEvent            types.Object `tfsdk:"usb_event"`
	User                types.Object `tfsdk:"user"`
	GkEvent             types.Object `tfsdk:"gk_event"`
	KeylogRegisterEvent types.Object `tfsdk:"keylog_register_event"`
	MrtEvent            types.Object `tfsdk:"mrt_event"`
}

// alertEventTypeModel maps each event type entry with attrs and related.
type alertEventTypeModel struct {
	Attrs   types.List `tfsdk:"attrs"`
	Related types.List `tfsdk:"related"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type actionConfigAPIModel struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Hash        string               `json:"hash"`
	Created     string               `json:"created"`
	Updated     string               `json:"updated"`
	AlertConfig *alertConfigAPIModel `json:"alertConfig"`
}

type alertConfigAPIModel struct {
	Data *alertDataAPIModel `json:"data"`
}

type alertDataAPIModel struct {
	Binary              *alertEventTypeAPIModel `json:"binary"`
	ClickEvent          *alertEventTypeAPIModel `json:"clickEvent"`
	DownloadEvent       *alertEventTypeAPIModel `json:"downloadEvent"`
	File                *alertEventTypeAPIModel `json:"file"`
	FsEvent             *alertEventTypeAPIModel `json:"fsEvent"`
	Group               *alertEventTypeAPIModel `json:"group"`
	ProcEvent           *alertEventTypeAPIModel `json:"procEvent"`
	Process             *alertEventTypeAPIModel `json:"process"`
	ScreenshotEvent     *alertEventTypeAPIModel `json:"screenshotEvent"`
	UsbEvent            *alertEventTypeAPIModel `json:"usbEvent"`
	User                *alertEventTypeAPIModel `json:"user"`
	GkEvent             *alertEventTypeAPIModel `json:"gkEvent"`
	KeylogRegisterEvent *alertEventTypeAPIModel `json:"keylogRegisterEvent"`
	MrtEvent            *alertEventTypeAPIModel `json:"mrtEvent"`
}

type alertEventTypeAPIModel struct {
	Attrs   []string `json:"attrs"`
	Related []string `json:"related"`
}
