// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// PlanResourceModel maps the resource schema data.
type PlanResourceModel struct {
	ID                   types.String   `tfsdk:"id"`
	Hash                 types.String   `tfsdk:"hash"`
	Name                 types.String   `tfsdk:"name"`
	Description          types.String   `tfsdk:"description"`
	LogLevel             types.String   `tfsdk:"log_level"`
	AutoUpdate           types.Bool     `tfsdk:"auto_update"`
	ActionConfigs        types.String   `tfsdk:"action_configs"`
	ExceptionSets        types.List     `tfsdk:"exception_sets"`
	Telemetry            types.String   `tfsdk:"telemetry"`
	TelemetryV2          types.String   `tfsdk:"telemetry_v2"`
	USBControlSet        types.String   `tfsdk:"usb_control_set"`
	AnalyticSets         types.List     `tfsdk:"analytic_sets"`
	CommsConfig          types.Object   `tfsdk:"comms_config"`
	InfoSync             types.Object   `tfsdk:"info_sync"`
	SignaturesFeedConfig types.Object   `tfsdk:"signatures_feed_config"`
	Created              types.String   `tfsdk:"created"`
	Updated              types.String   `tfsdk:"updated"`
	Timeouts             timeouts.Value `tfsdk:"timeouts"`
}

// planAnalyticSetModel maps PlanAnalyticSetInput / response.
type planAnalyticSetModel struct {
	Type        types.String `tfsdk:"type"`
	AnalyticSet types.String `tfsdk:"analytic_set"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type planAPIModel struct {
	ID                   string                      `json:"id"`
	Hash                 string                      `json:"hash"`
	Name                 string                      `json:"name"`
	Description          string                      `json:"description"`
	Created              string                      `json:"created"`
	Updated              string                      `json:"updated"`
	LogLevel             string                      `json:"logLevel"`
	AutoUpdate           bool                        `json:"autoUpdate"`
	CommsConfig          *planCommsConfigAPIModel    `json:"commsConfig"`
	InfoSync             *planInfoSyncAPIModel       `json:"infoSync"`
	SignaturesFeedConfig *planSignaturesFeedAPIModel `json:"signaturesFeedConfig"`
	ActionConfigs        *planRefAPIModel            `json:"actionConfigs"`
	ExceptionSets        []planExceptionSetAPIModel  `json:"exceptionSets"`
	USBControlSet        *planRefAPIModel            `json:"usbControlSet"`
	Telemetry            *planRefAPIModel            `json:"telemetry"`
	TelemetryV2          *planRefAPIModel            `json:"telemetryV2"`
	AnalyticSets         []planAnalyticSetAPIModel   `json:"analyticSets"`
}

type planCommsConfigAPIModel struct {
	FQDN     string `json:"fqdn"`
	Protocol string `json:"protocol"`
}

type planInfoSyncAPIModel struct {
	Attrs                []string `json:"attrs"`
	InsightsSyncInterval int64    `json:"insightsSyncInterval"`
}

type planSignaturesFeedAPIModel struct {
	Mode string `json:"mode"`
}

type planRefAPIModel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type planExceptionSetAPIModel struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
}

type planAnalyticSetAPIModel struct {
	Type        string                     `json:"type"`
	AnalyticSet planAnalyticSetRefAPIModel `json:"analyticSet"`
}

type planAnalyticSetRefAPIModel struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Managed bool   `json:"managed"`
}
