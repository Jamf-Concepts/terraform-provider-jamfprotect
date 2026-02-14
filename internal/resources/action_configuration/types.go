// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ActionConfigResourceModel maps the resource schema data.
type ActionConfigResourceModel struct {
	ID                types.String   `tfsdk:"id"`
	Hash              types.String   `tfsdk:"hash"`
	Name              types.String   `tfsdk:"name"`
	Description       types.String   `tfsdk:"description"`
	DataCollection    types.Object   `tfsdk:"data_collection"`
	EndpointHTTP      types.Object   `tfsdk:"endpoint_http"`
	EndpointKafka     types.Object   `tfsdk:"endpoint_kafka"`
	EndpointSyslog    types.Object   `tfsdk:"endpoint_syslog"`
	EndpointLogFile   types.Object   `tfsdk:"endpoint_log_file"`
	EndpointJamfCloud types.Object   `tfsdk:"endpoint_jamf_cloud"`
	Created           types.String   `tfsdk:"created"`
	Updated           types.String   `tfsdk:"updated"`
	Timeouts          timeouts.Value `tfsdk:"timeouts"`
}

// dataCollectionModel maps the top-level data_collection attribute.
type dataCollectionModel struct {
	Data types.Object `tfsdk:"data"`
}

// dataCollectionDataModel maps the data_collection.data nested attribute containing all event types.
type dataCollectionDataModel struct {
	Binary                  types.Object `tfsdk:"binary"`
	SyntheticClickEvent     types.Object `tfsdk:"synthetic_click_event"`
	DownloadEvent           types.Object `tfsdk:"download_event"`
	File                    types.Object `tfsdk:"file"`
	FileSystemEvent         types.Object `tfsdk:"file_system_event"`
	Group                   types.Object `tfsdk:"group"`
	ProcessEvent            types.Object `tfsdk:"process_event"`
	Process                 types.Object `tfsdk:"process"`
	ScreenshotEvent         types.Object `tfsdk:"screenshot_event"`
	UsbEvent                types.Object `tfsdk:"usb_event"`
	User                    types.Object `tfsdk:"user"`
	GatekeeperEvent         types.Object `tfsdk:"gatekeeper_event"`
	KeylogRegisterEvent     types.Object `tfsdk:"keylog_register_event"`
	MalwareRemovalToolEvent types.Object `tfsdk:"malware_removal_tool_event"`
}

// alertEventTypeModel maps each event type entry with attrs and related.
type alertEventTypeModel struct {
	Attrs   types.List `tfsdk:"attrs"`
	Related types.List `tfsdk:"related"`
}

// Endpoint models map UI data endpoint blocks.
type endpointHTTPModel struct {
	Enabled            types.Bool   `tfsdk:"enabled"`
	SupportedReports   types.List   `tfsdk:"supported_reports"`
	BatchSizeIndex     types.Int64  `tfsdk:"batch_size_index"`
	BatchWindowSeconds types.Int64  `tfsdk:"batch_window_seconds"`
	BatchSizeInBytes   types.Int64  `tfsdk:"batch_size_in_bytes"`
	BatchDelimiter     types.String `tfsdk:"batch_delimiter"`
	URL                types.String `tfsdk:"url"`
	Method             types.String `tfsdk:"method"`
	Headers            types.List   `tfsdk:"headers"`
}

type endpointKafkaModel struct {
	Enabled            types.Bool   `tfsdk:"enabled"`
	SupportedReports   types.List   `tfsdk:"supported_reports"`
	BatchSizeIndex     types.Int64  `tfsdk:"batch_size_index"`
	BatchWindowSeconds types.Int64  `tfsdk:"batch_window_seconds"`
	BatchSizeInBytes   types.Int64  `tfsdk:"batch_size_in_bytes"`
	BatchDelimiter     types.String `tfsdk:"batch_delimiter"`
	Host               types.String `tfsdk:"host"`
	Port               types.Int64  `tfsdk:"port"`
	Topic              types.String `tfsdk:"topic"`
	ClientCN           types.String `tfsdk:"client_cn"`
	ServerCN           types.String `tfsdk:"server_cn"`
}

type endpointSyslogModel struct {
	Enabled            types.Bool   `tfsdk:"enabled"`
	SupportedReports   types.List   `tfsdk:"supported_reports"`
	BatchSizeIndex     types.Int64  `tfsdk:"batch_size_index"`
	BatchWindowSeconds types.Int64  `tfsdk:"batch_window_seconds"`
	BatchSizeInBytes   types.Int64  `tfsdk:"batch_size_in_bytes"`
	BatchDelimiter     types.String `tfsdk:"batch_delimiter"`
	Host               types.String `tfsdk:"host"`
	Port               types.Int64  `tfsdk:"port"`
	Scheme             types.String `tfsdk:"scheme"`
}

type endpointLogFileModel struct {
	Enabled            types.Bool   `tfsdk:"enabled"`
	SupportedReports   types.List   `tfsdk:"supported_reports"`
	BatchSizeIndex     types.Int64  `tfsdk:"batch_size_index"`
	BatchWindowSeconds types.Int64  `tfsdk:"batch_window_seconds"`
	BatchSizeInBytes   types.Int64  `tfsdk:"batch_size_in_bytes"`
	BatchDelimiter     types.String `tfsdk:"batch_delimiter"`
	Path               types.String `tfsdk:"path"`
	Permissions        types.String `tfsdk:"permissions"`
	MaxSizeMB          types.Int64  `tfsdk:"max_size_mb"`
	Ownership          types.String `tfsdk:"ownership"`
	Backups            types.Int64  `tfsdk:"backups"`
}

type endpointJamfCloudModel struct {
	Enabled            types.Bool   `tfsdk:"enabled"`
	SupportedReports   types.List   `tfsdk:"supported_reports"`
	BatchSizeIndex     types.Int64  `tfsdk:"batch_size_index"`
	BatchWindowSeconds types.Int64  `tfsdk:"batch_window_seconds"`
	BatchSizeInBytes   types.Int64  `tfsdk:"batch_size_in_bytes"`
	BatchDelimiter     types.String `tfsdk:"batch_delimiter"`
	DestinationFilter  types.String `tfsdk:"destination_filter"`
}

type endpointHeaderModel struct {
	Header types.String `tfsdk:"header"`
	Value  types.String `tfsdk:"value"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type actionConfigAPIModel struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Hash        string                 `json:"hash"`
	Created     string                 `json:"created"`
	Updated     string                 `json:"updated"`
	AlertConfig *alertConfigAPIModel   `json:"alertConfig"`
	Clients     []reportClientAPIModel `json:"clients"`
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

type reportClientAPIModel struct {
	ID               string                     `json:"id"`
	Type             string                     `json:"type"`
	SupportedReports []string                   `json:"supportedReports"`
	BatchConfig      *batchConfigAPIModel       `json:"batchConfig"`
	Params           reportClientParamsAPIModel `json:"params"`
}

type batchConfigAPIModel struct {
	Delimiter       string `json:"delimiter"`
	SizeIndex       int64  `json:"sizeIndex"`
	WindowInSeconds int64  `json:"windowInSeconds"`
	SizeInBytes     int64  `json:"sizeInBytes"`
}

type reportClientParamsAPIModel struct {
	DestinationFilter string                       `json:"destinationFilter"`
	Headers           []reportClientHeaderAPIModel `json:"headers"`
	Method            string                       `json:"method"`
	URL               string                       `json:"url"`
	Host              string                       `json:"host"`
	Port              int64                        `json:"port"`
	Topic             string                       `json:"topic"`
	ClientCN          string                       `json:"clientCN"`
	ServerCN          string                       `json:"serverCN"`
	Scheme            string                       `json:"scheme"`
	Path              string                       `json:"path"`
	Permissions       string                       `json:"permissions"`
	MaxSizeMB         int64                        `json:"maxSizeMB"`
	Ownership         string                       `json:"ownership"`
	Backups           int64                        `json:"backups"`
}

type reportClientHeaderAPIModel struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}
