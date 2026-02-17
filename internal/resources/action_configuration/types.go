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
	AlertDataCollect  types.Object   `tfsdk:"alert_data_collection"`
	HTTPEndpoints     types.List     `tfsdk:"http_endpoints"`
	KafkaEndpoints    types.List     `tfsdk:"kafka_endpoints"`
	SyslogEndpoints   types.List     `tfsdk:"syslog_endpoints"`
	LogFileEndpoint   types.Object   `tfsdk:"log_file_endpoint"`
	JamfCloudEndpoint types.Object   `tfsdk:"jamf_protect_cloud_endpoint"`
	Created           types.String   `tfsdk:"created"`
	Updated           types.String   `tfsdk:"updated"`
	Timeouts          timeouts.Value `tfsdk:"timeouts"`
}

// alertDataCollectionModel maps the alert_data_collection attribute.
type alertDataCollectionModel struct {
	EventTypes types.Object `tfsdk:"event_types"`
}

// alertEventTypesModel maps alert_data_collection.event_types containing all event types.
type alertEventTypesModel struct {
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

// alertEventTypeModel maps each event type entry with extended data attributes.
type alertEventTypeModel struct {
	ExtendedDataAttributes types.Set `tfsdk:"extended_data_attributes"`
}

// httpEndpointBlockModel maps each HTTP endpoint block.
type httpEndpointBlockModel struct {
	CollectAlerts types.Set    `tfsdk:"collect_alerts"`
	CollectLogs   types.Set    `tfsdk:"collect_logs"`
	Batching      types.Object `tfsdk:"batching"`
	HTTP          types.Object `tfsdk:"http"`
}

// kafkaEndpointBlockModel maps each Kafka endpoint block.
type kafkaEndpointBlockModel struct {
	CollectAlerts types.Set    `tfsdk:"collect_alerts"`
	CollectLogs   types.Set    `tfsdk:"collect_logs"`
	Batching      types.Object `tfsdk:"batching"`
	Kafka         types.Object `tfsdk:"kafka"`
}

// syslogEndpointBlockModel maps each Syslog endpoint block.
type syslogEndpointBlockModel struct {
	CollectAlerts types.Set    `tfsdk:"collect_alerts"`
	CollectLogs   types.Set    `tfsdk:"collect_logs"`
	Batching      types.Object `tfsdk:"batching"`
	Syslog        types.Object `tfsdk:"syslog"`
}

// logFileEndpointBlockModel maps the Log File endpoint block.
type logFileEndpointBlockModel struct {
	CollectAlerts types.Set    `tfsdk:"collect_alerts"`
	CollectLogs   types.Set    `tfsdk:"collect_logs"`
	Batching      types.Object `tfsdk:"batching"`
	LogFile       types.Object `tfsdk:"log_file"`
}

// jamfProtectCloudEndpointBlockModel maps the Jamf Protect Cloud endpoint block.
type jamfProtectCloudEndpointBlockModel struct {
	CollectAlerts    types.Set    `tfsdk:"collect_alerts"`
	CollectLogs      types.Set    `tfsdk:"collect_logs"`
	Batching         types.Object `tfsdk:"batching"`
	JamfProtectCloud types.Object `tfsdk:"jamf_protect_cloud"`
}

// batchingModel maps batching configuration for a data endpoint.
type batchingModel struct {
	EventsPerBatch        types.Int64  `tfsdk:"events_per_batch"`
	BatchingWindowSeconds types.Int64  `tfsdk:"batching_window_seconds"`
	EventDelimiter        types.String `tfsdk:"event_delimiter"`
	MaxBatchSizeBytes     types.Int64  `tfsdk:"max_batch_size_bytes"`
}

// httpEndpointModel maps HTTP endpoint settings.
type httpEndpointModel struct {
	URL     types.String `tfsdk:"url"`
	Method  types.String `tfsdk:"method"`
	Headers types.List   `tfsdk:"headers"`
}

// kafkaEndpointModel maps Kafka endpoint settings.
type kafkaEndpointModel struct {
	Host     types.String `tfsdk:"host"`
	Port     types.Int64  `tfsdk:"port"`
	Topic    types.String `tfsdk:"topic"`
	ClientCN types.String `tfsdk:"client_cn"`
	ServerCN types.String `tfsdk:"server_cn"`
}

// syslogEndpointModel maps Syslog endpoint settings.
type syslogEndpointModel struct {
	Host     types.String `tfsdk:"host"`
	Port     types.Int64  `tfsdk:"port"`
	Protocol types.String `tfsdk:"protocol"`
}

// logFileEndpointModel maps Log File endpoint settings.
type logFileEndpointModel struct {
	Path          types.String `tfsdk:"path"`
	Ownership     types.String `tfsdk:"ownership"`
	Permissions   types.String `tfsdk:"permissions"`
	MaxFileSizeMB types.Int64  `tfsdk:"max_file_size_mb"`
	MaxBackups    types.Int64  `tfsdk:"max_backups"`
}

// jamfProtectCloudEndpointModel maps Jamf Protect Cloud endpoint settings.
type jamfProtectCloudEndpointModel struct {
	DestinationFilter types.String `tfsdk:"destination_filter"`
}

// endpointHeaderModel maps the nested headers block used in HTTP and Jamf Cloud endpoints.
type endpointHeaderModel struct {
	Header types.String `tfsdk:"header"`
	Value  types.String `tfsdk:"value"`
}
