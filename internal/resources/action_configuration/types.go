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
	BinaryIncludedDataAttributes                  types.Set `tfsdk:"binary_included_data_attributes"`
	SyntheticClickEventIncludedDataAttributes     types.Set `tfsdk:"synthetic_click_event_included_data_attributes"`
	DownloadEventIncludedDataAttributes           types.Set `tfsdk:"download_event_included_data_attributes"`
	FileIncludedDataAttributes                    types.Set `tfsdk:"file_included_data_attributes"`
	FileSystemEventIncludedDataAttributes         types.Set `tfsdk:"file_system_event_included_data_attributes"`
	GroupIncludedDataAttributes                   types.Set `tfsdk:"group_included_data_attributes"`
	ProcessEventIncludedDataAttributes            types.Set `tfsdk:"process_event_included_data_attributes"`
	ProcessIncludedDataAttributes                 types.Set `tfsdk:"process_included_data_attributes"`
	ScreenshotEventIncludedDataAttributes         types.Set `tfsdk:"screenshot_event_included_data_attributes"`
	UsbEventIncludedDataAttributes                types.Set `tfsdk:"usb_event_included_data_attributes"`
	UserIncludedDataAttributes                    types.Set `tfsdk:"user_included_data_attributes"`
	GatekeeperEventIncludedDataAttributes         types.Set `tfsdk:"gatekeeper_event_included_data_attributes"`
	KeylogRegisterEventIncludedDataAttributes     types.Set `tfsdk:"keylog_register_event_included_data_attributes"`
	MalwareRemovalToolEventIncludedDataAttributes types.Set `tfsdk:"malware_removal_tool_event_included_data_attributes"`
}

// httpEndpointBlockModel maps each HTTP endpoint block.
type httpEndpointBlockModel struct {
	CollectAlerts         types.Set    `tfsdk:"collect_alerts"`
	CollectLogs           types.Set    `tfsdk:"collect_logs"`
	EventsPerBatch        types.Int64  `tfsdk:"events_per_batch"`
	BatchingWindowSeconds types.Int64  `tfsdk:"batching_window_seconds"`
	EventDelimiter        types.String `tfsdk:"event_delimiter"`
	MaxBatchSizeBytes     types.Int64  `tfsdk:"max_batch_size_bytes"`
	URL                   types.String `tfsdk:"url"`
	Method                types.String `tfsdk:"method"`
	Headers               types.List   `tfsdk:"headers"`
}

// kafkaEndpointBlockModel maps each Kafka endpoint block.
type kafkaEndpointBlockModel struct {
	CollectAlerts types.Set    `tfsdk:"collect_alerts"`
	CollectLogs   types.Set    `tfsdk:"collect_logs"`
	Host          types.String `tfsdk:"host"`
	Port          types.Int64  `tfsdk:"port"`
	Topic         types.String `tfsdk:"topic"`
	ClientCN      types.String `tfsdk:"client_cn"`
	ServerCN      types.String `tfsdk:"server_cn"`
}

// syslogEndpointBlockModel maps each Syslog endpoint block.
type syslogEndpointBlockModel struct {
	CollectAlerts types.Set    `tfsdk:"collect_alerts"`
	CollectLogs   types.Set    `tfsdk:"collect_logs"`
	Host          types.String `tfsdk:"host"`
	Port          types.Int64  `tfsdk:"port"`
	Protocol      types.String `tfsdk:"protocol"`
}

// logFileEndpointBlockModel maps the Log File endpoint block.
type logFileEndpointBlockModel struct {
	CollectAlerts types.Set    `tfsdk:"collect_alerts"`
	CollectLogs   types.Set    `tfsdk:"collect_logs"`
	Path          types.String `tfsdk:"path"`
	Ownership     types.String `tfsdk:"ownership"`
	Permissions   types.String `tfsdk:"permissions"`
	MaxFileSizeMB types.Int64  `tfsdk:"max_file_size_mb"`
	MaxBackups    types.Int64  `tfsdk:"max_backups"`
}

// jamfProtectCloudEndpointBlockModel maps the Jamf Protect Cloud endpoint block.
type jamfProtectCloudEndpointBlockModel struct {
	CollectAlerts     types.Set    `tfsdk:"collect_alerts"`
	CollectLogs       types.Set    `tfsdk:"collect_logs"`
	DestinationFilter types.String `tfsdk:"destination_filter"`
}

// endpointHeaderModel maps the nested headers block used in HTTP and Jamf Cloud endpoints.
type endpointHeaderModel struct {
	Header types.String `tfsdk:"header"`
	Value  types.String `tfsdk:"value"`
}
