package action_configuration

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// alertDataCollectionAttrTypes defines the attribute types for alert_data_collection.
var alertDataCollectionAttrTypes = map[string]attr.Type{
	"binary_included_data_attributes":                types.SetType{ElemType: types.StringType},
	"synthetic_click_event_included_data_attributes": types.SetType{ElemType: types.StringType},
	"download_event_included_data_attributes":        types.SetType{ElemType: types.StringType},
	"file_included_data_attributes":                  types.SetType{ElemType: types.StringType},
	"file_system_event_included_data_attributes":     types.SetType{ElemType: types.StringType},
	"group_included_data_attributes":                 types.SetType{ElemType: types.StringType},
	"process_event_included_data_attributes":         types.SetType{ElemType: types.StringType},
	"process_included_data_attributes":               types.SetType{ElemType: types.StringType},
	"screenshot_event_included_data_attributes":      types.SetType{ElemType: types.StringType},
	"user_included_data_attributes":                  types.SetType{ElemType: types.StringType},
	"gatekeeper_event_included_data_attributes":      types.SetType{ElemType: types.StringType},
	"keylog_register_event_included_data_attributes": types.SetType{ElemType: types.StringType},
}

// endpointHeaderAttrTypes defines the attribute types for an endpoint header.
var endpointHeaderAttrTypes = map[string]attr.Type{
	"header": types.StringType,
	"value":  types.StringType,
}

// httpEndpointBlockAttrTypes defines the attribute types for an HTTP endpoint block.
var httpEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts":          types.SetType{ElemType: types.StringType},
	"collect_logs":            types.SetType{ElemType: types.StringType},
	"events_per_batch":        types.Int64Type,
	"batching_window_seconds": types.Int64Type,
	"event_delimiter":         types.StringType,
	"max_batch_size_bytes":    types.Int64Type,
	"url":                     types.StringType,
	"method":                  types.StringType,
	"headers":                 types.ListType{ElemType: types.ObjectType{AttrTypes: endpointHeaderAttrTypes}},
}

// kafkaEndpointBlockAttrTypes defines the attribute types for a Kafka endpoint block.
var kafkaEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts": types.SetType{ElemType: types.StringType},
	"collect_logs":   types.SetType{ElemType: types.StringType},
	"host":           types.StringType,
	"port":           types.Int64Type,
	"topic":          types.StringType,
	"client_cn":      types.StringType,
	"server_cn":      types.StringType,
}

// syslogEndpointBlockAttrTypes defines the attribute types for a Syslog endpoint block.
var syslogEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts": types.SetType{ElemType: types.StringType},
	"collect_logs":   types.SetType{ElemType: types.StringType},
	"host":           types.StringType,
	"port":           types.Int64Type,
	"protocol":       types.StringType,
}

// logFileEndpointBlockAttrTypes defines the attribute types for a Log File endpoint block.
var logFileEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts":   types.SetType{ElemType: types.StringType},
	"collect_logs":     types.SetType{ElemType: types.StringType},
	"path":             types.StringType,
	"ownership":        types.StringType,
	"permissions":      types.StringType,
	"max_file_size_mb": types.Int64Type,
	"max_backups":      types.Int64Type,
}

// jamfProtectCloudEndpointBlockAttrTypes defines the attribute types for a Jamf Protect Cloud endpoint block.
var jamfProtectCloudEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts":     types.SetType{ElemType: types.StringType},
	"collect_logs":       types.SetType{ElemType: types.StringType},
	"destination_filter": types.StringType,
}
