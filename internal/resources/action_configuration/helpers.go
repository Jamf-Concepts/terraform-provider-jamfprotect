// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"
	"encoding/json"
	"fmt"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// ---------------------------------------------------------------------------
// Alert config attribute type definitions for ObjectValue construction
// ---------------------------------------------------------------------------

// alertEventTypeAttrTypes defines the attribute types for each event type object.
var alertEventTypeAttrTypes = map[string]attr.Type{
	"extended_data_attributes": types.SetType{ElemType: types.StringType},
}

// alertEventTypesAttrTypes defines the attribute types for the alert_data_collection.event_types object.
var alertEventTypesAttrTypes = map[string]attr.Type{
	"binary":                     types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"synthetic_click_event":      types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"download_event":             types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"file":                       types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"file_system_event":          types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"group":                      types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"process_event":              types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"process":                    types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"screenshot_event":           types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"usb_event":                  types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"user":                       types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"gatekeeper_event":           types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"keylog_register_event":      types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"malware_removal_tool_event": types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
}

// alertDataCollectionAttrTypes defines the attribute types for alert_data_collection.
var alertDataCollectionAttrTypes = map[string]attr.Type{
	"event_types": types.ObjectType{AttrTypes: alertEventTypesAttrTypes},
}

// eventTypeMapping maps snake_case Terraform attribute names to camelCase API field names.
var eventTypeMapping = []struct {
	tfName  string
	apiName string
}{
	{"binary", "binary"},
	{"synthetic_click_event", "clickEvent"},
	{"download_event", "downloadEvent"},
	{"file", "file"},
	{"file_system_event", "fsEvent"},
	{"group", "group"},
	{"process_event", "procEvent"},
	{"process", "process"},
	{"screenshot_event", "screenshotEvent"},
	{"usb_event", "usbEvent"},
	{"user", "user"},
	{"gatekeeper_event", "gkEvent"},
	{"keylog_register_event", "keylogRegisterEvent"},
	{"malware_removal_tool_event", "mrtEvent"},
}

var extendedDataAttributeToAttr = map[string]string{
	"Sha1":                "sha1hex",
	"Sha256":              "sha256hex",
	"Extended Attributes": "xattrs",
	"Is App Bundle":       "isAppBundle",
	"Is Screenshot":       "isScreenShot",
	"Is Quarantined":      "isQuarantined",
	"Is Download":         "isDownload",
	"Is Directory":        "isDirectory",
	"Downloaded From":     "downloadedFrom",
	"Signing Information": "signingInfo",
	"Args":                "args",
	"Is GUI App":          "guiAPP",
	"App Path":            "appPath",
	"name":                "name",
}

var extendedDataAttributeToRelated = map[string]string{
	"File":                 "file",
	"Process":              "process",
	"User":                 "user",
	"Group":                "group",
	"Binary":               "binary",
	"Blocked Process":      "process",
	"Blocked Binary":       "binary",
	"Source Process":       "process",
	"Destination Process":  "process",
	"Parent":               "process",
	"Process Group Leader": "process",
}

var attrToExtendedDataAttribute = map[string]string{
	"sha1hex":        "Sha1",
	"sha256hex":      "Sha256",
	"xattrs":         "Extended Attributes",
	"isAppBundle":    "Is App Bundle",
	"isScreenShot":   "Is Screenshot",
	"isQuarantined":  "Is Quarantined",
	"isDownload":     "Is Download",
	"isDirectory":    "Is Directory",
	"downloadedFrom": "Downloaded From",
	"signingInfo":    "Signing Information",
	"args":           "Args",
	"guiAPP":         "Is GUI App",
	"appPath":        "App Path",
	"name":           "name",
}

var relatedToExtendedDataAttribute = map[string]string{
	"file":    "File",
	"process": "Process",
	"user":    "User",
	"group":   "Group",
	"binary":  "Binary",
}

var endpointHeaderAttrTypes = map[string]attr.Type{
	"header": types.StringType,
	"value":  types.StringType,
}

var batchingAttrTypes = map[string]attr.Type{
	"events_per_batch":        types.Int64Type,
	"batching_window_seconds": types.Int64Type,
	"event_delimiter":         types.StringType,
	"max_batch_size_bytes":    types.Int64Type,
}

var httpEndpointAttrTypes = map[string]attr.Type{
	"url":     types.StringType,
	"method":  types.StringType,
	"headers": types.ListType{ElemType: types.ObjectType{AttrTypes: endpointHeaderAttrTypes}},
}

var kafkaEndpointAttrTypes = map[string]attr.Type{
	"host":      types.StringType,
	"port":      types.Int64Type,
	"topic":     types.StringType,
	"client_cn": types.StringType,
	"server_cn": types.StringType,
}

var syslogEndpointAttrTypes = map[string]attr.Type{
	"host":     types.StringType,
	"port":     types.Int64Type,
	"protocol": types.StringType,
}

var logFileEndpointAttrTypes = map[string]attr.Type{
	"path":             types.StringType,
	"ownership":        types.StringType,
	"permissions":      types.StringType,
	"max_file_size_mb": types.Int64Type,
	"max_backups":      types.Int64Type,
}

var jamfProtectCloudEndpointAttrTypes = map[string]attr.Type{
	"destination_filter": types.StringType,
}

var httpEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts": types.SetType{ElemType: types.StringType},
	"collect_logs":   types.SetType{ElemType: types.StringType},
	"batching":       types.ObjectType{AttrTypes: batchingAttrTypes},
	"http":           types.ObjectType{AttrTypes: httpEndpointAttrTypes},
}

var kafkaEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts": types.SetType{ElemType: types.StringType},
	"collect_logs":   types.SetType{ElemType: types.StringType},
	"batching":       types.ObjectType{AttrTypes: batchingAttrTypes},
	"kafka":          types.ObjectType{AttrTypes: kafkaEndpointAttrTypes},
}

var syslogEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts": types.SetType{ElemType: types.StringType},
	"collect_logs":   types.SetType{ElemType: types.StringType},
	"batching":       types.ObjectType{AttrTypes: batchingAttrTypes},
	"syslog":         types.ObjectType{AttrTypes: syslogEndpointAttrTypes},
}

var logFileEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts": types.SetType{ElemType: types.StringType},
	"collect_logs":   types.SetType{ElemType: types.StringType},
	"batching":       types.ObjectType{AttrTypes: batchingAttrTypes},
	"log_file":       types.ObjectType{AttrTypes: logFileEndpointAttrTypes},
}

var jamfProtectCloudEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts":     types.SetType{ElemType: types.StringType},
	"collect_logs":       types.SetType{ElemType: types.StringType},
	"batching":           types.ObjectType{AttrTypes: batchingAttrTypes},
	"jamf_protect_cloud": types.ObjectType{AttrTypes: jamfProtectCloudEndpointAttrTypes},
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractEventType extracts an alertEventTypeModel from the alertDataModel for the given field.
func extractEventType(ctx context.Context, dataObj types.Object, tfName string, diags *diag.Diagnostics) alertEventTypeModel {
	var dataModel alertEventTypesModel
	diags.Append(dataObj.As(ctx, &dataModel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return alertEventTypeModel{}
	}

	var fieldObj types.Object
	switch tfName {
	case "binary":
		fieldObj = dataModel.Binary
	case "synthetic_click_event":
		fieldObj = dataModel.SyntheticClickEvent
	case "download_event":
		fieldObj = dataModel.DownloadEvent
	case "file":
		fieldObj = dataModel.File
	case "file_system_event":
		fieldObj = dataModel.FileSystemEvent
	case "group":
		fieldObj = dataModel.Group
	case "process_event":
		fieldObj = dataModel.ProcessEvent
	case "process":
		fieldObj = dataModel.Process
	case "screenshot_event":
		fieldObj = dataModel.ScreenshotEvent
	case "usb_event":
		fieldObj = dataModel.UsbEvent
	case "user":
		fieldObj = dataModel.User
	case "gatekeeper_event":
		fieldObj = dataModel.GatekeeperEvent
	case "keylog_register_event":
		fieldObj = dataModel.KeylogRegisterEvent
	case "malware_removal_tool_event":
		fieldObj = dataModel.MalwareRemovalToolEvent
	}

	var et alertEventTypeModel
	diags.Append(fieldObj.As(ctx, &et, basetypes.ObjectAsOptions{})...)
	return et
}

func splitExtendedDataAttributes(values []string, diags *diag.Diagnostics) ([]string, []string) {
	attrs := []string{}
	related := []string{}
	for _, value := range values {
		if attr, ok := extendedDataAttributeToAttr[value]; ok {
			attrs = append(attrs, attr)
			continue
		}
		if rel, ok := extendedDataAttributeToRelated[value]; ok {
			related = append(related, rel)
			continue
		}
		diags.AddError("Unsupported extended data attribute",
			fmt.Sprintf("%q is not a supported extended data attribute value", value))
	}
	return attrs, related
}

func mergeExtendedDataAttributes(tfName string, attrs []string, related []string, diags *diag.Diagnostics) []string {
	combined := []string{}
	seen := map[string]struct{}{}
	appendLabel := func(label string) {
		if _, exists := seen[label]; exists {
			return
		}
		seen[label] = struct{}{}
		combined = append(combined, label)
	}

	for _, attr := range attrs {
		label, ok := attrToExtendedDataAttribute[attr]
		if !ok {
			diags.AddError("Unsupported alert attribute",
				fmt.Sprintf("%q is not a supported alert attribute value", attr))
			continue
		}
		appendLabel(label)
	}

	if len(related) == 0 {
		return combined
	}

	switch tfName {
	case "keylog_register_event":
		processLabels := []string{"Source Process", "Destination Process"}
		processCount := 0
		for _, rel := range related {
			if rel == "process" {
				if processCount < len(processLabels) {
					appendLabel(processLabels[processCount])
					processCount++
				} else {
					appendLabel("Process")
				}
				continue
			}
			label, ok := relatedToExtendedDataAttribute[rel]
			if !ok {
				diags.AddError("Unsupported related object",
					fmt.Sprintf("%q is not a supported related object value", rel))
				continue
			}
			appendLabel(label)
		}
		return combined
	case "process":
		processLabels := []string{"Parent", "Process Group Leader"}
		processCount := 0
		for _, rel := range related {
			if rel == "process" {
				if processCount < len(processLabels) {
					appendLabel(processLabels[processCount])
					processCount++
				} else {
					appendLabel("Process")
				}
				continue
			}
			label, ok := relatedToExtendedDataAttribute[rel]
			if !ok {
				diags.AddError("Unsupported related object",
					fmt.Sprintf("%q is not a supported related object value", rel))
				continue
			}
			appendLabel(label)
		}
		return combined
	case "gatekeeper_event":
		for _, rel := range related {
			switch rel {
			case "process":
				appendLabel("Blocked Process")
				continue
			case "binary":
				appendLabel("Blocked Binary")
				continue
			}
			label, ok := relatedToExtendedDataAttribute[rel]
			if !ok {
				diags.AddError("Unsupported related object",
					fmt.Sprintf("%q is not a supported related object value", rel))
				continue
			}
			appendLabel(label)
		}
		return combined
	default:
		for _, rel := range related {
			label, ok := relatedToExtendedDataAttribute[rel]
			if !ok {
				diags.AddError("Unsupported related object",
					fmt.Sprintf("%q is not a supported related object value", rel))
				continue
			}
			appendLabel(label)
		}
		return combined
	}
}

func (r *ActionConfigResource) buildInput(ctx context.Context, data ActionConfigResourceModel, diags *diag.Diagnostics) *jamfprotect.ActionConfigInput {
	input := &jamfprotect.ActionConfigInput{
		Name: data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	// Extract the alert_data_collection -> event_types nested structure.
	var collection alertDataCollectionModel
	diags.Append(data.AlertDataCollect.As(ctx, &collection, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	apiData := map[string]any{}
	for _, m := range eventTypeMapping {
		et := extractEventType(ctx, collection.EventTypes, m.tfName, diags)
		if diags.HasError() {
			return nil
		}
		attrs, related := splitExtendedDataAttributes(common.SetToStrings(ctx, et.ExtendedDataAttributes, diags), diags)
		if diags.HasError() {
			return nil
		}
		apiData[m.apiName] = map[string]any{
			"attrs":   attrs,
			"related": related,
		}
	}

	input.AlertConfig = map[string]any{
		"data": apiData,
	}

	clients := r.buildClients(ctx, data, diags)
	if diags.HasError() {
		return nil
	}
	if len(clients) > 0 {
		input.Clients = clients
	} else {
		input.Clients = nil
	}

	return input
}

func (r *ActionConfigResource) buildClients(ctx context.Context, data ActionConfigResourceModel, diags *diag.Diagnostics) []map[string]any {
	clients := []map[string]any{}

	clients = append(clients, buildHTTPEndpointClients(ctx, data.HTTPEndpoints, diags)...)
	clients = append(clients, buildKafkaEndpointClients(ctx, data.KafkaEndpoints, diags)...)
	clients = append(clients, buildSyslogEndpointClients(ctx, data.SyslogEndpoints, diags)...)
	if client := buildLogFileEndpointClient(ctx, data.LogFileEndpoint, diags); client != nil {
		clients = append(clients, client)
	}
	if client := buildJamfProtectCloudEndpointClient(ctx, data.JamfCloudEndpoint, diags); client != nil {
		clients = append(clients, client)
	}

	return clients
}

func buildEndpointClient(ctx context.Context, clientType string, collectAlerts types.Set, collectLogs types.Set, batching types.Object, params map[string]any, diags *diag.Diagnostics) map[string]any {
	supportedReports := buildSupportedReports(ctx, collectAlerts, collectLogs, diags)
	if diags.HasError() {
		return nil
	}

	batchConfig := buildBatchingConfig(ctx, batching, diags)
	if diags.HasError() {
		return nil
	}

	client := map[string]any{
		"type": clientType,
	}
	if len(batchConfig) > 0 {
		client["batchConfig"] = batchConfig
	}
	if len(supportedReports) > 0 {
		client["supportedReports"] = supportedReports
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		diags.AddError("Error serializing "+clientType+" client params", err.Error())
		return nil
	}
	client["params"] = string(paramsJSON)

	return client
}

func buildHTTPEndpointClients(ctx context.Context, list types.List, diags *diag.Diagnostics) []map[string]any {
	clients := []map[string]any{}
	if list.IsNull() || list.IsUnknown() {
		return clients
	}
	var endpoints []httpEndpointBlockModel
	diags.Append(list.ElementsAs(ctx, &endpoints, false)...)
	if diags.HasError() {
		return clients
	}
	for _, endpoint := range endpoints {
		params := buildHTTPParams(ctx, endpoint.HTTP, diags)
		if diags.HasError() {
			return clients
		}
		if client := buildEndpointClient(ctx, "Http", endpoint.CollectAlerts, endpoint.CollectLogs, endpoint.Batching, params, diags); client != nil {
			clients = append(clients, client)
		}
	}
	return clients
}

func buildKafkaEndpointClients(ctx context.Context, list types.List, diags *diag.Diagnostics) []map[string]any {
	clients := []map[string]any{}
	if list.IsNull() || list.IsUnknown() {
		return clients
	}
	var endpoints []kafkaEndpointBlockModel
	diags.Append(list.ElementsAs(ctx, &endpoints, false)...)
	if diags.HasError() {
		return clients
	}
	for _, endpoint := range endpoints {
		params := buildKafkaParams(ctx, endpoint.Kafka, diags)
		if diags.HasError() {
			return clients
		}
		if client := buildEndpointClient(ctx, "Kafka", endpoint.CollectAlerts, endpoint.CollectLogs, endpoint.Batching, params, diags); client != nil {
			clients = append(clients, client)
		}
	}
	return clients
}

func buildSyslogEndpointClients(ctx context.Context, list types.List, diags *diag.Diagnostics) []map[string]any {
	clients := []map[string]any{}
	if list.IsNull() || list.IsUnknown() {
		return clients
	}
	var endpoints []syslogEndpointBlockModel
	diags.Append(list.ElementsAs(ctx, &endpoints, false)...)
	if diags.HasError() {
		return clients
	}
	for _, endpoint := range endpoints {
		params := buildSyslogParams(ctx, endpoint.Syslog, diags)
		if diags.HasError() {
			return clients
		}
		if client := buildEndpointClient(ctx, "Syslog", endpoint.CollectAlerts, endpoint.CollectLogs, endpoint.Batching, params, diags); client != nil {
			clients = append(clients, client)
		}
	}
	return clients
}

func buildLogFileEndpointClient(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var endpoint logFileEndpointBlockModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}
	params := buildLogFileParams(ctx, endpoint.LogFile, diags)
	if diags.HasError() {
		return nil
	}
	return buildEndpointClient(ctx, "LogFile", endpoint.CollectAlerts, endpoint.CollectLogs, endpoint.Batching, params, diags)
}

func buildJamfProtectCloudEndpointClient(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var endpoint jamfProtectCloudEndpointBlockModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}
	params := buildJamfProtectCloudParams(ctx, endpoint.JamfProtectCloud, diags)
	if diags.HasError() {
		return nil
	}
	return buildEndpointClient(ctx, "JamfCloud", endpoint.CollectAlerts, endpoint.CollectLogs, endpoint.Batching, params, diags)
}

func buildSupportedReports(ctx context.Context, collectAlerts types.Set, collectLogs types.Set, diags *diag.Diagnostics) []string {
	reports := map[string]struct{}{}

	for _, alert := range common.SetToStrings(ctx, collectAlerts, diags) {
		switch alert {
		case "high":
			reports["AlertHigh"] = struct{}{}
		case "medium":
			reports["AlertMedium"] = struct{}{}
		case "low":
			reports["AlertLow"] = struct{}{}
		case "informational":
			reports["AlertInformational"] = struct{}{}
		}
	}

	for _, logType := range common.SetToStrings(ctx, collectLogs, diags) {
		switch logType {
		case "telemetry":
			reports["Telemetry"] = struct{}{}
		case "unified_logs":
			reports["UnifiedLogging"] = struct{}{}
		}
	}

	result := make([]string, 0, len(reports))
	for report := range reports {
		result = append(result, report)
	}

	return result
}

func buildBatchingConfig(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return map[string]any{}
	}

	var batching batchingModel
	diags.Append(obj.As(ctx, &batching, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return map[string]any{}
	}

	batch := map[string]any{}
	if !batching.EventsPerBatch.IsNull() && !batching.EventsPerBatch.IsUnknown() {
		batch["sizeIndex"] = batching.EventsPerBatch.ValueInt64()
	}
	if !batching.BatchingWindowSeconds.IsNull() && !batching.BatchingWindowSeconds.IsUnknown() {
		batch["windowInSeconds"] = batching.BatchingWindowSeconds.ValueInt64()
	}
	if !batching.EventDelimiter.IsNull() && !batching.EventDelimiter.IsUnknown() {
		batch["delimiter"] = batching.EventDelimiter.ValueString()
	}
	if !batching.MaxBatchSizeBytes.IsNull() && !batching.MaxBatchSizeBytes.IsUnknown() {
		batch["sizeInBytes"] = batching.MaxBatchSizeBytes.ValueInt64()
	}
	return batch
}

func buildHTTPParams(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return map[string]any{}
	}

	var endpoint httpEndpointModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return map[string]any{}
	}

	params := map[string]any{}
	if !endpoint.URL.IsNull() && !endpoint.URL.IsUnknown() {
		params["url"] = endpoint.URL.ValueString()
	}
	if !endpoint.Method.IsNull() && !endpoint.Method.IsUnknown() {
		params["method"] = endpoint.Method.ValueString()
	}
	if !endpoint.Headers.IsNull() && !endpoint.Headers.IsUnknown() {
		var headers []endpointHeaderModel
		diags.Append(endpoint.Headers.ElementsAs(ctx, &headers, false)...)
		if diags.HasError() {
			return map[string]any{}
		}
		headerItems := make([]map[string]any, 0, len(headers))
		for _, h := range headers {
			item := map[string]any{}
			if !h.Header.IsNull() && !h.Header.IsUnknown() {
				item["header"] = h.Header.ValueString()
			}
			if !h.Value.IsNull() && !h.Value.IsUnknown() {
				item["value"] = h.Value.ValueString()
			}
			if len(item) > 0 {
				headerItems = append(headerItems, item)
			}
		}
		params["headers"] = headerItems
	}

	return params
}

func buildKafkaParams(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return map[string]any{}
	}

	var endpoint kafkaEndpointModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return map[string]any{}
	}

	params := map[string]any{}
	if !endpoint.Host.IsNull() && !endpoint.Host.IsUnknown() {
		params["host"] = endpoint.Host.ValueString()
	}
	if !endpoint.Port.IsNull() && !endpoint.Port.IsUnknown() {
		params["port"] = endpoint.Port.ValueInt64()
	}
	if !endpoint.Topic.IsNull() && !endpoint.Topic.IsUnknown() {
		params["topic"] = endpoint.Topic.ValueString()
	}
	if !endpoint.ClientCN.IsNull() && !endpoint.ClientCN.IsUnknown() {
		params["clientCN"] = endpoint.ClientCN.ValueString()
	}
	if !endpoint.ServerCN.IsNull() && !endpoint.ServerCN.IsUnknown() {
		params["serverCN"] = endpoint.ServerCN.ValueString()
	}

	return params
}

func buildSyslogParams(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return map[string]any{}
	}

	var endpoint syslogEndpointModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return map[string]any{}
	}

	params := map[string]any{}
	if !endpoint.Host.IsNull() && !endpoint.Host.IsUnknown() {
		params["host"] = endpoint.Host.ValueString()
	}
	if !endpoint.Port.IsNull() && !endpoint.Port.IsUnknown() {
		params["port"] = endpoint.Port.ValueInt64()
	}
	if !endpoint.Protocol.IsNull() && !endpoint.Protocol.IsUnknown() {
		params["scheme"] = endpoint.Protocol.ValueString()
	}

	return params
}

func buildLogFileParams(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return map[string]any{}
	}

	var endpoint logFileEndpointModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return map[string]any{}
	}

	params := map[string]any{}
	if !endpoint.Path.IsNull() && !endpoint.Path.IsUnknown() {
		params["path"] = endpoint.Path.ValueString()
	}
	if !endpoint.Permissions.IsNull() && !endpoint.Permissions.IsUnknown() {
		params["permissions"] = endpoint.Permissions.ValueString()
	}
	if !endpoint.MaxFileSizeMB.IsNull() && !endpoint.MaxFileSizeMB.IsUnknown() {
		params["maxSizeMB"] = endpoint.MaxFileSizeMB.ValueInt64()
	}
	if !endpoint.Ownership.IsNull() && !endpoint.Ownership.IsUnknown() {
		params["ownership"] = endpoint.Ownership.ValueString()
	}
	if !endpoint.MaxBackups.IsNull() && !endpoint.MaxBackups.IsUnknown() {
		params["backups"] = endpoint.MaxBackups.ValueInt64()
	}

	return params
}

func buildJamfProtectCloudParams(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return map[string]any{}
	}

	var endpoint jamfProtectCloudEndpointModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return map[string]any{}
	}

	params := map[string]any{}
	if !endpoint.DestinationFilter.IsNull() && !endpoint.DestinationFilter.IsUnknown() {
		params["destinationFilter"] = endpoint.DestinationFilter.ValueString()
	}
	return params
}

// eventTypeToObjectValue converts an API event type model to a Terraform ObjectValue.
func eventTypeToObjectValue(tfName string, et *jamfprotect.AlertEventType, diags *diag.Diagnostics) types.Object {
	if et == nil {
		et = &jamfprotect.AlertEventType{Attrs: []string{}, Related: []string{}}
	}

	attrs := map[string]attr.Value{
		"extended_data_attributes": common.StringsToSet(mergeExtendedDataAttributes(tfName, et.Attrs, et.Related, diags)),
	}

	obj, d := types.ObjectValue(alertEventTypeAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

// apiEventTypeGetter returns the API event type model for a given API field name.
func apiEventTypeGetter(apiData *jamfprotect.AlertData, apiName string) *jamfprotect.AlertEventType {
	switch apiName {
	case "binary":
		return apiData.Binary
	case "clickEvent":
		return apiData.ClickEvent
	case "downloadEvent":
		return apiData.DownloadEvent
	case "file":
		return apiData.File
	case "fsEvent":
		return apiData.FsEvent
	case "group":
		return apiData.Group
	case "procEvent":
		return apiData.ProcEvent
	case "process":
		return apiData.Process
	case "screenshotEvent":
		return apiData.ScreenshotEvent
	case "usbEvent":
		return apiData.UsbEvent
	case "user":
		return apiData.User
	case "gkEvent":
		return apiData.GkEvent
	case "keylogRegisterEvent":
		return apiData.KeylogRegisterEvent
	case "mrtEvent":
		return apiData.MrtEvent
	default:
		return nil
	}
}

func (r *ActionConfigResource) apiToState(_ context.Context, data *ActionConfigResourceModel, api jamfprotect.ActionConfig, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Hash = types.StringValue(api.Hash)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringValue("")
	}

	// Build alert_data_collection object from API response.
	if api.AlertConfig != nil && api.AlertConfig.Data != nil {
		dataAttrs := map[string]attr.Value{}
		for _, m := range eventTypeMapping {
			apiET := apiEventTypeGetter(api.AlertConfig.Data, m.apiName)
			dataAttrs[m.tfName] = eventTypeToObjectValue(m.tfName, apiET, diags)
		}
		if diags.HasError() {
			return
		}

		dataObj, d := types.ObjectValue(alertEventTypesAttrTypes, dataAttrs)
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		collectionObj, d := types.ObjectValue(alertDataCollectionAttrTypes, map[string]attr.Value{
			"event_types": dataObj,
		})
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		data.AlertDataCollect = collectionObj
	}

	data.HTTPEndpoints = buildHTTPEndpointsState(api.Clients, diags)
	data.KafkaEndpoints = buildKafkaEndpointsState(api.Clients, diags)
	data.SyslogEndpoints = buildSyslogEndpointsState(api.Clients, diags)
	data.LogFileEndpoint = buildLogFileEndpointState(api.Clients, diags)
	data.JamfCloudEndpoint = buildJamfProtectCloudEndpointState(api.Clients, diags)
}

func buildHTTPEndpointsState(clients []jamfprotect.ReportClient, diags *diag.Diagnostics) types.List {
	items := make([]attr.Value, 0)
	for _, client := range clients {
		if client.Type != "Http" {
			continue
		}
		attrs := buildEndpointBlockAttrs(client, apiHTTPToObjectValue(client, diags), httpEndpointBlockAttrTypes, diags)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: httpEndpointBlockAttrTypes})
		}
		obj, d := types.ObjectValue(httpEndpointBlockAttrTypes, attrs)
		diags.Append(d...)
		items = append(items, obj)
	}
	if len(items) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: httpEndpointBlockAttrTypes})
	}
	list, d := types.ListValue(types.ObjectType{AttrTypes: httpEndpointBlockAttrTypes}, items)
	diags.Append(d...)
	return list
}

func buildKafkaEndpointsState(clients []jamfprotect.ReportClient, diags *diag.Diagnostics) types.List {
	items := make([]attr.Value, 0)
	for _, client := range clients {
		if client.Type != "Kafka" {
			continue
		}
		attrs := buildEndpointBlockAttrs(client, apiKafkaToObjectValue(client, diags), kafkaEndpointBlockAttrTypes, diags)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: kafkaEndpointBlockAttrTypes})
		}
		obj, d := types.ObjectValue(kafkaEndpointBlockAttrTypes, attrs)
		diags.Append(d...)
		items = append(items, obj)
	}
	if len(items) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: kafkaEndpointBlockAttrTypes})
	}
	list, d := types.ListValue(types.ObjectType{AttrTypes: kafkaEndpointBlockAttrTypes}, items)
	diags.Append(d...)
	return list
}

func buildSyslogEndpointsState(clients []jamfprotect.ReportClient, diags *diag.Diagnostics) types.List {
	items := make([]attr.Value, 0)
	for _, client := range clients {
		if client.Type != "Syslog" {
			continue
		}
		attrs := buildEndpointBlockAttrs(client, apiSyslogToObjectValue(client, diags), syslogEndpointBlockAttrTypes, diags)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: syslogEndpointBlockAttrTypes})
		}
		obj, d := types.ObjectValue(syslogEndpointBlockAttrTypes, attrs)
		diags.Append(d...)
		items = append(items, obj)
	}
	if len(items) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: syslogEndpointBlockAttrTypes})
	}
	list, d := types.ListValue(types.ObjectType{AttrTypes: syslogEndpointBlockAttrTypes}, items)
	diags.Append(d...)
	return list
}

func buildLogFileEndpointState(clients []jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	for _, client := range clients {
		if client.Type != "LogFile" {
			continue
		}
		attrs := buildEndpointBlockAttrs(client, apiLogFileToObjectValue(client, diags), logFileEndpointBlockAttrTypes, diags)
		if diags.HasError() {
			return types.ObjectNull(logFileEndpointBlockAttrTypes)
		}
		obj, d := types.ObjectValue(logFileEndpointBlockAttrTypes, attrs)
		diags.Append(d...)
		return obj
	}
	return types.ObjectNull(logFileEndpointBlockAttrTypes)
}

func buildJamfProtectCloudEndpointState(clients []jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	for _, client := range clients {
		if client.Type != "JamfCloud" {
			continue
		}
		attrs := buildEndpointBlockAttrs(client, apiJamfProtectCloudToObjectValue(client, diags), jamfProtectCloudEndpointBlockAttrTypes, diags)
		if diags.HasError() {
			return types.ObjectNull(jamfProtectCloudEndpointBlockAttrTypes)
		}
		obj, d := types.ObjectValue(jamfProtectCloudEndpointBlockAttrTypes, attrs)
		diags.Append(d...)
		return obj
	}
	return types.ObjectNull(jamfProtectCloudEndpointBlockAttrTypes)
}

func buildEndpointBlockAttrs(client jamfprotect.ReportClient, settings types.Object, attrTypes map[string]attr.Type, diags *diag.Diagnostics) map[string]attr.Value {
	collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
	batchingObj := batchingToObjectValue(client.BatchConfig, diags)
	attrs := map[string]attr.Value{
		"collect_alerts": common.StringsToSet(collectAlerts),
		"collect_logs":   common.StringsToSet(collectLogs),
		"batching":       batchingObj,
	}
	if _, ok := attrTypes["http"]; ok {
		attrs["http"] = settings
	}
	if _, ok := attrTypes["kafka"]; ok {
		attrs["kafka"] = settings
	}
	if _, ok := attrTypes["syslog"]; ok {
		attrs["syslog"] = settings
	}
	if _, ok := attrTypes["log_file"]; ok {
		attrs["log_file"] = settings
	}
	if _, ok := attrTypes["jamf_protect_cloud"]; ok {
		attrs["jamf_protect_cloud"] = settings
	}
	return attrs
}

func splitSupportedReports(reports []string) ([]string, []string) {
	alerts := []string{}
	logs := []string{}
	for _, report := range reports {
		switch report {
		case "AlertHigh":
			alerts = append(alerts, "high")
		case "AlertMedium":
			alerts = append(alerts, "medium")
		case "AlertLow":
			alerts = append(alerts, "low")
		case "AlertInformational":
			alerts = append(alerts, "informational")
		case "Telemetry":
			logs = append(logs, "telemetry")
		case "UnifiedLogging":
			logs = append(logs, "unified_logs")
		}
	}
	return alerts, logs
}

func batchingToObjectValue(batch *jamfprotect.BatchConfig, diags *diag.Diagnostics) types.Object {
	if batch == nil {
		return types.ObjectNull(batchingAttrTypes)
	}
	attrs := map[string]attr.Value{
		"events_per_batch":        types.Int64Value(batch.SizeIndex),
		"batching_window_seconds": types.Int64Value(batch.WindowInSeconds),
		"event_delimiter":         stringValueOrNullValue(batch.Delimiter),
		"max_batch_size_bytes":    int64ValueOrNullValue(batch.SizeInBytes),
	}
	obj, d := types.ObjectValue(batchingAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiHTTPToObjectValue(client jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	headersList := types.ListNull(types.ObjectType{AttrTypes: endpointHeaderAttrTypes})
	if len(client.Params.Headers) > 0 {
		items := make([]attr.Value, 0, len(client.Params.Headers))
		for _, h := range client.Params.Headers {
			obj, d := types.ObjectValue(endpointHeaderAttrTypes, map[string]attr.Value{
				"header": types.StringValue(h.Header),
				"value":  types.StringValue(h.Value),
			})
			diags.Append(d...)
			items = append(items, obj)
		}
		list, d := types.ListValue(types.ObjectType{AttrTypes: endpointHeaderAttrTypes}, items)
		diags.Append(d...)
		headersList = list
	}

	attrs := map[string]attr.Value{
		"url":     stringValueOrNullValue(client.Params.URL),
		"method":  stringValueOrNullValue(client.Params.Method),
		"headers": headersList,
	}

	obj, d := types.ObjectValue(httpEndpointAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiKafkaToObjectValue(client jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"host":      stringValueOrNullValue(client.Params.Host),
		"port":      int64ValueOrNullValue(client.Params.Port),
		"topic":     stringValueOrNullValue(client.Params.Topic),
		"client_cn": stringValueOrNullValue(client.Params.ClientCN),
		"server_cn": stringValueOrNullValue(client.Params.ServerCN),
	}

	obj, d := types.ObjectValue(kafkaEndpointAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiSyslogToObjectValue(client jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"host":     stringValueOrNullValue(client.Params.Host),
		"port":     int64ValueOrNullValue(client.Params.Port),
		"protocol": stringValueOrNullValue(client.Params.Scheme),
	}

	obj, d := types.ObjectValue(syslogEndpointAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiLogFileToObjectValue(client jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"path":             stringValueOrNullValue(client.Params.Path),
		"permissions":      stringValueOrNullValue(client.Params.Permissions),
		"max_file_size_mb": int64ValueOrNullValue(client.Params.MaxSizeMB),
		"ownership":        stringValueOrNullValue(client.Params.Ownership),
		"max_backups":      int64ValueOrNullValue(client.Params.Backups),
	}

	obj, d := types.ObjectValue(logFileEndpointAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiJamfProtectCloudToObjectValue(client jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"destination_filter": stringValueOrNullValue(client.Params.DestinationFilter),
	}

	obj, d := types.ObjectValue(jamfProtectCloudEndpointAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func int64ValueOrNullValue(value int64) attr.Value {
	if value == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(value)
}

func stringValueOrNullValue(value string) attr.Value {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}
