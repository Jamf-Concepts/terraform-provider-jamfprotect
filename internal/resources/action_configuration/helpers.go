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

// alertDataCollectionAttrTypes defines the attribute types for alert_data_collection.
var alertDataCollectionAttrTypes = map[string]attr.Type{
	"binary_included_data_attributes":                     types.SetType{ElemType: types.StringType},
	"synthetic_click_event_included_data_attributes":      types.SetType{ElemType: types.StringType},
	"download_event_included_data_attributes":             types.SetType{ElemType: types.StringType},
	"file_included_data_attributes":                       types.SetType{ElemType: types.StringType},
	"file_system_event_included_data_attributes":          types.SetType{ElemType: types.StringType},
	"group_included_data_attributes":                      types.SetType{ElemType: types.StringType},
	"process_event_included_data_attributes":              types.SetType{ElemType: types.StringType},
	"process_included_data_attributes":                    types.SetType{ElemType: types.StringType},
	"screenshot_event_included_data_attributes":           types.SetType{ElemType: types.StringType},
	"usb_event_included_data_attributes":                  types.SetType{ElemType: types.StringType},
	"user_included_data_attributes":                       types.SetType{ElemType: types.StringType},
	"gatekeeper_event_included_data_attributes":           types.SetType{ElemType: types.StringType},
	"keylog_register_event_included_data_attributes":      types.SetType{ElemType: types.StringType},
	"malware_removal_tool_event_included_data_attributes": types.SetType{ElemType: types.StringType},
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
	"Name":                "name",
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
	"name":           "Name",
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

var kafkaEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts": types.SetType{ElemType: types.StringType},
	"collect_logs":   types.SetType{ElemType: types.StringType},
	"host":           types.StringType,
	"port":           types.Int64Type,
	"topic":          types.StringType,
	"client_cn":      types.StringType,
	"server_cn":      types.StringType,
}

var syslogEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts": types.SetType{ElemType: types.StringType},
	"collect_logs":   types.SetType{ElemType: types.StringType},
	"host":           types.StringType,
	"port":           types.Int64Type,
	"protocol":       types.StringType,
}

var logFileEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts":   types.SetType{ElemType: types.StringType},
	"collect_logs":     types.SetType{ElemType: types.StringType},
	"path":             types.StringType,
	"ownership":        types.StringType,
	"permissions":      types.StringType,
	"max_file_size_mb": types.Int64Type,
	"max_backups":      types.Int64Type,
}

var jamfProtectCloudEndpointBlockAttrTypes = map[string]attr.Type{
	"collect_alerts":     types.SetType{ElemType: types.StringType},
	"collect_logs":       types.SetType{ElemType: types.StringType},
	"destination_filter": types.StringType,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractEventTypeAttributes returns the included data attributes set for the given event type.
func extractEventTypeAttributes(tfName string, dataModel alertDataCollectionModel) types.Set {
	switch tfName {
	case "binary":
		return dataModel.BinaryIncludedDataAttributes
	case "synthetic_click_event":
		return dataModel.SyntheticClickEventIncludedDataAttributes
	case "download_event":
		return dataModel.DownloadEventIncludedDataAttributes
	case "file":
		return dataModel.FileIncludedDataAttributes
	case "file_system_event":
		return dataModel.FileSystemEventIncludedDataAttributes
	case "group":
		return dataModel.GroupIncludedDataAttributes
	case "process_event":
		return dataModel.ProcessEventIncludedDataAttributes
	case "process":
		return dataModel.ProcessIncludedDataAttributes
	case "screenshot_event":
		return dataModel.ScreenshotEventIncludedDataAttributes
	case "usb_event":
		return dataModel.UsbEventIncludedDataAttributes
	case "user":
		return dataModel.UserIncludedDataAttributes
	case "gatekeeper_event":
		return dataModel.GatekeeperEventIncludedDataAttributes
	case "keylog_register_event":
		return dataModel.KeylogRegisterEventIncludedDataAttributes
	case "malware_removal_tool_event":
		return dataModel.MalwareRemovalToolEventIncludedDataAttributes
	default:
		return types.SetNull(types.StringType)
	}
}

func eventTypeAttrName(tfName string) string {
	return tfName + "_included_data_attributes"
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

	// Extract the alert_data_collection structure.
	var collection alertDataCollectionModel
	diags.Append(data.AlertDataCollect.As(ctx, &collection, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	apiData := map[string]any{}
	for _, m := range eventTypeMapping {
		attributes := extractEventTypeAttributes(m.tfName, collection)
		attrs, related := splitExtendedDataAttributes(common.SetToStrings(ctx, attributes, diags), diags)
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

func buildEndpointClient(ctx context.Context, clientType string, collectAlerts types.Set, collectLogs types.Set, batchConfig map[string]any, params map[string]any, diags *diag.Diagnostics) map[string]any {
	supportedReports := buildSupportedReports(ctx, collectAlerts, collectLogs, diags)
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

func defaultNonHTTPBatchConfig() map[string]any {
	return map[string]any{
		"sizeIndex":       int64(1),
		"windowInSeconds": int64(0),
	}
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
		params := buildHTTPParams(ctx, endpoint, diags)
		if diags.HasError() {
			return clients
		}
		batchConfig := buildHTTPBatchConfig(endpoint)
		if client := buildEndpointClient(ctx, "Http", endpoint.CollectAlerts, endpoint.CollectLogs, batchConfig, params, diags); client != nil {
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
		params := buildKafkaParams(ctx, endpoint)
		if diags.HasError() {
			return clients
		}
		if client := buildEndpointClient(ctx, "Kafka", endpoint.CollectAlerts, endpoint.CollectLogs, defaultNonHTTPBatchConfig(), params, diags); client != nil {
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
		params := buildSyslogParams(ctx, endpoint)
		if diags.HasError() {
			return clients
		}
		if client := buildEndpointClient(ctx, "Syslog", endpoint.CollectAlerts, endpoint.CollectLogs, defaultNonHTTPBatchConfig(), params, diags); client != nil {
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
	params := buildLogFileParams(ctx, endpoint)
	if diags.HasError() {
		return nil
	}
	return buildEndpointClient(ctx, "LogFile", endpoint.CollectAlerts, endpoint.CollectLogs, defaultNonHTTPBatchConfig(), params, diags)
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
	params := buildJamfProtectCloudParams(ctx, endpoint)
	if diags.HasError() {
		return nil
	}
	return buildEndpointClient(ctx, "JamfCloud", endpoint.CollectAlerts, endpoint.CollectLogs, defaultNonHTTPBatchConfig(), params, diags)
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

func buildHTTPBatchConfig(endpoint httpEndpointBlockModel) map[string]any {
	batch := map[string]any{}
	if !endpoint.EventsPerBatch.IsNull() && !endpoint.EventsPerBatch.IsUnknown() {
		batch["sizeIndex"] = endpoint.EventsPerBatch.ValueInt64()
	}
	if !endpoint.BatchingWindowSeconds.IsNull() && !endpoint.BatchingWindowSeconds.IsUnknown() {
		batch["windowInSeconds"] = endpoint.BatchingWindowSeconds.ValueInt64()
	}
	if !endpoint.EventDelimiter.IsNull() && !endpoint.EventDelimiter.IsUnknown() {
		batch["delimiter"] = endpoint.EventDelimiter.ValueString()
	}
	if !endpoint.MaxBatchSizeBytes.IsNull() && !endpoint.MaxBatchSizeBytes.IsUnknown() {
		batch["sizeInBytes"] = endpoint.MaxBatchSizeBytes.ValueInt64()
	}
	return batch
}

func buildHTTPParams(ctx context.Context, endpoint httpEndpointBlockModel, diags *diag.Diagnostics) map[string]any {
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

func buildKafkaParams(_ context.Context, endpoint kafkaEndpointBlockModel) map[string]any {
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

func buildSyslogParams(_ context.Context, endpoint syslogEndpointBlockModel) map[string]any {
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

func buildLogFileParams(_ context.Context, endpoint logFileEndpointBlockModel) map[string]any {
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

func buildJamfProtectCloudParams(_ context.Context, endpoint jamfProtectCloudEndpointBlockModel) map[string]any {
	params := map[string]any{}
	if !endpoint.DestinationFilter.IsNull() && !endpoint.DestinationFilter.IsUnknown() {
		params["destinationFilter"] = endpoint.DestinationFilter.ValueString()
	}
	return params
}

// eventTypeToSetValue converts an API event type model to a Terraform Set value.
func eventTypeToSetValue(tfName string, et *jamfprotect.AlertEventType, diags *diag.Diagnostics) types.Set {
	if et == nil {
		et = &jamfprotect.AlertEventType{Attrs: []string{}, Related: []string{}}
	}

	return common.StringsToSet(mergeExtendedDataAttributes(tfName, et.Attrs, et.Related, diags))
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
			dataAttrs[eventTypeAttrName(m.tfName)] = eventTypeToSetValue(m.tfName, apiET, diags)
		}
		if diags.HasError() {
			return
		}

		dataObj, d := types.ObjectValue(alertDataCollectionAttrTypes, dataAttrs)
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		data.AlertDataCollect = dataObj
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
		collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
		attrs := map[string]attr.Value{
			"collect_alerts": common.StringsToSet(collectAlerts),
			"collect_logs":   common.StringsToSet(collectLogs),
			"url":            stringValueOrNullValue(client.Params.URL),
			"method":         stringValueOrNullValue(client.Params.Method),
			"headers":        buildHeadersList(client.Params.Headers, diags),
		}
		addBatchConfigAttrs(attrs, client.BatchConfig)
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
		collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
		attrs := map[string]attr.Value{
			"collect_alerts": common.StringsToSet(collectAlerts),
			"collect_logs":   common.StringsToSet(collectLogs),
			"host":           stringValueOrNullValue(client.Params.Host),
			"port":           int64ValueOrNullValue(client.Params.Port),
			"topic":          stringValueOrNullValue(client.Params.Topic),
			"client_cn":      stringValueOrNullValue(client.Params.ClientCN),
			"server_cn":      stringValueOrNullValue(client.Params.ServerCN),
		}
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
		collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
		attrs := map[string]attr.Value{
			"collect_alerts": common.StringsToSet(collectAlerts),
			"collect_logs":   common.StringsToSet(collectLogs),
			"host":           stringValueOrNullValue(client.Params.Host),
			"port":           int64ValueOrNullValue(client.Params.Port),
			"protocol":       stringValueOrNullValue(client.Params.Scheme),
		}
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
		collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
		attrs := map[string]attr.Value{
			"collect_alerts":   common.StringsToSet(collectAlerts),
			"collect_logs":     common.StringsToSet(collectLogs),
			"path":             stringValueOrNullValue(client.Params.Path),
			"permissions":      stringValueOrNullValue(client.Params.Permissions),
			"max_file_size_mb": int64ValueOrNullValue(client.Params.MaxSizeMB),
			"ownership":        stringValueOrNullValue(client.Params.Ownership),
			"max_backups":      int64ValueOrNullValue(client.Params.Backups),
		}
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
		collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
		attrs := map[string]attr.Value{
			"collect_alerts":     common.StringsToSet(collectAlerts),
			"collect_logs":       common.StringsToSet(collectLogs),
			"destination_filter": stringValueOrNullValue(client.Params.DestinationFilter),
		}
		if diags.HasError() {
			return types.ObjectNull(jamfProtectCloudEndpointBlockAttrTypes)
		}
		obj, d := types.ObjectValue(jamfProtectCloudEndpointBlockAttrTypes, attrs)
		diags.Append(d...)
		return obj
	}
	return types.ObjectNull(jamfProtectCloudEndpointBlockAttrTypes)
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

func addBatchConfigAttrs(attrs map[string]attr.Value, batch *jamfprotect.BatchConfig) {
	if batch == nil {
		attrs["events_per_batch"] = types.Int64Null()
		attrs["batching_window_seconds"] = types.Int64Null()
		attrs["event_delimiter"] = types.StringNull()
		attrs["max_batch_size_bytes"] = types.Int64Null()
		return
	}
	attrs["events_per_batch"] = types.Int64Value(batch.SizeIndex)
	attrs["batching_window_seconds"] = types.Int64Value(batch.WindowInSeconds)
	attrs["event_delimiter"] = stringValueOrNullValue(batch.Delimiter)
	attrs["max_batch_size_bytes"] = int64ValueOrNullValue(batch.SizeInBytes)
}

func buildHeadersList(headers []jamfprotect.ReportClientHeader, diags *diag.Diagnostics) types.List {
	if len(headers) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: endpointHeaderAttrTypes})
	}
	items := make([]attr.Value, 0, len(headers))
	for _, h := range headers {
		obj, d := types.ObjectValue(endpointHeaderAttrTypes, map[string]attr.Value{
			"header": types.StringValue(h.Header),
			"value":  types.StringValue(h.Value),
		})
		diags.Append(d...)
		items = append(items, obj)
	}
	list, d := types.ListValue(types.ObjectType{AttrTypes: endpointHeaderAttrTypes}, items)
	diags.Append(d...)
	return list
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
