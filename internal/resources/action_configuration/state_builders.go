// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

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
	case "user":
		return apiData.User
	case "gkEvent":
		return apiData.GkEvent
	case "keylogRegisterEvent":
		return apiData.KeylogRegisterEvent
	default:
		return nil
	}
}

// applyState maps the API response to the Terraform state model.
func (r *ActionConfigResource) applyState(_ context.Context, data *ActionConfigResourceModel, api jamfprotect.ActionConfig, diags *diag.Diagnostics) {
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

// buildHTTPEndpointsState constructs the state for HTTP endpoints from the API clients.
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
			"url":            common.StringValueOrNullValue(client.Params.URL),
			"method":         common.StringValueOrNullValue(client.Params.Method),
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

// buildKafkaEndpointsState constructs the state for Kafka endpoints from the API clients.
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
			"host":           common.StringValueOrNullValue(client.Params.Host),
			"port":           common.Int64ValueOrNullValue(client.Params.Port),
			"topic":          common.StringValueOrNullValue(client.Params.Topic),
			"client_cn":      common.StringValueOrNullValue(client.Params.ClientCN),
			"server_cn":      common.StringValueOrNullValue(client.Params.ServerCN),
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

// buildSyslogEndpointsState constructs the state for Syslog endpoints from the API clients.
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
			"host":           common.StringValueOrNullValue(client.Params.Host),
			"port":           common.Int64ValueOrNullValue(client.Params.Port),
			"protocol":       common.StringValueOrNullValue(client.Params.Scheme),
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

// buildLogFileEndpointState constructs the state for the Log File endpoint from the API clients.
func buildLogFileEndpointState(clients []jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	for _, client := range clients {
		if client.Type != "LogFile" {
			continue
		}
		collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
		attrs := map[string]attr.Value{
			"collect_alerts":   common.StringsToSet(collectAlerts),
			"collect_logs":     common.StringsToSet(collectLogs),
			"path":             common.StringValueOrNullValue(client.Params.Path),
			"permissions":      common.StringValueOrNullValue(client.Params.Permissions),
			"max_file_size_mb": common.Int64ValueOrNullValue(client.Params.MaxSizeMB),
			"ownership":        common.StringValueOrNullValue(client.Params.Ownership),
			"max_backups":      common.Int64ValueOrNullValue(client.Params.Backups),
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

// buildJamfProtectCloudEndpointState constructs the state for the Jamf Protect Cloud endpoint from the API clients.
func buildJamfProtectCloudEndpointState(clients []jamfprotect.ReportClient, diags *diag.Diagnostics) types.Object {
	for _, client := range clients {
		if client.Type != "JamfCloud" {
			continue
		}
		collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
		attrs := map[string]attr.Value{
			"collect_alerts":     common.StringsToSet(collectAlerts),
			"collect_logs":       common.StringsToSet(collectLogs),
			"destination_filter": common.StringValueOrNullValue(client.Params.DestinationFilter),
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

// splitSupportedReports takes a list of API supported report types and splits them into separate lists for alerts and logs.
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

// addBatchConfigAttrs adds batch configuration attributes to the given attribute map based on the provided API batch config.
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
	attrs["event_delimiter"] = common.StringValueOrNullValue(batch.Delimiter)
	attrs["max_batch_size_bytes"] = common.Int64ValueOrNullValue(batch.SizeInBytes)
}

// buildHeadersList converts a slice of API header models to a Terraform List value.
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
