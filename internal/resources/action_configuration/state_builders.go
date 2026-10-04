// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"

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
func (r *ActionConfigResource) applyState(ctx context.Context, data *ActionConfigResourceModel, api jamfprotect.ActionConfig, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)

	data.Description = types.StringValue(api.Description)

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
	} else {
		data.AlertDataCollect = types.ObjectNull(alertDataCollectionAttrTypes)
	}

	woHeaders := writeOnlyHeaders(ctx, data.HTTPEndpoints, diags)
	if diags.HasError() {
		return
	}
	data.HTTPEndpoints = buildHTTPEndpointsState(api.Clients, woHeaders, diags)
	data.KafkaEndpoints = buildKafkaEndpointsState(api.Clients, diags)
	data.SyslogEndpoints = buildSyslogEndpointsState(api.Clients, diags)
	data.LogFileEndpoint = buildLogFileEndpointState(api.Clients, diags)
	data.JamfCloudEndpoint = buildJamfProtectCloudEndpointState(api.Clients, diags)
}

// writeOnlyHeaders returns the HTTP headers in the prior model that use
// value_wo, keyed by position, so the state builder can keep their values out
// of state.
func writeOnlyHeaders(ctx context.Context, list types.List, diags *diag.Diagnostics) map[headerPosition]endpointHeaderModel {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var endpoints []httpEndpointBlockModel
	diags.Append(list.ElementsAs(ctx, &endpoints, false)...)
	if diags.HasError() {
		return nil
	}
	headers := map[headerPosition]endpointHeaderModel{}
	for i, endpoint := range endpoints {
		if endpoint.Headers.IsNull() || endpoint.Headers.IsUnknown() {
			continue
		}
		var models []endpointHeaderModel
		diags.Append(endpoint.Headers.ElementsAs(ctx, &models, false)...)
		if diags.HasError() {
			return nil
		}
		for j, h := range models {
			if common.IsKnownString(h.ValueWOVersion) {
				headers[headerPosition{endpoint: i, header: j}] = h
			}
		}
	}
	return headers
}

// buildHTTPEndpointsState constructs the state for HTTP endpoints from the API clients.
// woHeaders identifies headers managed through value_wo, whose values are not stored.
// When a prior value_wo header matches no API header, such as after an endpoint is
// deleted or a header renamed out of band, every unmatched header value is kept out
// of state, because any of them could hold that secret.
func buildHTTPEndpointsState(clients []jamfprotect.ReportClient, woHeaders map[headerPosition]endpointHeaderModel, diags *diag.Diagnostics) types.List {
	var httpClients []jamfprotect.ReportClient
	for _, client := range clients {
		if client.Type == "Http" {
			httpClients = append(httpClients, client)
		}
	}
	matches := make([]map[int]headerPosition, len(httpClients))
	consumed := map[headerPosition]bool{}
	for i, client := range httpClients {
		matches[i] = matchWriteOnlyHeaders(client.Params.Headers, i, woHeaders)
		for _, pos := range matches[i] {
			consumed[pos] = true
		}
	}
	failClosed := len(consumed) < len(woHeaders)
	if failClosed {
		warnUnmatchedWriteOnlyHeaders(woHeaders, consumed, diags)
	}

	items := make([]attr.Value, 0, len(httpClients))
	for i, client := range httpClients {
		collectAlerts, collectLogs := splitSupportedReports(client.SupportedReports)
		attrs := map[string]attr.Value{
			"collect_alerts": common.StringsToSet(collectAlerts),
			"collect_logs":   common.StringsToSet(collectLogs),
			"url":            common.StringValueOrNullValue(client.Params.URL),
			"method":         common.StringValueOrNullValue(client.Params.Method),
			"headers":        buildHeadersList(client.Params.Headers, matches[i], woHeaders, failClosed, diags),
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

// warnUnmatchedWriteOnlyHeaders adds a warning naming each prior value_wo header
// that no API header matched.
func warnUnmatchedWriteOnlyHeaders(woHeaders map[headerPosition]endpointHeaderModel, consumed map[headerPosition]bool, diags *diag.Diagnostics) {
	var unmatched []headerPosition
	for pos := range woHeaders {
		if !consumed[pos] {
			unmatched = append(unmatched, pos)
		}
	}
	slices.SortFunc(unmatched, func(a, b headerPosition) int {
		if a.endpoint != b.endpoint {
			return a.endpoint - b.endpoint
		}
		return a.header - b.header
	})
	names := make([]string, 0, len(unmatched))
	for _, pos := range unmatched {
		names = append(names, fmt.Sprintf("%q (http_endpoints[%d].headers[%d])", woHeaders[pos].Header.ValueString(), pos.endpoint, pos.header))
	}
	diags.AddWarning(
		"HTTP header values kept out of state",
		fmt.Sprintf("The action configuration no longer has a header matching the write-only header %s, so it may have been changed outside Terraform. "+
			"To keep a write-only value out of state, the values of all HTTP headers not matched to a write-only header are left null. "+
			"The next plan shows them as changes; applying it sends the configured values again.", strings.Join(names, ", ")),
	)
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

// matchWriteOnlyHeaders pairs API headers on an endpoint, by index, with the
// positions of the prior value_wo headers they carry forward. A header matches
// the prior header at the same position with the same name ignoring case;
// failing that, it takes the first unused prior value_wo header on the same
// endpoint with that name, so a header moved out of band still matches.
func matchWriteOnlyHeaders(headers []jamfprotect.ReportClientHeader, endpoint int, woHeaders map[headerPosition]endpointHeaderModel) map[int]headerPosition {
	matched := map[int]headerPosition{}
	used := map[int]bool{}
	for j, h := range headers {
		pos := headerPosition{endpoint: endpoint, header: j}
		if prior, ok := woHeaders[pos]; ok && strings.EqualFold(prior.Header.ValueString(), h.Header) {
			matched[j] = pos
			used[j] = true
		}
	}
	var candidates []int
	for pos := range woHeaders {
		if pos.endpoint == endpoint {
			candidates = append(candidates, pos.header)
		}
	}
	slices.Sort(candidates)
	for j, h := range headers {
		if _, ok := matched[j]; ok {
			continue
		}
		for _, c := range candidates {
			pos := headerPosition{endpoint: endpoint, header: c}
			if !used[c] && strings.EqualFold(woHeaders[pos].Header.ValueString(), h.Header) {
				matched[j] = pos
				used[c] = true
				break
			}
		}
	}
	return matched
}

// buildHeadersList converts a slice of API header models to a Terraform List value.
// A header in matched keeps its value out of state and carries the value_wo_version
// of its prior value_wo header forward. When failClosed is set, every other header
// also keeps its value out of state.
func buildHeadersList(headers []jamfprotect.ReportClientHeader, matched map[int]headerPosition, woHeaders map[headerPosition]endpointHeaderModel, failClosed bool, diags *diag.Diagnostics) types.List {
	if len(headers) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: endpointHeaderAttrTypes})
	}
	items := make([]attr.Value, 0, len(headers))
	for j, h := range headers {
		value := types.StringValue(h.Value)
		version := types.StringNull()
		if pos, ok := matched[j]; ok {
			value = types.StringNull()
			version = woHeaders[pos].ValueWOVersion
		} else if failClosed {
			value = types.StringNull()
		}
		obj, d := types.ObjectValue(endpointHeaderAttrTypes, map[string]attr.Value{
			"header":           types.StringValue(h.Header),
			"value":            value,
			"value_wo":         types.StringNull(),
			"value_wo_version": version,
		})
		diags.Append(d...)
		items = append(items, obj)
	}
	list, d := types.ListValue(types.ObjectType{AttrTypes: endpointHeaderAttrTypes}, items)
	diags.Append(d...)
	return list
}
