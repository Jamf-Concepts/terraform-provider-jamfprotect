package action_configuration

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

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
	case "user":
		return dataModel.UserIncludedDataAttributes
	case "gatekeeper_event":
		return dataModel.GatekeeperEventIncludedDataAttributes
	case "keylog_register_event":
		return dataModel.KeylogRegisterEventIncludedDataAttributes
	case "usb_event", "malware_removal_tool_event":
		return common.StringsToSet(nil)
	default:
		return types.SetNull(types.StringType)
	}
}

// splitExtendedDataAttributes splits the given extended data attribute values into API attributes and related fields.
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

// mergeExtendedDataAttributes merges the API attributes and related fields into a single list of extended data attribute values.
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

// buildInput constructs an ActionConfigInput from the given resource data.
func (r *ActionConfigResource) buildInput(ctx context.Context, data ActionConfigResourceModel, diags *diag.Diagnostics) *jamfprotect.ActionConfigInput {
	input := &jamfprotect.ActionConfigInput{
		Name: data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	var collection alertDataCollectionModel
	diags.Append(data.AlertDataCollect.As(ctx, &collection, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	apiData := map[string]any{}
	for _, m := range apiEventTypeMapping {
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
	// Always set Clients to an array (even if empty) - API expects array, not null
	input.Clients = clients

	return input
}

// buildClients constructs a list of client configurations from the given resource data.
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

// buildEndpointClient constructs a client configuration for the given parameters.
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

// defaultNonHTTPBatchConfig returns a default batch configuration for non-HTTP clients.
func defaultNonHTTPBatchConfig() map[string]any {
	return map[string]any{
		"sizeIndex":       int64(1),
		"windowInSeconds": int64(0),
	}
}

// buildHTTPEndpointClients constructs client configurations for HTTP endpoints from the given resource data.
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

// buildKafkaEndpointClients constructs client configurations for Kafka endpoints from the given resource data.
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

// buildSyslogEndpointClients constructs client configurations for Syslog endpoints from the given resource data.
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

// buildLogFileEndpointClient constructs a client configuration for a Log File endpoint from the given resource data.
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

// buildJamfProtectCloudEndpointClient constructs a client configuration for a Jamf Protect Cloud endpoint from the given resource data.
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

// buildSupportedReports constructs a list of supported report types based on the given alert and log collection settings.
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

	return slices.Collect(maps.Keys(reports))
}

// buildHTTPBatchConfig constructs a batch configuration for an HTTP endpoint from the given resource data.
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

// buildHTTPParams constructs the parameters for an HTTP endpoint client from the given resource data.
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

// buildKafkaParams constructs the parameters for a Kafka endpoint client from the given resource data.
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

// buildSyslogParams constructs the parameters for a Syslog endpoint client from the given resource data.
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

// buildLogFileParams constructs the parameters for a Log File endpoint client from the given resource data.
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

// buildJamfProtectCloudParams constructs the parameters for a Jamf Protect Cloud endpoint client from the given resource data.
func buildJamfProtectCloudParams(_ context.Context, endpoint jamfProtectCloudEndpointBlockModel) map[string]any {
	params := map[string]any{}
	if !endpoint.DestinationFilter.IsNull() && !endpoint.DestinationFilter.IsUnknown() {
		params["destinationFilter"] = endpoint.DestinationFilter.ValueString()
	}
	return params
}
