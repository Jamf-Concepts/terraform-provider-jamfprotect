// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package action_configuration

import (
	"context"
	"encoding/json"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// ---------------------------------------------------------------------------
// GraphQL queries — stripped of @skip/@include RBAC directives.
// ---------------------------------------------------------------------------

const actionConfigFields = `
fragment ActionConfigsFields on ActionConfigs {
  id
  name
  description
  hash
  created
  updated
  alertConfig {
    data {
      binary { attrs related }
			clickEvent { attrs related }
      downloadEvent { attrs related }
      file { attrs related }
      fsEvent { attrs related }
      group { attrs related }
      procEvent { attrs related }
      process { attrs related }
      screenshotEvent { attrs related }
      usbEvent { attrs related }
      user { attrs related }
      gkEvent { attrs related }
      keylogRegisterEvent { attrs related }
      mrtEvent { attrs related }
    }
  }
	clients {
		id
		type
		supportedReports
		batchConfig {
			delimiter
			sizeIndex
			windowInSeconds
			sizeInBytes
		}
		params {
			... on JamfCloudClientParams { destinationFilter }
			... on HttpClientParams { headers { header value } method url }
			... on KafkaClientParams { host port topic clientCN serverCN }
			... on SyslogClientParams { host port scheme }
			... on LogFileClientParams { path permissions maxSizeMB ownership backups }
		}
	}
}
`

const createActionConfigMutation = `
mutation createActionConfigs(
  $name: String!,
  $description: String!,
	$alertConfig: ActionConfigsAlertConfigInput!,
	$clients: [ReportClientInput!]
) {
  createActionConfigs(input: {
    name: $name,
    description: $description,
		alertConfig: $alertConfig,
		clients: $clients
  }) {
    ...ActionConfigsFields
  }
}
` + actionConfigFields

const getActionConfigQuery = `
query getActionConfigs($id: ID!) {
  getActionConfigs(id: $id) {
    ...ActionConfigsFields
  }
}
` + actionConfigFields

const updateActionConfigMutation = `
mutation updateActionConfigs(
  $id: ID!,
  $name: String!,
  $description: String!,
	$alertConfig: ActionConfigsAlertConfigInput!,
	$clients: [ReportClientInput!]
) {
  updateActionConfigs(id: $id, input: {
    name: $name,
    description: $description,
		alertConfig: $alertConfig,
		clients: $clients
  }) {
    ...ActionConfigsFields
  }
}
` + actionConfigFields

const deleteActionConfigMutation = `
mutation deleteActionConfigs($id: ID!) {
  deleteActionConfigs(id: $id) {
    id
  }
}
`

const listActionConfigsQuery = `
query listActionConfigs($nextToken: String, $direction: OrderDirection!, $field: ActionConfigsOrderField!) {
  listActionConfigs(
    input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
  ) {
    items {
      id
      name
      description
      created
      updated
    }
    pageInfo {
      next
      total
    }
  }
}
`

// ---------------------------------------------------------------------------
// Alert config attribute type definitions for ObjectValue construction
// ---------------------------------------------------------------------------

// alertEventTypeAttrTypes defines the attribute types for each event type object.
var alertEventTypeAttrTypes = map[string]attr.Type{
	"attrs":   types.ListType{ElemType: types.StringType},
	"related": types.ListType{ElemType: types.StringType},
}

// dataCollectionAttrTypes defines the attribute types for the data_collection.data object.
var dataCollectionAttrTypes = map[string]attr.Type{
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

// dataCollectionWrapperAttrTypes defines the attribute types for the data_collection object.
var dataCollectionWrapperAttrTypes = map[string]attr.Type{
	"data": types.ObjectType{AttrTypes: dataCollectionAttrTypes},
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

var endpointHeaderAttrTypes = map[string]attr.Type{
	"header": types.StringType,
	"value":  types.StringType,
}

var endpointHTTPAttrTypes = map[string]attr.Type{
	"enabled":              types.BoolType,
	"supported_reports":    types.ListType{ElemType: types.StringType},
	"batch_size_index":     types.Int64Type,
	"batch_window_seconds": types.Int64Type,
	"batch_size_in_bytes":  types.Int64Type,
	"batch_delimiter":      types.StringType,
	"url":                  types.StringType,
	"method":               types.StringType,
	"headers":              types.ListType{ElemType: types.ObjectType{AttrTypes: endpointHeaderAttrTypes}},
}

var endpointKafkaAttrTypes = map[string]attr.Type{
	"enabled":              types.BoolType,
	"supported_reports":    types.ListType{ElemType: types.StringType},
	"batch_size_index":     types.Int64Type,
	"batch_window_seconds": types.Int64Type,
	"batch_size_in_bytes":  types.Int64Type,
	"batch_delimiter":      types.StringType,
	"host":                 types.StringType,
	"port":                 types.Int64Type,
	"topic":                types.StringType,
	"client_cn":            types.StringType,
	"server_cn":            types.StringType,
}

var endpointSyslogAttrTypes = map[string]attr.Type{
	"enabled":              types.BoolType,
	"supported_reports":    types.ListType{ElemType: types.StringType},
	"batch_size_index":     types.Int64Type,
	"batch_window_seconds": types.Int64Type,
	"batch_size_in_bytes":  types.Int64Type,
	"batch_delimiter":      types.StringType,
	"host":                 types.StringType,
	"port":                 types.Int64Type,
	"scheme":               types.StringType,
}

var endpointLogFileAttrTypes = map[string]attr.Type{
	"enabled":              types.BoolType,
	"supported_reports":    types.ListType{ElemType: types.StringType},
	"batch_size_index":     types.Int64Type,
	"batch_window_seconds": types.Int64Type,
	"batch_size_in_bytes":  types.Int64Type,
	"batch_delimiter":      types.StringType,
	"path":                 types.StringType,
	"permissions":          types.StringType,
	"max_size_mb":          types.Int64Type,
	"ownership":            types.StringType,
	"backups":              types.Int64Type,
}

var endpointJamfCloudAttrTypes = map[string]attr.Type{
	"enabled":              types.BoolType,
	"supported_reports":    types.ListType{ElemType: types.StringType},
	"batch_size_index":     types.Int64Type,
	"batch_window_seconds": types.Int64Type,
	"batch_size_in_bytes":  types.Int64Type,
	"batch_delimiter":      types.StringType,
	"destination_filter":   types.StringType,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractEventType extracts an alertEventTypeModel from the alertDataModel for the given field.
func extractEventType(ctx context.Context, dataObj types.Object, tfName string, diags *diag.Diagnostics) alertEventTypeModel {
	var dataModel dataCollectionDataModel
	diags.Append(dataObj.As(ctx, &dataModel, basetypes.ObjectAsOptions{})...)

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

func (r *ActionConfigResource) buildVariables(ctx context.Context, data ActionConfigResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name": data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	// Extract the data_collection -> data nested structure.
	var collection dataCollectionModel
	diags.Append(data.DataCollection.As(ctx, &collection, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	apiData := map[string]any{}
	for _, m := range eventTypeMapping {
		et := extractEventType(ctx, collection.Data, m.tfName, diags)
		if diags.HasError() {
			return nil
		}
		apiData[m.apiName] = map[string]any{
			"attrs":   common.ListToStrings(ctx, et.Attrs, diags),
			"related": common.ListToStrings(ctx, et.Related, diags),
		}
	}

	vars["alertConfig"] = map[string]any{
		"data": apiData,
	}

	clients := r.buildClients(ctx, data, diags)
	if diags.HasError() {
		return nil
	}
	if len(clients) > 0 {
		vars["clients"] = clients
	} else {
		vars["clients"] = nil
	}

	return vars
}

func (r *ActionConfigResource) buildClients(ctx context.Context, data ActionConfigResourceModel, diags *diag.Diagnostics) []map[string]any {
	clients := []map[string]any{}

	if client := buildHTTPClient(ctx, data.EndpointHTTP, diags); client != nil {
		clients = append(clients, client)
	}
	if client := buildKafkaClient(ctx, data.EndpointKafka, diags); client != nil {
		clients = append(clients, client)
	}
	if client := buildSyslogClient(ctx, data.EndpointSyslog, diags); client != nil {
		clients = append(clients, client)
	}
	if client := buildLogFileClient(ctx, data.EndpointLogFile, diags); client != nil {
		clients = append(clients, client)
	}
	if client := buildJamfCloudClient(ctx, data.EndpointJamfCloud, diags); client != nil {
		clients = append(clients, client)
	}

	return clients
}

func buildHTTPClient(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}

	var endpoint endpointHTTPModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
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
			return nil
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

	return buildClientFromEndpoint(
		ctx,
		"Http",
		endpoint.Enabled,
		endpoint.SupportedReports,
		endpoint.BatchSizeIndex,
		endpoint.BatchWindowSeconds,
		endpoint.BatchSizeInBytes,
		endpoint.BatchDelimiter,
		params,
		diags,
	)
}

func buildKafkaClient(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var endpoint endpointKafkaModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
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

	return buildClientFromEndpoint(
		ctx,
		"Kafka",
		endpoint.Enabled,
		endpoint.SupportedReports,
		endpoint.BatchSizeIndex,
		endpoint.BatchWindowSeconds,
		endpoint.BatchSizeInBytes,
		endpoint.BatchDelimiter,
		params,
		diags,
	)
}

func buildSyslogClient(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var endpoint endpointSyslogModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	params := map[string]any{}
	if !endpoint.Host.IsNull() && !endpoint.Host.IsUnknown() {
		params["host"] = endpoint.Host.ValueString()
	}
	if !endpoint.Port.IsNull() && !endpoint.Port.IsUnknown() {
		params["port"] = endpoint.Port.ValueInt64()
	}
	if !endpoint.Scheme.IsNull() && !endpoint.Scheme.IsUnknown() {
		params["scheme"] = endpoint.Scheme.ValueString()
	}

	return buildClientFromEndpoint(
		ctx,
		"Syslog",
		endpoint.Enabled,
		endpoint.SupportedReports,
		endpoint.BatchSizeIndex,
		endpoint.BatchWindowSeconds,
		endpoint.BatchSizeInBytes,
		endpoint.BatchDelimiter,
		params,
		diags,
	)
}

func buildLogFileClient(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var endpoint endpointLogFileModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	params := map[string]any{}
	if !endpoint.Path.IsNull() && !endpoint.Path.IsUnknown() {
		params["path"] = endpoint.Path.ValueString()
	}
	if !endpoint.Permissions.IsNull() && !endpoint.Permissions.IsUnknown() {
		params["permissions"] = endpoint.Permissions.ValueString()
	}
	if !endpoint.MaxSizeMB.IsNull() && !endpoint.MaxSizeMB.IsUnknown() {
		params["maxSizeMB"] = endpoint.MaxSizeMB.ValueInt64()
	}
	if !endpoint.Ownership.IsNull() && !endpoint.Ownership.IsUnknown() {
		params["ownership"] = endpoint.Ownership.ValueString()
	}
	if !endpoint.Backups.IsNull() && !endpoint.Backups.IsUnknown() {
		params["backups"] = endpoint.Backups.ValueInt64()
	}

	return buildClientFromEndpoint(
		ctx,
		"LogFile",
		endpoint.Enabled,
		endpoint.SupportedReports,
		endpoint.BatchSizeIndex,
		endpoint.BatchWindowSeconds,
		endpoint.BatchSizeInBytes,
		endpoint.BatchDelimiter,
		params,
		diags,
	)
}

func buildJamfCloudClient(ctx context.Context, obj types.Object, diags *diag.Diagnostics) map[string]any {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var endpoint endpointJamfCloudModel
	diags.Append(obj.As(ctx, &endpoint, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	params := map[string]any{}
	if !endpoint.DestinationFilter.IsNull() && !endpoint.DestinationFilter.IsUnknown() {
		params["destinationFilter"] = endpoint.DestinationFilter.ValueString()
	}
	return buildClientFromEndpoint(
		ctx,
		"JamfCloud",
		endpoint.Enabled,
		endpoint.SupportedReports,
		endpoint.BatchSizeIndex,
		endpoint.BatchWindowSeconds,
		endpoint.BatchSizeInBytes,
		endpoint.BatchDelimiter,
		params,
		diags,
	)
}

func buildClientFromEndpoint(
	ctx context.Context,
	clientType string,
	enabled types.Bool,
	supportedReports types.List,
	batchSizeIndex types.Int64,
	batchWindowSeconds types.Int64,
	batchSizeInBytes types.Int64,
	batchDelimiter types.String,
	params map[string]any,
	diags *diag.Diagnostics,
) map[string]any {
	if !boolValueOrTrue(enabled) {
		return nil
	}

	client := map[string]any{
		"type": clientType,
	}
	if batch := buildBatchConfig(batchSizeIndex, batchWindowSeconds, batchSizeInBytes, batchDelimiter); len(batch) > 0 {
		client["batchConfig"] = batch
	}
	if !supportedReports.IsNull() && !supportedReports.IsUnknown() {
		client["supportedReports"] = common.ListToStrings(ctx, supportedReports, diags)
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		diags.AddError("Error serializing "+clientType+" client params", err.Error())
		return nil
	}
	client["params"] = string(paramsJSON)

	return client
}

func buildBatchConfig(sizeIndex types.Int64, windowSeconds types.Int64, sizeInBytes types.Int64, delimiter types.String) map[string]any {
	batch := map[string]any{}
	if !sizeIndex.IsNull() && !sizeIndex.IsUnknown() {
		batch["sizeIndex"] = sizeIndex.ValueInt64()
	}
	if !windowSeconds.IsNull() && !windowSeconds.IsUnknown() {
		batch["windowInSeconds"] = windowSeconds.ValueInt64()
	}
	if !sizeInBytes.IsNull() && !sizeInBytes.IsUnknown() {
		batch["sizeInBytes"] = sizeInBytes.ValueInt64()
	}
	if !delimiter.IsNull() && !delimiter.IsUnknown() {
		batch["delimiter"] = delimiter.ValueString()
	}
	return batch
}

func boolValueOrTrue(value types.Bool) bool {
	if value.IsNull() || value.IsUnknown() {
		return true
	}
	return value.ValueBool()
}

// eventTypeToObjectValue converts an API event type model to a Terraform ObjectValue.
func eventTypeToObjectValue(et *alertEventTypeAPIModel, diags *diag.Diagnostics) types.Object {
	if et == nil {
		et = &alertEventTypeAPIModel{Attrs: []string{}, Related: []string{}}
	}

	attrs := map[string]attr.Value{
		"attrs":   common.StringsToList(et.Attrs),
		"related": common.StringsToList(et.Related),
	}

	obj, d := types.ObjectValue(alertEventTypeAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

// apiEventTypeGetter returns the API event type model for a given API field name.
func apiEventTypeGetter(apiData *alertDataAPIModel, apiName string) *alertEventTypeAPIModel {
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

func (r *ActionConfigResource) apiToState(_ context.Context, data *ActionConfigResourceModel, api actionConfigAPIModel, diags *diag.Diagnostics) {
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

	// Build data_collection object from API response.
	if api.AlertConfig != nil && api.AlertConfig.Data != nil {
		dataAttrs := map[string]attr.Value{}
		for _, m := range eventTypeMapping {
			apiET := apiEventTypeGetter(api.AlertConfig.Data, m.apiName)
			dataAttrs[m.tfName] = eventTypeToObjectValue(apiET, diags)
		}
		if diags.HasError() {
			return
		}

		dataObj, d := types.ObjectValue(dataCollectionAttrTypes, dataAttrs)
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		collectionObj, d := types.ObjectValue(dataCollectionWrapperAttrTypes, map[string]attr.Value{
			"data": dataObj,
		})
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		data.DataCollection = collectionObj
	}

	data.EndpointHTTP = types.ObjectNull(endpointHTTPAttrTypes)
	data.EndpointKafka = types.ObjectNull(endpointKafkaAttrTypes)
	data.EndpointSyslog = types.ObjectNull(endpointSyslogAttrTypes)
	data.EndpointLogFile = types.ObjectNull(endpointLogFileAttrTypes)
	data.EndpointJamfCloud = types.ObjectNull(endpointJamfCloudAttrTypes)

	for _, client := range api.Clients {
		switch client.Type {
		case "Http":
			data.EndpointHTTP = apiHTTPToObjectValue(client, diags)
		case "Kafka":
			data.EndpointKafka = apiKafkaToObjectValue(client, diags)
		case "Syslog":
			data.EndpointSyslog = apiSyslogToObjectValue(client, diags)
		case "LogFile":
			data.EndpointLogFile = apiLogFileToObjectValue(client, diags)
		case "JamfCloud":
			data.EndpointJamfCloud = apiJamfCloudToObjectValue(client, diags)
		}
	}
}

func apiHTTPToObjectValue(client reportClientAPIModel, diags *diag.Diagnostics) types.Object {
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
		"enabled":              types.BoolValue(true),
		"supported_reports":    common.StringsToList(client.SupportedReports),
		"batch_size_index":     int64ValueOrNull(client.BatchConfig, "sizeIndex"),
		"batch_window_seconds": int64ValueOrNull(client.BatchConfig, "windowInSeconds"),
		"batch_size_in_bytes":  int64ValueOrNull(client.BatchConfig, "sizeInBytes"),
		"batch_delimiter":      stringValueOrNull(client.BatchConfig, "delimiter"),
		"url":                  stringValueOrNullValue(client.Params.URL),
		"method":               stringValueOrNullValue(client.Params.Method),
		"headers":              headersList,
	}

	obj, d := types.ObjectValue(endpointHTTPAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiKafkaToObjectValue(client reportClientAPIModel, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"enabled":              types.BoolValue(true),
		"supported_reports":    common.StringsToList(client.SupportedReports),
		"batch_size_index":     int64ValueOrNull(client.BatchConfig, "sizeIndex"),
		"batch_window_seconds": int64ValueOrNull(client.BatchConfig, "windowInSeconds"),
		"batch_size_in_bytes":  types.Int64Null(),
		"batch_delimiter":      types.StringNull(),
		"host":                 stringValueOrNullValue(client.Params.Host),
		"port":                 types.Int64Value(client.Params.Port),
		"topic":                stringValueOrNullValue(client.Params.Topic),
		"client_cn":            stringValueOrNullValue(client.Params.ClientCN),
		"server_cn":            stringValueOrNullValue(client.Params.ServerCN),
	}

	obj, d := types.ObjectValue(endpointKafkaAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiSyslogToObjectValue(client reportClientAPIModel, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"enabled":              types.BoolValue(true),
		"supported_reports":    common.StringsToList(client.SupportedReports),
		"batch_size_index":     int64ValueOrNull(client.BatchConfig, "sizeIndex"),
		"batch_window_seconds": int64ValueOrNull(client.BatchConfig, "windowInSeconds"),
		"batch_size_in_bytes":  types.Int64Null(),
		"batch_delimiter":      types.StringNull(),
		"host":                 stringValueOrNullValue(client.Params.Host),
		"port":                 types.Int64Value(client.Params.Port),
		"scheme":               stringValueOrNullValue(client.Params.Scheme),
	}

	obj, d := types.ObjectValue(endpointSyslogAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiLogFileToObjectValue(client reportClientAPIModel, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"enabled":              types.BoolValue(true),
		"supported_reports":    common.StringsToList(client.SupportedReports),
		"batch_size_index":     int64ValueOrNull(client.BatchConfig, "sizeIndex"),
		"batch_window_seconds": int64ValueOrNull(client.BatchConfig, "windowInSeconds"),
		"batch_size_in_bytes":  types.Int64Null(),
		"batch_delimiter":      types.StringNull(),
		"path":                 stringValueOrNullValue(client.Params.Path),
		"permissions":          stringValueOrNullValue(client.Params.Permissions),
		"max_size_mb":          types.Int64Value(client.Params.MaxSizeMB),
		"ownership":            stringValueOrNullValue(client.Params.Ownership),
		"backups":              types.Int64Value(client.Params.Backups),
	}

	obj, d := types.ObjectValue(endpointLogFileAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func apiJamfCloudToObjectValue(client reportClientAPIModel, diags *diag.Diagnostics) types.Object {
	attrs := map[string]attr.Value{
		"enabled":              types.BoolValue(true),
		"supported_reports":    common.StringsToList(client.SupportedReports),
		"batch_size_index":     int64ValueOrNull(client.BatchConfig, "sizeIndex"),
		"batch_window_seconds": int64ValueOrNull(client.BatchConfig, "windowInSeconds"),
		"batch_size_in_bytes":  types.Int64Null(),
		"batch_delimiter":      types.StringNull(),
		"destination_filter":   stringValueOrNullValue(client.Params.DestinationFilter),
	}

	obj, d := types.ObjectValue(endpointJamfCloudAttrTypes, attrs)
	diags.Append(d...)
	return obj
}

func int64ValueOrNull(batch *batchConfigAPIModel, field string) attr.Value {
	if batch == nil {
		return types.Int64Null()
	}
	switch field {
	case "sizeIndex":
		return types.Int64Value(batch.SizeIndex)
	case "windowInSeconds":
		return types.Int64Value(batch.WindowInSeconds)
	case "sizeInBytes":
		return types.Int64Value(batch.SizeInBytes)
	default:
		return types.Int64Null()
	}
}

func stringValueOrNull(batch *batchConfigAPIModel, field string) attr.Value {
	if batch == nil {
		return types.StringNull()
	}
	if field == "delimiter" {
		if batch.Delimiter == "" {
			return types.StringNull()
		}
		return types.StringValue(batch.Delimiter)
	}
	return types.StringNull()
}

func stringValueOrNullValue(value string) attr.Value {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}
