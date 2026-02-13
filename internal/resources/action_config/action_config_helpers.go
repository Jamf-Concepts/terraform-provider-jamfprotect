// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package actionconfig

import (
	"context"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/common"

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
}
`

const createActionConfigMutation = `
mutation createActionConfigs(
  $name: String!,
  $description: String!,
  $alertConfig: ActionConfigsAlertConfigInput!
) {
  createActionConfigs(input: {
    name: $name,
    description: $description,
    alertConfig: $alertConfig
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
  $alertConfig: ActionConfigsAlertConfigInput!
) {
  updateActionConfigs(id: $id, input: {
    name: $name,
    description: $description,
    alertConfig: $alertConfig
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

// alertDataAttrTypes defines the attribute types for the data object.
var alertDataAttrTypes = map[string]attr.Type{
	"binary":                types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"click_event":           types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"download_event":        types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"file":                  types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"fs_event":              types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"group":                 types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"proc_event":            types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"process":               types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"screenshot_event":      types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"usb_event":             types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"user":                  types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"gk_event":              types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"keylog_register_event": types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
	"mrt_event":             types.ObjectType{AttrTypes: alertEventTypeAttrTypes},
}

// alertConfigAttrTypes defines the attribute types for the alert_config object.
var alertConfigAttrTypes = map[string]attr.Type{
	"data": types.ObjectType{AttrTypes: alertDataAttrTypes},
}

// eventTypeMapping maps snake_case Terraform attribute names to camelCase API field names.
var eventTypeMapping = []struct {
	tfName  string
	apiName string
}{
	{"binary", "binary"},
	{"click_event", "clickEvent"},
	{"download_event", "downloadEvent"},
	{"file", "file"},
	{"fs_event", "fsEvent"},
	{"group", "group"},
	{"proc_event", "procEvent"},
	{"process", "process"},
	{"screenshot_event", "screenshotEvent"},
	{"usb_event", "usbEvent"},
	{"user", "user"},
	{"gk_event", "gkEvent"},
	{"keylog_register_event", "keylogRegisterEvent"},
	{"mrt_event", "mrtEvent"},
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractEventType extracts an alertEventTypeModel from the alertDataModel for the given field.
func extractEventType(ctx context.Context, dataObj types.Object, tfName string, diags *diag.Diagnostics) alertEventTypeModel {
	var dataModel alertDataModel
	diags.Append(dataObj.As(ctx, &dataModel, basetypes.ObjectAsOptions{})...)

	var fieldObj types.Object
	switch tfName {
	case "binary":
		fieldObj = dataModel.Binary
	case "click_event":
		fieldObj = dataModel.ClickEvent
	case "download_event":
		fieldObj = dataModel.DownloadEvent
	case "file":
		fieldObj = dataModel.File
	case "fs_event":
		fieldObj = dataModel.FsEvent
	case "group":
		fieldObj = dataModel.Group
	case "proc_event":
		fieldObj = dataModel.ProcEvent
	case "process":
		fieldObj = dataModel.Process
	case "screenshot_event":
		fieldObj = dataModel.ScreenshotEvent
	case "usb_event":
		fieldObj = dataModel.UsbEvent
	case "user":
		fieldObj = dataModel.User
	case "gk_event":
		fieldObj = dataModel.GkEvent
	case "keylog_register_event":
		fieldObj = dataModel.KeylogRegisterEvent
	case "mrt_event":
		fieldObj = dataModel.MrtEvent
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

	// Extract the alert_config -> data nested structure.
	var alertConfig alertConfigModel
	diags.Append(data.AlertConfig.As(ctx, &alertConfig, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	apiData := map[string]any{}
	for _, m := range eventTypeMapping {
		et := extractEventType(ctx, alertConfig.Data, m.tfName, diags)
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

	return vars
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
		data.Description = types.StringNull()
	}

	// Build alert_config object from API response.
	if api.AlertConfig != nil && api.AlertConfig.Data != nil {
		dataAttrs := map[string]attr.Value{}
		for _, m := range eventTypeMapping {
			apiET := apiEventTypeGetter(api.AlertConfig.Data, m.apiName)
			dataAttrs[m.tfName] = eventTypeToObjectValue(apiET, diags)
		}
		if diags.HasError() {
			return
		}

		dataObj, d := types.ObjectValue(alertDataAttrTypes, dataAttrs)
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		alertConfigObj, d := types.ObjectValue(alertConfigAttrTypes, map[string]attr.Value{
			"data": dataObj,
		})
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		data.AlertConfig = alertConfigObj
	}
}
