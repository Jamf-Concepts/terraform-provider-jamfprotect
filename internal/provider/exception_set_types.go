// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ExceptionSetResourceModel maps the resource schema data.
type ExceptionSetResourceModel struct {
	ID           types.String   `tfsdk:"id"`
	Name         types.String   `tfsdk:"name"`
	Description  types.String   `tfsdk:"description"`
	Exceptions   types.List     `tfsdk:"exceptions"`
	EsExceptions types.List     `tfsdk:"es_exceptions"`
	Created      types.String   `tfsdk:"created"`
	Updated      types.String   `tfsdk:"updated"`
	Managed      types.Bool     `tfsdk:"managed"`
	Timeouts     timeouts.Value `tfsdk:"timeouts"`
}

// exceptionModel maps the exceptions nested attribute.
type exceptionModel struct {
	Type           types.String `tfsdk:"type"`
	Value          types.String `tfsdk:"value"`
	AppSigningInfo types.Object `tfsdk:"app_signing_info"`
	IgnoreActivity types.String `tfsdk:"ignore_activity"`
	AnalyticTypes  types.List   `tfsdk:"analytic_types"`
	AnalyticUuid   types.String `tfsdk:"analytic_uuid"`
}

// esExceptionModel maps the es_exceptions nested attribute.
type esExceptionModel struct {
	Type              types.String `tfsdk:"type"`
	Value             types.String `tfsdk:"value"`
	AppSigningInfo    types.Object `tfsdk:"app_signing_info"`
	IgnoreActivity    types.String `tfsdk:"ignore_activity"`
	IgnoreListType    types.String `tfsdk:"ignore_list_type"`
	IgnoreListSubType types.String `tfsdk:"ignore_list_subtype"`
	EventType         types.String `tfsdk:"event_type"`
}

// appSigningInfoModel maps the app_signing_info nested attribute.
type appSigningInfoModel struct {
	AppId  types.String `tfsdk:"app_id"`
	TeamId types.String `tfsdk:"team_id"`
}

// ---------------------------------------------------------------------------
// API models (match the JSON returned by the GraphQL API)
// ---------------------------------------------------------------------------

type exceptionSetResourceAPIModel struct {
	UUID         string                `json:"uuid"`
	Name         string                `json:"name"`
	Description  string                `json:"description"`
	Exceptions   []exceptionAPIModel   `json:"exceptions"`
	EsExceptions []esExceptionAPIModel `json:"esExceptions"`
	Created      string                `json:"created"`
	Updated      string                `json:"updated"`
	Managed      bool                  `json:"managed"`
}

type exceptionAPIModel struct {
	Type           string                  `json:"type"`
	Value          string                  `json:"value"`
	AppSigningInfo *appSigningInfoAPIModel `json:"appSigningInfo"`
	IgnoreActivity string                  `json:"ignoreActivity"`
	AnalyticTypes  []string                `json:"analyticTypes"`
	AnalyticUuid   string                  `json:"analyticUuid"`
}

type esExceptionAPIModel struct {
	Type              string                  `json:"type"`
	Value             string                  `json:"value"`
	AppSigningInfo    *appSigningInfoAPIModel `json:"appSigningInfo"`
	IgnoreActivity    string                  `json:"ignoreActivity"`
	IgnoreListType    string                  `json:"ignoreListType"`
	IgnoreListSubType string                  `json:"ignoreListSubType"`
	EventType         string                  `json:"eventType"`
}

type appSigningInfoAPIModel struct {
	AppId  string `json:"appId"`
	TeamId string `json:"teamId"`
}
