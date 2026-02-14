// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package exception_set

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ExceptionSetResourceModel maps the resource schema data.
type ExceptionSetResourceModel struct {
	ID           types.String   `tfsdk:"id"`
	Name         types.String   `tfsdk:"name"`
	Description  types.String   `tfsdk:"description"`
	Exceptions   types.Set      `tfsdk:"exception"`
	EsExceptions types.Set      `tfsdk:"endpoint_security_exception"`
	Created      types.String   `tfsdk:"created"`
	Updated      types.String   `tfsdk:"updated"`
	Managed      types.Bool     `tfsdk:"managed"`
	Timeouts     timeouts.Value `tfsdk:"timeouts"`
}

// exceptionModel maps the exceptions nested attribute.
type exceptionModel struct {
	Type           types.String `tfsdk:"type"`
	Value          types.String `tfsdk:"value"`
	AppID          types.String `tfsdk:"app_id"`
	TeamID         types.String `tfsdk:"team_id"`
	IgnoreActivity types.String `tfsdk:"ignore_activity"`
	AnalyticTypes  types.List   `tfsdk:"analytic_types"`
	AnalyticUuid   types.String `tfsdk:"analytic_uuid"`
}

// esExceptionModel maps the es_exceptions nested attribute.
type esExceptionModel struct {
	Type              types.String `tfsdk:"type"`
	Value             types.String `tfsdk:"value"`
	AppID             types.String `tfsdk:"app_id"`
	TeamID            types.String `tfsdk:"team_id"`
	IgnoreActivity    types.String `tfsdk:"ignore_activity"`
	IgnoreListType    types.String `tfsdk:"ignore_list_type"`
	IgnoreListSubType types.String `tfsdk:"ignore_list_subtype"`
	EventType         types.String `tfsdk:"event_type"`
}
