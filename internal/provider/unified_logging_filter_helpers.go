// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// GraphQL queries
// ---------------------------------------------------------------------------

const unifiedLoggingFilterFields = `
fragment UnifiedLoggingFilterFields on UnifiedLoggingFilter {
  uuid
  name
  description
  created
  updated
  filter
  tags
  enabled
  level
}
`

const createUnifiedLoggingFilterMutation = `
mutation createUnifiedLoggingFilter(
  $name: String!,
  $description: String,
  $tags: [String]!,
  $filter: String!,
  $enabled: Boolean,
  $level: UNIFIED_LOGGING_LEVEL!
) {
  createUnifiedLoggingFilter(input: {
    name: $name,
    description: $description,
    tags: $tags,
    filter: $filter,
    enabled: $enabled,
    level: $level
  }) {
    ...UnifiedLoggingFilterFields
  }
}
` + unifiedLoggingFilterFields

const getUnifiedLoggingFilterQuery = `
query getUnifiedLoggingFilter($uuid: ID!) {
  getUnifiedLoggingFilter(uuid: $uuid) {
    ...UnifiedLoggingFilterFields
  }
}
` + unifiedLoggingFilterFields

const updateUnifiedLoggingFilterMutation = `
mutation updateUnifiedLoggingFilter(
  $uuid: ID!,
  $name: String!,
  $description: String,
  $filter: String!,
  $tags: [String]!,
  $enabled: Boolean,
  $level: UNIFIED_LOGGING_LEVEL!
) {
  updateUnifiedLoggingFilter(uuid: $uuid, input: {
    name: $name,
    description: $description,
    filter: $filter,
    tags: $tags,
    enabled: $enabled,
    level: $level
  }) {
    ...UnifiedLoggingFilterFields
  }
}
` + unifiedLoggingFilterFields

const deleteUnifiedLoggingFilterMutation = `
mutation deleteUnifiedLoggingFilter($uuid: ID!) {
  deleteUnifiedLoggingFilter(uuid: $uuid) {
    uuid
  }
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *UnifiedLoggingFilterResource) buildVariables(ctx context.Context, data UnifiedLoggingFilterResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":    data.Name.ValueString(),
		"filter":  data.Filter.ValueString(),
		"level":   data.Level.ValueString(),
		"enabled": data.Enabled.ValueBool(),
	}
	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	}
	vars["tags"] = listToStrings(ctx, data.Tags, diags)
	return vars
}

func (r *UnifiedLoggingFilterResource) apiToState(data *UnifiedLoggingFilterResourceModel, api unifiedLoggingFilterAPIModel) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Filter = types.StringValue(api.Filter)
	data.Level = types.StringValue(api.Level)
	data.Enabled = types.BoolValue(api.Enabled)
	data.Tags = stringsToList(api.Tags)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringValue("")
	}
}
