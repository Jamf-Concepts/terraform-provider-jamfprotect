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

const preventListFields = `
fragment PreventListFields on PreventList {
  id
  name
  type
  count
  list
  created
  description
}
`

const createPreventListMutation = `
mutation createPreventList(
  $name: String!,
  $tags: [String]!,
  $type: PREVENT_LIST_TYPE!,
  $list: [String]!,
  $description: String
) {
  createPreventList(input: {
    name: $name,
    tags: $tags,
    type: $type,
    list: $list,
    description: $description
  }) {
    ...PreventListFields
  }
}
` + preventListFields

const getPreventListQuery = `
query getPreventList($id: ID!) {
  getPreventList(id: $id) {
    ...PreventListFields
  }
}
` + preventListFields

const updatePreventListMutation = `
mutation updatePreventList(
  $id: ID!,
  $name: String!,
  $tags: [String]!,
  $type: PREVENT_LIST_TYPE!,
  $list: [String]!,
  $description: String
) {
  updatePreventList(id: $id, input: {
    name: $name,
    tags: $tags,
    type: $type,
    list: $list,
    description: $description
  }) {
    ...PreventListFields
  }
}
` + preventListFields

const deletePreventListMutation = `
mutation deletePreventList($id: ID!) {
  deletePreventList(id: $id) {
    id
  }
}
`

const listPreventListsQuery = `
query listPreventLists($nextToken: String, $direction: OrderDirection!, $field: PreventListOrderField!) {
  listPreventLists(
    input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
  ) {
    items {
      ...PreventListFields
    }
    pageInfo {
      next
      total
    }
  }
}
` + preventListFields

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *PreventListResource) buildVariables(ctx context.Context, data PreventListResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name": data.Name.ValueString(),
		"type": data.Type.ValueString(),
	}
	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}
	vars["tags"] = listToStrings(ctx, data.Tags, diags)
	vars["list"] = listToStrings(ctx, data.List, diags)
	return vars
}

func (r *PreventListResource) apiToState(_ context.Context, data *PreventListResourceModel, api preventListAPIModel, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.Type = types.StringValue(api.Type)
	data.EntryCount = types.Int64Value(api.Count)
	data.Created = types.StringValue(api.Created)
	data.List = stringsToList(api.List)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}
}
