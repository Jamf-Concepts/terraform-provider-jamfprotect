// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package analytic_set

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// GraphQL queries
// ---------------------------------------------------------------------------

const analyticSetFields = `
fragment AnalyticSetFields on AnalyticSet {
  uuid
  name
  description
  analytics @skip(if: $excludeAnalytics) {
    uuid
    name
    jamf
  }
  plans @include(if: $RBAC_Plan) {
    id
    name
  }
  created
  updated
  managed
  types
}
`

const createAnalyticSetMutation = `
mutation createAnalyticSet(
  $name: String!,
  $description: String,
  $types: [ANALYTIC_SET_TYPE!],
  $analytics: [ID!]!,
  $RBAC_Plan: Boolean!,
  $excludeAnalytics: Boolean!
) {
  createAnalyticSet(input: {
    name: $name,
    description: $description,
    analytics: $analytics,
    types: $types
  }) {
    ...AnalyticSetFields
  }
}
` + analyticSetFields

const getAnalyticSetQuery = `
query getAnalyticSet(
  $uuid: ID!,
  $RBAC_Plan: Boolean!,
  $excludeAnalytics: Boolean!
) {
  getAnalyticSet(uuid: $uuid) {
    ...AnalyticSetFields
  }
}
` + analyticSetFields

const updateAnalyticSetMutation = `
mutation updateAnalyticSet(
  $uuid: ID!,
  $name: String!,
  $description: String,
  $types: [ANALYTIC_SET_TYPE!],
  $analytics: [ID!]!,
  $RBAC_Plan: Boolean!,
  $excludeAnalytics: Boolean!
) {
  updateAnalyticSet(uuid: $uuid, input: {
    name: $name,
    description: $description,
    analytics: $analytics,
    types: $types
  }) {
    ...AnalyticSetFields
  }
}
` + analyticSetFields

const deleteAnalyticSetMutation = `
mutation deleteAnalyticSet($uuid: ID!) {
  deleteAnalyticSet(uuid: $uuid) {
    uuid
  }
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildVariables converts the Terraform model into GraphQL mutation variables.
func (r *AnalyticSetResource) buildVariables(ctx context.Context, data AnalyticSetResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":             data.Name.ValueString(),
		"types":            []string{"Report"},
		"RBAC_Plan":        true,
		"excludeAnalytics": false,
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	// Analytics is required
	vars["analytics"] = common.SetToStrings(ctx, data.Analytics, diags)

	return vars
}

// apiToState maps the API response into the Terraform state model.
func (r *AnalyticSetResource) apiToState(_ context.Context, data *AnalyticSetResourceModel, api analyticSetResourceAPIModel, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.UUID)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.Managed = types.BoolValue(api.Managed)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringValue("")
	}

	// Analytics - convert from array of objects to just UUIDs
	var analyticUUIDs []string
	for _, a := range api.Analytics {
		analyticUUIDs = append(analyticUUIDs, a.UUID)
	}
	data.Analytics = common.StringsToSet(analyticUUIDs)
}
