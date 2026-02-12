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

const telemetryV2Fields = `
fragment TelemetryV2Fields on TelemetryV2 {
  id
  name
  description
  created
  updated
  logFiles
  logFileCollection
  performanceMetrics
  events
  fileHashing
}
`

const createTelemetryV2Mutation = `
mutation createTelemetryV2(
  $name: String!,
  $description: String,
  $logFiles: [String!]!,
  $logFileCollection: Boolean!,
  $performanceMetrics: Boolean!,
  $events: [ES_EVENTS_ENUM]!,
  $fileHashing: Boolean!
) {
  createTelemetryV2(input: {
    name: $name,
    description: $description,
    logFiles: $logFiles,
    logFileCollection: $logFileCollection,
    performanceMetrics: $performanceMetrics,
    events: $events,
    fileHashing: $fileHashing
  }) {
    ...TelemetryV2Fields
  }
}
` + telemetryV2Fields

const getTelemetryV2Query = `
query getTelemetryV2($id: ID!) {
  getTelemetryV2(id: $id) {
    ...TelemetryV2Fields
  }
}
` + telemetryV2Fields

const updateTelemetryV2Mutation = `
mutation updateTelemetryV2(
  $id: ID!,
  $name: String!,
  $description: String,
  $logFiles: [String!]!,
  $logFileCollection: Boolean!,
  $performanceMetrics: Boolean!,
  $events: [ES_EVENTS_ENUM]!,
  $fileHashing: Boolean!
) {
  updateTelemetryV2(id: $id, input: {
    name: $name,
    description: $description,
    logFiles: $logFiles,
    logFileCollection: $logFileCollection,
    performanceMetrics: $performanceMetrics,
    events: $events,
    fileHashing: $fileHashing
  }) {
    ...TelemetryV2Fields
  }
}
` + telemetryV2Fields

const deleteTelemetryV2Mutation = `
mutation deleteTelemetryV2($id: ID!) {
  deleteTelemetryV2(id: $id) {
    id
  }
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *TelemetryV2Resource) buildVariables(ctx context.Context, data TelemetryV2ResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":               data.Name.ValueString(),
		"logFileCollection":  data.LogFileCollection.ValueBool(),
		"performanceMetrics": data.PerformanceMetrics.ValueBool(),
		"fileHashing":        data.FileHashing.ValueBool(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	vars["logFiles"] = listToStrings(ctx, data.LogFiles, diags)
	vars["events"] = listToStrings(ctx, data.Events, diags)
	return vars
}

func (r *TelemetryV2Resource) apiToState(_ context.Context, data *TelemetryV2ResourceModel, api telemetryV2APIModel, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.LogFileCollection = types.BoolValue(api.LogFileCollection)
	data.PerformanceMetrics = types.BoolValue(api.PerformanceMetrics)
	data.FileHashing = types.BoolValue(api.FileHashing)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.LogFiles = stringsToList(api.LogFiles)
	data.Events = stringsToList(api.Events)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}
}
