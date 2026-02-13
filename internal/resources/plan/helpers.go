// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package plan

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// GraphQL queries — stripped of @skip/@include RBAC directives
// ---------------------------------------------------------------------------

const planFields = `
fragment PlanFields on Plan {
  id
  hash
  name
  description
  created
  updated
  logLevel
  autoUpdate
  commsConfig {
    fqdn
    protocol
  }
  infoSync {
    attrs
    insightsSyncInterval
  }
  signaturesFeedConfig {
    mode
  }
  actionConfigs {
    id
    name
  }
  exceptionSets {
    uuid
    name
    managed
  }
  usbControlSet {
    id
    name
  }
  telemetry {
    id
    name
  }
  telemetryV2 {
    id
    name
  }
  analyticSets {
    type
    analyticSet {
      uuid
      name
      managed
    }
  }
}
`

const createPlanMutation = `
mutation createPlan(
  $name: String!,
  $description: String!,
  $logLevel: LOG_LEVEL_ENUM,
  $actionConfigs: ID!,
  $exceptionSets: [ID!],
  $telemetry: ID,
  $telemetryV2: ID,
  $analyticSets: [PlanAnalyticSetInput!],
  $usbControlSet: ID,
  $commsConfig: CommsConfigInput!,
  $infoSync: InfoSyncInput!,
  $autoUpdate: Boolean!,
  $signaturesFeedConfig: SignaturesFeedConfigInput!
) {
  createPlan(input: {
    name: $name,
    description: $description,
    logLevel: $logLevel,
    actionConfigs: $actionConfigs,
    exceptionSets: $exceptionSets,
    telemetry: $telemetry,
    telemetryV2: $telemetryV2,
    analyticSets: $analyticSets,
    usbControlSet: $usbControlSet,
    commsConfig: $commsConfig,
    infoSync: $infoSync,
    autoUpdate: $autoUpdate,
    signaturesFeedConfig: $signaturesFeedConfig
  }) {
    ...PlanFields
  }
}
` + planFields

const getPlanQuery = `
query getPlan($id: ID!) {
  getPlan(id: $id) {
    ...PlanFields
  }
}
` + planFields

const updatePlanMutation = `
mutation updatePlan(
  $id: ID!,
  $name: String!,
  $description: String!,
  $logLevel: LOG_LEVEL_ENUM,
  $actionConfigs: ID!,
  $exceptionSets: [ID!],
  $telemetry: ID,
  $telemetryV2: ID,
  $analyticSets: [PlanAnalyticSetInput!],
  $usbControlSet: ID,
  $commsConfig: CommsConfigInput!,
  $infoSync: InfoSyncInput!,
  $autoUpdate: Boolean!,
  $signaturesFeedConfig: SignaturesFeedConfigInput!
) {
  updatePlan(id: $id, input: {
    name: $name,
    description: $description,
    logLevel: $logLevel,
    actionConfigs: $actionConfigs,
    exceptionSets: $exceptionSets,
    telemetry: $telemetry,
    telemetryV2: $telemetryV2,
    analyticSets: $analyticSets,
    usbControlSet: $usbControlSet,
    commsConfig: $commsConfig,
    infoSync: $infoSync,
    autoUpdate: $autoUpdate,
    signaturesFeedConfig: $signaturesFeedConfig
  }) {
    ...PlanFields
  }
}
` + planFields

const deletePlanMutation = `
mutation deletePlan($id: ID!) {
  deletePlan(id: $id) {
    id
  }
}
`

const listPlansQuery = `
query listPlans($nextToken: String, $direction: OrderDirection!, $field: PlanOrderField!) {
  listPlans(
    input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
  ) {
    items {
      ...PlanFields
    }
    pageInfo {
      next
      total
    }
  }
}
` + planFields

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildVariables converts the Terraform model into GraphQL mutation variables.
func (r *PlanResource) buildVariables(ctx context.Context, data PlanResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":          data.Name.ValueString(),
		"actionConfigs": data.ActionConfigs.ValueString(),
		"autoUpdate":    data.AutoUpdate.ValueBool(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	if !data.LogLevel.IsNull() {
		vars["logLevel"] = data.LogLevel.ValueString()
	}

	if !data.Telemetry.IsNull() {
		vars["telemetry"] = data.Telemetry.ValueString()
	}

	if !data.TelemetryV2.IsNull() {
		vars["telemetryV2"] = data.TelemetryV2.ValueString()
	}

	if !data.USBControlSet.IsNull() {
		vars["usbControlSet"] = data.USBControlSet.ValueString()
	}

	// Exception sets.
	if !data.ExceptionSets.IsNull() {
		vars["exceptionSets"] = common.ListToStrings(ctx, data.ExceptionSets, diags)
	}

	// Analytic sets.
	var analyticSets []map[string]any
	if !data.AnalyticSets.IsNull() {
		var setModels []planAnalyticSetModel
		diags.Append(data.AnalyticSets.ElementsAs(ctx, &setModels, false)...)
		for _, s := range setModels {
			analyticSets = append(analyticSets, map[string]any{
				"type": s.Type.ValueString(),
				"uuid": s.AnalyticSet.ValueString(),
			})
		}
	}
	if analyticSets != nil {
		vars["analyticSets"] = analyticSets
	}

	// Comms config (required).
	if !data.CommsConfig.IsNull() {
		commsAttrs := data.CommsConfig.Attributes()
		fqdn, ok := commsAttrs["fqdn"].(types.String)
		if !ok {
			diags.AddError("Type assertion failed", "fqdn is not a types.String")
			return nil
		}
		protocol, ok := commsAttrs["protocol"].(types.String)
		if !ok {
			diags.AddError("Type assertion failed", "protocol is not a types.String")
			return nil
		}
		vars["commsConfig"] = map[string]any{
			"fqdn":     fqdn.ValueString(),
			"protocol": protocol.ValueString(),
		}
	} else {
		vars["commsConfig"] = map[string]any{
			"fqdn":     "",
			"protocol": "",
		}
	}

	// Info sync (required).
	if !data.InfoSync.IsNull() {
		infoAttrs := data.InfoSync.Attributes()
		attrsList, ok := infoAttrs["attrs"].(types.List)
		if !ok {
			diags.AddError("Type assertion failed", "attrs is not a types.List")
			return nil
		}
		syncInterval, ok := infoAttrs["insights_sync_interval"].(types.Int64)
		if !ok {
			diags.AddError("Type assertion failed", "insights_sync_interval is not a types.Int64")
			return nil
		}
		vars["infoSync"] = map[string]any{
			"attrs":                common.ListToStrings(ctx, attrsList, diags),
			"insightsSyncInterval": syncInterval.ValueInt64(),
		}
	} else {
		vars["infoSync"] = map[string]any{
			"attrs":                []string{},
			"insightsSyncInterval": 0,
		}
	}

	// Signatures feed config (required).
	if !data.SignaturesFeedConfig.IsNull() {
		sigAttrs := data.SignaturesFeedConfig.Attributes()
		mode, ok := sigAttrs["mode"].(types.String)
		if !ok {
			diags.AddError("Type assertion failed", "mode is not a types.String")
			return nil
		}
		vars["signaturesFeedConfig"] = map[string]any{
			"mode": mode.ValueString(),
		}
	} else {
		vars["signaturesFeedConfig"] = map[string]any{
			"mode": "blocking",
		}
	}

	return vars
}

// apiToState maps the API response into the Terraform state model.
func (r *PlanResource) apiToState(_ context.Context, data *PlanResourceModel, api planAPIModel, diags *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Hash = types.StringValue(api.Hash)
	data.Name = types.StringValue(api.Name)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.AutoUpdate = types.BoolValue(api.AutoUpdate)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}

	if api.LogLevel != "" {
		data.LogLevel = types.StringValue(api.LogLevel)
	} else {
		data.LogLevel = types.StringNull()
	}

	// Action configs — the API returns an object with id+name; we store just the ID.
	if api.ActionConfigs != nil {
		data.ActionConfigs = types.StringValue(api.ActionConfigs.ID)
	}

	// Exception sets — extract UUIDs.
	if len(api.ExceptionSets) > 0 {
		uuids := make([]string, len(api.ExceptionSets))
		for i, es := range api.ExceptionSets {
			uuids[i] = es.UUID
		}
		data.ExceptionSets = common.StringsToList(uuids)
	} else {
		data.ExceptionSets = types.ListNull(types.StringType)
	}

	// Telemetry references.
	if api.Telemetry != nil && api.Telemetry.ID != "" {
		data.Telemetry = types.StringValue(api.Telemetry.ID)
	} else {
		data.Telemetry = types.StringNull()
	}

	if api.TelemetryV2 != nil && api.TelemetryV2.ID != "" {
		data.TelemetryV2 = types.StringValue(api.TelemetryV2.ID)
	} else {
		data.TelemetryV2 = types.StringNull()
	}

	// USB control set.
	if api.USBControlSet != nil && api.USBControlSet.ID != "" {
		data.USBControlSet = types.StringValue(api.USBControlSet.ID)
	} else {
		data.USBControlSet = types.StringNull()
	}

	// Analytic sets.
	analyticSetAttrTypes := map[string]attr.Type{
		"type":         types.StringType,
		"analytic_set": types.StringType,
	}
	if len(api.AnalyticSets) > 0 {
		var setVals []attr.Value
		for _, as := range api.AnalyticSets {
			setVals = append(setVals, types.ObjectValueMust(analyticSetAttrTypes, map[string]attr.Value{
				"type":         types.StringValue(as.Type),
				"analytic_set": types.StringValue(as.AnalyticSet.UUID),
			}))
		}
		setList, d := types.ListValue(types.ObjectType{AttrTypes: analyticSetAttrTypes}, setVals)
		diags.Append(d...)
		data.AnalyticSets = setList
	} else {
		data.AnalyticSets = types.ListNull(types.ObjectType{AttrTypes: analyticSetAttrTypes})
	}

	// Comms config.
	commsAttrTypes := map[string]attr.Type{
		"fqdn":     types.StringType,
		"protocol": types.StringType,
	}
	if api.CommsConfig != nil {
		data.CommsConfig = types.ObjectValueMust(commsAttrTypes, map[string]attr.Value{
			"fqdn":     types.StringValue(api.CommsConfig.FQDN),
			"protocol": types.StringValue(api.CommsConfig.Protocol),
		})
	} else {
		data.CommsConfig = types.ObjectNull(commsAttrTypes)
	}

	// Info sync.
	infoSyncAttrTypes := map[string]attr.Type{
		"attrs":                  types.ListType{ElemType: types.StringType},
		"insights_sync_interval": types.Int64Type,
	}
	if api.InfoSync != nil {
		data.InfoSync = types.ObjectValueMust(infoSyncAttrTypes, map[string]attr.Value{
			"attrs":                  common.StringsToList(api.InfoSync.Attrs),
			"insights_sync_interval": types.Int64Value(api.InfoSync.InsightsSyncInterval),
		})
	} else {
		data.InfoSync = types.ObjectNull(infoSyncAttrTypes)
	}

	// Signatures feed config.
	sigFeedAttrTypes := map[string]attr.Type{
		"mode": types.StringType,
	}
	if api.SignaturesFeedConfig != nil {
		data.SignaturesFeedConfig = types.ObjectValueMust(sigFeedAttrTypes, map[string]attr.Value{
			"mode": types.StringValue(api.SignaturesFeedConfig.Mode),
		})
	} else {
		data.SignaturesFeedConfig = types.ObjectNull(sigFeedAttrTypes)
	}
}
