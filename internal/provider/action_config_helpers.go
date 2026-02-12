// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// GraphQL queries — stripped of @skip/@include RBAC directives.
// The alertConfig response is complex with many nested types; we request it
// in full and expose it as a JSON string for maximum flexibility.
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *ActionConfigResource) buildVariables(data ActionConfigResourceModel) (map[string]any, error) {
	vars := map[string]any{
		"name": data.Name.ValueString(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	// Parse the alert_config JSON string into a map for the GraphQL variables.
	var alertConfig any
	if err := json.Unmarshal([]byte(data.AlertConfig.ValueString()), &alertConfig); err != nil {
		return nil, fmt.Errorf("alert_config must be valid JSON: %w", err)
	}
	vars["alertConfig"] = alertConfig

	return vars, nil
}

func (r *ActionConfigResource) apiToState(data *ActionConfigResourceModel, api actionConfigAPIModel) {
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

	// Store the alert config as a JSON string.
	if api.AlertConfig != nil {
		data.AlertConfig = types.StringValue(string(api.AlertConfig))
	}
}
