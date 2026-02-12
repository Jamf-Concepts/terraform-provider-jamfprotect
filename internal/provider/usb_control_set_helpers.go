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

const usbControlSetFields = `
fragment USBControlSetFields on USBControlSet {
  id
  name
  description
  defaultMountAction
  defaultMessageAction
  rules {
    mountAction
    messageAction
    type
    ... on VendorRule {
      vendors
      applyTo
    }
    ... on SerialRule {
      serials
      applyTo
    }
    ... on ProductRule {
      products {
        vendor
        product
      }
      applyTo
    }
  }
  created
  updated
}
`

const createUSBControlSetMutation = `
mutation createUSBControlSet(
  $name: String!,
  $description: String,
  $defaultMountAction: USBCONTROL_MOUNT_ACTION_TYPE_ENUM!,
  $defaultMessageAction: String,
  $rules: [USBControlRuleInput!]!
) {
  createUSBControlSet(input: {
    name: $name,
    description: $description,
    defaultMountAction: $defaultMountAction,
    defaultMessageAction: $defaultMessageAction,
    rules: $rules
  }) {
    ...USBControlSetFields
  }
}
` + usbControlSetFields

const getUSBControlSetQuery = `
query getUSBControlSet($id: ID!) {
  getUSBControlSet(id: $id) {
    ...USBControlSetFields
  }
}
` + usbControlSetFields

const updateUSBControlSetMutation = `
mutation updateUSBControlSet(
  $id: ID!,
  $name: String!,
  $description: String,
  $defaultMountAction: USBCONTROL_MOUNT_ACTION_TYPE_ENUM!,
  $defaultMessageAction: String,
  $rules: [USBControlRuleInput!]!
) {
  updateUSBControlSet(id: $id, input: {
    name: $name,
    description: $description,
    defaultMountAction: $defaultMountAction,
    defaultMessageAction: $defaultMessageAction,
    rules: $rules
  }) {
    ...USBControlSetFields
  }
}
` + usbControlSetFields

const deleteUSBControlSetMutation = `
mutation deleteUSBControlSet($id: ID!) {
  deleteUSBControlSet(id: $id) {
    id
  }
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *USBControlSetResource) buildVariables(ctx context.Context, data USBControlSetResourceModel, diags *diag.Diagnostics) map[string]any {
	vars := map[string]any{
		"name":               data.Name.ValueString(),
		"defaultMountAction": data.DefaultMountAction.ValueString(),
	}

	if !data.Description.IsNull() {
		vars["description"] = data.Description.ValueString()
	} else {
		vars["description"] = ""
	}

	if !data.DefaultMessageAction.IsNull() {
		vars["defaultMessageAction"] = data.DefaultMessageAction.ValueString()
	} else {
		vars["defaultMessageAction"] = ""
	}

	rules := make([]map[string]any, 0, len(data.Rules))
	for _, rule := range data.Rules {
		r := buildRuleVariable(ctx, rule, diags)
		if diags.HasError() {
			return nil
		}
		rules = append(rules, r)
	}
	vars["rules"] = rules
	return vars
}

func buildRuleVariable(ctx context.Context, rule USBRuleModel, diags *diag.Diagnostics) map[string]any {
	r := map[string]any{
		"type":        rule.Type.ValueString(),
		"mountAction": rule.MountAction.ValueString(),
	}

	if !rule.MessageAction.IsNull() {
		r["messageAction"] = rule.MessageAction.ValueString()
	}

	if !rule.ApplyTo.IsNull() {
		r["applyTo"] = rule.ApplyTo.ValueString()
	}

	switch rule.Type.ValueString() {
	case "VendorRule":
		r["vendors"] = listToStrings(ctx, rule.Vendors, diags)
	case "SerialRule":
		r["serials"] = listToStrings(ctx, rule.Serials, diags)
	case "ProductRule":
		products := make([]map[string]any, 0, len(rule.Products))
		for _, p := range rule.Products {
			products = append(products, map[string]any{
				"vendor":  p.Vendor.ValueString(),
				"product": p.Product.ValueString(),
			})
		}
		r["products"] = products
	}

	return r
}

func (r *USBControlSetResource) apiToState(_ context.Context, data *USBControlSetResourceModel, api usbControlSetAPIModel, _ *diag.Diagnostics) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.DefaultMountAction = types.StringValue(api.DefaultMountAction)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}

	if api.DefaultMessageAction != "" {
		data.DefaultMessageAction = types.StringValue(api.DefaultMessageAction)
	} else {
		data.DefaultMessageAction = types.StringNull()
	}

	rules := make([]USBRuleModel, 0, len(api.Rules))
	for _, apiRule := range api.Rules {
		rule := USBRuleModel{
			Type:        types.StringValue(apiRule.Type),
			MountAction: types.StringValue(apiRule.MountAction),
		}

		if apiRule.MessageAction != "" {
			rule.MessageAction = types.StringValue(apiRule.MessageAction)
		} else {
			rule.MessageAction = types.StringNull()
		}

		if apiRule.ApplyTo != "" {
			rule.ApplyTo = types.StringValue(apiRule.ApplyTo)
		} else {
			rule.ApplyTo = types.StringNull()
		}

		switch apiRule.Type {
		case "VendorRule":
			rule.Vendors = stringsToList(apiRule.Vendors)
			rule.Serials = types.ListNull(types.StringType)
		case "SerialRule":
			rule.Serials = stringsToList(apiRule.Serials)
			rule.Vendors = types.ListNull(types.StringType)
		case "ProductRule":
			products := make([]USBProductModel, 0, len(apiRule.Products))
			for _, p := range apiRule.Products {
				products = append(products, USBProductModel{
					Vendor:  types.StringValue(p.Vendor),
					Product: types.StringValue(p.Product),
				})
			}
			rule.Products = products
			rule.Vendors = types.ListNull(types.StringType)
			rule.Serials = types.ListNull(types.StringType)
		default:
			rule.Vendors = types.ListNull(types.StringType)
			rule.Serials = types.ListNull(types.StringType)
		}

		rules = append(rules, rule)
	}
	data.Rules = rules
}
