// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"context"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/common"

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

const listUSBControlSetsQuery = `
query listUSBControlSets($nextToken: String, $direction: OrderDirection!, $field: USBControlOrderField!) {
  listUSBControlSets(
    input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
  ) {
    items {
      ...USBControlSetFields
    }
    pageInfo {
      next
      total
    }
  }
}
` + usbControlSetFields

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
	ruleType := normalizeUSBRuleType(rule.Type.ValueString())
	r := map[string]any{
		"type": ruleType,
	}

	baseRule := map[string]any{
		"mountAction": rule.MountAction.ValueString(),
	}
	if !rule.MessageAction.IsNull() {
		baseRule["messageAction"] = rule.MessageAction.ValueString()
	}

	switch ruleType {
	case "Vendor":
		if !rule.ApplyTo.IsNull() {
			baseRule["applyTo"] = rule.ApplyTo.ValueString()
		}
		baseRule["vendors"] = common.ListToStrings(ctx, rule.Vendors, diags)
		r["vendorRule"] = baseRule
	case "Serial":
		if !rule.ApplyTo.IsNull() {
			baseRule["applyTo"] = rule.ApplyTo.ValueString()
		}
		baseRule["serials"] = common.ListToStrings(ctx, rule.Serials, diags)
		r["serialRule"] = baseRule
	case "Product":
		if !rule.ApplyTo.IsNull() {
			baseRule["applyTo"] = rule.ApplyTo.ValueString()
		}
		products := make([]map[string]any, 0, len(rule.Products))
		for _, p := range rule.Products {
			products = append(products, map[string]any{
				"vendor":  p.Vendor.ValueString(),
				"product": p.Product.ValueString(),
			})
		}
		baseRule["products"] = products
		r["productRule"] = baseRule
	case "Encryption":
		r["encryptionRule"] = baseRule
	default:
		diags.AddError("Unsupported USB control rule type", "Unsupported rule type: "+rule.Type.ValueString())
		return nil
	}

	return r
}

func normalizeUSBRuleType(ruleType string) string {
	switch ruleType {
	case "VendorRule":
		return "Vendor"
	case "SerialRule":
		return "Serial"
	case "ProductRule":
		return "Product"
	case "EncryptionRule":
		return "Encryption"
	default:
		return ruleType
	}
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
			Type:        types.StringValue(normalizeUSBRuleType(apiRule.Type)),
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

		switch normalizeUSBRuleType(apiRule.Type) {
		case "Vendor":
			rule.Vendors = common.StringsToList(apiRule.Vendors)
			rule.Serials = types.ListNull(types.StringType)
		case "Serial":
			rule.Serials = common.StringsToList(apiRule.Serials)
			rule.Vendors = types.ListNull(types.StringType)
		case "Product":
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
