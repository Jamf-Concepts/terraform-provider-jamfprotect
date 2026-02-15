// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"context"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (r *RemovableStorageControlSetResource) buildInput(ctx context.Context, data RemovableStorageControlSetResourceModel, diags *diag.Diagnostics) *jamfprotect.RemovableStorageControlSetInput {
	input := jamfprotect.RemovableStorageControlSetInput{
		Name:               data.Name.ValueString(),
		DefaultMountAction: data.DefaultMountAction.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	if !data.DefaultMessageAction.IsNull() {
		input.DefaultMessageAction = data.DefaultMessageAction.ValueString()
	} else {
		input.DefaultMessageAction = ""
	}

	rules := make([]jamfprotect.RemovableStorageControlRuleInput, 0, len(data.Rules))
	for _, rule := range data.Rules {
		ruleInput := buildRuleInput(ctx, rule, diags)
		if diags.HasError() {
			return nil
		}
		rules = append(rules, ruleInput)
	}
	input.Rules = rules
	return &input
}

func buildRuleInput(ctx context.Context, rule RemovableStorageRuleModel, diags *diag.Diagnostics) jamfprotect.RemovableStorageControlRuleInput {
	ruleType := normalizeRemovableStorageRuleType(rule.Type.ValueString())
	input := jamfprotect.RemovableStorageControlRuleInput{Type: ruleType}

	baseRule := jamfprotect.RemovableStorageControlRuleDetails{
		MountAction: rule.MountAction.ValueString(),
	}
	if !rule.MessageAction.IsNull() {
		value := rule.MessageAction.ValueString()
		baseRule.MessageAction = &value
	}
	if !rule.ApplyTo.IsNull() {
		value := rule.ApplyTo.ValueString()
		baseRule.ApplyTo = &value
	}

	switch ruleType {
	case "Vendor":
		baseRule.Vendors = common.ListToStrings(ctx, rule.Vendors, diags)
		input.VendorRule = &baseRule
	case "Serial":
		baseRule.Serials = common.ListToStrings(ctx, rule.Serials, diags)
		input.SerialRule = &baseRule
	case "Product":
		products := make([]jamfprotect.RemovableStorageControlProductPair, 0, len(rule.Products))
		for _, p := range rule.Products {
			products = append(products, jamfprotect.RemovableStorageControlProductPair{
				Vendor:  p.Vendor.ValueString(),
				Product: p.Product.ValueString(),
			})
		}
		productRule := jamfprotect.RemovableStorageControlProductRuleDetails{
			MountAction:   baseRule.MountAction,
			MessageAction: baseRule.MessageAction,
			ApplyTo:       baseRule.ApplyTo,
			Products:      products,
		}
		input.ProductRule = &productRule
	case "Encryption":
		input.EncryptionRule = &baseRule
	default:
		diags.AddError("Unsupported removable storage control rule type", "Unsupported rule type: "+rule.Type.ValueString())
		return jamfprotect.RemovableStorageControlRuleInput{}
	}

	return input
}

func normalizeRemovableStorageRuleType(ruleType string) string {
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

func (r *RemovableStorageControlSetResource) apiToState(_ context.Context, data *RemovableStorageControlSetResourceModel, api jamfprotect.RemovableStorageControlSet, _ *diag.Diagnostics) {
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

	rules := make([]RemovableStorageRuleModel, 0, len(api.Rules))
	for _, apiRule := range api.Rules {
		ruleType := normalizeRemovableStorageRuleType(apiRule.Type)
		rule := RemovableStorageRuleModel{
			Type:        types.StringValue(ruleType),
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

		switch ruleType {
		case "Vendor":
			rule.Vendors = common.StringsToList(apiRule.Vendors)
			rule.Serials = types.ListNull(types.StringType)
			rule.Products = nil
		case "Serial":
			rule.Serials = common.StringsToList(apiRule.Serials)
			rule.Vendors = types.ListNull(types.StringType)
			rule.Products = nil
		case "Product":
			products := make([]RemovableStorageProductModel, 0, len(apiRule.Products))
			for _, p := range apiRule.Products {
				products = append(products, RemovableStorageProductModel{
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
			rule.Products = nil
		}

		rules = append(rules, rule)
	}
	data.Rules = rules
}
