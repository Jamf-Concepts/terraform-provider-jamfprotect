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
		DefaultMountAction: data.DefaultPermission.ValueString(),
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	if !data.DefaultLocalNotificationMessage.IsNull() {
		input.DefaultMessageAction = data.DefaultLocalNotificationMessage.ValueString()
	} else {
		input.DefaultMessageAction = ""
	}

	rules := make([]jamfprotect.RemovableStorageControlRuleInput, 0)

	for _, override := range data.OverrideEncryptedDevices {
		rules = append(rules, buildEncryptedOverrideRule(override))
	}

	for _, override := range data.OverrideVendorID {
		rule, ok := buildVendorOverrideRule(ctx, override, diags)
		if !ok {
			return nil
		}
		rules = append(rules, rule)
	}

	for _, override := range data.OverrideSerialNumber {
		rule, ok := buildSerialOverrideRule(ctx, override, diags)
		if !ok {
			return nil
		}
		rules = append(rules, rule)
	}

	for _, override := range data.OverrideProductID {
		rules = append(rules, buildProductOverrideRule(override))
	}

	input.Rules = rules
	return &input
}

func buildEncryptedOverrideRule(override RemovableStorageEncryptedOverrideModel) jamfprotect.RemovableStorageControlRuleInput {
	baseRule := buildRuleDetails(override.Permission, override.LocalNotificationMessage, types.StringNull())
	return jamfprotect.RemovableStorageControlRuleInput{
		Type:           "Encryption",
		EncryptionRule: &baseRule,
	}
}

func buildVendorOverrideRule(ctx context.Context, override RemovableStorageVendorOverrideModel, diags *diag.Diagnostics) (jamfprotect.RemovableStorageControlRuleInput, bool) {
	baseRule := buildRuleDetails(override.Permission, override.LocalNotificationMessage, override.ApplyTo)
	baseRule.Vendors = common.ListToStrings(ctx, override.VendorIDs, diags)
	if diags.HasError() {
		return jamfprotect.RemovableStorageControlRuleInput{}, false
	}
	return jamfprotect.RemovableStorageControlRuleInput{
		Type:       "Vendor",
		VendorRule: &baseRule,
	}, true
}

func buildSerialOverrideRule(ctx context.Context, override RemovableStorageSerialOverrideModel, diags *diag.Diagnostics) (jamfprotect.RemovableStorageControlRuleInput, bool) {
	baseRule := buildRuleDetails(override.Permission, override.LocalNotificationMessage, override.ApplyTo)
	baseRule.Serials = common.ListToStrings(ctx, override.SerialNumbers, diags)
	if diags.HasError() {
		return jamfprotect.RemovableStorageControlRuleInput{}, false
	}
	return jamfprotect.RemovableStorageControlRuleInput{
		Type:       "Serial",
		SerialRule: &baseRule,
	}, true
}

func buildProductOverrideRule(override RemovableStorageProductOverrideModel) jamfprotect.RemovableStorageControlRuleInput {
	baseRule := buildRuleDetails(override.Permission, override.LocalNotificationMessage, override.ApplyTo)
	products := make([]jamfprotect.RemovableStorageControlProductPair, 0, len(override.ProductIDs))
	for _, product := range override.ProductIDs {
		products = append(products, jamfprotect.RemovableStorageControlProductPair{
			Vendor:  product.VendorID.ValueString(),
			Product: product.ProductID.ValueString(),
		})
	}
	productRule := jamfprotect.RemovableStorageControlProductRuleDetails{
		MountAction:   baseRule.MountAction,
		MessageAction: baseRule.MessageAction,
		ApplyTo:       baseRule.ApplyTo,
		Products:      products,
	}
	return jamfprotect.RemovableStorageControlRuleInput{
		Type:        "Product",
		ProductRule: &productRule,
	}
}

func buildRuleDetails(permission types.String, message types.String, applyTo types.String) jamfprotect.RemovableStorageControlRuleDetails {
	baseRule := jamfprotect.RemovableStorageControlRuleDetails{
		MountAction: permission.ValueString(),
	}
	if !message.IsNull() {
		value := message.ValueString()
		baseRule.MessageAction = &value
	}
	if !applyTo.IsNull() {
		value := applyTo.ValueString()
		baseRule.ApplyTo = &value
	}
	return baseRule
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
	data.DefaultPermission = types.StringValue(api.DefaultMountAction)
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)

	if api.Description != "" {
		data.Description = types.StringValue(api.Description)
	} else {
		data.Description = types.StringNull()
	}

	if api.DefaultMessageAction != "" {
		data.DefaultLocalNotificationMessage = types.StringValue(api.DefaultMessageAction)
	} else {
		data.DefaultLocalNotificationMessage = types.StringNull()
	}

	encryptedOverrides := make([]RemovableStorageEncryptedOverrideModel, 0)
	vendorOverrides := make([]RemovableStorageVendorOverrideModel, 0)
	serialOverrides := make([]RemovableStorageSerialOverrideModel, 0)
	productOverrides := make([]RemovableStorageProductOverrideModel, 0)

	for _, apiRule := range api.Rules {
		ruleType := normalizeRemovableStorageRuleType(apiRule.Type)
		localMessage := types.StringNull()
		if apiRule.MessageAction != "" {
			localMessage = types.StringValue(apiRule.MessageAction)
		}
		applyTo := types.StringNull()
		if apiRule.ApplyTo != "" {
			applyTo = types.StringValue(apiRule.ApplyTo)
		}

		switch ruleType {
		case "Encryption":
			encryptedOverrides = append(encryptedOverrides, RemovableStorageEncryptedOverrideModel{
				Permission:               types.StringValue(apiRule.MountAction),
				LocalNotificationMessage: localMessage,
			})
		case "Vendor":
			vendorOverrides = append(vendorOverrides, RemovableStorageVendorOverrideModel{
				Permission:               types.StringValue(apiRule.MountAction),
				LocalNotificationMessage: localMessage,
				ApplyTo:                  applyTo,
				VendorIDs:                common.StringsToList(apiRule.Vendors),
			})
		case "Serial":
			serialOverrides = append(serialOverrides, RemovableStorageSerialOverrideModel{
				Permission:               types.StringValue(apiRule.MountAction),
				LocalNotificationMessage: localMessage,
				ApplyTo:                  applyTo,
				SerialNumbers:            common.StringsToList(apiRule.Serials),
			})
		case "Product":
			products := make([]RemovableStorageProductIDModel, 0, len(apiRule.Products))
			for _, p := range apiRule.Products {
				products = append(products, RemovableStorageProductIDModel{
					VendorID:  types.StringValue(p.Vendor),
					ProductID: types.StringValue(p.Product),
				})
			}
			productOverrides = append(productOverrides, RemovableStorageProductOverrideModel{
				Permission:               types.StringValue(apiRule.MountAction),
				LocalNotificationMessage: localMessage,
				ApplyTo:                  applyTo,
				ProductIDs:               products,
			})
		}
	}

	data.OverrideEncryptedDevices = encryptedOverrides
	data.OverrideVendorID = vendorOverrides
	data.OverrideSerialNumber = serialOverrides
	data.OverrideProductID = productOverrides
}
