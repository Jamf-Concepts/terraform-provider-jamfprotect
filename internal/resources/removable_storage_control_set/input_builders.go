// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
)

// buildInput builds the API input from the resource model.
func (r *RemovableStorageControlSetResource) buildInput(ctx context.Context, data RemovableStorageControlSetResourceModel, diags *diag.Diagnostics) *jamfprotect.RemovableStorageControlSetInput {
	input := jamfprotect.RemovableStorageControlSetInput{
		Name:               data.Name.ValueString(),
		DefaultMountAction: permissionToAPI(data.DefaultPermission.ValueString()),
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
		MountAction: permissionToAPI(permission.ValueString()),
	}
	if !message.IsNull() {
		baseRule.MessageAction = new(message.ValueString())
	}
	if !applyTo.IsNull() {
		baseRule.ApplyTo = new(applyTo.ValueString())
	}
	return baseRule
}
