// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package removable_storage_control_set

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	common "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// apiToState maps the API response into the resource state.
func (r *RemovableStorageControlSetResource) apiToState(_ context.Context, data *RemovableStorageControlSetResourceModel, api jamfprotect.RemovableStorageControlSet) {
	data.ID = types.StringValue(api.ID)
	data.Name = types.StringValue(api.Name)
	data.DefaultPermission = types.StringValue(permissionFromAPI(api.DefaultMountAction))
	data.Created = types.StringValue(api.Created)
	data.Updated = types.StringValue(api.Updated)
	data.Description = types.StringValue(api.Description)
	data.DefaultLocalNotificationMessage = types.StringValue(api.DefaultMessageAction)

	encryptedOverrides := make([]RemovableStorageEncryptedOverrideModel, 0)
	vendorOverrides := make([]RemovableStorageVendorOverrideModel, 0)
	serialOverrides := make([]RemovableStorageSerialOverrideModel, 0)
	productOverrides := make([]RemovableStorageProductOverrideModel, 0)

	for _, apiRule := range api.Rules {
		ruleType := normalizeRemovableStorageRuleType(apiRule.Type)
		localMessage := types.StringValue(apiRule.MessageAction)
		applyTo := types.StringValue(apiRule.ApplyTo)

		permission := types.StringValue(permissionFromAPI(apiRule.MountAction))

		switch ruleType {
		case "Encryption":
			encryptedOverrides = append(encryptedOverrides, RemovableStorageEncryptedOverrideModel{
				Permission:               permission,
				LocalNotificationMessage: localMessage,
			})
		case "Vendor":
			vendorOverrides = append(vendorOverrides, RemovableStorageVendorOverrideModel{
				Permission:               permission,
				LocalNotificationMessage: localMessage,
				ApplyTo:                  applyTo,
				VendorIDs:                common.StringsToList(apiRule.Vendors),
			})
		case "Serial":
			serialOverrides = append(serialOverrides, RemovableStorageSerialOverrideModel{
				Permission:               permission,
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
				Permission:               permission,
				LocalNotificationMessage: localMessage,
				ApplyTo:                  applyTo,
				ProductIDs:               products,
			})
		}
	}

	if len(encryptedOverrides) > 0 || data.OverrideEncryptedDevices != nil {
		data.OverrideEncryptedDevices = encryptedOverrides
	}
	if len(vendorOverrides) > 0 || data.OverrideVendorID != nil {
		data.OverrideVendorID = vendorOverrides
	}
	if len(serialOverrides) > 0 || data.OverrideSerialNumber != nil {
		data.OverrideSerialNumber = serialOverrides
	}
	if len(productOverrides) > 0 || data.OverrideProductID != nil {
		data.OverrideProductID = productOverrides
	}
}
