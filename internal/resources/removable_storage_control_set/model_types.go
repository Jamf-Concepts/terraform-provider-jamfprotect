package removable_storage_control_set

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// RemovableStorageControlSetResourceModel maps the resource schema data.
type RemovableStorageControlSetResourceModel struct {
	ID                              types.String                             `tfsdk:"id"`
	Name                            types.String                             `tfsdk:"name"`
	Description                     types.String                             `tfsdk:"description"`
	DefaultPermission               types.String                             `tfsdk:"default_permission"`
	DefaultLocalNotificationMessage types.String                             `tfsdk:"default_local_notification_message"`
	OverrideEncryptedDevices        []RemovableStorageEncryptedOverrideModel `tfsdk:"override_encrypted_devices"`
	OverrideVendorID                []RemovableStorageVendorOverrideModel    `tfsdk:"override_vendor_id"`
	OverrideProductID               []RemovableStorageProductOverrideModel   `tfsdk:"override_product_id"`
	OverrideSerialNumber            []RemovableStorageSerialOverrideModel    `tfsdk:"override_serial_number"`
	Created                         types.String                             `tfsdk:"created"`
	Updated                         types.String                             `tfsdk:"updated"`
	Timeouts                        timeouts.Value                           `tfsdk:"timeouts"`
}

// RemovableStorageEncryptedOverrideModel represents overrides for encrypted devices.
type RemovableStorageEncryptedOverrideModel struct {
	Permission               types.String `tfsdk:"permission"`
	LocalNotificationMessage types.String `tfsdk:"local_notification_message"`
}

// RemovableStorageVendorOverrideModel represents overrides for vendor IDs.
type RemovableStorageVendorOverrideModel struct {
	Permission               types.String `tfsdk:"permission"`
	LocalNotificationMessage types.String `tfsdk:"local_notification_message"`
	ApplyTo                  types.String `tfsdk:"apply_to"`
	VendorIDs                types.List   `tfsdk:"vendor_ids"`
}

// RemovableStorageSerialOverrideModel represents overrides for serial numbers.
type RemovableStorageSerialOverrideModel struct {
	Permission               types.String `tfsdk:"permission"`
	LocalNotificationMessage types.String `tfsdk:"local_notification_message"`
	ApplyTo                  types.String `tfsdk:"apply_to"`
	SerialNumbers            types.List   `tfsdk:"serial_numbers"`
}

// RemovableStorageProductOverrideModel represents overrides for product IDs.
type RemovableStorageProductOverrideModel struct {
	Permission               types.String                     `tfsdk:"permission"`
	LocalNotificationMessage types.String                     `tfsdk:"local_notification_message"`
	ApplyTo                  types.String                     `tfsdk:"apply_to"`
	ProductIDs               []RemovableStorageProductIDModel `tfsdk:"product_id"`
}

// RemovableStorageProductIDModel represents a vendor+product pair.
type RemovableStorageProductIDModel struct {
	VendorID  types.String `tfsdk:"vendor_id"`
	ProductID types.String `tfsdk:"product_id"`
}
