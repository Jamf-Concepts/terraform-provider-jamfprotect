# Example: Removable Storage Control with Product ID Override
# This example demonstrates USB device control with specific product ID overrides,
# allowing certain approved USB devices while blocking others.

resource "jamfprotect_removable_storage_control_set" "selective_usb_control" {
  name        = "Selective USB Device Control"
  description = "Block most USB devices, allow specific approved devices"

  # Default: prevent all removable storage
  default_permission                 = "Prevented"
  default_local_notification_message = "USB storage devices are not allowed on this system."

  # Allow specific approved USB devices by product ID
  override_product_id {
    apply_to                   = "All"
    permission                 = "Allow"
    local_notification_message = "Approved USB device detected."

    product_id = [
      {
        vendor_id  = "0x0781" # SanDisk
        product_id = "0x5567" # SanDisk Cruzer Blade
      },
      {
        vendor_id  = "0x0930" # Toshiba
        product_id = "0x6544" # Toshiba TransMemory
      },
    ]
  }

  # Allow encrypted devices (assuming they meet company encryption standards)
  override_encrypted_devices {
    permission                 = "Allow"
    local_notification_message = "Encrypted USB device allowed."
  }
}
