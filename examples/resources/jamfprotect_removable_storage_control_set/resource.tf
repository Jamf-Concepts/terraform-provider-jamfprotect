# Example: Removable Storage Control with Serial Number Allow List
# This example uses serial numbers to maintain an allow list of specific devices
# that are allowed, useful for managing corporate-issued USB devices.

resource "jamfprotect_removable_storage_control_set" "serial_allow_list" {
  name        = "Corporate USB Allow List"
  description = "Allow only corporate-issued USB devices by serial number"

  # Default: prevent all devices
  default_permission                 = "Prevent"
  default_local_notification_message = "Only corporate-issued USB devices are allowed."

  # Override for specific serial numbers (corporate devices)
  override_serial_number = [
    {
      apply_to                   = "All"
      permission                 = "Read and Write"
      local_notification_message = "Corporate USB device detected and allowed."

      serial_numbers = [
        "ABC123456789",
        "DEF987654321",
        "GHI456123789",
      ]
    }
  ]

  # Allow all devices from specific vendor (e.g., corporate-approved vendor)
  override_vendor_id = [
    {
      apply_to                   = "All"
      permission                 = "Read Only"
      local_notification_message = "Approved vendor device detected - read-only access granted."

      vendor_ids = [
        "0x0781", # SanDisk
        "0x13fe", # Kingston
      ]
    }
  ]

  # Encrypted devices get read-only access
  override_encrypted_devices = [
    {
      permission                 = "Read Only"
      local_notification_message = "Encrypted device detected - read-only access granted."
    }
  ]
}

# Example: Removable Storage Control with Product ID Override
# This example demonstrates USB device control with specific product ID overrides,
# allowing certain approved USB devices while blocking others.

resource "jamfprotect_removable_storage_control_set" "selective_usb_control" {
  name        = "Selective USB Device Control"
  description = "Block most USB devices, allow specific approved devices"

  # Default: prevent all removable storage
  default_permission                 = "Prevent"
  default_local_notification_message = "USB storage devices are not allowed on this system."

  # Allow specific approved USB devices by product ID
  override_product_id = [
    {
      apply_to                   = "All"
      permission                 = "Read and Write"
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
  ]

  # Allow encrypted devices (assuming they meet company encryption standards)
  override_encrypted_devices = [
    {
      permission                 = "Read and Write"
      local_notification_message = "Encrypted USB device allowed."
    }
  ]
}
