# Example: Removable Storage Control with Serial Number Whitelist
# This example uses serial numbers to maintain a whitelist of specific devices
# that are allowed, useful for managing corporate-issued USB devices.

resource "jamfprotect_removable_storage_control_set" "serial_whitelist" {
  name        = "Corporate USB Whitelist"
  description = "Allow only corporate-issued USB devices by serial number"

  # Default: prevent all devices
  default_permission                 = "Prevented"
  default_local_notification_message = "Only corporate-issued USB devices are allowed."

  # Override for specific serial numbers (corporate devices)
  override_serial_number {
    apply_to                   = "All"
    permission                 = "Allow"
    local_notification_message = "Corporate USB device detected and allowed."

    serial_numbers = [
      "ABC123456789",
      "DEF987654321",
      "GHI456123789",
    ]
  }

  # Allow all devices from specific vendor (e.g., corporate-approved vendor)
  override_vendor_id {
    apply_to                   = "All"
    permission                 = "ReadOnly"
    local_notification_message = "Approved vendor device detected - read-only access granted."

    vendor_ids = [
      "0x0781", # SanDisk
      "0x13fe", # Kingston
    ]
  }

  # Encrypted devices get read-only access
  override_encrypted_devices {
    permission                 = "ReadOnly"
    local_notification_message = "Encrypted device detected - read-only access granted."
  }
}
