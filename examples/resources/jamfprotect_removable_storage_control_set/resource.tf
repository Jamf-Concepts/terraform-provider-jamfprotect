resource "jamfprotect_removable_storage_control_set" "example" {
  default_local_notification_message = "This removable storage device is not allowed.."
  default_permission                 = "Prevented"
  description                        = "Managed by Terraform"
  name                               = "Example"
  timeouts                           = null
  override_encrypted_devices {
    local_notification_message = "This removable storage device is limited to read-only."
    permission                 = "ReadOnly"
  }
  override_product_id {
    apply_to                   = "All"
    local_notification_message = "This removable storage device is limited to read-only."
    permission                 = "ReadOnly"
    product_id = [
      {
        product_id = "0x1434"
        vendor_id  = "0x1921"
      },
    ]
  }
  override_serial_number {
    apply_to                   = "All"
    local_notification_message = "This removable storage device is limited to read-only."
    permission                 = "ReadOnly"
    serial_numbers             = ["EXAMPLE"]
  }
  override_vendor_id {
    apply_to                   = "All"
    local_notification_message = "This removable storage device is limited to read-only."
    permission                 = "ReadOnly"
    vendor_ids                 = ["0x1921", "0x1434"]
  }
}
