resource "jamfprotect_removable_storage_control_set" "example" {
  default_local_notification_message = "This removable storage device is not allowed."
  default_permission                 = "Prevent"
  description                        = "Managed by Terraform"
  name                               = "Example"
  timeouts                           = null
  override_encrypted_devices = [
    {
      local_notification_message = "This removable storage device is limited to read-only."
      permission                 = "Read Only"
    }
  ]
  override_product_id = [
    {
      apply_to                   = "All"
      local_notification_message = "This removable storage device is limited to read-only."
      permission                 = "Read Only"
      product_id = [
        {
          product_id = "0x1434"
          vendor_id  = "0x1921"
        },
      ]
    }
  ]
  override_serial_number = [
    {
      apply_to                   = "All"
      local_notification_message = "This removable storage device is limited to read-only."
      permission                 = "Read Only"
      serial_numbers             = ["EXAMPLE"]
    }
  ]
  override_vendor_id = [
    {
      apply_to                   = "All"
      local_notification_message = "This removable storage device is limited to read-only."
      permission                 = "Read Only"
      vendor_ids                 = ["0x1921", "0x1434"]
    }
  ]
}
