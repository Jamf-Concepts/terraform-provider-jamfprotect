# A basic USB control set that restricts removable storage to read-only.
resource "jamfprotect_usb_control_set" "default" {
  name                   = "Default USB Policy"
  description            = "Restrict removable storage to read-only by default."
  default_mount_action   = "ReadOnly"
  default_message_action = "This removable storage device is limited to read-only."
  rules                  = []
}

# A USB control set with vendor and serial rules.
resource "jamfprotect_usb_control_set" "with_rules" {
  name                   = "USB Policy with Rules"
  description            = "Allow specific vendors and serials, block everything else."
  default_mount_action   = "Prevented"
  default_message_action = "USB devices are not allowed."

  rules = [
    {
      type         = "VendorRule"
      mount_action = "ReadWrite"
      apply_to     = "All"
      vendors      = ["05ac", "1234"]
    },
    {
      type         = "SerialRule"
      mount_action = "ReadWrite"
      apply_to     = "All"
      serials      = ["ABC123", "DEF456"]
    },
    {
      type         = "ProductRule"
      mount_action = "ReadOnly"
      apply_to     = "All"
      products = [
        {
          vendor  = "05ac"
          product = "1234"
        }
      ]
    }
  ]
}
