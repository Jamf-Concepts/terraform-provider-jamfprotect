resource "jamfprotect_analytic" "example" {
  name                            = "Example Analytic"
  description                     = "Created by Terraform"
  sensor_type                     = "GPFSEvent"
  predicate                       = "( $event.type  CONTAINS[d] Thingie )"
  add_to_jamf_pro_smart_group     = true
  jamf_pro_smart_group_identifier = "my-group"
  categories                      = ["Evasion"]
  level                           = 0
  severity                        = "Medium"
  snapshot_files                  = ["/path/to/test.doc"]
  tags                            = ["Research", "T1560"]
  context_item = [
    {
      expressions = ["first", "second", "third"]
      name        = "Example Context Item"
      type        = "String"
    },
  ]
}
