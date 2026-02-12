# First create an action configuration for the plan to reference.
resource "jamfprotect_action_config" "default" {
  name        = "Default Action Config"
  description = "Default alert data enrichment settings."

  alert_config = jsonencode({
    data = {
      binary              = { attrs = ["signingInfo", "isAppBundle"], related = ["process"] }
      clickEvent          = { attrs = [], related = [] }
      downloadEvent       = { attrs = ["sourceUrl"], related = ["file", "process"] }
      file                = { attrs = ["sha256hex", "path"], related = [] }
      fsEvent             = { attrs = ["path"], related = ["process", "file"] }
      group               = { attrs = [], related = [] }
      procEvent           = { attrs = ["ppid", "uid"], related = ["process"] }
      process             = { attrs = ["name", "path", "pid"], related = ["binary", "user"] }
      screenshotEvent     = { attrs = [], related = [] }
      usbEvent            = { attrs = [], related = [] }
      user                = { attrs = ["name", "uid"], related = [] }
      gkEvent             = { attrs = [], related = [] }
      keylogRegisterEvent = { attrs = [], related = [] }
      mrtEvent            = { attrs = [], related = [] }
    }
  })
}

# Create a plan that uses the action configuration.
resource "jamfprotect_plan" "endpoint_security" {
  name           = "Endpoint Security Plan"
  description    = "Standard endpoint security plan with threat prevention."
  action_configs = jamfprotect_action_config.default.id
  auto_update    = true

  comms_config {
    fqdn     = "your-tenant.protect.jamfcloud.com"
    protocol = "MQTT"
  }

  info_sync {
    attrs                  = ["arch", "os_version", "serial_number"]
    insights_sync_interval = 86400
  }

  signatures_feed_config {
    mode = "ON"
  }
}
