# First create an action configuration for the plan to reference.
resource "jamfprotect_action_config" "default" {
  name        = "Default Action Config"
  description = "Default alert data enrichment settings."

  alert_config = {
    data = {
      binary                = { attrs = ["signingInfo", "isAppBundle"], related = ["process"] }
      click_event           = { attrs = [], related = [] }
      download_event        = { attrs = ["sourceUrl"], related = ["file", "process"] }
      file                  = { attrs = ["sha256hex", "path"], related = [] }
      fs_event              = { attrs = ["path"], related = ["process", "file"] }
      group                 = { attrs = [], related = [] }
      proc_event            = { attrs = ["ppid", "uid"], related = ["process"] }
      process               = { attrs = ["name", "path", "pid"], related = ["binary", "user"] }
      screenshot_event      = { attrs = [], related = [] }
      usb_event             = { attrs = [], related = [] }
      user                  = { attrs = ["name", "uid"], related = [] }
      gk_event              = { attrs = [], related = [] }
      keylog_register_event = { attrs = [], related = [] }
      mrt_event             = { attrs = [], related = [] }
    }
  }
}

# Create a plan that uses the action configuration.
resource "jamfprotect_plan" "endpoint_security" {
  name           = "Endpoint Security Plan"
  description    = "Standard endpoint security plan with threat prevention."
  action_configs = jamfprotect_action_config.default.id
  auto_update    = true

  comms_config = {
    fqdn     = "your-tenant.protect.jamfcloud.com"
    protocol = "mqtt"
  }

  info_sync = {
    attrs                  = ["arch", "hostName", "serial"]
    insights_sync_interval = 86400
  }

  signatures_feed_config = {
    mode = "blocking"
  }
}
