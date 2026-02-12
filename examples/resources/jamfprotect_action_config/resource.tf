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
