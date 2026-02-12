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
