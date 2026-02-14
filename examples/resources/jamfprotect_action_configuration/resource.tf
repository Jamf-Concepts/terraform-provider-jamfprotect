resource "jamfprotect_action_configuration" "example" {
  name        = "Example Action Configuration"
  description = "This is an example action configuration created by Terraform."
  data_collection = {
    data = {
      binary = {
        attrs   = ["sha1hex", "sha256hex", "xattrs", "isAppBundle", "isScreenShot", "isQuarantined", "isDownload", "isDirectory", "downloadedFrom", "signingInfo"]
        related = ["user", "group"]
      }
      download_event = {
        attrs   = []
        related = ["file"]
      }
      file = {
        attrs   = ["sha1hex", "sha256hex", "xattrs", "isAppBundle", "isScreenShot", "isQuarantined", "isDownload", "isDirectory", "downloadedFrom", "signingInfo"]
        related = ["user", "group"]
      }
      file_system_event = {
        attrs   = []
        related = ["file", "process", "user", "group"]
      }
      gatekeeper_event = {
        attrs   = []
        related = ["process", "binary"]
      }
      group = {
        attrs   = ["name"]
        related = []
      }
      keylog_register_event = {
        attrs   = []
        related = ["process", "process"]
      }
      malware_removal_tool_event = {
        attrs   = []
        related = []
      }
      process = {
        attrs   = ["args", "guiAPP", "signingInfo", "appPath"]
        related = ["binary", "user", "group", "process", "process"]
      }
      process_event = {
        attrs   = []
        related = ["process"]
      }
      screenshot_event = {
        attrs   = []
        related = ["file"]
      }
      synthetic_click_event = {
        attrs   = []
        related = ["process", "user", "group"]
      }
      usb_event = {
        attrs   = []
        related = []
      }
      user = {
        attrs   = ["name"]
        related = []
      }
    }
  }
  endpoint_http = {
    batch_delimiter      = "\n"
    batch_size_in_bytes  = 1100
    batch_size_index     = 2
    batch_window_seconds = 1
    enabled              = true
    headers = [
      {
        header = "Content-Type"
        value  = "application/json"
      },
    ]
    method            = "POST"
    supported_reports = ["AlertMedium"]
    url               = "https://example.com"
  }
  endpoint_jamf_cloud = {
    batch_size_index     = 1
    batch_window_seconds = 0
    destination_filter   = null
    enabled              = true
    supported_reports    = ["AlertInformational", "AlertLow", "AlertMedium", "AlertHigh", "Telemetry", "UnifiedLogging"]
  }
  endpoint_kafka = {
    batch_size_index     = 1
    batch_window_seconds = 0
    client_cn            = "EXAMPLE_CLIENT"
    enabled              = true
    host                 = "example.com"
    port                 = 9093
    server_cn            = "EXAMPLE_SERVER"
    supported_reports    = ["Telemetry"]
    topic                = "EXAMPLE"
  }
  endpoint_log_file = {
    backups              = 10
    batch_size_index     = 1
    batch_window_seconds = 0
    enabled              = true
    max_size_mb          = 50
    ownership            = "root:wheel"
    path                 = "/var/log/JamfProtect.log"
    permissions          = "0640"
    supported_reports    = ["AlertHigh", "AlertMedium", "AlertLow", "AlertInformational", "Telemetry", "UnifiedLogging"]
  }
  endpoint_syslog = {

    batch_size_index     = 1
    batch_window_seconds = 0
    enabled              = true
    host                 = "example.com"
    port                 = 6514
    scheme               = "tls"
    supported_reports    = ["AlertHigh"]
  }
}
