resource "jamfprotect_action_configuration" "example" {
  name        = "Example Action Configuration 222"
  description = "This is an example action configuration created by Terraform."
  alert_data_collection = {
    event_types = {
      binary = {
        extended_data_attributes = ["Sha1", "Sha256", "Extended Attributes", "Is App Bundle", "Is Screenshot", "Is Quarantined", "Is Download", "Is Directory", "Downloaded From", "Signing Information", "User", "Group"]
      }
      download_event = {
        extended_data_attributes = ["File"]
      }
      file = {
        extended_data_attributes = ["Sha1", "Sha256", "Extended Attributes", "Is App Bundle", "Is Screenshot", "Is Quarantined", "Is Download", "Is Directory", "Downloaded From", "Signing Information", "User", "Group"]
      }
      file_system_event = {
        extended_data_attributes = ["File", "Process", "User", "Group"]
      }
      gatekeeper_event = {
        extended_data_attributes = ["Blocked Process", "Blocked Binary"]
      }
      group = {
        extended_data_attributes = ["name"]
      }
      keylog_register_event = {
        extended_data_attributes = ["Source Process", "Destination Process"]
      }
      malware_removal_tool_event = {
        extended_data_attributes = []
      }
      process = {
        extended_data_attributes = ["Args", "Is GUI App", "Signing Information", "App Path", "Binary", "User", "Group", "Parent", "Process Group Leader"]
      }
      process_event = {
        extended_data_attributes = ["Process"]
      }
      screenshot_event = {
        extended_data_attributes = ["File"]
      }
      synthetic_click_event = {
        extended_data_attributes = ["Process", "User", "Group"]
      }
      usb_event = {
        extended_data_attributes = []
      }
      user = {
        extended_data_attributes = ["name"]
      }
    }
  }
  http_endpoints = [
    {
      collect_alerts = ["medium"]
      collect_logs   = []
      batching = {
        events_per_batch        = 2
        batching_window_seconds = 1
        event_delimiter         = "\n"
        max_batch_size_bytes    = 1100
      }
      http = {
        url    = "https://example.com"
        method = "POST"
        headers = [
          {
            header = "Content-Type"
            value  = "application/json"
          },
        ]
      }
    },
  ]
  kafka_endpoints = [
    {
      collect_alerts = []
      collect_logs   = ["telemetry"]
      batching = {
        events_per_batch        = 1
        batching_window_seconds = 0
      }
      kafka = {
        host      = "example.com"
        port      = 9093
        topic     = "EXAMPLE"
        client_cn = "EXAMPLE_CLIENT"
        server_cn = "EXAMPLE_SERVER"
      }
    },
  ]
  syslog_endpoints = [
    {
      collect_alerts = ["high"]
      collect_logs   = []
      batching = {
        events_per_batch        = 1
        batching_window_seconds = 0
      }
      syslog = {
        host     = "example.com"
        port     = 6514
        protocol = "tls"
      }
    },
  ]
  log_file_endpoint = {
    collect_alerts = ["high", "medium", "low", "informational"]
    collect_logs   = ["telemetry", "unified_logs"]
    batching = {
      events_per_batch        = 1
      batching_window_seconds = 0
    }
    log_file = {
      path             = "/var/log/JamfProtect.log"
      ownership        = "root:wheel"
      permissions      = "0640"
      max_file_size_mb = 50
      max_backups      = 10
    }
  }
  jamf_protect_cloud_endpoint = {
    collect_alerts = ["informational", "low", "medium", "high"]
    collect_logs   = ["telemetry", "unified_logs"]
    batching = {
      events_per_batch        = 1
      batching_window_seconds = 0
    }
    jamf_protect_cloud = {
      destination_filter = null
    }
  }
}
