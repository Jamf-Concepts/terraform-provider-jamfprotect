---
page_title: "jamfprotect_action_configuration Resource - jamfprotect"
subcategory: ""
description: |-
  Manages an action configuration in Jamf Protect. Action configurations define the alert data enrichment settings and reporting clients for a plan.
---

# jamfprotect_action_configuration (Resource)

Manages an action configuration in Jamf Protect. Action configurations define the alert data enrichment settings and reporting clients for a plan.

## Example Usage

```terraform
# Example: Action Configuration with HTTP Endpoint
# This example shows how to configure alert forwarding to an external HTTP endpoint
# such as a SIEM, SOAR, or webhook integration.

resource "jamfprotect_action_configuration" "http_integration" {
  name        = "HTTP Endpoint Integration"
  description = "Forward high-severity alerts to external SIEM via HTTP"

  # Alert data enrichment configuration
  alert_data_collection = {
    binary_included_data_attributes                = ["Sha1", "Sha256", "Signing Information", "Is App Bundle"]
    download_event_included_data_attributes        = ["File"]
    file_included_data_attributes                  = ["Sha1", "Sha256", "Signing Information", "Downloaded From"]
    file_system_event_included_data_attributes     = ["File", "Process", "User"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process", "Blocked Binary"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process", "Destination Process"]
    process_included_data_attributes               = ["Args", "Signing Information", "Binary", "User", "Group"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process", "User"]
    user_included_data_attributes                  = ["Name"]
  }

  # HTTP endpoint for external SIEM integration
  http_endpoints = [
    {
      collect_alerts          = ["high", "medium"]
      collect_logs            = []
      events_per_batch        = 100
      batching_window_seconds = 30
      event_delimiter         = "\n"
      max_batch_size_bytes    = 1048576 # 1 MB
      url                     = "https://siem.example.com/api/v1/alerts"
      method                  = "POST"
      headers = [
        {
          header = "Content-Type"
          value  = "application/json"
        },
        {
          header = "Authorization"
          value  = "Bearer YOUR_API_TOKEN"
        },
      ]
    },
  ]

  # Keep Jamf Protect Cloud endpoint for other alert severities and logs
  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["low", "informational"]
    collect_logs       = ["telemetry", "unified_logs"]
    destination_filter = null
  }
}

# Example: Action Configuration with Kafka Integration
# This example shows how to stream telemetry data to Apache Kafka for real-time analysis.

resource "jamfprotect_action_configuration" "kafka_telemetry" {
  name        = "Kafka Streaming Integration"
  description = "Stream telemetry data to Kafka for real-time analytics"

  # Full data collection for telemetry
  alert_data_collection = {
    binary_included_data_attributes                = ["Sha1", "Sha256", "Signing Information", "Is App Bundle", "Extended Attributes"]
    download_event_included_data_attributes        = ["File"]
    file_included_data_attributes                  = ["Sha1", "Sha256", "Extended Attributes", "Is Quarantined", "Is Download", "Downloaded From", "Signing Information"]
    file_system_event_included_data_attributes     = ["File", "Process", "User", "Group"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process", "Blocked Binary"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process", "Destination Process"]
    process_included_data_attributes               = ["Args", "Is GUI App", "Signing Information", "App Path", "Binary", "User", "Group", "Parent", "Process Group Leader"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process", "User", "Group"]
    user_included_data_attributes                  = ["Name"]
  }

  # Kafka endpoint for streaming telemetry
  kafka_endpoints = [
    {
      collect_alerts = []
      collect_logs   = ["telemetry", "unified_logs"]
      host           = "kafka.example.com"
      port           = 9093
      topic          = "jamf-protect-telemetry"
      client_cn      = "jamf-protect-client"
      server_cn      = "kafka-server"
    },
  ]

  # Keep high-priority alerts going to Jamf Cloud
  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["high", "medium", "low", "informational"]
    collect_logs       = []
    destination_filter = null
  }
}

# Example: Action Configuration with Syslog Integration
# This example demonstrates forwarding alerts to a syslog server for centralized logging.

resource "jamfprotect_action_configuration" "syslog_integration" {
  name        = "Syslog Centralized Logging"
  description = "Forward high-severity alerts to central syslog server"

  # Minimal data collection for syslog alerts
  alert_data_collection = {
    binary_included_data_attributes                = ["Sha256", "Signing Information"]
    download_event_included_data_attributes        = ["File"]
    file_included_data_attributes                  = ["Sha256", "Signing Information"]
    file_system_event_included_data_attributes     = ["File", "Process"]
    gatekeeper_event_included_data_attributes      = ["Blocked Process"]
    group_included_data_attributes                 = ["Name"]
    keylog_register_event_included_data_attributes = ["Source Process", "Destination Process"]
    process_included_data_attributes               = ["Binary", "User", "Group"]
    process_event_included_data_attributes         = ["Process"]
    screenshot_event_included_data_attributes      = ["File"]
    synthetic_click_event_included_data_attributes = ["Process"]
    user_included_data_attributes                  = ["Name"]
  }

  # Syslog endpoint with TLS encryption
  syslog_endpoints = [
    {
      collect_alerts = ["high", "medium"]
      collect_logs   = []
      host           = "syslog.example.com"
      port           = 6514
      protocol       = "tls"
    },
  ]

  # Local log file for backup and debugging
  log_file_endpoint = {
    collect_alerts   = ["high", "medium", "low"]
    collect_logs     = []
    path             = "/var/log/jamf-protect-alerts.log"
    ownership        = "root:wheel"
    permissions      = "0640"
    max_file_size_mb = 100
    max_backups      = 5
  }

  # Jamf Cloud for informational alerts and telemetry
  jamf_protect_cloud_endpoint = {
    collect_alerts     = ["low", "informational"]
    collect_logs       = ["telemetry", "unified_logs"]
    destination_filter = null
  }
}
```



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `alert_data_collection` (Attributes) Alert data collection options from the Jamf Protect UI. (see [below for nested schema](#nestedatt--alert_data_collection))
- `name` (String) The name of the action configuration.

### Optional

- `description` (String) A description of the action configuration.
- `http_endpoints` (Attributes List) HTTP data endpoints configured in the Jamf Protect UI. (see [below for nested schema](#nestedatt--http_endpoints))
- `jamf_protect_cloud_endpoint` (Attributes) Jamf Protect Cloud data endpoint configured in the Jamf Protect UI. (see [below for nested schema](#nestedatt--jamf_protect_cloud_endpoint))
- `kafka_endpoints` (Attributes List) Kafka data endpoints configured in the Jamf Protect UI. (see [below for nested schema](#nestedatt--kafka_endpoints))
- `log_file_endpoint` (Attributes) Log file data endpoint configured in the Jamf Protect UI. (see [below for nested schema](#nestedatt--log_file_endpoint))
- `syslog_endpoints` (Attributes List) Syslog data endpoints configured in the Jamf Protect UI. (see [below for nested schema](#nestedatt--syslog_endpoints))
- `timeouts` (Attributes) (see [below for nested schema](#nestedatt--timeouts))

### Read-Only

- `created` (String) The creation timestamp.
- `hash` (String) The configuration hash.
- `id` (String) The unique identifier of the action configuration.
- `updated` (String) The last-updated timestamp.

<a id="nestedatt--alert_data_collection"></a>
### Nested Schema for `alert_data_collection`

Required:

- `binary_included_data_attributes` (Set of String) Included data attributes for binary events. Valid options are: `Sha1`, `Sha256`, `Extended Attributes`, `Is App Bundle`, `Is Screenshot`, `Is Quarantined`, `Is Download`, `Is Directory`, `Downloaded From`, `Signing Information`, `User`, `Group`.
- `download_event_included_data_attributes` (Set of String) Included data attributes for download events. Valid options are: `File`.
- `file_included_data_attributes` (Set of String) Included data attributes for file events. Valid options are: `Sha1`, `Sha256`, `Extended Attributes`, `Is App Bundle`, `Is Screenshot`, `Is Quarantined`, `Is Download`, `Is Directory`, `Downloaded From`, `Signing Information`, `User`, `Group`.
- `file_system_event_included_data_attributes` (Set of String) Included data attributes for file system events. Valid options are: `File`, `Process`, `User`, `Group`.
- `gatekeeper_event_included_data_attributes` (Set of String) Included data attributes for gatekeeper events. Valid options are: `Blocked Process`, `Blocked Binary`.
- `group_included_data_attributes` (Set of String) Included data attributes for group events. Valid options are: `Name`.
- `keylog_register_event_included_data_attributes` (Set of String) Included data attributes for keylog register events. Valid options are: `Source Process`, `Destination Process`.
- `process_event_included_data_attributes` (Set of String) Included data attributes for process events. Valid options are: `Process`.
- `process_included_data_attributes` (Set of String) Included data attributes for process metadata. Valid options are: `Args`, `Is GUI App`, `Signing Information`, `App Path`, `Binary`, `User`, `Group`, `Parent`, `Process Group Leader`.
- `screenshot_event_included_data_attributes` (Set of String) Included data attributes for screenshot events. Valid options are: `File`.
- `synthetic_click_event_included_data_attributes` (Set of String) Included data attributes for synthetic click events. Valid options are: `Process`, `User`, `Group`.
- `user_included_data_attributes` (Set of String) Included data attributes for user events. Valid options are: `Name`.


<a id="nestedatt--http_endpoints"></a>
### Nested Schema for `http_endpoints`

Optional:

- `batching_window_seconds` (Number) Maximum time in seconds between when an event occurs and when it is sent.
- `collect_alerts` (Set of String) Alert severities collected by this endpoint. Valid options are: `high`, `medium`, `low`, `informational`.
- `collect_logs` (Set of String) Log types collected by this endpoint. Valid options are: `telemetry`, `unified_logs`.
- `event_delimiter` (String) Delimiter used between batched records.
- `events_per_batch` (Number) Maximum number of events per batch.
- `headers` (Attributes List) HTTP headers. (see [below for nested schema](#nestedatt--http_endpoints--headers))
- `max_batch_size_bytes` (Number) Maximum batch size in bytes.
- `method` (String) HTTP request method. Valid options are: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`.
- `url` (String) HTTP destination URL.

<a id="nestedatt--http_endpoints--headers"></a>
### Nested Schema for `http_endpoints.headers`

Optional:

- `header` (String)
- `value` (String)



<a id="nestedatt--jamf_protect_cloud_endpoint"></a>
### Nested Schema for `jamf_protect_cloud_endpoint`

Optional:

- `collect_alerts` (Set of String) Alert severities collected by this endpoint. Valid options are: `high`, `medium`, `low`, `informational`.
- `collect_logs` (Set of String) Log types collected by this endpoint. Valid options are: `telemetry`, `unified_logs`.
- `destination_filter` (String) Destination filter (if configured).


<a id="nestedatt--kafka_endpoints"></a>
### Nested Schema for `kafka_endpoints`

Optional:

- `client_cn` (String) Kafka client certificate CN.
- `collect_alerts` (Set of String) Alert severities collected by this endpoint. Valid options are: `high`, `medium`, `low`, `informational`.
- `collect_logs` (Set of String) Log types collected by this endpoint. Valid options are: `telemetry`, `unified_logs`.
- `host` (String) Kafka host.
- `port` (Number) Kafka port.
- `server_cn` (String) Kafka server certificate CN.
- `topic` (String) Kafka topic.


<a id="nestedatt--log_file_endpoint"></a>
### Nested Schema for `log_file_endpoint`

Optional:

- `collect_alerts` (Set of String) Alert severities collected by this endpoint. Valid options are: `high`, `medium`, `low`, `informational`.
- `collect_logs` (Set of String) Log types collected by this endpoint. Valid options are: `telemetry`, `unified_logs`.
- `max_backups` (Number) Maximum number of backup files to keep.
- `max_file_size_mb` (Number) Maximum file size in MB before rotating.
- `ownership` (String) User and group that own the log file.
- `path` (String) Log file path.
- `permissions` (String) Log file permissions.


<a id="nestedatt--syslog_endpoints"></a>
### Nested Schema for `syslog_endpoints`

Optional:

- `collect_alerts` (Set of String) Alert severities collected by this endpoint. Valid options are: `high`, `medium`, `low`, `informational`.
- `collect_logs` (Set of String) Log types collected by this endpoint. Valid options are: `telemetry`, `unified_logs`.
- `host` (String) Syslog host.
- `port` (Number) Syslog port.
- `protocol` (String) Syslog protocol. Valid options are: `tls`, `tcp`, `udp`.


<a id="nestedatt--timeouts"></a>
### Nested Schema for `timeouts`

Optional:

- `create` (String) A string that can be [parsed as a duration](https://pkg.go.dev/time#ParseDuration) consisting of numbers and unit suffixes, such as "30s" or "2h45m". Valid time units are "s" (seconds), "m" (minutes), "h" (hours).
- `delete` (String) A string that can be [parsed as a duration](https://pkg.go.dev/time#ParseDuration) consisting of numbers and unit suffixes, such as "30s" or "2h45m". Valid time units are "s" (seconds), "m" (minutes), "h" (hours). Setting a timeout for a Delete operation is only applicable if changes are saved into state before the destroy operation occurs.
- `read` (String) A string that can be [parsed as a duration](https://pkg.go.dev/time#ParseDuration) consisting of numbers and unit suffixes, such as "30s" or "2h45m". Valid time units are "s" (seconds), "m" (minutes), "h" (hours). Read operations occur during any refresh or planning operation when refresh is enabled.
- `update` (String) A string that can be [parsed as a duration](https://pkg.go.dev/time#ParseDuration) consisting of numbers and unit suffixes, such as "30s" or "2h45m". Valid time units are "s" (seconds), "m" (minutes), "h" (hours).

## Import

### Using terraform import command

```shell
terraform import jamfprotect_action_configuration.example "<action-configuration-id>"
```

### Using import blocks (Terraform 1.5+)

**Import by ID:**

```terraform
# Terraform 1.5+ Import Example
# Import an existing Jamf Protect action configuration using the import block.

import {
  to = jamfprotect_action_configuration.imported
  id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}

resource "jamfprotect_action_configuration" "imported" {
  # Configuration will be populated during import
  # After import, run 'terraform plan' to see the current state
}
```

