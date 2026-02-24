package data_retention

import (
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// DataRetentionResourceModel maps the resource schema data.
type DataRetentionResourceModel struct {
	ID                        types.String   `tfsdk:"id"`
	InformationalAlertDays    types.Int64    `tfsdk:"informational_alert_days"`
	LowMediumHighSeverityDays types.Int64    `tfsdk:"low_medium_high_severity_alert_days"`
	ArchivedDataDays          types.Int64    `tfsdk:"archived_data_days"`
	Updated                   types.String   `tfsdk:"updated"`
	Timeouts                  timeouts.Value `tfsdk:"timeouts"`
}
