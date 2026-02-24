package data_retention

import "github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"

// buildDataRetentionInput builds the API input from the Terraform model.
func buildDataRetentionInput(data DataRetentionResourceModel) jamfprotect.DataRetentionInput {
	return jamfprotect.DataRetentionInput{
		DatabaseLogDays:   data.InformationalAlertDays.ValueInt64(),
		DatabaseAlertDays: data.LowMediumHighSeverityDays.ValueInt64(),
		ColdAlertDays:     data.ArchivedDataDays.ValueInt64(),
	}
}
