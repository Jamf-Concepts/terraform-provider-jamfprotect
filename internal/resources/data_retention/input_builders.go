// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package data_retention

import "github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"

// buildDataRetentionInput builds the API input from the Terraform model.
func buildDataRetentionInput(data DataRetentionResourceModel) jamfprotect.DataRetentionInput {
	return jamfprotect.DataRetentionInput{
		DatabaseLogDays:   data.InformationalAlertDays.ValueInt64(),
		DatabaseAlertDays: data.LowMediumHighSeverityDays.ValueInt64(),
		ColdAlertDays:     data.ArchivedDataDays.ValueInt64(),
	}
}
