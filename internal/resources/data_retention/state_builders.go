package data_retention

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// apiToState maps the API response into the Terraform state model.
func (r *DataRetentionResource) apiToState(_ context.Context, data *DataRetentionResourceModel, api jamfprotect.DataRetentionSettings) {
	data.ID = types.StringValue(dataRetentionResourceID)
	data.InformationalAlertDays = types.Int64Value(api.Database.Log.NumberOfDays)
	data.LowMediumHighSeverityDays = types.Int64Value(api.Database.Alert.NumberOfDays)
	data.ArchivedDataDays = types.Int64Value(api.Cold.Alert.NumberOfDays)
	data.Updated = types.StringValue(api.Updated)
}
