package analytic_set

import (
	"context"
	"strings"

	common "github.com/smithjw/terraform-provider-jamfprotect/internal/common/helpers"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/jamfprotect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// buildInput converts the Terraform model into the service input.
func (r *AnalyticSetResource) buildInput(ctx context.Context, data AnalyticSetResourceModel, diags *diag.Diagnostics) *jamfprotect.AnalyticSetInput {
	input := &jamfprotect.AnalyticSetInput{
		Name:  data.Name.ValueString(),
		Types: []string{"Report"},
	}

	if !data.Description.IsNull() {
		input.Description = data.Description.ValueString()
	} else {
		input.Description = ""
	}

	input.Analytics = common.SetToStrings(ctx, data.Analytics, diags)

	return input
}

// validateAnalyticsExist ensures every analytic UUID exists in Jamf Protect.
func (r *AnalyticSetResource) validateAnalyticsExist(ctx context.Context, analytics []string, diags *diag.Diagnostics) {
	if len(analytics) == 0 {
		return
	}

	items, err := r.service.ListAnalytics(ctx)
	if err != nil {
		diags.AddError("Error listing analytics", err.Error())
		return
	}

	existing := map[string]bool{}
	for _, a := range items {
		existing[a.UUID] = true
	}

	missing := []string{}
	for _, id := range analytics {
		if id == "" {
			continue
		}
		if !existing[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		diags.AddError(
			"Referenced analytics missing",
			"This analytic set references analytics that do not exist in Jamf Protect: "+strings.Join(missing, ", ")+". Remove them from your configuration or recreate them before applying.",
		)
	}
}
