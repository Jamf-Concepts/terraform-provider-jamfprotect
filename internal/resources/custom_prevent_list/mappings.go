package custom_prevent_list

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// preventTypeUIToAPI is a mapping of user-friendly prevent type names to the corresponding API values.
var preventTypeUIToAPI = map[string]string{
	"Team ID":             "TEAMID",
	"File Hash":           "FILEHASH",
	"Code Directory Hash": "CDHASH",
	"Signing ID":          "SIGNINGID",
}

// preventTypeAPIToUI is a mapping of API prevent type values to user-friendly names for display in Terraform.
var preventTypeAPIToUI = map[string]string{
	"TEAMID":    "Team ID",
	"FILEHASH":  "File Hash",
	"CDHASH":    "Code Directory Hash",
	"SIGNINGID": "Signing ID",
}

// preventTypeOptions is a list of valid prevent type options for validation and display purposes.
var preventTypeOptions = []string{
	"Team ID",
	"File Hash",
	"Code Directory Hash",
	"Signing ID",
}

// mapPreventTypeUIToAPI maps a user-friendly prevent type name to the corresponding API value. If the provided value is not recognized, it adds an error to the diagnostics and returns an empty string.
func mapPreventTypeUIToAPI(value string, diags *diag.Diagnostics) string {
	if apiValue, ok := preventTypeUIToAPI[value]; ok {
		return apiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := preventTypeAPIToUI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported prevent type",
		fmt.Sprintf("%q is not a supported prevent type", value),
	)
	return ""
}

// mapPreventTypeAPIToUI maps an API prevent type value to a user-friendly name for display in Terraform. If the provided value is not recognized, it adds an error to the diagnostics and returns the original value.
func mapPreventTypeAPIToUI(value string, diags *diag.Diagnostics) string {
	if uiValue, ok := preventTypeAPIToUI[value]; ok {
		return uiValue
	}
	if value == "" {
		return ""
	}
	if _, ok := preventTypeUIToAPI[value]; ok {
		return value
	}
	diags.AddError(
		"Unsupported prevent type",
		fmt.Sprintf("%q is not a supported prevent type", value),
	)
	return value
}
