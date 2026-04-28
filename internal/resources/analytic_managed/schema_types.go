// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package analytic_managed

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var analyticContextAttrTypes = map[string]attr.Type{
	"name":        types.StringType,
	"type":        types.StringType,
	"expressions": types.SetType{ElemType: types.StringType},
}

var tenantActionAttrTypes = map[string]attr.Type{
	"name":       types.StringType,
	"parameters": types.MapType{ElemType: types.StringType},
}

var severityOptions = []string{
	"High",
	"Medium",
	"Low",
	"Informational",
}

var sensorTypeAPIToUI = map[string]string{
	"GPFSEvent":             "File System Event",
	"GPDownloadEvent":       "Download Event",
	"GPProcessEvent":        "Process Event",
	"GPScreenshotEvent":     "Screenshot Event",
	"GPKeylogRegisterEvent": "Keylog Register Event",
	"GPClickEvent":          "Synthetic Click Event",
	"GPMRTEvent":            "Malware Removal Tool Event",
	"GPUSBEvent":            "USB Event",
	"GPGatekeeperEvent":     "Gatekeeper Event",
}
