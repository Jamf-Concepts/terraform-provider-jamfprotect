// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package action_configuration

// eventTypeMapping maps snake_case Terraform attribute names to camelCase API field names.
var eventTypeMapping = []struct {
	tfName  string
	apiName string
}{
	{"binary", "binary"},
	{"synthetic_click_event", "clickEvent"},
	{"download_event", "downloadEvent"},
	{"file", "file"},
	{"file_system_event", "fsEvent"},
	{"group", "group"},
	{"process_event", "procEvent"},
	{"process", "process"},
	{"screenshot_event", "screenshotEvent"},
	{"user", "user"},
	{"gatekeeper_event", "gkEvent"},
	{"keylog_register_event", "keylogRegisterEvent"},
}

// apiEventTypeMapping includes event types required by the API, even if the schema omits them.
var apiEventTypeMapping = []struct {
	tfName  string
	apiName string
}{
	{"binary", "binary"},
	{"synthetic_click_event", "clickEvent"},
	{"download_event", "downloadEvent"},
	{"file", "file"},
	{"file_system_event", "fsEvent"},
	{"group", "group"},
	{"process_event", "procEvent"},
	{"process", "process"},
	{"screenshot_event", "screenshotEvent"},
	{"user", "user"},
	{"gatekeeper_event", "gkEvent"},
	{"keylog_register_event", "keylogRegisterEvent"},
	{"usb_event", "usbEvent"},
	{"malware_removal_tool_event", "mrtEvent"},
}

// extendedDataAttributeToAttr maps extended data attribute names to their corresponding API attribute names.
var extendedDataAttributeToAttr = map[string]string{
	"Sha1":                "sha1hex",
	"Sha256":              "sha256hex",
	"Extended Attributes": "xattrs",
	"Is App Bundle":       "isAppBundle",
	"Is Screenshot":       "isScreenShot",
	"Is Quarantined":      "isQuarantined",
	"Is Download":         "isDownload",
	"Is Directory":        "isDirectory",
	"Downloaded From":     "downloadedFrom",
	"Signing Information": "signingInfo",
	"Args":                "args",
	"Is GUI App":          "guiAPP",
	"App Path":            "appPath",
	"Name":                "name",
}

// extendedDataAttributeToRelated maps extended data attribute names to their related field (e.g. File, Process).
var extendedDataAttributeToRelated = map[string]string{
	"File":                 "file",
	"Process":              "process",
	"User":                 "user",
	"Group":                "group",
	"Binary":               "binary",
	"Blocked Process":      "process",
	"Blocked Binary":       "binary",
	"Source Process":       "process",
	"Destination Process":  "process",
	"Parent":               "process",
	"Process Group Leader": "process",
}

// attrToExtendedDataAttribute maps API attribute names to their corresponding extended data attribute names.
var attrToExtendedDataAttribute = map[string]string{
	"sha1hex":        "Sha1",
	"sha256hex":      "Sha256",
	"xattrs":         "Extended Attributes",
	"isAppBundle":    "Is App Bundle",
	"isScreenShot":   "Is Screenshot",
	"isQuarantined":  "Is Quarantined",
	"isDownload":     "Is Download",
	"isDirectory":    "Is Directory",
	"downloadedFrom": "Downloaded From",
	"signingInfo":    "Signing Information",
	"args":           "Args",
	"guiAPP":         "Is GUI App",
	"appPath":        "App Path",
	"name":           "Name",
}

// relatedToExtendedDataAttribute maps related field names to their corresponding extended data attribute names.
var relatedToExtendedDataAttribute = map[string]string{
	"file":    "File",
	"process": "Process",
	"user":    "User",
	"group":   "Group",
	"binary":  "Binary",
}

// eventTypeAttrName returns the Terraform attribute name for a given event type.
func eventTypeAttrName(tfName string) string {
	return tfName + "_included_data_attributes"
}
