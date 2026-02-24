package removable_storage_control_set

// permissionUIOptions defines the valid permission options for the UI.
var permissionUIOptions = []string{"Prevent", "Read and Write", "Read Only"}

// permissionUIToAPI maps the UI permission options to the API values.
var permissionUIToAPI = map[string]string{
	"Prevent":        "Prevented",
	"Read and Write": "ReadWrite",
	"Read Only":      "ReadOnly",
}

// permissionAPIToUI maps the API permission values to the UI options.
var permissionAPIToUI = map[string]string{
	"Prevented": "Prevent",
	"ReadWrite": "Read and Write",
	"ReadOnly":  "Read Only",
}

// permissionToAPI maps the UI permission option to the API value.
func permissionToAPI(value string) string {
	mapped, ok := permissionUIToAPI[value]
	if ok {
		return mapped
	}
	return value
}

// permissionFromAPI maps the API permission value to the UI option.
func permissionFromAPI(value string) string {
	mapped, ok := permissionAPIToUI[value]
	if ok {
		return mapped
	}
	return value
}

// normalizeRemovableStorageRuleType normalizes the rule type by removing "Rule" suffixes for better UI display.
func normalizeRemovableStorageRuleType(ruleType string) string {
	switch ruleType {
	case "VendorRule":
		return "Vendor"
	case "SerialRule":
		return "Serial"
	case "ProductRule":
		return "Product"
	case "EncryptionRule":
		return "Encryption"
	default:
		return ruleType
	}
}
