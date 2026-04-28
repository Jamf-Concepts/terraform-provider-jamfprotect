// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package plan

// logLevelUIOptions lists supported log level labels.
var logLevelUIOptions = []string{"Error", "Warning", "Info", "Debug", "Verbose"}

// logLevelUIToAPI maps UI labels to API enum values.
var logLevelUIToAPI = map[string]string{
	"Error":   "ERROR",
	"Warning": "WARNING",
	"Info":    "INFO",
	"Debug":   "DEBUG",
	"Verbose": "VERBOSE",
}

// logLevelAPIToUI maps API enum values to UI labels.
var logLevelAPIToUI = map[string]string{
	"ERROR":   "Error",
	"WARNING": "Warning",
	"INFO":    "Info",
	"DEBUG":   "Debug",
	"VERBOSE": "Verbose",
}

// communicationsProtocolUIOptions lists supported communications protocol labels.
var communicationsProtocolUIOptions = []string{"MQTT:443", "WebSocket/MQTT:443"}

// communicationsProtocolUIToAPI maps UI protocol labels to API values.
var communicationsProtocolUIToAPI = map[string]string{
	"MQTT:443":           "mqtt",
	"WebSocket/MQTT:443": "wss/mqtt",
}

// communicationsProtocolAPIToUI maps API protocol values to UI labels.
var communicationsProtocolAPIToUI = map[string]string{
	"mqtt":     "MQTT:443",
	"wss/mqtt": "WebSocket/MQTT:443",
}

// endpointThreatPreventionUIOptions lists supported endpoint threat prevention labels.
var endpointThreatPreventionUIOptions = []string{"Block and report", "Report only", "Disable"}

// advancedThreatControlsUIOptions lists supported advanced threat controls labels.
var advancedThreatControlsUIOptions = []string{"Block and report", "Report only", "Disable"}

// tamperPreventionUIOptions lists supported tamper prevention labels.
var tamperPreventionUIOptions = []string{"Block and report", "Disable"}

// threatPreventionStrategyUIOptions lists supported threat prevention strategy labels.
var threatPreventionStrategyUIOptions = []string{"Legacy", "Managed", "Custom"}

// threatPreventionStrategyUIToAPI maps UI strategy labels to API enum values.
var threatPreventionStrategyUIToAPI = map[string]string{
	"Legacy":  "LEGACY",
	"Managed": "MANAGED",
	"Custom":  "CUSTOM_ENGINES",
}

// threatPreventionStrategyAPIToUI maps API enum values to UI labels.
var threatPreventionStrategyAPIToUI = map[string]string{
	"LEGACY":         "Legacy",
	"MANAGED":        "Managed",
	"CUSTOM_ENGINES": "Custom",
}

// customEngineConfigModeUIOptions lists supported per-engine mode labels.
var customEngineConfigModeUIOptions = []string{"Block and report", "Report only", "Disabled"}

// customEngineConfigModeUIToAPI maps UI mode labels to API enum values.
var customEngineConfigModeUIToAPI = map[string]string{
	"Block and report": "PREVENT",
	"Report only":      "REPORT",
	"Disabled":         "DISABLED",
}

// customEngineConfigModeAPIToUI maps API enum values to UI mode labels.
var customEngineConfigModeAPIToUI = map[string]string{
	"PREVENT":  "Block and report",
	"REPORT":   "Report only",
	"DISABLED": "Disabled",
}

// threatPreventionStrategyToAPI maps a UI strategy label to an API enum value.
func threatPreventionStrategyToAPI(value string) string {
	if mapped, ok := threatPreventionStrategyUIToAPI[value]; ok {
		return mapped
	}
	return value
}

// threatPreventionStrategyFromAPI maps an API enum value to a UI strategy label.
func threatPreventionStrategyFromAPI(value string) string {
	if mapped, ok := threatPreventionStrategyAPIToUI[value]; ok {
		return mapped
	}
	return value
}

// customEngineConfigModeToAPI maps a UI mode label to an API enum value.
func customEngineConfigModeToAPI(value string) (string, bool) {
	mapped, ok := customEngineConfigModeUIToAPI[value]
	return mapped, ok
}

// customEngineConfigModeFromAPI maps an API enum value to a UI mode label.
func customEngineConfigModeFromAPI(value string) (string, bool) {
	mapped, ok := customEngineConfigModeAPIToUI[value]
	return mapped, ok
}

// logLevelToAPI maps UI values to API values.
func logLevelToAPI(value string) string {
	mapped, ok := logLevelUIToAPI[value]
	if ok {
		return mapped
	}
	return value
}

// logLevelFromAPI maps API values to UI values.
func logLevelFromAPI(value string) string {
	mapped, ok := logLevelAPIToUI[value]
	if ok {
		return mapped
	}
	return value
}

// communicationsProtocolToAPI maps UI values to API values.
func communicationsProtocolToAPI(value string) string {
	mapped, ok := communicationsProtocolUIToAPI[value]
	if ok {
		return mapped
	}
	return value
}

// communicationsProtocolFromAPI maps API values to UI values.
func communicationsProtocolFromAPI(value string) string {
	mapped, ok := communicationsProtocolAPIToUI[value]
	if ok {
		return mapped
	}
	return value
}
