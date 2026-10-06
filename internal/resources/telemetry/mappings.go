// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package telemetry

// logApplicationsAndProcessesEvents lists event names for app/process telemetry.
var logApplicationsAndProcessesEvents = []string{"chroot", "cs_invalidated", "exec"}

// logAccessAndAuthenticationEvents lists event names for access/auth telemetry.
var logAccessAndAuthenticationEvents = []string{"authentication", "login_login", "login_logout", "lw_session_lock", "lw_session_login", "lw_session_logout", "lw_session_unlock", "openssh_login", "openssh_logout", "pty_close", "pty_grant", "screensharing_attach", "screensharing_detach", "su", "sudo"}

// logUsersAndGroupsEvents lists event names for user/group telemetry.
var logUsersAndGroupsEvents = []string{"od_attribute_set", "od_attribute_value_add", "od_attribute_value_remove", "od_create_group", "od_create_user", "od_delete_group", "od_delete_user", "od_disable_user", "od_enable_user", "od_group_add", "od_group_remove", "od_group_set", "od_modify_password"}

// logPersistenceEvents lists event names for persistence telemetry.
var logPersistenceEvents = []string{"btm_launch_item_add", "btm_launch_item_remove"}

// logHardwareAndSoftwareEvents lists event names for hardware/software telemetry.
var logHardwareAndSoftwareEvents = []string{"mount", "remount", "unmount"}

// logAppleSecurityEvents lists event names for Apple security telemetry.
var logAppleSecurityEvents = []string{"gatekeeper_user_override", "xp_malware_detected", "xp_malware_remediated"}

// logSystemEvents lists event names for system telemetry.
var logSystemEvents = []string{"kextload", "kextunload", "profile_add", "profile_remove", "settime", "tcc_modify"}

// logNetworkEvents lists event names for network telemetry.
var logNetworkEvents = []string{"network_connect"}

// telemetryEventCategory pairs a category attribute with the events it collects.
type telemetryEventCategory struct {
	Attribute string
	Events    []string
}

// telemetryEventCategories lists every event category the resource exposes as a boolean attribute.
var telemetryEventCategories = []telemetryEventCategory{
	{Attribute: "log_applications_and_processes", Events: logApplicationsAndProcessesEvents},
	{Attribute: "log_access_and_authentication", Events: logAccessAndAuthenticationEvents},
	{Attribute: "log_users_and_groups", Events: logUsersAndGroupsEvents},
	{Attribute: "log_persistence", Events: logPersistenceEvents},
	{Attribute: "log_hardware_and_software", Events: logHardwareAndSoftwareEvents},
	{Attribute: "log_apple_security", Events: logAppleSecurityEvents},
	{Attribute: "log_system", Events: logSystemEvents},
	{Attribute: "log_network", Events: logNetworkEvents},
}
