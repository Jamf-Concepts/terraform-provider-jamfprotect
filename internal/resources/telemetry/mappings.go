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
