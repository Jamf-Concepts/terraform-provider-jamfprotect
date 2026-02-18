// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/action_configuration"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/analytic"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/analytic_set"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/custom_prevent_list"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/exception_set"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/plan"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/removable_storage_control_set"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/telemetry"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/unified_logging_filter"
)

func TestProviderSchema(t *testing.T) {
	t.Parallel()

	p := New("test")()
	resp := &provider.SchemaResponse{}
	p.Schema(context.Background(), provider.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	// Verify required attributes exist.
	for _, attr := range []string{"url", "client_id", "client_secret"} {
		if _, ok := resp.Schema.Attributes[attr]; !ok {
			t.Errorf("expected attribute %q in provider schema", attr)
		}
	}
}

func TestProviderMetadata(t *testing.T) {
	t.Parallel()

	p := New("1.2.3")()
	resp := &provider.MetadataResponse{}
	p.Metadata(context.Background(), provider.MetadataRequest{}, resp)

	if resp.TypeName != "jamfprotect" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect", resp.TypeName)
	}
	if resp.Version != "1.2.3" {
		t.Errorf("expected Version %q, got %q", "1.2.3", resp.Version)
	}
}

func TestAnalyticResourceSchema(t *testing.T) {
	t.Parallel()

	r := analytic.NewAnalyticResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "sensor_type", "predicate", "level", "severity", "tags", "categories", "snapshot_files", "context_item"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in analytic schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in analytic schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be required.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in analytic schema")
	}
	if !desc.IsRequired() {
		t.Error("expected 'description' to be required")
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in analytic schema")
	}
}

func TestCustomPreventListResourceSchema(t *testing.T) {
	t.Parallel()

	r := custom_prevent_list.NewCustomPreventListResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "prevent_type", "list_data"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in prevent list schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "entry_count", "created"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in prevent list schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in prevent list schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in prevent list schema")
	}
}

func TestUnifiedLoggingFilterResourceSchema(t *testing.T) {
	t.Parallel()

	r := unified_logging_filter.NewUnifiedLoggingFilterResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "filter", "tags"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in unified logging filter schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in unified logging filter schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in unified logging filter schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// enabled should be optional + computed (has default).
	enabled, ok := resp.Schema.Attributes["enabled"]
	if !ok {
		t.Fatal("expected attribute 'enabled' in schema")
	}
	if !enabled.IsOptional() {
		t.Error("expected 'enabled' to be optional")
	}
	if !enabled.IsComputed() {
		t.Error("expected 'enabled' to be computed (has default)")
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in unified logging filter schema")
	}
}

func TestAnalyticResourceMetadata(t *testing.T) {
	t.Parallel()

	r := analytic.NewAnalyticResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_analytic" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_analytic", resp.TypeName)
	}
}

func TestCustomPreventListResourceMetadata(t *testing.T) {
	t.Parallel()

	r := custom_prevent_list.NewCustomPreventListResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_custom_prevent_list" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_custom_prevent_list", resp.TypeName)
	}
}

func TestUnifiedLoggingFilterResourceMetadata(t *testing.T) {
	t.Parallel()

	r := unified_logging_filter.NewUnifiedLoggingFilterResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_unified_logging_filter" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_unified_logging_filter", resp.TypeName)
	}
}

func TestActionConfigResourceSchema(t *testing.T) {
	t.Parallel()

	r := action_configuration.NewActionConfigResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "alert_data_collection"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in action config schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "hash", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in action config schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// alert_data_collection should be a SingleNestedAttribute containing event types.
	collectionAttr, ok := resp.Schema.Attributes["alert_data_collection"]
	if !ok {
		t.Fatal("expected attribute 'alert_data_collection' in schema")
	}
	collectionNested, ok := collectionAttr.(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("expected 'alert_data_collection' to be a SingleNestedAttribute")
	}
	eventTypes := []string{
		"binary", "synthetic_click_event", "download_event", "file", "file_system_event",
		"group", "process_event", "process", "screenshot_event",
		"user", "gatekeeper_event", "keylog_register_event",
	}
	for _, et := range eventTypes {
		attrName := et + "_included_data_attributes"
		etAttr, ok := collectionNested.Attributes[attrName]
		if !ok {
			t.Errorf("expected event type %q in alert_data_collection", attrName)
			continue
		}
		if _, ok := etAttr.(schema.SetAttribute); !ok {
			t.Errorf("expected event type %q to be a SetAttribute", attrName)
			continue
		}
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in action config schema")
	}
}

func TestActionConfigResourceMetadata(t *testing.T) {
	t.Parallel()

	r := action_configuration.NewActionConfigResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_action_configuration" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_action_configuration", resp.TypeName)
	}
}

func TestPlanResourceSchema(t *testing.T) {
	t.Parallel()

	r := plan.NewPlanResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "action_configuration", "reporting_interval"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in plan schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "hash", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in plan schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	optionalAttrs := []string{
		"description",
		"log_level",
		"communications_protocol",
		"endpoint_threat_prevention",
		"advanced_threat_controls",
		"tamper_prevention",
		"exception_sets",
		"telemetry",
		"removable_storage_control_set",
		"analytic_sets",
		"report_architecture",
		"report_hostname",
		"report_kernel_version",
		"report_memory_size",
		"report_model_name",
		"report_serial_number",
		"compliance_baseline_reporting",
		"report_os_version",
	}
	for _, attr := range optionalAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in plan schema", attr)
			continue
		}
		if !a.IsOptional() {
			t.Errorf("expected attribute %q to be optional", attr)
		}
	}

	// log_level should be optional + computed (has default).
	logLevel, ok := resp.Schema.Attributes["log_level"]
	if !ok {
		t.Fatal("expected attribute 'log_level' in schema")
	}
	if !logLevel.IsOptional() {
		t.Error("expected 'log_level' to be optional")
	}
	if !logLevel.IsComputed() {
		t.Error("expected 'log_level' to be computed (has default)")
	}

	// communications_protocol should be optional + computed (has default).
	communicationsProtocol, ok := resp.Schema.Attributes["communications_protocol"]
	if !ok {
		t.Fatal("expected attribute 'communications_protocol' in schema")
	}
	if !communicationsProtocol.IsOptional() {
		t.Error("expected 'communications_protocol' to be optional")
	}
	if !communicationsProtocol.IsComputed() {
		t.Error("expected 'communications_protocol' to be computed (has default)")
	}

	// telemetry should be optional.
	telemetry, ok := resp.Schema.Attributes["telemetry"]
	if !ok {
		t.Fatal("expected attribute 'telemetry' in schema")
	}
	if !telemetry.IsOptional() {
		t.Error("expected 'telemetry' to be optional")
	}

	// auto_update should be optional + computed (has default).
	autoUpdate, ok := resp.Schema.Attributes["auto_update"]
	if !ok {
		t.Fatal("expected attribute 'auto_update' in schema")
	}
	if !autoUpdate.IsOptional() {
		t.Error("expected 'auto_update' to be optional")
	}
	if !autoUpdate.IsComputed() {
		t.Error("expected 'auto_update' to be computed (has default)")
	}

	// endpoint_threat_prevention should be optional + computed (has default).
	endpointThreatPrevention, ok := resp.Schema.Attributes["endpoint_threat_prevention"]
	if !ok {
		t.Fatal("expected attribute 'endpoint_threat_prevention' in schema")
	}
	if !endpointThreatPrevention.IsOptional() {
		t.Error("expected 'endpoint_threat_prevention' to be optional")
	}
	if !endpointThreatPrevention.IsComputed() {
		t.Error("expected 'endpoint_threat_prevention' to be computed (has default)")
	}

	advancedThreatControls, ok := resp.Schema.Attributes["advanced_threat_controls"]
	if !ok {
		t.Fatal("expected attribute 'advanced_threat_controls' in schema")
	}
	if !advancedThreatControls.IsOptional() {
		t.Error("expected 'advanced_threat_controls' to be optional")
	}
	if !advancedThreatControls.IsComputed() {
		t.Error("expected 'advanced_threat_controls' to be computed")
	}

	tamperPrevention, ok := resp.Schema.Attributes["tamper_prevention"]
	if !ok {
		t.Fatal("expected attribute 'tamper_prevention' in schema")
	}
	if !tamperPrevention.IsOptional() {
		t.Error("expected 'tamper_prevention' to be optional")
	}
	if !tamperPrevention.IsComputed() {
		t.Error("expected 'tamper_prevention' to be computed")
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in plan schema")
	}
}

func TestPlanResourceMetadata(t *testing.T) {
	t.Parallel()

	r := plan.NewPlanResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_plan" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_plan", resp.TypeName)
	}
}

func TestRemovableStorageControlSetResourceSchema(t *testing.T) {
	t.Parallel()

	r := removable_storage_control_set.NewRemovableStorageControlSetResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "default_permission"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in RemovableStorage control set schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in RemovableStorage control set schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in RemovableStorage control set schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// default_local_notification_message should be optional + computed.
	msgAction, ok := resp.Schema.Attributes["default_local_notification_message"]
	if !ok {
		t.Fatal("expected attribute 'default_local_notification_message' in RemovableStorage control set schema")
	}
	if !msgAction.IsOptional() {
		t.Error("expected 'default_local_notification_message' to be optional")
	}
	if !msgAction.IsComputed() {
		t.Error("expected 'default_local_notification_message' to be computed")
	}

	// override blocks should exist.
	for _, block := range []string{
		"override_encrypted_devices",
		"override_vendor_id",
		"override_product_id",
		"override_serial_number",
	} {
		_, ok := resp.Schema.Blocks[block]
		if !ok {
			t.Errorf("expected block %q in RemovableStorage control set schema", block)
			continue
		}
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in RemovableStorage control set schema")
	}
}

func TestRemovableStorageControlSetResourceMetadata(t *testing.T) {
	t.Parallel()

	r := removable_storage_control_set.NewRemovableStorageControlSetResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_removable_storage_control_set" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_removable_storage_control_set", resp.TypeName)
	}
}

func TestAnalyticSetResourceSchema(t *testing.T) {
	t.Parallel()

	r := analytic_set.NewAnalyticSetResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	// name and analytics should be required.
	for _, attr := range []string{"name", "analytics"} {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in analytic set schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in analytic set schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in analytic set schema")
	}
}

func TestAnalyticSetResourceMetadata(t *testing.T) {
	t.Parallel()

	r := analytic_set.NewAnalyticSetResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_analytic_set" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_analytic_set", resp.TypeName)
	}
}

func TestExceptionSetResourceSchema(t *testing.T) {
	t.Parallel()

	r := exception_set.NewExceptionSetResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	// name should be required.
	name, ok := resp.Schema.Attributes["name"]
	if !ok {
		t.Fatal("expected attribute 'name' in exception set schema")
	}
	if !name.IsRequired() {
		t.Error("expected 'name' to be required")
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in exception set schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in exception set schema")
	}

	if _, ok := resp.Schema.Blocks["exception"]; !ok {
		t.Error("expected block 'exception' in exception set schema")
	}
	if _, ok := resp.Schema.Blocks["endpoint_security_exception"]; !ok {
		t.Error("expected block 'endpoint_security_exception' in exception set schema")
	}
}

func TestExceptionSetResourceMetadata(t *testing.T) {
	t.Parallel()

	r := exception_set.NewExceptionSetResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_exception_set" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_exception_set", resp.TypeName)
	}
}

func TestTelemetryV2ResourceSchema(t *testing.T) {
	t.Parallel()

	r := telemetry.NewTelemetryV2Resource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "log_file_path"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in telemetry v2 schema", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected attribute %q to be required", attr)
		}
	}

	computedAttrs := []string{"id", "created", "updated"}
	for _, attr := range computedAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in telemetry v2 schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in telemetry v2 schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// Boolean attrs should be optional + computed (have defaults).
	for _, attr := range []string{
		"collect_diagnostic_and_crash_reports",
		"collect_performance_metrics",
		"file_hashes",
		"log_applications_and_processes",
		"log_access_and_authentication",
		"log_users_and_groups",
		"log_persistence",
		"log_hardware_and_software",
		"log_apple_security",
		"log_system",
	} {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in telemetry v2 schema", attr)
			continue
		}
		if !a.IsOptional() {
			t.Errorf("expected attribute %q to be optional", attr)
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed (has default)", attr)
		}
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in telemetry v2 schema")
	}
}

func TestTelemetryV2ResourceMetadata(t *testing.T) {
	t.Parallel()

	r := telemetry.NewTelemetryV2Resource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_telemetry" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_telemetry", resp.TypeName)
	}
}

// ---------------------------------------------------------------------------
// Data source schema tests
// ---------------------------------------------------------------------------

func TestPlansDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := plan.NewPlansDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	plansAttr, ok := resp.Schema.Attributes["plans"]
	if !ok {
		t.Fatal("expected attribute 'plans' in data source schema")
	}
	if !plansAttr.IsComputed() {
		t.Error("expected 'plans' to be computed")
	}
}

func TestPlansDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := plan.NewPlansDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_plans" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_plans", resp.TypeName)
	}
}

func TestAnalyticsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := analytic.NewAnalyticsDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	analyticsAttr, ok := resp.Schema.Attributes["analytics"]
	if !ok {
		t.Fatal("expected attribute 'analytics' in data source schema")
	}
	if !analyticsAttr.IsComputed() {
		t.Error("expected 'analytics' to be computed")
	}
}

func TestAnalyticsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := analytic.NewAnalyticsDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_analytics" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_analytics", resp.TypeName)
	}
}

func TestActionConfigsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := action_configuration.NewActionConfigsDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	actionConfigsAttr, ok := resp.Schema.Attributes["action_configs"]
	if !ok {
		t.Fatal("expected attribute 'action_configs' in data source schema")
	}
	if !actionConfigsAttr.IsComputed() {
		t.Error("expected 'action_configs' to be computed")
	}
}

func TestActionConfigsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := action_configuration.NewActionConfigsDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_action_configurations" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_action_configurations", resp.TypeName)
	}
}

func TestCustomPreventListsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := custom_prevent_list.NewCustomPreventListsDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	customPreventListsAttr, ok := resp.Schema.Attributes["custom_prevent_lists"]
	if !ok {
		t.Fatal("expected attribute 'custom_prevent_lists' in data source schema")
	}
	if !customPreventListsAttr.IsComputed() {
		t.Error("expected 'custom_prevent_lists' to be computed")
	}
}

func TestCustomPreventListsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := custom_prevent_list.NewCustomPreventListsDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_custom_prevent_lists" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_custom_prevent_lists", resp.TypeName)
	}
}

func TestUnifiedLoggingFiltersDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := unified_logging_filter.NewUnifiedLoggingFiltersDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	filtersAttr, ok := resp.Schema.Attributes["unified_logging_filters"]
	if !ok {
		t.Fatal("expected attribute 'unified_logging_filters' in data source schema")
	}
	if !filtersAttr.IsComputed() {
		t.Error("expected 'unified_logging_filters' to be computed")
	}
}

func TestUnifiedLoggingFiltersDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := unified_logging_filter.NewUnifiedLoggingFiltersDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_unified_logging_filters" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_unified_logging_filters", resp.TypeName)
	}
}

func TestRemovableStorageControlSetsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := removable_storage_control_set.NewRemovableStorageControlSetsDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	_, ok := resp.Schema.Blocks["removable_storage_control_sets"]
	if !ok {
		t.Fatal("expected block 'removable_storage_control_sets' in data source schema")
	}
}

func TestRemovableStorageControlSetsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := removable_storage_control_set.NewRemovableStorageControlSetsDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_removable_storage_control_sets" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_removable_storage_control_sets", resp.TypeName)
	}
}

func TestTelemetriesV2DataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := telemetry.NewTelemetriesV2DataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	telemetriesAttr, ok := resp.Schema.Attributes["telemetries"]
	if !ok {
		t.Fatal("expected attribute 'telemetries' in data source schema")
	}
	if !telemetriesAttr.IsComputed() {
		t.Error("expected 'telemetries' to be computed")
	}
}

func TestTelemetriesV2DataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := telemetry.NewTelemetriesV2DataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_telemetries" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_telemetries", resp.TypeName)
	}
}

func TestAnalyticSetsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := analytic_set.NewAnalyticSetsDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	analyticSetsAttr, ok := resp.Schema.Attributes["analytic_sets"]
	if !ok {
		t.Fatal("expected attribute 'analytic_sets' in data source schema")
	}
	if !analyticSetsAttr.IsComputed() {
		t.Error("expected 'analytic_sets' to be computed")
	}
}

func TestAnalyticSetsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := analytic_set.NewAnalyticSetsDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_analytic_sets" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_analytic_sets", resp.TypeName)
	}
}

func TestExceptionSetsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := exception_set.NewExceptionSetsDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	exceptionSetsAttr, ok := resp.Schema.Attributes["exception_sets"]
	if !ok {
		t.Fatal("expected attribute 'exception_sets' in data source schema")
	}
	if !exceptionSetsAttr.IsComputed() {
		t.Error("expected 'exception_sets' to be computed")
	}
}

func TestExceptionSetsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := exception_set.NewExceptionSetsDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_exception_sets" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_exception_sets", resp.TypeName)
	}
}

func TestProviderDataSources(t *testing.T) {
	t.Parallel()

	provider := New("test")()
	p, ok := provider.(*JamfProtectProvider)
	if !ok {
		t.Fatal("provider is not a *JamfProtectProvider")
	}
	dataSources := p.DataSources(context.Background())

	if len(dataSources) != 9 {
		t.Errorf("expected 9 data sources, got %d", len(dataSources))
	}
}
