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
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/exception_set"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/plan"
	"github.com/smithjw/terraform-provider-jamfprotect/internal/resources/prevent_list"
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

	requiredAttrs := []string{"name", "input_type", "filter", "level", "severity", "tags", "categories", "snapshot_files", "analytic_actions", "context"}
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

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in analytic schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in analytic schema")
	}
}

func TestPreventListResourceSchema(t *testing.T) {
	t.Parallel()

	r := prevent_list.NewPreventListResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "type", "tags", "list"}
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

	requiredAttrs := []string{"name", "filter", "level", "tags"}
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

func TestPreventListResourceMetadata(t *testing.T) {
	t.Parallel()

	r := prevent_list.NewPreventListResource()
	resp := &resource.MetadataResponse{}
	r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_prevent_list" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_prevent_list", resp.TypeName)
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

	requiredAttrs := []string{"name", "data_collection"}
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

	// data_collection should be a SingleNestedAttribute containing data with event types.
	collectionAttr, ok := resp.Schema.Attributes["data_collection"]
	if !ok {
		t.Fatal("expected attribute 'data_collection' in schema")
	}
	collectionNested, ok := collectionAttr.(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("expected 'data_collection' to be a SingleNestedAttribute")
	}
	dataAttr, ok := collectionNested.Attributes["data"]
	if !ok {
		t.Fatal("expected 'data' attribute inside data_collection")
	}
	dataNested, ok := dataAttr.(schema.SingleNestedAttribute)
	if !ok {
		t.Fatal("expected 'data' to be a SingleNestedAttribute")
	}

	eventTypes := []string{
		"binary", "synthetic_click_event", "download_event", "file", "file_system_event",
		"group", "process_event", "process", "screenshot_event", "usb_event",
		"user", "gatekeeper_event", "keylog_register_event", "malware_removal_tool_event",
	}
	for _, et := range eventTypes {
		etAttr, ok := dataNested.Attributes[et]
		if !ok {
			t.Errorf("expected event type %q in data_collection.data", et)
			continue
		}
		etNested, ok := etAttr.(schema.SingleNestedAttribute)
		if !ok {
			t.Errorf("expected event type %q to be a SingleNestedAttribute", et)
			continue
		}
		if _, ok := etNested.Attributes["attrs"]; !ok {
			t.Errorf("expected 'attrs' attribute in event type %q", et)
		}
		if _, ok := etNested.Attributes["related"]; !ok {
			t.Errorf("expected 'related' attribute in event type %q", et)
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

	requiredAttrs := []string{"name", "action_configs", "comms_config", "info_sync", "signatures_feed_config"}
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

	optionalAttrs := []string{"description", "log_level", "exception_sets", "telemetry", "telemetry", "removable_storage_control_set", "analytic_sets"}
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

func TestUSBControlSetResourceSchema(t *testing.T) {
	t.Parallel()

	r := removable_storage_control_set.NewUSBControlSetResource()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	requiredAttrs := []string{"name", "default_mount_action", "rules"}
	for _, attr := range requiredAttrs {
		a, ok := resp.Schema.Attributes[attr]
		if !ok {
			t.Errorf("expected attribute %q in USB control set schema", attr)
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
			t.Errorf("expected attribute %q in USB control set schema", attr)
			continue
		}
		if !a.IsComputed() {
			t.Errorf("expected attribute %q to be computed", attr)
		}
	}

	// description should be optional + computed.
	desc, ok := resp.Schema.Attributes["description"]
	if !ok {
		t.Fatal("expected attribute 'description' in USB control set schema")
	}
	if !desc.IsOptional() {
		t.Error("expected 'description' to be optional")
	}
	if !desc.IsComputed() {
		t.Error("expected 'description' to be computed")
	}

	// default_message_action should be optional + computed.
	msgAction, ok := resp.Schema.Attributes["default_message_action"]
	if !ok {
		t.Fatal("expected attribute 'default_message_action' in USB control set schema")
	}
	if !msgAction.IsOptional() {
		t.Error("expected 'default_message_action' to be optional")
	}
	if !msgAction.IsComputed() {
		t.Error("expected 'default_message_action' to be computed")
	}

	// rules should be a ListNestedAttribute.
	rulesAttr, ok := resp.Schema.Attributes["rules"]
	if !ok {
		t.Fatal("expected attribute 'rules' in USB control set schema")
	}
	rulesNested, ok := rulesAttr.(schema.ListNestedAttribute)
	if !ok {
		t.Fatal("expected 'rules' to be a ListNestedAttribute")
	}

	// Verify rule nested attributes.
	ruleAttrs := rulesNested.NestedObject.Attributes
	for _, attr := range []string{"type", "mount_action"} {
		a, ok := ruleAttrs[attr]
		if !ok {
			t.Errorf("expected attribute %q in rules nested object", attr)
			continue
		}
		if !a.IsRequired() {
			t.Errorf("expected rule attribute %q to be required", attr)
		}
	}
	for _, attr := range []string{"message_action", "apply_to", "vendors", "serials", "products"} {
		if _, ok := ruleAttrs[attr]; !ok {
			t.Errorf("expected attribute %q in rules nested object", attr)
		}
	}

	// timeouts should exist.
	if _, ok := resp.Schema.Attributes["timeouts"]; !ok {
		t.Error("expected attribute 'timeouts' in USB control set schema")
	}
}

func TestUSBControlSetResourceMetadata(t *testing.T) {
	t.Parallel()

	r := removable_storage_control_set.NewUSBControlSetResource()
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

	requiredAttrs := []string{"name", "log_files", "events"}
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
	for _, attr := range []string{"log_file_collection", "performance_metrics", "file_hashing"} {
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

func TestPreventListsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := prevent_list.NewPreventListsDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	preventListsAttr, ok := resp.Schema.Attributes["prevent_lists"]
	if !ok {
		t.Fatal("expected attribute 'prevent_lists' in data source schema")
	}
	if !preventListsAttr.IsComputed() {
		t.Error("expected 'prevent_lists' to be computed")
	}
}

func TestPreventListsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := prevent_list.NewPreventListsDataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_prevent_lists" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_prevent_lists", resp.TypeName)
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

func TestUSBControlSetsDataSourceSchema(t *testing.T) {
	t.Parallel()

	ds := removable_storage_control_set.NewUSBControlSetsDataSource()
	resp := &datasource.SchemaResponse{}
	ds.Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	usbAttr, ok := resp.Schema.Attributes["removable_storage_control_sets"]
	if !ok {
		t.Fatal("expected attribute 'removable_storage_control_sets' in data source schema")
	}
	if !usbAttr.IsComputed() {
		t.Error("expected 'removable_storage_control_sets' to be computed")
	}
}

func TestUSBControlSetsDataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := removable_storage_control_set.NewUSBControlSetsDataSource()
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

	telemetriesAttr, ok := resp.Schema.Attributes["telemetries_v2"]
	if !ok {
		t.Fatal("expected attribute 'telemetries_v2' in data source schema")
	}
	if !telemetriesAttr.IsComputed() {
		t.Error("expected 'telemetries_v2' to be computed")
	}
}

func TestTelemetriesV2DataSourceMetadata(t *testing.T) {
	t.Parallel()

	ds := telemetry.NewTelemetriesV2DataSource()
	resp := &datasource.MetadataResponse{}
	ds.Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "jamfprotect"}, resp)

	if resp.TypeName != "jamfprotect_telemetries_v2" {
		t.Errorf("expected TypeName %q, got %q", "jamfprotect_telemetries_v2", resp.TypeName)
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
