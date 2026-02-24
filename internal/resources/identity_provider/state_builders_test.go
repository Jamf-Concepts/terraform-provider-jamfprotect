package identity_provider

import (
	"testing"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/jamfprotect"
)

// TestConnectionAPIToDataSourceItem_AllFields verifies that all API fields are correctly mapped to the data source item model.
func TestConnectionAPIToDataSourceItem_AllFields(t *testing.T) {
	t.Parallel()

	api := jamfprotect.Connection{
		ID:                "34",
		Name:              "okta-connection",
		RequireKnownUsers: true,
		Button:            "okta_button",
		Created:           "2024-03-05T18:22:30.588228Z",
		Updated:           "2026-02-19T16:21:59.677866Z",
		Strategy:          "oidc",
		GroupsSupport:     false,
		Source:            "JAMF_PROTECT_SSO",
	}

	item := connectionAPIToDataSourceItem(api)

	if item.ID.ValueString() != "34" {
		t.Errorf("expected ID %q, got %q", "34", item.ID.ValueString())
	}
	if item.Name.ValueString() != "okta-connection" {
		t.Errorf("expected Name %q, got %q", "okta-connection", item.Name.ValueString())
	}
	if item.RequireKnownUsers.ValueBool() != true {
		t.Errorf("expected RequireKnownUsers true, got false")
	}
	if item.Button.ValueString() != "okta_button" {
		t.Errorf("expected Button %q, got %q", "okta_button", item.Button.ValueString())
	}
	if item.Created.ValueString() != "2024-03-05T18:22:30.588228Z" {
		t.Errorf("expected Created %q, got %q", "2024-03-05T18:22:30.588228Z", item.Created.ValueString())
	}
	if item.Updated.ValueString() != "2026-02-19T16:21:59.677866Z" {
		t.Errorf("expected Updated %q, got %q", "2026-02-19T16:21:59.677866Z", item.Updated.ValueString())
	}
	if item.Strategy.ValueString() != "oidc" {
		t.Errorf("expected Strategy %q, got %q", "oidc", item.Strategy.ValueString())
	}
	if item.GroupsSupport.ValueBool() != false {
		t.Errorf("expected GroupsSupport false, got true")
	}
	if item.Source.ValueString() != "JAMF_PROTECT_SSO" {
		t.Errorf("expected Source %q, got %q", "JAMF_PROTECT_SSO", item.Source.ValueString())
	}
}

// TestConnectionAPIToDataSourceItem_EmptyFields verifies that empty string fields produce empty string values.
func TestConnectionAPIToDataSourceItem_EmptyFields(t *testing.T) {
	t.Parallel()

	api := jamfprotect.Connection{}

	item := connectionAPIToDataSourceItem(api)

	if item.ID.ValueString() != "" {
		t.Errorf("expected empty ID, got %q", item.ID.ValueString())
	}
	if item.Name.ValueString() != "" {
		t.Errorf("expected empty Name, got %q", item.Name.ValueString())
	}
	if item.RequireKnownUsers.ValueBool() != false {
		t.Errorf("expected RequireKnownUsers false, got true")
	}
	if item.Button.ValueString() != "" {
		t.Errorf("expected empty Button, got %q", item.Button.ValueString())
	}
	if item.Created.ValueString() != "" {
		t.Errorf("expected empty Created, got %q", item.Created.ValueString())
	}
	if item.Updated.ValueString() != "" {
		t.Errorf("expected empty Updated, got %q", item.Updated.ValueString())
	}
	if item.Strategy.ValueString() != "" {
		t.Errorf("expected empty Strategy, got %q", item.Strategy.ValueString())
	}
	if item.GroupsSupport.ValueBool() != false {
		t.Errorf("expected GroupsSupport false, got true")
	}
	if item.Source.ValueString() != "" {
		t.Errorf("expected empty Source, got %q", item.Source.ValueString())
	}
}
