// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

const removableStorageControlSetFields = `
fragment USBControlSetFields on USBControlSet {
	id
	name
	description
	defaultMountAction
	defaultMessageAction
	rules {
		mountAction
		messageAction
		type
		... on VendorRule {
			vendors
			applyTo
		}
		... on SerialRule {
			serials
			applyTo
		}
		... on ProductRule {
			products {
			vendor
			product
		}
			applyTo
		}
	}
	plans {
		id
		name
	}
	created
	updated
}
`

const createRemovableStorageControlSetMutation = `
mutation createUSBControlSet(
	$name: String!,
	$description: String,
	$defaultMountAction: USBCONTROL_MOUNT_ACTION_TYPE_ENUM!,
	$defaultMessageAction: String,
	$rules: [USBControlRuleInput!]!
) {
	createUSBControlSet(input: {
		name: $name,
		description: $description,
		defaultMountAction: $defaultMountAction,
		defaultMessageAction: $defaultMessageAction,
		rules: $rules
	}) {
		...USBControlSetFields
	}
}
` + removableStorageControlSetFields

const getRemovableStorageControlSetQuery = `
query getUSBControlSet($id: ID!) {
	getUSBControlSet(id: $id) {
		...USBControlSetFields
	}
}
` + removableStorageControlSetFields

const updateRemovableStorageControlSetMutation = `
mutation updateUSBControlSet(
	$id: ID!,
	$name: String!,
	$description: String,
	$defaultMountAction: USBCONTROL_MOUNT_ACTION_TYPE_ENUM!,
	$defaultMessageAction: String,
	$rules: [USBControlRuleInput!]!
) {
	updateUSBControlSet(id: $id, input: {
		name: $name,
		description: $description,
		defaultMountAction: $defaultMountAction,
		defaultMessageAction: $defaultMessageAction,
		rules: $rules
	}) {
		...USBControlSetFields
	}
}
` + removableStorageControlSetFields

const deleteRemovableStorageControlSetMutation = `
mutation deleteUSBControlSet($id: ID!) {
	deleteUSBControlSet(id: $id) {
		id
	}
}
`

const listRemovableStorageControlSetsQuery = `
query listUSBControlSets($nextToken: String, $direction: OrderDirection!, $field: USBControlOrderField!) {
	listUSBControlSets(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
	) {
		items {
			...USBControlSetFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + removableStorageControlSetFields

// RemovableStorageControlSetInput represents a removable storage control set create/update payload.
type RemovableStorageControlSetInput struct {
	Name                 string
	Description          string
	DefaultMountAction   string
	DefaultMessageAction string
	Rules                []RemovableStorageControlRuleInput
}

// RemovableStorageControlRuleInput represents a removable storage control rule input variant.
type RemovableStorageControlRuleInput struct {
	Type           string                                     `json:"type"`
	VendorRule     *RemovableStorageControlRuleDetails        `json:"vendorRule,omitempty"`
	SerialRule     *RemovableStorageControlRuleDetails        `json:"serialRule,omitempty"`
	ProductRule    *RemovableStorageControlProductRuleDetails `json:"productRule,omitempty"`
	EncryptionRule *RemovableStorageControlRuleDetails        `json:"encryptionRule,omitempty"`
}

// RemovableStorageControlRuleDetails represents shared rule fields.
type RemovableStorageControlRuleDetails struct {
	MountAction   string   `json:"mountAction"`
	MessageAction *string  `json:"messageAction,omitempty"`
	ApplyTo       *string  `json:"applyTo,omitempty"`
	Vendors       []string `json:"vendors,omitempty"`
	Serials       []string `json:"serials,omitempty"`
}

// RemovableStorageControlProductRuleDetails represents product rule details.
type RemovableStorageControlProductRuleDetails struct {
	MountAction   string                               `json:"mountAction"`
	MessageAction *string                              `json:"messageAction,omitempty"`
	ApplyTo       *string                              `json:"applyTo,omitempty"`
	Products      []RemovableStorageControlProductPair `json:"products,omitempty"`
}

// RemovableStorageControlProductPair represents a vendor+product pair.
type RemovableStorageControlProductPair struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// RemovableStorageControlSetPlan represents a plan entry.
type RemovableStorageControlSetPlan struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RemovableStorageControlRule represents a removable storage control rule in API responses.
type RemovableStorageControlRule struct {
	Type          string                               `json:"type"`
	MountAction   string                               `json:"mountAction"`
	MessageAction string                               `json:"messageAction"`
	ApplyTo       string                               `json:"applyTo"`
	Vendors       []string                             `json:"vendors"`
	Serials       []string                             `json:"serials"`
	Products      []RemovableStorageControlProductPair `json:"products"`
}

// RemovableStorageControlSet represents a removable storage control set in API responses.
type RemovableStorageControlSet struct {
	ID                   string                           `json:"id"`
	Name                 string                           `json:"name"`
	Description          string                           `json:"description"`
	DefaultMountAction   string                           `json:"defaultMountAction"`
	DefaultMessageAction string                           `json:"defaultMessageAction"`
	Rules                []RemovableStorageControlRule    `json:"rules"`
	Plans                []RemovableStorageControlSetPlan `json:"plans"`
	Created              string                           `json:"created"`
	Updated              string                           `json:"updated"`
}

// CreateRemovableStorageControlSet creates a new removable storage control set.
func (s *Service) CreateRemovableStorageControlSet(ctx context.Context, input RemovableStorageControlSetInput) (RemovableStorageControlSet, error) {
	vars := map[string]any{
		"name":                 input.Name,
		"description":          input.Description,
		"defaultMountAction":   input.DefaultMountAction,
		"defaultMessageAction": input.DefaultMessageAction,
		"rules":                input.Rules,
	}
	var result struct {
		CreateRemovableStorageControlSet RemovableStorageControlSet `json:"createUSBControlSet"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", createRemovableStorageControlSetMutation, vars, &result); err != nil {
		return RemovableStorageControlSet{}, fmt.Errorf("CreateRemovableStorageControlSet: %w", err)
	}
	return result.CreateRemovableStorageControlSet, nil
}

// GetRemovableStorageControlSet retrieves a removable storage control set by ID.
func (s *Service) GetRemovableStorageControlSet(ctx context.Context, id string) (*RemovableStorageControlSet, error) {
	vars := map[string]any{"id": id}
	var result struct {
		GetRemovableStorageControlSet *RemovableStorageControlSet `json:"getUSBControlSet"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getRemovableStorageControlSetQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetRemovableStorageControlSet(%s): %w", id, err)
	}
	return result.GetRemovableStorageControlSet, nil
}

// UpdateRemovableStorageControlSet updates a removable storage control set by ID.
func (s *Service) UpdateRemovableStorageControlSet(ctx context.Context, id string, input RemovableStorageControlSetInput) (RemovableStorageControlSet, error) {
	vars := map[string]any{
		"id":                   id,
		"name":                 input.Name,
		"description":          input.Description,
		"defaultMountAction":   input.DefaultMountAction,
		"defaultMessageAction": input.DefaultMessageAction,
		"rules":                input.Rules,
	}
	var result struct {
		UpdateRemovableStorageControlSet RemovableStorageControlSet `json:"updateUSBControlSet"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", updateRemovableStorageControlSetMutation, vars, &result); err != nil {
		return RemovableStorageControlSet{}, fmt.Errorf("UpdateRemovableStorageControlSet(%s): %w", id, err)
	}
	return result.UpdateRemovableStorageControlSet, nil
}

// DeleteRemovableStorageControlSet deletes a removable storage control set by ID.
func (s *Service) DeleteRemovableStorageControlSet(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	if err := s.client.DoGraphQL(ctx, "/app", deleteRemovableStorageControlSetMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteRemovableStorageControlSet(%s): %w", id, err)
	}
	return nil
}

// ListRemovableStorageControlSets returns all removable storage control sets.
func (s *Service) ListRemovableStorageControlSets(ctx context.Context) ([]RemovableStorageControlSet, error) {
	items, err := client.ListAll[RemovableStorageControlSet](ctx, s.client, "/app", listRemovableStorageControlSetsQuery, map[string]any{
		"direction": "ASC",
		"field":     "created",
	}, "listUSBControlSets")
	if err != nil {
		return nil, fmt.Errorf("ListRemovableStorageControlSets: %w", err)
	}
	return items, nil
}
