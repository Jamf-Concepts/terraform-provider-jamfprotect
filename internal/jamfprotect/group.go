// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/client"
)

// groupFields defines the GraphQL fragment for group fields.
const groupFields = `
fragment GroupFields on Group {
	id
	name
	connection @include(if: $RBAC_Connection) {
		id
		name
	}
	assignedRoles @include(if: $RBAC_Role) {
		id
		name
	}
	accessGroup
	created
	updated
}
`

// listGroupsQuery defines the GraphQL query for listing groups with pagination and RBAC options.
const listGroupsQuery = `
query listGroups($pageSize: Int, $nextToken: String, $direction: OrderDirection!, $field: GroupOrderField!, $RBAC_Connection: Boolean!, $RBAC_Role: Boolean!) {
	listGroups(
		input: {next: $nextToken, pageSize: $pageSize, order: {direction: $direction, field: $field}}
	) {
		items {
			...GroupFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + groupFields

// getGroupQuery defines the GraphQL query for retrieving a group by ID with RBAC options.
const getGroupQuery = `
query getGroup($id: ID!, $RBAC_Connection: Boolean!, $RBAC_Role: Boolean!) {
	getGroup(id: $id) {
		...GroupFields
	}
}
` + groupFields

// createGroupMutation defines the GraphQL mutation for creating a group.
const createGroupMutation = `
mutation createGroup($name: String!, $connectionId: ID, $accessGroup: Boolean, $roleIds: [ID], $RBAC_Connection: Boolean!, $RBAC_Role: Boolean!) {
	createGroup(
		input: {name: $name, connectionId: $connectionId, accessGroup: $accessGroup, roleIds: $roleIds}
	) {
		...GroupFields
	}
}
` + groupFields

// updateGroupMutation defines the GraphQL mutation for updating a group.
const updateGroupMutation = `
mutation updateGroup($id: ID!, $name: String!, $accessGroup: Boolean, $roleIds: [ID], $RBAC_Connection: Boolean!, $RBAC_Role: Boolean!) {
	updateGroup(
		id: $id
		input: {name: $name, accessGroup: $accessGroup, roleIds: $roleIds}
	) {
		...GroupFields
	}
}
` + groupFields

// deleteGroupMutation defines the GraphQL mutation for deleting a group.
const deleteGroupMutation = `
mutation deleteGroup($id: ID!) {
	deleteGroup(id: $id) {
		id
	}
}
`

// GroupInput is the create/update input for a group.
type GroupInput struct {
	Name         string
	ConnectionID *string
	AccessGroup  bool
	RoleIDs      []string
}

// GroupConnection represents a group connection.
type GroupConnection struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GroupRole represents a role assigned to a group.
type GroupRole struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Group represents a Jamf Protect group.
type Group struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Connection    *GroupConnection `json:"connection"`
	AssignedRoles []GroupRole      `json:"assignedRoles"`
	AccessGroup   bool             `json:"accessGroup"`
	Created       string           `json:"created"`
	Updated       string           `json:"updated"`
}

// CreateGroup creates a new group.
func (s *Service) CreateGroup(ctx context.Context, input GroupInput) (Group, error) {
	vars := buildGroupVariables(input)
	var result struct {
		CreateGroup Group `json:"createGroup"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", createGroupMutation, vars, &result); err != nil {
		return Group{}, fmt.Errorf("CreateGroup: %w", err)
	}
	return result.CreateGroup, nil
}

// GetGroup retrieves a group by ID.
func (s *Service) GetGroup(ctx context.Context, id string) (*Group, error) {
	vars := mergeVars(map[string]any{
		"id": id,
	}, rbacGroup)
	var result struct {
		GetGroup *Group `json:"getGroup"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getGroupQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetGroup(%s): %w", id, err)
	}
	return result.GetGroup, nil
}

// UpdateGroup updates an existing group.
func (s *Service) UpdateGroup(ctx context.Context, id string, input GroupInput) (Group, error) {
	vars := buildGroupVariables(input)
	vars["id"] = id
	var result struct {
		UpdateGroup Group `json:"updateGroup"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", updateGroupMutation, vars, &result); err != nil {
		return Group{}, fmt.Errorf("UpdateGroup(%s): %w", id, err)
	}
	return result.UpdateGroup, nil
}

// DeleteGroup deletes a group by ID.
func (s *Service) DeleteGroup(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	if err := s.client.DoGraphQL(ctx, "/app", deleteGroupMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteGroup(%s): %w", id, err)
	}
	return nil
}

// ListGroups retrieves all groups.
func (s *Service) ListGroups(ctx context.Context) ([]Group, error) {
	groups, err := client.ListAll[Group](ctx, s.client, "/app", listGroupsQuery, mergeVars(map[string]any{
		"pageSize":  100,
		"direction": "ASC",
		"field":     "name",
	}, rbacGroup), "listGroups")
	if err != nil {
		return nil, fmt.Errorf("ListGroups: %w", err)
	}
	return groups, nil
}

// buildGroupVariables builds the GraphQL variables for creating/updating a group from the GroupInput.
func buildGroupVariables(input GroupInput) map[string]any {
	vars := mergeVars(map[string]any{
		"name":         input.Name,
		"roleIds":      input.RoleIDs,
		"accessGroup":  input.AccessGroup,
		"connectionId": nil,
	}, rbacGroup)

	if input.ConnectionID != nil {
		vars["connectionId"] = *input.ConnectionID
	}

	return vars
}
