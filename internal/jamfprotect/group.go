// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import "context"

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
		return Group{}, err
	}
	return result.CreateGroup, nil
}

// GetGroup retrieves a group by ID.
func (s *Service) GetGroup(ctx context.Context, id string) (*Group, error) {
	vars := map[string]any{
		"id":              id,
		"RBAC_Connection": true,
		"RBAC_Role":       true,
	}
	var result struct {
		GetGroup *Group `json:"getGroup"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getGroupQuery, vars, &result); err != nil {
		return nil, err
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
		return Group{}, err
	}
	return result.UpdateGroup, nil
}

// DeleteGroup deletes a group by ID.
func (s *Service) DeleteGroup(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	return s.client.DoGraphQL(ctx, "/app", deleteGroupMutation, vars, nil)
}

// ListGroups retrieves all groups.
func (s *Service) ListGroups(ctx context.Context) ([]Group, error) {
	allItems := make([]Group, 0)
	var nextToken *string

	for {
		vars := map[string]any{
			"pageSize":        100,
			"direction":       "ASC",
			"field":           "name",
			"RBAC_Connection": true,
			"RBAC_Role":       true,
		}
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		var result struct {
			ListGroups struct {
				Items    []Group `json:"items"`
				PageInfo struct {
					Next  *string `json:"next"`
					Total int     `json:"total"`
				} `json:"pageInfo"`
			} `json:"listGroups"`
		}
		if err := s.client.DoGraphQL(ctx, "/app", listGroupsQuery, vars, &result); err != nil {
			return nil, err
		}

		allItems = append(allItems, result.ListGroups.Items...)
		if result.ListGroups.PageInfo.Next == nil {
			break
		}
		nextToken = result.ListGroups.PageInfo.Next
	}

	return allItems, nil
}

// buildGroupVariables builds the GraphQL variables for creating/updating a group from the GroupInput.
func buildGroupVariables(input GroupInput) map[string]any {
	vars := map[string]any{
		"name":            input.Name,
		"roleIds":         input.RoleIDs,
		"accessGroup":     input.AccessGroup,
		"RBAC_Connection": true,
		"RBAC_Role":       true,
		"connectionId":    nil,
	}

	if input.ConnectionID != nil {
		vars["connectionId"] = *input.ConnectionID
	}

	return vars
}
