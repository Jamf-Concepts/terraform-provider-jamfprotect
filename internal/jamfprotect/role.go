// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

// roleFields defines the GraphQL fragment for role fields.
const roleFields = `
fragment RoleFields on Role {
	id
	name
	permissions {
		R
		W
	}
	created
	updated
}
`

// listRolesQuery defines the GraphQL query for listing roles.
const listRolesQuery = `
query listRoles($pageSize: Int, $nextToken: String, $direction: OrderDirection!, $field: RoleOrderField!) {
	listRoles(
		input: {next: $nextToken, pageSize: $pageSize, order: {direction: $direction, field: $field}}
	) {
		items {
			...RoleFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + roleFields

// getRoleQuery defines the GraphQL query for retrieving a role by ID.
const getRoleQuery = `
query getRole($id: ID!) {
	getRole(id: $id) {
		...RoleFields
	}
}
` + roleFields

// createRoleMutation defines the GraphQL mutation for creating a role.
const createRoleMutation = `
mutation createRole($name: String!, $readResources: [RBAC_RESOURCE!]!, $writeResources: [RBAC_RESOURCE!]!) {
	createRole(
		input: {name: $name, readResources: $readResources, writeResources: $writeResources}
	) {
		...RoleFields
	}
}
` + roleFields

// updateRoleMutation defines the GraphQL mutation for updating a role.
const updateRoleMutation = `
mutation updateRole($id: ID!, $name: String!, $readResources: [RBAC_RESOURCE!]!, $writeResources: [RBAC_RESOURCE!]!) {
	updateRole(
		id: $id
		input: {name: $name, readResources: $readResources, writeResources: $writeResources}
	) {
		...RoleFields
	}
}
` + roleFields

// deleteRoleMutation defines the GraphQL mutation for deleting a role.
const deleteRoleMutation = `
mutation deleteRole($id: ID!) {
	deleteRole(id: $id) {
		...RoleFields
	}
}
` + roleFields

// RoleInput is the create/update input for a role.
type RoleInput struct {
	Name           string
	ReadResources  []string
	WriteResources []string
}

// RolePermissions represents role permissions.
type RolePermissions struct {
	Read  []string `json:"R"`
	Write []string `json:"W"`
}

// Role represents a Jamf Protect role.
type Role struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Permissions RolePermissions `json:"permissions"`
	Created     string          `json:"created"`
	Updated     string          `json:"updated"`
}

// CreateRole creates a new role.
func (s *Service) CreateRole(ctx context.Context, input RoleInput) (Role, error) {
	vars := buildRoleVariables(input)
	var result struct {
		CreateRole Role `json:"createRole"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", createRoleMutation, vars, &result); err != nil {
		return Role{}, err
	}
	return result.CreateRole, nil
}

// GetRole retrieves a role by ID.
func (s *Service) GetRole(ctx context.Context, id string) (*Role, error) {
	vars := map[string]any{"id": id}
	var result struct {
		GetRole *Role `json:"getRole"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getRoleQuery, vars, &result); err != nil {
		return nil, err
	}
	return result.GetRole, nil
}

// UpdateRole updates an existing role.
func (s *Service) UpdateRole(ctx context.Context, id string, input RoleInput) (Role, error) {
	vars := buildRoleVariables(input)
	vars["id"] = id
	var result struct {
		UpdateRole Role `json:"updateRole"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", updateRoleMutation, vars, &result); err != nil {
		return Role{}, err
	}
	return result.UpdateRole, nil
}

// DeleteRole deletes a role by ID.
func (s *Service) DeleteRole(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	return s.client.DoGraphQL(ctx, "/app", deleteRoleMutation, vars, nil)
}

// ListRoles retrieves all roles.
func (s *Service) ListRoles(ctx context.Context) ([]Role, error) {
	return client.ListAll[Role](ctx, s.client, "/app", listRolesQuery, map[string]any{
		"pageSize":  100,
		"direction": "ASC",
		"field":     "name",
	}, "listRoles")
}

// buildRoleVariables builds the GraphQL variables for creating/updating a role.
func buildRoleVariables(input RoleInput) map[string]any {
	return map[string]any{
		"name":           input.Name,
		"readResources":  input.ReadResources,
		"writeResources": input.WriteResources,
	}
}
