package jamfprotect

import (
	"context"
	"fmt"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

// userFields defines the GraphQL fragment for user fields.
const userFields = `
fragment UserFields on User {
	id
	email
	sub @skip(if: $hasLimitedAppAccess)
	connection @include(if: $RBAC_Connection) {
		id
		name
		requireKnownUsers
		source
	}
	assignedRoles @skip(if: $hasLimitedAppAccess) @include(if: $RBAC_Role) {
		id
		name
	}
	assignedGroups @skip(if: $hasLimitedAppAccess) @include(if: $RBAC_Group) {
		id
		name
		assignedRoles @include(if: $RBAC_Role) {
			id
			name
		}
	}
	lastLogin
	source @skip(if: $hasLimitedAppAccess)
	receiveEmailAlert
	emailAlertMinSeverity
	extraAttrs @skip(if: $hasLimitedAppAccess)
	created
	updated
}
`

// listUsersQuery defines the GraphQL query for listing users with pagination and RBAC options.
const listUsersQuery = `
query listUsers($pageSize: Int, $nextToken: String, $direction: OrderDirection!, $field: UserOrderField!, $hasLimitedAppAccess: Boolean!, $RBAC_Connection: Boolean!, $RBAC_Role: Boolean!, $RBAC_Group: Boolean!) {
	listUsers(
		input: {next: $nextToken, pageSize: $pageSize, order: {direction: $direction, field: $field}}
	) {
		items {
			...UserFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + userFields

// getUserQuery defines the GraphQL query for retrieving a user by ID with RBAC options.
const getUserQuery = `
query getUser($id: ID!, $hasLimitedAppAccess: Boolean!, $RBAC_Connection: Boolean!, $RBAC_Role: Boolean!, $RBAC_Group: Boolean!) {
	getUser(id: $id) {
		...UserFields
	}
}
` + userFields

// createUserMutation defines the GraphQL mutation for creating a user.
const createUserMutation = `
mutation createUser($email: AWSEmail!, $roleIds: [ID], $groupIds: [ID], $connectionId: ID, $receiveEmailAlert: Boolean!, $emailAlertMinSeverity: SEVERITY!, $RBAC_Role: Boolean!, $RBAC_Group: Boolean!, $RBAC_Connection: Boolean!, $hasLimitedAppAccess: Boolean!) {
	createUser(
		input: {email: $email, roleIds: $roleIds, groupIds: $groupIds, connectionId: $connectionId, receiveEmailAlert: $receiveEmailAlert, emailAlertMinSeverity: $emailAlertMinSeverity}
	) {
		...UserFields
	}
}
` + userFields

// updateUserMutation defines the GraphQL mutation for updating a user.
const updateUserMutation = `
mutation updateUser($id: ID!, $roleIds: [ID], $groupIds: [ID], $receiveEmailAlert: Boolean!, $emailAlertMinSeverity: SEVERITY!, $RBAC_Role: Boolean!, $RBAC_Group: Boolean!, $RBAC_Connection: Boolean!, $hasLimitedAppAccess: Boolean!) {
	updateUser(
		id: $id
		input: {roleIds: $roleIds, groupIds: $groupIds, receiveEmailAlert: $receiveEmailAlert, emailAlertMinSeverity: $emailAlertMinSeverity}
	) {
		...UserFields
	}
}
` + userFields

// deleteUserMutation defines the GraphQL mutation for deleting a user.
const deleteUserMutation = `
mutation deleteUser($id: ID!) {
	deleteUser(id: $id) {
		id
	}
}
`

// UserInput is the create/update input for a user.
type UserInput struct {
	Email                 string
	RoleIDs               []string
	GroupIDs              []string
	ConnectionID          *string
	ReceiveEmailAlert     bool
	EmailAlertMinSeverity string
}

// UserConnection represents a user connection.
type UserConnection struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	RequireKnownUsers bool   `json:"requireKnownUsers"`
	Source            string `json:"source"`
}

// UserRole represents a role assigned to a user.
type UserRole struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserGroup represents a group assigned to a user.
type UserGroup struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	AssignedRoles []UserRole `json:"assignedRoles"`
}

// User represents a Jamf Protect user.
type User struct {
	ID                    string          `json:"id"`
	Email                 string          `json:"email"`
	Sub                   *string         `json:"sub"`
	Connection            *UserConnection `json:"connection"`
	AssignedRoles         []UserRole      `json:"assignedRoles"`
	AssignedGroups        []UserGroup     `json:"assignedGroups"`
	LastLogin             *string         `json:"lastLogin"`
	Source                string          `json:"source"`
	ReceiveEmailAlert     bool            `json:"receiveEmailAlert"`
	EmailAlertMinSeverity string          `json:"emailAlertMinSeverity"`
	ExtraAttrs            string          `json:"extraAttrs"`
	Created               string          `json:"created"`
	Updated               string          `json:"updated"`
}

// CreateUser creates a new user.
func (s *Service) CreateUser(ctx context.Context, input UserInput) (User, error) {
	vars := buildUserVariables(input)
	var result struct {
		CreateUser User `json:"createUser"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", createUserMutation, vars, &result); err != nil {
		return User{}, fmt.Errorf("CreateUser: %w", err)
	}
	return result.CreateUser, nil
}

// GetUser retrieves a user by ID.
func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
	vars := mergeVars(map[string]any{
		"id":                  id,
		"hasLimitedAppAccess": false,
	}, rbacUser)
	var result struct {
		GetUser *User `json:"getUser"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getUserQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetUser(%s): %w", id, err)
	}
	return result.GetUser, nil
}

// UpdateUser updates an existing user.
func (s *Service) UpdateUser(ctx context.Context, id string, input UserInput) (User, error) {
	vars := buildUserVariables(input)
	vars["id"] = id
	var result struct {
		UpdateUser User `json:"updateUser"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", updateUserMutation, vars, &result); err != nil {
		return User{}, fmt.Errorf("UpdateUser(%s): %w", id, err)
	}
	return result.UpdateUser, nil
}

// DeleteUser deletes a user by ID.
func (s *Service) DeleteUser(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	if err := s.client.DoGraphQL(ctx, "/app", deleteUserMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteUser(%s): %w", id, err)
	}
	return nil
}

// ListUsers retrieves all users.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	users, err := client.ListAll[User](ctx, s.client, "/app", listUsersQuery, mergeVars(map[string]any{
		"pageSize":            100,
		"direction":           "ASC",
		"field":               "email",
		"hasLimitedAppAccess": false,
	}, rbacUser), "listUsers")
	if err != nil {
		return nil, fmt.Errorf("ListUsers: %w", err)
	}
	return users, nil
}

// buildUserVariables builds the GraphQL variables for creating/updating a user from the UserInput.
func buildUserVariables(input UserInput) map[string]any {
	vars := mergeVars(map[string]any{
		"roleIds":               input.RoleIDs,
		"groupIds":              input.GroupIDs,
		"receiveEmailAlert":     input.ReceiveEmailAlert,
		"emailAlertMinSeverity": input.EmailAlertMinSeverity,
		"hasLimitedAppAccess":   false,
		"connectionId":          nil,
	}, rbacUser)

	if input.Email != "" {
		vars["email"] = input.Email
	}

	if input.ConnectionID != nil {
		vars["connectionId"] = *input.ConnectionID
	}

	return vars
}
