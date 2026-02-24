package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/terraform-provider-jamfprotect/internal/client"
)

// apiClientFields defines the GraphQL fragment for API client fields.
const apiClientFields = `
fragment ApiClientFields on ApiClient {
	clientId
	created
	name
	assignedRoles {
		id
		name
	}
	password
}
`

// listApiClientsQuery defines the GraphQL query for listing API clients.
const listApiClientsQuery = `
query listApiClients($nextToken: String, $direction: OrderDirection!, $field: ApiClientOrderField!) {
	listApiClients(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
	) {
		items {
			...ApiClientFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + apiClientFields

// getApiClientQuery defines the GraphQL query for retrieving an API client by ID.
const getApiClientQuery = `
query getApiClient($clientId: ID!) {
	getApiClient(clientId: $clientId) {
		...ApiClientFields
	}
}
` + apiClientFields

// createApiClientMutation defines the GraphQL mutation for creating an API client.
const createApiClientMutation = `
mutation createApiClient($name: String!, $roleIds: [ID]) {
	createApiClient(input: {name: $name, roleIds: $roleIds}) {
		...ApiClientFields
	}
}
` + apiClientFields

// updateApiClientMutation defines the GraphQL mutation for updating an API client.
const updateApiClientMutation = `
mutation updateApiClient($clientId: ID!, $name: String!, $roleIds: [ID]) {
	updateApiClient(clientId: $clientId, input: {name: $name, roleIds: $roleIds}) {
		...ApiClientFields
	}
}
` + apiClientFields

// deleteApiClientMutation defines the GraphQL mutation for deleting an API client.
const deleteApiClientMutation = `
mutation deleteApiClient($clientId: ID!) {
	deleteApiClient(clientId: $clientId) {
		clientId
	}
}
`

// ApiClientInput is the create/update input for an API client.
type ApiClientInput struct {
	Name    string
	RoleIDs []string
}

// ApiClientRole represents a role assigned to an API client.
type ApiClientRole struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ApiClient represents an API client in Jamf Protect.
type ApiClient struct {
	ClientID      string          `json:"clientId"`
	Created       string          `json:"created"`
	Name          string          `json:"name"`
	AssignedRoles []ApiClientRole `json:"assignedRoles"`
	Password      string          `json:"password"`
}

// CreateApiClient creates a new API client.
func (s *Service) CreateApiClient(ctx context.Context, input ApiClientInput) (ApiClient, error) {
	vars := buildApiClientVariables(input)
	var result struct {
		CreateApiClient ApiClient `json:"createApiClient"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", createApiClientMutation, vars, &result); err != nil {
		return ApiClient{}, fmt.Errorf("CreateApiClient: %w", err)
	}
	return result.CreateApiClient, nil
}

// GetApiClient retrieves an API client by ID.
func (s *Service) GetApiClient(ctx context.Context, clientID string) (*ApiClient, error) {
	vars := map[string]any{"clientId": clientID}
	var result struct {
		GetApiClient *ApiClient `json:"getApiClient"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", getApiClientQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetApiClient(%s): %w", clientID, err)
	}
	return result.GetApiClient, nil
}

// UpdateApiClient updates an existing API client.
func (s *Service) UpdateApiClient(ctx context.Context, clientID string, input ApiClientInput) (ApiClient, error) {
	vars := buildApiClientVariables(input)
	vars["clientId"] = clientID
	var result struct {
		UpdateApiClient ApiClient `json:"updateApiClient"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", updateApiClientMutation, vars, &result); err != nil {
		return ApiClient{}, fmt.Errorf("UpdateApiClient(%s): %w", clientID, err)
	}
	return result.UpdateApiClient, nil
}

// DeleteApiClient deletes an API client by ID.
func (s *Service) DeleteApiClient(ctx context.Context, clientID string) error {
	vars := map[string]any{"clientId": clientID}
	if err := s.client.DoGraphQL(ctx, "/app", deleteApiClientMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteApiClient(%s): %w", clientID, err)
	}
	return nil
}

// ListApiClients retrieves all API clients.
func (s *Service) ListApiClients(ctx context.Context) ([]ApiClient, error) {
	clients, err := client.ListAll[ApiClient](ctx, s.client, "/app", listApiClientsQuery, map[string]any{
		"direction": "DESC",
		"field":     "created",
	}, "listApiClients")
	if err != nil {
		return nil, fmt.Errorf("ListApiClients: %w", err)
	}
	return clients, nil
}

// buildApiClientVariables builds the GraphQL variables for creating/updating an API client.
func buildApiClientVariables(input ApiClientInput) map[string]any {
	return map[string]any{
		"name":    input.Name,
		"roleIds": input.RoleIDs,
	}
}
