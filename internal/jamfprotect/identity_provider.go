// Copyright (c) James Smith 2025
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/smithjw/terraform-provider-jamfprotect/internal/client"
)

// connectionFields defines the GraphQL fragment for identity provider connection fields.
const connectionFields = `
fragment ConnectionFields on Connection {
	id
	name
	requireKnownUsers
	button
	created
	updated
	strategy
	groupsSupport
	source
}
`

// listConnectionsQuery defines the GraphQL query for listing identity provider connections.
const listConnectionsQuery = `
query listConnections($pageSize: Int, $nextToken: String, $direction: OrderDirection!, $field: ConnectionOrderField!) {
	listConnections(
		input: {next: $nextToken, pageSize: $pageSize, order: {direction: $direction, field: $field}}
	) {
		items {
			...ConnectionFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + connectionFields

// Connection represents an identity provider connection in Jamf Protect.
type Connection struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	RequireKnownUsers bool   `json:"requireKnownUsers"`
	Button            string `json:"button"`
	Created           string `json:"created"`
	Updated           string `json:"updated"`
	Strategy          string `json:"strategy"`
	GroupsSupport     bool   `json:"groupsSupport"`
	Source            string `json:"source"`
}

// ListConnections retrieves all identity provider connections.
func (s *Service) ListConnections(ctx context.Context) ([]Connection, error) {
	connections, err := client.ListAll[Connection](ctx, s.client, "/app", listConnectionsQuery, map[string]any{
		"direction": "ASC",
		"field":     "name",
	}, "listConnections")
	if err != nil {
		return nil, fmt.Errorf("ListConnections: %w", err)
	}
	return connections, nil
}
