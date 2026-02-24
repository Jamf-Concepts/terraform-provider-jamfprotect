package client

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
)

// PaginatedResult is the common shape returned by all paginated list queries.
type PaginatedResult[T any] struct {
	Items    []T `json:"items"`
	PageInfo struct {
		Next  *string `json:"next"`
		Total int     `json:"total"`
	} `json:"pageInfo"`
}

// ListAll executes a paginated GraphQL list query, accumulating all pages.
// The resultKey must match the JSON field name of the list operation in the
// GraphQL response (e.g. "listGroups", "listRoles").
func ListAll[T any](
	ctx context.Context,
	c *Client,
	endpoint string,
	query string,
	baseVars map[string]any,
	resultKey string,
) ([]T, error) {
	var allItems []T
	var nextToken *string

	for {
		vars := maps.Clone(baseVars)
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		raw := make(map[string]json.RawMessage)
		if err := c.DoGraphQL(ctx, endpoint, query, vars, &raw); err != nil {
			return nil, err
		}

		data, ok := raw[resultKey]
		if !ok {
			return nil, fmt.Errorf("response missing expected key %q", resultKey)
		}

		var page PaginatedResult[T]
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("decoding %s: %w", resultKey, err)
		}

		allItems = append(allItems, page.Items...)
		if page.PageInfo.Next == nil {
			break
		}
		nextToken = page.PageInfo.Next
	}

	return allItems, nil
}
