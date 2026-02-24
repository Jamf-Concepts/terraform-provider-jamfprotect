// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MPL-2.0

package jamfprotect

import (
	"context"
	"fmt"
)

// dataForwardingGetQuery defines the GraphQL query for data forwarding settings.
const dataForwardingGetQuery = `
query getDataForward {
  getOrganization {
    ...DataForwardFields
  }
}

fragment DataForwardFields on Organization {
  uuid
  forward {
    s3 {
      bucket
      enabled
      encrypted
      prefix
      role
      cloudformation
    }
    sentinel {
      enabled
      customerId
      sharedKey
      logType
      domain
    }
    sentinelV2 {
      enabled
      secretExists
      azureTenantId
      azureClientId
      endpoint
      alerts {
        enabled
        dcrImmutableId
        streamName
      }
      ulogs {
        enabled
        dcrImmutableId
        streamName
      }
      telemetries {
        enabled
        dcrImmutableId
        streamName
      }
      telemetriesV2 {
        enabled
        dcrImmutableId
        streamName
      }
    }
  }
}
`

// dataForwardingUpdateMutation defines the GraphQL mutation for data forwarding settings.
const dataForwardingUpdateMutation = `
mutation updateOrganizationForward($s3: OrganizationS3ForwardInput!, $sentinel: OrganizationSentinelForwardInput!, $sentinelV2: OrganizationSentinelV2ForwardInput!) {
  updateOrganizationForward(
    input: {s3: $s3, sentinel: $sentinel, sentinelV2: $sentinelV2}
  ) {
    ...DataForwardFields
  }
}

fragment DataForwardFields on Organization {
  uuid
  forward {
    s3 {
      bucket
      enabled
      encrypted
      prefix
      role
      cloudformation
    }
    sentinel {
      enabled
      customerId
      sharedKey
      logType
      domain
    }
    sentinelV2 {
      enabled
      secretExists
      azureTenantId
      azureClientId
      endpoint
      alerts {
        enabled
        dcrImmutableId
        streamName
      }
      ulogs {
        enabled
        dcrImmutableId
        streamName
      }
      telemetries {
        enabled
        dcrImmutableId
        streamName
      }
      telemetriesV2 {
        enabled
        dcrImmutableId
        streamName
      }
    }
  }
}
`

// ForwardS3 represents S3 forwarding settings.
type ForwardS3 struct {
	Bucket         string `json:"bucket"`
	Enabled        bool   `json:"enabled"`
	Encrypted      bool   `json:"encrypted"`
	Prefix         string `json:"prefix"`
	Role           string `json:"role"`
	CloudFormation string `json:"cloudformation"`
}

// ForwardSentinel represents Sentinel forwarding settings.
type ForwardSentinel struct {
	Enabled    bool   `json:"enabled"`
	CustomerID string `json:"customerId"`
	SharedKey  string `json:"sharedKey"`
	LogType    string `json:"logType"`
	Domain     string `json:"domain"`
}

// DataStream represents a Sentinel v2 data stream.
type DataStream struct {
	Enabled        bool    `json:"enabled"`
	DcrImmutableID *string `json:"dcrImmutableId"`
	StreamName     *string `json:"streamName"`
}

// ForwardSentinelV2 represents Sentinel v2 forwarding settings.
type ForwardSentinelV2 struct {
	Enabled       bool       `json:"enabled"`
	SecretExists  bool       `json:"secretExists"`
	AzureTenantID string     `json:"azureTenantId"`
	AzureClientID string     `json:"azureClientId"`
	Endpoint      string     `json:"endpoint"`
	Alerts        DataStream `json:"alerts"`
	ULogs         DataStream `json:"ulogs"`
	Telemetries   DataStream `json:"telemetries"`
	TelemetriesV2 DataStream `json:"telemetriesV2"`
}

// DataForwardingSettings represents organization forwarding settings.
type DataForwardingSettings struct {
	S3         ForwardS3         `json:"s3"`
	Sentinel   ForwardSentinel   `json:"sentinel"`
	SentinelV2 ForwardSentinelV2 `json:"sentinelV2"`
}

// ForwardS3Input captures S3 forwarding updates.
type ForwardS3Input struct {
	Bucket    string `json:"bucket"`
	Enabled   bool   `json:"enabled"`
	Encrypted bool   `json:"encrypted"`
	Prefix    string `json:"prefix"`
	Role      string `json:"role"`
}

// ForwardSentinelInput captures Sentinel forwarding updates.
type ForwardSentinelInput struct {
	Enabled    bool   `json:"enabled"`
	CustomerID string `json:"customerId"`
	SharedKey  string `json:"sharedKey"`
	LogType    string `json:"logType"`
	Domain     string `json:"domain"`
}

// DataStreamInput captures Sentinel v2 data stream updates.
type DataStreamInput struct {
	Enabled        bool    `json:"enabled"`
	DcrImmutableID *string `json:"dcrImmutableId,omitempty"`
	StreamName     *string `json:"streamName,omitempty"`
}

// ForwardSentinelV2Input captures Sentinel v2 forwarding updates.
type ForwardSentinelV2Input struct {
	Enabled           bool            `json:"enabled"`
	AzureTenantID     string          `json:"azureTenantId"`
	AzureClientID     string          `json:"azureClientId"`
	AzureClientSecret *string         `json:"azureClientSecret,omitempty"`
	Endpoint          string          `json:"endpoint"`
	Alerts            DataStreamInput `json:"alerts"`
	ULogs             DataStreamInput `json:"ulogs"`
	Telemetries       DataStreamInput `json:"telemetries"`
	TelemetriesV2     DataStreamInput `json:"telemetriesV2"`
}

// DataForwardingInput captures updates for forwarding settings.
type DataForwardingInput struct {
	S3         ForwardS3Input         `json:"s3"`
	Sentinel   ForwardSentinelInput   `json:"sentinel"`
	SentinelV2 ForwardSentinelV2Input `json:"sentinelV2"`
}

// DataForwardingResult represents organization forwarding settings with UUID.
type DataForwardingResult struct {
	UUID    string                 `json:"uuid"`
	Forward DataForwardingSettings `json:"forward"`
}

// GetDataForwarding retrieves organization forwarding settings.
func (s *Service) GetDataForwarding(ctx context.Context) (DataForwardingResult, error) {
	var result struct {
		GetOrganization DataForwardingResult `json:"getOrganization"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", dataForwardingGetQuery, nil, &result); err != nil {
		return DataForwardingResult{}, fmt.Errorf("GetDataForwarding: %w", err)
	}
	return result.GetOrganization, nil
}

// UpdateDataForwarding updates organization forwarding settings.
func (s *Service) UpdateDataForwarding(ctx context.Context, input DataForwardingInput) (DataForwardingResult, error) {
	vars := map[string]any{
		"s3":         input.S3,
		"sentinel":   input.Sentinel,
		"sentinelV2": input.SentinelV2,
	}
	var result struct {
		UpdateOrganizationForward DataForwardingResult `json:"updateOrganizationForward"`
	}
	if err := s.client.DoGraphQL(ctx, "/app", dataForwardingUpdateMutation, vars, &result); err != nil {
		return DataForwardingResult{}, fmt.Errorf("UpdateDataForwarding: %w", err)
	}
	return result.UpdateOrganizationForward, nil
}
