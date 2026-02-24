package data_forwarding

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// amazonS3ForwardingAttrTypes defines the attribute types for amazon_s3.
var amazonS3ForwardingAttrTypes = map[string]attr.Type{
	"bucket_name":             types.StringType,
	"enabled":                 types.BoolType,
	"encrypt_forwarding_data": types.BoolType,
	"prefix":                  types.StringType,
	"iam_role":                types.StringType,
	"cloudformation_template": types.StringType,
	"external_id":             types.StringType,
}

// dataStreamAttrTypes defines the attribute types for a data stream.
var dataStreamAttrTypes = map[string]attr.Type{
	"enabled":                           types.BoolType,
	"data_collection_rule_immutable_id": types.StringType,
	"stream_name":                       types.StringType,
}

// microsoftSentinelForwardingAttrTypes defines the attribute types for microsoft_sentinel.
var microsoftSentinelForwardingAttrTypes = map[string]attr.Type{
	"enabled":                  types.BoolType,
	"secret_exists":            types.BoolType,
	"directory_id":             types.StringType,
	"application_id":           types.StringType,
	"data_collection_endpoint": types.StringType,
	"application_secret_value": types.StringType,
	"alerts":                   types.ObjectType{AttrTypes: dataStreamAttrTypes},
	"unified_logs":             types.ObjectType{AttrTypes: dataStreamAttrTypes},
	"telemetry_deprecated":     types.ObjectType{AttrTypes: dataStreamAttrTypes},
	"telemetry":                types.ObjectType{AttrTypes: dataStreamAttrTypes},
}
