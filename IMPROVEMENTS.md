# Provider Improvements

Ideas for future development of terraform-provider-jamfprotect, roughly ordered by value.

## Provider Enhancements

### Filter Expression Validation

The provider validates enum fields, string lengths, and set values at plan time, but analytic `filter` expressions are only validated by the API at apply time. A plan-time syntax validator would catch malformed filters earlier.

This would require building or vendoring a parser for the Jamf Protect predicate language.

**Effort:** Medium | **Impact:** Medium

### Data Source Filtering

List data sources (e.g. `jamfprotect_analytics`, `jamfprotect_plans`) return all objects. Adding optional filter arguments would let users narrow results server-side rather than using `for` expressions in HCL.

```hcl
data "jamfprotect_analytics" "critical" {
  filter = {
    severity   = ["High"]
    categories = ["Privilege Escalation", "Execution"]
  }
}
```

This depends on whether the GraphQL API supports server-side filtering for each endpoint.

**Effort:** Medium | **Impact:** Low-Medium

## External Modules

These are not provider changes — they belong in separate repositories that consume the provider.

### Analytic Library

A Terraform module providing pre-built analytics for common threat detection patterns (privilege escalation, persistence mechanisms, suspicious downloads, etc.). Users could enable/disable individual analytics and customise severity and tags.

### Plan Profiles

A Terraform module with opinionated plan configurations for common use cases: endpoint protection, compliance, threat hunting, developer workstations. Each profile would wire up appropriate action configurations, telemetry, analytics, and exception sets.

## Not Planned

### Inline Resources in Plans

Plans reference other resources by ID (action configurations, analytic sets, etc.). An alternative would be letting users define these inline within a plan block. This is **not planned** because:

- The Terraform Plugin Framework does not support having both a string attribute and a nested block with the same name
- Implicit resource lifecycle hidden inside another resource breaks Terraform conventions
- The explicit resource model makes dependencies visible and enables reuse across plans
