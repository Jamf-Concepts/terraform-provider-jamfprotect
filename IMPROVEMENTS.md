# Provider Improvements for v0.2.0+

This document outlines potential improvements to make the terraform-provider-jamfprotect more user-friendly, efficient, and idiomatic Terraform.

## 🎯 High Priority - Adoption Accelerators

### 1. **Simplified Plan Resource with Inline Resources** (HIGH IMPACT)

**Problem:** Users must create separate resources for action_configuration, analytic_sets, etc., then reference them by ID in plans.

**Current Experience:**

```hcl
resource "jamfprotect_action_config" "default" {
  name = "Default Action Config"
  # ... complex configuration
}

resource "jamfprotect_plan" "main" {
  name           = "My Plan"
  action_configuration = jamfprotect_action_config.default.id  # String ID reference
}
```

**Improved Experience:**

```hcl
resource "jamfprotect_plan" "main" {
  name = "My Plan"
  
  # Option 1: Reference existing resource
  action_configuration = jamfprotect_action_config.default.id
  
  # Option 2: Inline definition (provider manages lifecycle)
  action_configuration {
    name = "Inline Action Config"
    alert_config {
      # ... configuration
    }
  }
}
```

**Implementation:**

- Add `action_configuration` SingleNestedBlock alongside `action_configuration` string attribute
- Use ConflictsWith validator to ensure only one is set
- Provider internally creates/updates/deletes the inline resource
- Similar pattern for: `analytic_set`, `exception_set`, `telemetry_v2`, `usb_control_set`

**Benefits:**

- Reduces boilerplate by 50%+
- Clearer ownership model (plan owns inline resources)
- Easier for beginners

---

### 2. **Analytic Library Module** (HIGH IMPACT)

**Problem:** Users must write complex filter expressions and know all valid `input_type` values, context types, and action parameters.

**Solution:** Provide a Terraform module with pre-built analytics as a library.

**Structure:**

```
modules/
  analytic-library/
    main.tf                    # Module entry point
    variables.tf               # Customization variables
    outputs.tf                 # Analytic IDs
    analytics/
      process/
        suspicious_process.tf
        privilege_escalation.tf
        crypto_miner.tf
      file/
        ransomware_detection.tf
        sensitive_file_access.tf
      network/
        c2_communication.tf
```

**Usage:**

```hcl
module "security_analytics" {
  source = "github.com/smithjw/terraform-jamfprotect-analytics"
  
  # Enable specific analytics
  enable_suspicious_process    = true
  enable_privilege_escalation  = true
  enable_ransomware_detection  = true
  
  # Customize thresholds
  suspicious_process_severity = "Critical"
  
  # Tags applied to all analytics
  tags = ["production", "finance-dept"]
}

resource "jamfprotect_analytic_set" "critical" {
  name      = "Critical Security Analytics"
  analytics = module.security_analytics.enabled_analytic_ids
}
```

**Benefits:**

- Immediate value - users don't need to learn Jamf Protect query language
- Best practices codified
- Community contributions
- Version-controlled analytic updates

---

### 3. **Plan Templates / Profiles** (MEDIUM IMPACT)

**Problem:** Creating a production-ready plan requires understanding many settings.

**Solution:** Provide plan "profiles" as preset configurations.

**Implementation via Module:**

```hcl
module "standard_plan" {
  source = "./modules/plan-profiles"
  
  profile = "endpoint-protection"  # or "compliance", "threat-hunting", "minimal"
  
  # Customizations
  plan_name        = "Production Endpoints"
  tenant_fqdn      = "example.protect.jamfcloud.com"
  auto_update      = true
  telemetry_level  = "standard"  # minimal, standard, verbose
}

# Use the plan
output "plan_id" {
  value = module.standard_plan.plan_id
}
```

**Profiles:**

- `endpoint-protection` - Balanced security + performance
- `compliance` - NIST, CIS benchmarks
- `threat-hunting` - Maximum telemetry, all analytics
- `minimal` - Lightweight, essential security only
- `developer` - Reduced noise, dev-friendly exceptions

---

## 🔧 Medium Priority - User Experience

### 4. **Analytic Set Smart Selection** (MEDIUM IMPACT)

**Problem:** Users must manually list analytic UUIDs or use complex for-loops with data sources.

**Current:**

```hcl
data "jamfprotect_analytics" "all" {}

resource "jamfprotect_analytic_set" "critical" {
  analytics = [
    for a in data.jamfprotect_analytics.all.analytics :
    a.id if contains(a.tags, "critical") && a.severity == "High"
  ]
}
```

**Improved with Dynamic Block Helper:**

```hcl
resource "jamfprotect_analytic_set" "critical" {
  name = "Critical Analytics"
  
  # Filter criteria (provider does the lookup)
  analytic_filter {
    tags         = ["critical", "production"]
    severity     = ["High", "Critical"]
    categories   = ["Execution", "Privilege Escalation"]
    min_level    = 5
    input_types  = ["GPProcessEvent", "GPFSEvent"]
  }
}
```

**Implementation:**

- Add `analytic_filter` block to `jamfprotect_analytic_set` resource
- Provider queries analytics data source internally
- Filters applied server-side or client-side
- Computed `analytics` attribute shows resolved UUIDs

---

### 5. **Validation Helpers** (MEDIUM IMPACT)

**Problem:** Users don't know if their filter expressions or context types are valid until Terraform apply fails.

**Solution 1: Plan-Time Validation**

```hcl
resource "jamfprotect_analytic" "test" {
  name       = "Test Analytic"
  input_type = "GPProcessEvent"
  filter     = "( $event.process.name == 'malware' )"  # Validated at plan time
  
  # Provider validates:
  # - Filter syntax
  # - Available fields for input_type
  # - Context type compatibility
}
```

**Solution 2: Terraform `validate` Command Support**

```bash
terraform validate
# Provider checks:
# ✓ All filter expressions are syntactically valid
# ✓ All referenced fields exist for the input_type
# ✓ All context types are valid
# ✓ Action parameters match expected schema
```

**Implementation:**

- Add custom validators using `terraform-plugin-framework/resource/schema/validator`
- Optionally: HTTP call to Jamf Protect API for server-side validation (with caching)

---

### 6. **Exception Set Builder** (LOW-MEDIUM IMPACT)

**Problem:** Exception sets have complex nested structure with many optional fields.

**Current:**

```hcl
resource "jamfprotect_exception_set" "dev" {
  name = "Developer Exceptions"
  
  exceptions = [
    {
      type            = "User"
      value           = "developer"
      ignore_activity = "Analytics"
      analytic_types  = ["GPProcessEvent"]
    },
    # ... repeat for each exception
  ]
}
```

**Improved with Helper Functions (Terraform 1.8+):**

```hcl
resource "jamfprotect_exception_set" "dev" {
  name = "Developer Exceptions"
  
  # Helper functions for common patterns
  exceptions = concat(
    jamfprotect_exception_user(["developer", "tester"], ["GPProcessEvent"]),
    jamfprotect_exception_path(["/tmp/*", "/var/log/*"], ["GPFSEvent"]),
    jamfprotect_exception_team_id(["ABC123XYZ"], all_analytics = true)
  )
}
```

**Note:** This requires provider-defined functions (Terraform Plugin Framework 1.4+). Alternative: use locals for now.

---

## 🚀 Advanced Features

### 7. **Drift Detection Enhancements** (LOW IMPACT)

**Problem:** Jamf Protect allows manual edits in UI. Terraform doesn't detect some field changes.

**Solution:** Add computed fields for commonly modified attributes:

```hcl
resource "jamfprotect_plan" "main" {
  name = "Production Plan"
  
  # ... configuration
  
  # Computed attributes for drift detection
  last_modified_by  = "user@example.com"  # Computed
  last_modified_at  = "2026-02-13T..."     # Computed
  modified_in_ui    = false                # Computed, true if hash mismatch
}
```

**Implementation:**

- Add `lastModifiedBy`, `lastModifiedAt` to GraphQL queries
- Provider compares configuration hash with API hash
- Set `modified_in_ui` computed field when mismatch detected

---

### 8. **Bulk Import Tool** (LOW IMPACT)

**Problem:** Migrating existing Jamf Protect configuration to Terraform requires manual `terraform import` for each resource.

**Solution:** CLI tool to generate Terraform configuration from existing tenant.

**Usage:**

```bash
# Export all resources from tenant
tfprotect export \
  --url https://tenant.protect.jamfcloud.com \
  --client-id $CLIENT_ID \
  --client-secret $CLIENT_SECRET \
  --output ./jamfprotect/

# Generates:
# ./jamfprotect/
#   analytics.tf          # All analytics
#   analytic_sets.tf      # All analytic sets
#   exception_sets.tf     # All exception sets
#   plans.tf              # All plans
#   imports.sh            # terraform import commands
```

**Implementation:**

- Separate CLI tool (not in provider)
- Uses same GraphQL client
- Generates `.tf` files + `terraform import` script
- Optional: `--filter` for selective export

---

### 9. **State Migration Helpers** (LOW IMPACT)

**Problem:** API changes or resource refactoring can break existing Terraform state.

**Solution:** Provide state migration resources or documentation.

**Documentation:**

```markdown
## Migrating from v0.1.0 to v0.2.0

### Analytic Action Parameters Changed from String to Map

Before (v0.1.0):
```hcl
analytic_actions = [{
  name       = "SmartGroup"
  parameters = "{\"id\":\"smartgroup\"}"
}]
```

After (v0.2.0):

```hcl
analytic_actions = [{
  name       = "SmartGroup"
  parameters = {
    id = "smartgroup"
  }
}]
```

**Migration:**

```bash
# Update terraform configuration, then:
terraform state rm 'jamfprotect_analytic.example'
terraform import 'jamfprotect_analytic.example' uuid-here
```

```

---

### 10. **Testing Utilities** (LOW IMPACT)

**Problem:** Users can't easily test analytics before deploying to production.

**Solution:** Add `test_mode` or `dry_run` capabilities.

**Possible Implementation:**
```hcl
resource "jamfprotect_analytic" "test" {
  name       = "Test Analytic"
  input_type = "GPProcessEvent"
  filter     = "( $event.process.name == 'test' )"
  
  # Optional: don't activate in Jamf Protect yet
  enabled = false
  
  lifecycle {
    # Prevent accidental activation
    prevent_destroy = true
  }
}
```

Or provide a data source for validation:

```hcl
data "jamfprotect_analytic_validation" "test" {
  input_type = "GPProcessEvent"
  filter     = "( $event.process.name == 'test' )"
  
  # Returns: valid, error_message, available_fields
}

output "is_valid" {
  value = data.jamfprotect_analytic_validation.test.valid
}
```

---

## 📊 Priority Matrix

| Feature | Impact | Effort | Priority | Version |
|---------|--------|--------|----------|---------|
| Simplified Plan (Inline Resources) | High | High | P1 | v0.3.0 |
| Analytic Library Module | High | Medium | P1 | v0.2.0 |
| Plan Templates/Profiles | Medium | Medium | P2 | v0.2.0 |
| Analytic Set Smart Selection | Medium | Medium | P2 | v0.3.0 |
| Validation Helpers | Medium | Low | P2 | v0.2.0 |
| Exception Set Builder | Low-Med | Low | P3 | v0.3.0 |
| Drift Detection | Low | Low | P3 | v0.4.0 |
| Bulk Import Tool | Low | High | P3 | v0.4.0 |
| State Migration Helpers | Low | Low | P4 | As needed |
| Testing Utilities | Low | Medium | P4 | v0.4.0 |

---

## 🎯 Recommended Roadmap

### v0.2.0 - Quick Wins (Next Release)

- ✅ Analytic Library Module (external repo)
- ✅ Plan Templates Module (external repo)
- ✅ Basic validation helpers
- ✅ Documentation improvements

### v0.3.0 - Major UX Improvements

- ✅ Inline resource support for Plans
- ✅ Analytic Set smart filtering
- ✅ Exception Set builder functions

### v0.4.0 - Advanced Features

- ✅ Bulk import tool
- ✅ Enhanced drift detection
- ✅ Testing utilities

---

## 💡 Additional Considerations

### Error Messages

- Add more helpful error messages with suggestions
- Include links to documentation
- Provide examples of correct syntax

### Documentation

- Add more examples for common use cases
- Create video tutorials
- Provide migration guides

### Community

- Set up GitHub Discussions for questions
- Create examples repository
- Encourage community contributions

---

## 🚀 Quick Start for v0.2.0

To implement the highest-impact features in v0.2.0:

1. **Create separate repository: `terraform-jamfprotect-modules`**
   - `modules/analytic-library/` - Pre-built analytics
   - `modules/plan-profiles/` - Standard plan configurations
   - `examples/` - Common patterns

2. **Add validation to existing resources**
   - Custom validators for filter syntax
   - Validators for enum fields with suggestions
   - Better error messages

3. **Improve documentation**
   - Add "Getting Started" guide
   - Add "Common Patterns" guide
   - Add "Best Practices" guide

Would you like me to start implementing any of these improvements for v0.2.0?
