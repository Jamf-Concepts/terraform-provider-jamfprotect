# Provider Schema Improvement TODO

Tracking improvements to make the provider feel idiomatic Terraform rather than a raw GraphQL API wrapper.

## Remaining

- [ ] **#2** Restructure `action_config` `alert_config` from JSON blob to typed nested blocks (DO LAST)
  - Model 14 event types as optional `SingleNestedBlock`s
  - Each with `attributes` (list of strings) and `related` (list of strings)
  - Consider keeping `jsonencode()` escape hatch alongside typed blocks

## Completed

- [x] **#9** Add operation timeouts via `terraform-plugin-framework-timeouts` v0.7.0
  - Added `timeouts` attribute (attribute syntax, not block) to all 5 resources
  - All CRUD operations wrapped with `context.WithTimeout` (30s default)
  - Updated schema tests to verify `timeouts` attribute exists
- [x] **#1** Add `stringvalidator.OneOf()` to all enum fields across all resources
  - `analytic`: `input_type`, `severity`
  - `plan`: `log_level`, `signatures_feed_config.mode`, `comms_config.protocol`, `analytic_sets.type`
  - `prevent_list`: `type`
  - `unified_logging_filter`: `level`
- [x] **#3** Replace analytic `analytic_actions.parameters` JSON string with `MapAttribute{ElementType: StringType}`
- [x] **#4** Standardize `description` to `Optional + Computed` across all resources
- [x] **#5** Standardize ID naming to `id` everywhere, mapping to `uuid` internally where the API uses it
- [x] **#6** Add `RequiresReplace()` to immutable fields (`input_type` on analytic, `type` on prevent_list)
- [x] **#7** Add defaults for fields with known API defaults
  - `plan.log_level` default `"ERROR"`
  - `plan.signatures_feed_config.mode` default `"blocking"`
  - `plan.comms_config.protocol` default `"mqtt"`
- [x] **#8** Split resource files into `*_resource.go` / `*_types.go` / `*_helpers.go` per resource
