# Provider Schema Improvement TODO

Tracking improvements to make the provider feel idiomatic Terraform rather than a raw GraphQL API wrapper.

## High Priority

- [ ] **#1** Add `stringvalidator.OneOf()` to all enum fields across all resources
  - `analytic`: `input_type`, `severity`, `context.type`
  - `plan`: `log_level`, `signatures_feed_config.mode`, `comms_config.protocol`, `analytic_sets.type`
  - `prevent_list`: `type`
  - `unified_logging_filter`: `level`
- [ ] **#3** Replace analytic `analytic_actions.parameters` JSON string with `MapAttribute{ElementType: StringType}`
- [ ] **#4** Standardize `description` to `Optional + Computed` across all resources
  - Currently: analytic=Required, plan/action_config=Optional+Computed, prevent_list/ULF=Optional only
- [ ] **#5** Standardize ID naming to `id` everywhere, mapping to `uuid` internally where the API uses it
  - Currently: analytic and ULF use `uuid`, plan/action_config/prevent_list use `id`

## Medium Priority

- [ ] **#6** Add `RequiresReplace()` to immutable fields (e.g. `input_type` on analytics)
- [ ] **#7** Add defaults for fields with known API defaults
  - `plan.log_level` default `"ERROR"`
  - `plan.signatures_feed_config.mode` default `"blocking"`
  - `plan.comms_config.protocol` default `"mqtt"`

## Low Priority

- [ ] **#8** Split resource files into resource.go / types.go / helpers.go per resource package
- [ ] **#9** Add operation timeouts via `terraform-plugin-framework-timeouts`

## Deferred (Biggest Change)

- [ ] **#2** Restructure `action_config` `alert_config` from JSON blob to typed nested blocks
  - Model 14 event types as optional `SingleNestedBlock`s
  - Each with `attributes` (list of strings) and `related` (list of strings)
  - Consider keeping `jsonencode()` escape hatch alongside typed blocks

## Completed

_(Items will be moved here as they are finished)_
