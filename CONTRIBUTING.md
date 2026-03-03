# Contributing

Thank you for your interest in contributing to the Terraform Provider for Jamf Protect.

## Prerequisites

- **Go** >= 1.26 (see `go.mod` for the exact version)
- **Terraform** >= 1.13
- **golangci-lint** for linting
- A Jamf Protect tenant with API credentials (for acceptance tests only)

## Getting Started

```bash
# Clone the repository
git clone https://github.com/Jamf-Concepts/terraform-provider-jamfprotect.git
cd terraform-provider-jamfprotect

# Build, lint, and generate docs
make
```

## Development Workflow

1. Create a feature branch from `main`.
2. Make your changes following the conventions in [AGENTS.md](AGENTS.md).
3. Run formatting, linting, and tests before committing:

   ```bash
   make fmt
   make lint
   make test
   ```

4. Regenerate documentation if schema descriptions changed:

   ```bash
   make generate
   ```

5. Open a pull request against `main`. CI will run build, lint, doc generation, and unit tests automatically.
6. Acceptance tests run automatically after integration tests pass, or can be triggered manually.

## Adding a New Resource

1. Add service methods in `internal/jamfprotect/` for the new resource (Create, Get, Update, Delete, List).
2. Create the resource package under `internal/resources/<resource_name>/` following the file conventions in [AGENTS.md](AGENTS.md#resource-package-file-conventions).
3. Register the resource in `internal/provider/provider.go` in the `Resources()` method.
4. Add tests:
   - Schema and metadata tests in `internal/provider/schema_test.go`.
   - Acceptance tests in `internal/resources/<resource_name>/resource_test.go`.
5. Add example `.tf` files under `examples/resources/jamfprotect_<resource_name>/`.
6. Run `make generate` to regenerate documentation.
7. Run `make test` to verify all tests pass.

## Adding a New Data Source

Follow the same pattern as resources, but implement `datasource.DataSource` instead of `resource.Resource`. Place the data source in the same resource package (e.g., `internal/resources/<resource_name>/data_source.go`).

## Project Structure

See [AGENTS.md](AGENTS.md) for the full project structure and conventions. Key directories:

| Directory              | Purpose                                                  |
| ---------------------- | -------------------------------------------------------- |
| `internal/provider/`   | Provider configuration and resource registration         |
| `internal/resources/`  | Resource, data source, and list resource implementations |
| `internal/jamfprotect/`| Service layer (GraphQL operations)                       |
| `internal/client/`     | GraphQL transport client, auth, and error handling       |
| `internal/common/`     | Shared helpers, constants, and validators                |
| `internal/testutil/`   | Acceptance test utilities                                |
| `examples/`            | Example `.tf` configurations                             |
| `templates/`           | tfplugindocs templates for doc generation                |
| `docs/`                | Auto-generated provider documentation                    |

## Dependencies

This project uses native Go, `golang.org/x` packages, and Terraform Plugin Framework packages. Do not introduce third-party dependencies without discussion.

## Commit Messages

Use [conventional commit](https://www.conventionalcommits.org/) style messages:

- `feat: add device_group import support`
- `fix: handle nil response in plan state builder`
- `test: add schema validation for action configuration`
- `refactor: extract common polling logic to helpers`
- `chore: update CI workflow action versions`
- `docs: update README with new resource examples`

## Pull Requests

- Keep PRs focused -- one feature or fix per PR.
- Include unit tests for new code.
- Include acceptance tests for new resources and data sources.
- Update `examples/` for new Terraform constructs.
- Run `make generate` if schema descriptions changed (to update docs).
- CI must pass before merge.

## Reporting Issues

Open an issue on GitHub with:

- Provider version and Terraform version.
- Relevant Terraform configuration (redact credentials).
- Expected vs actual behaviour.
- Any error messages or logs.
