# Go Dependency Management Guide

This guide explains how to safely update Go dependencies in the terraform-provider-jamfprotect repository.

## Quick Reference

```bash
# Check for available updates
go list -m -u all

# Update all dependencies to latest minor/patch versions
go get -u ./...

# Update a specific dependency
go get github.com/hashicorp/terraform-plugin-framework@latest

# Update to a specific version
go get github.com/hashicorp/terraform-plugin-framework@v1.18.0

# Clean up and verify
mise run tidy
mise run test
```

---

## Safe Update Process

### Step 1: Check Current Versions

```bash
# View current dependencies
cat go.mod

# Check for available updates
go list -m -u all | grep -E "^\w" | head -20
```

The output shows: `package current-version [latest-version]`

Example:
```
github.com/hashicorp/terraform-plugin-framework v1.17.0 [v1.18.0]
```

### Step 2: Update Dependencies Safely

#### Option A: Update All Patch/Minor Versions (Recommended)

This updates to the latest compatible versions without breaking changes:

```bash
# Update all dependencies (respects semantic versioning)
go get -u ./...

# Clean up go.mod and go.sum
mise run tidy

# Verify everything still compiles
go build ./...
```

#### Option B: Update Only Direct Dependencies

If you want more control:

```bash
# Update only the dependencies listed in the 'require' section
go get -u github.com/hashicorp/terraform-plugin-framework@latest
go get -u github.com/hashicorp/terraform-plugin-framework-timeouts@latest
go get -u github.com/hashicorp/terraform-plugin-framework-validators@latest
go get -u github.com/hashicorp/terraform-plugin-go@latest
go get -u github.com/hashicorp/terraform-plugin-log@latest
go get -u github.com/hashicorp/terraform-plugin-testing@latest

mise run tidy
```

#### Option C: Update Specific Packages

If you only want to update certain packages:

```bash
# Update just the framework
go get -u github.com/hashicorp/terraform-plugin-framework@latest

# Update testing tools
go get -u github.com/hashicorp/terraform-plugin-testing@latest

mise run tidy
```

### Step 3: Test Thoroughly

After updating dependencies, run all tests:

```bash
# Run unit tests
mise run test

# Check for any test failures
echo $?  # Should be 0

# Verify linting still passes
mise run lint

# Build the provider
mise run build

# Optional: Run acceptance tests (requires credentials)
mise run testacc
```

### Step 4: Review Breaking Changes

Check the changelogs of updated packages for breaking changes:

```bash
# Get list of updated packages
git diff go.mod

# For each major dependency, check their changelog
# Example:
open "https://github.com/hashicorp/terraform-plugin-framework/releases"
```

**Key Dependencies to Watch:**
- `terraform-plugin-framework` - Core provider framework
- `terraform-plugin-go` - Protocol implementation
- `terraform-plugin-testing` - Test framework

### Step 5: Commit Changes

```bash
git add go.mod go.sum
git commit -m "Update Go dependencies to latest versions"
git push origin main
```

---

## Dependency Update Strategy

### Conservative (Recommended for Stable Releases)

Update only patch versions (bug fixes):

```bash
# Update to latest patch versions only
go get -u=patch ./...
mise run tidy
```

Example: `v1.17.0` → `v1.17.1` (safe, only bug fixes)

### Moderate (Recommended for Development)

Update to latest minor versions (new features, backward compatible):

```bash
# Update to latest minor versions
go get -u ./...
mise run tidy
```

Example: `v1.17.0` → `v1.18.0` (new features, should be compatible)

### Aggressive (Use with Caution)

Update to latest major versions (may have breaking changes):

```bash
# Update to absolute latest (including major versions)
go get -u ./...
go get github.com/some/package/v2@latest  # Major version change

mise run tidy
```

Example: `v1.17.0` → `v2.0.0` (may break existing code)

---

## Current Dependency Analysis

Based on `go list -m -u all`, here are the notable updates available:

### Direct Dependencies (What We Explicitly Use)

| Package | Current | Latest | Type | Risk |
|---------|---------|--------|------|------|
| terraform-plugin-framework | v1.17.0 | v1.17.0 | Current | 🟢 None |
| terraform-plugin-framework-timeouts | v0.7.0 | v0.7.0 | Current | 🟢 None |
| terraform-plugin-framework-validators | v0.19.0 | v0.19.0 | Current | 🟢 None |
| terraform-plugin-go | v0.29.0 | v0.29.0 | Current | 🟢 None |
| terraform-plugin-log | v0.10.0 | v0.10.0 | Current | 🟢 None |
| terraform-plugin-testing | v1.14.0 | v1.14.0 | Current | 🟢 None |

**Status:** ✅ All direct dependencies are already at latest versions!

### Indirect Dependencies (Transitive)

Several indirect dependencies have updates available:

| Package | Current | Latest | Impact |
|---------|---------|--------|--------|
| ProtonMail/go-crypto | v1.1.6 | v1.3.0 | Minor |
| cloudflare/circl | v1.6.1 | v1.6.3 | Patch |
| agext/levenshtein | v1.2.2 | v1.2.3 | Patch |
| Masterminds/semver/v3 | v3.2.0 | v3.4.0 | Minor |
| creack/pty | v1.1.9 | v1.1.24 | Minor |

**Status:** 🟡 Updates available but not required (indirect dependencies)

---

## Recommendation for v0.1.0

### Before v0.1.0 Release

**✅ Keep current versions** - All direct dependencies are already latest and stable.

**Why:**
- All tests are passing
- Linter reports 0 issues
- No security vulnerabilities reported
- Proven stable combination

### After v0.1.0 Release

**Monitor for updates** and update on a regular cadence:

```bash
# Monthly dependency check
go list -m -u all > dependency-updates.txt
git diff --no-index /dev/null dependency-updates.txt
```

**Update when:**
- Security vulnerabilities are reported
- New features needed from dependencies
- Bug fixes available for known issues
- Before major version releases (v0.2.0, v1.0.0)

---

## Automated Dependency Updates

### Option 1: Dependabot (GitHub)

GitHub Dependabot can automatically create PRs for dependency updates.

**Create `.github/dependabot.yml`:**

```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    groups:
      # Group Terraform Plugin Framework updates together
      terraform-plugins:
        patterns:
          - "github.com/hashicorp/terraform-plugin-*"
      # Group security updates
      security:
        patterns:
          - "github.com/ProtonMail/go-crypto"
          - "github.com/cloudflare/circl"
    labels:
      - "dependencies"
      - "go"
```

**Benefits:**
- Automatic PRs for updates
- Grouped related updates
- Security alerts
- Works with private repos

### Option 2: Renovate (More Features)

Renovate provides more customization than Dependabot.

**Create `renovate.json`:**

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:base"],
  "packageRules": [
    {
      "matchPackagePatterns": ["github.com/hashicorp/terraform-plugin-*"],
      "groupName": "Terraform Plugin Framework"
    },
    {
      "matchUpdateTypes": ["patch"],
      "automerge": true
    }
  ],
  "schedule": ["before 10am on monday"]
}
```

### Option 3: Manual Updates (Current Approach)

Periodically run:

```bash
# Check for updates
go list -m -u all | grep "\["

# Update
go get -u ./...
mise run tidy
mise run test
```

---

## Security Scanning

Check for known vulnerabilities:

```bash
# Scan for vulnerabilities
go list -json -m all | docker run --rm -i sonatypeoss/nancy:latest sleuth

# Or use govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

---

## Dependency Update Checklist

When updating dependencies, follow this checklist:

- [ ] Check for available updates: `go list -m -u all`
- [ ] Review changelogs for breaking changes
- [ ] Update dependencies: `go get -u ./...`
- [ ] Run tidy: `mise run tidy`
- [ ] Verify build: `mise run build`
- [ ] Run tests: `mise run test`
- [ ] Run linter: `mise run lint`
- [ ] Check for vulnerabilities: `govulncheck ./...`
- [ ] Run acceptance tests: `mise run testacc` (if possible)
- [ ] Update CHANGELOG.md if dependencies affect functionality
- [ ] Commit changes: `git add go.mod go.sum && git commit -m "Update Go dependencies"`
- [ ] Create PR or push to main
- [ ] Monitor CI/CD for any failures

---

## Common Scenarios

### Scenario 1: Security Vulnerability Detected

```bash
# Update just the vulnerable package
go get github.com/vulnerable/package@v1.2.3

# Verify fix
govulncheck ./...

# Test
mise run test

# Commit immediately
git add go.mod go.sum
git commit -m "Security: Update vulnerable/package to v1.2.3"
git push origin main
```

### Scenario 2: New Framework Feature Needed

```bash
# Update to latest framework version
go get github.com/hashicorp/terraform-plugin-framework@latest

# Check what changed
git diff go.mod

# Update code to use new features
# ... make code changes ...

# Test thoroughly
mise run test
mise run lint

# Commit
git add .
git commit -m "Update terraform-plugin-framework to v1.18.0 for new features"
```

### Scenario 3: Pre-Release Dependency Update

Before major releases (v0.2.0, v1.0.0):

```bash
# Update all to latest
go get -u ./...
mise run tidy

# Full test suite
mise run check
mise run testacc

# Document in CHANGELOG
echo "- Updated all Go dependencies to latest versions" >> CHANGELOG.md

git add .
git commit -m "Update dependencies for v0.2.0 release"
```

---

## Rollback Procedure

If an update causes issues:

```bash
# Restore previous versions
git checkout HEAD~1 go.mod go.sum

# Or restore specific version
go get github.com/some/package@v1.2.0

# Clean and rebuild
go clean -cache
mise run tidy
mise run build
mise run test
```

---

## Best Practices

1. ✅ **Update regularly** - Monthly or quarterly schedule
2. ✅ **Test thoroughly** - Never skip tests after updates
3. ✅ **Update before releases** - Keep dependencies fresh for major versions
4. ✅ **Group related updates** - Update all HashiCorp packages together
5. ✅ **Review changelogs** - Always check for breaking changes
6. ✅ **One dependency at a time** - For major updates, update individually
7. ✅ **Monitor CI/CD** - Catch issues early in automated tests
8. ✅ **Document breaking changes** - Update CHANGELOG.md if needed

---

## Current Status: v0.1.0

**Dependencies:** ✅ **ALL UP TO DATE**

All direct dependencies are at their latest stable versions:
- terraform-plugin-framework: v1.17.0 ✅
- terraform-plugin-go: v0.29.0 ✅
- terraform-plugin-testing: v1.14.0 ✅

**Recommendation:** No updates needed for v0.1.0 release. Dependencies are current and stable.

---

## Future: Dependabot Setup

For ongoing maintenance, I recommend setting up Dependabot after v0.1.0:

```bash
# Create dependabot config
cat > .github/dependabot.yml << 'EOF'
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      terraform-plugins:
        patterns:
          - "github.com/hashicorp/terraform-plugin-*"
EOF

git add .github/dependabot.yml
git commit -m "Add Dependabot configuration for Go dependencies"
git push origin main
```

This will automatically create PRs for dependency updates every week.

---

Would you like me to set up Dependabot now, or keep the current stable dependencies for v0.1.0?
