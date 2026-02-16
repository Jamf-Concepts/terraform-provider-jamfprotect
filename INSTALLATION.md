# Installing terraform-provider-jamfprotect (Private Distribution)

Since this provider is distributed privately via GitHub Releases, you need to install it manually.

## Quick Start

The easiest way to install the provider is using the provided script:

```bash
# Download and run the installation script
curl -fsSL https://raw.githubusercontent.com/smithjw/terraform-provider-jamfprotect/main/scripts/install-provider.sh | bash -s -- 0.1.0

# For private repository (requires GitHub personal access token)
export GITHUB_TOKEN="your-github-pat-here"
./scripts/install-provider.sh 0.1.0
```

______________________________________________________________________

## Manual Installation

If you prefer to install manually:

### 1. Determine Your Platform

```bash
uname -sm
# Examples:
# Darwin arm64   → macOS Apple Silicon (darwin_arm64)
# Darwin x86_64  → macOS Intel (darwin_amd64)
# Linux x86_64   → Linux (linux_amd64)
```

### 2. Download the Provider

Visit the [Releases page](https://github.com/smithjw/terraform-provider-jamfprotect/releases) and download the appropriate file:

| Platform            | File                                                     |
| ------------------- | -------------------------------------------------------- |
| macOS Apple Silicon | `terraform-provider-jamfprotect_0.1.0_darwin_arm64.zip`  |
| macOS Intel         | `terraform-provider-jamfprotect_0.1.0_darwin_amd64.zip`  |
| Linux 64-bit        | `terraform-provider-jamfprotect_0.1.0_linux_amd64.zip`   |
| Windows 64-bit      | `terraform-provider-jamfprotect_0.1.0_windows_amd64.zip` |

### 3. Install to Plugin Directory

#### macOS / Linux

```bash
VERSION="0.1.0"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture
[[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
[[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

# Create plugin directory
PLUGIN_DIR="${HOME}/.terraform.d/plugins/github.com/smithjw/jamfprotect/${VERSION}/${OS}_${ARCH}"
mkdir -p "${PLUGIN_DIR}"

# Extract downloaded zip
unzip ~/Downloads/terraform-provider-jamfprotect_${VERSION}_${OS}_${ARCH}.zip -d "${PLUGIN_DIR}"

# Make executable
chmod +x "${PLUGIN_DIR}"/terraform-provider-*

# Verify
ls -l "${PLUGIN_DIR}"
```

#### Windows (PowerShell)

```powershell
$VERSION = "0.1.0"
$ARCH = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

# Create plugin directory
$PluginDir = "$env:APPDATA\terraform.d\plugins\github.com\smithjw\jamfprotect\$VERSION\windows_$ARCH"
New-Item -ItemType Directory -Force -Path $PluginDir

# Extract (assuming zip is in Downloads)
Expand-Archive -Path "$env:USERPROFILE\Downloads\terraform-provider-jamfprotect_${VERSION}_windows_${ARCH}.zip" -DestinationPath $PluginDir -Force

# Verify
Get-ChildItem $PluginDir
```

______________________________________________________________________

## Configuration

### Terraform Configuration

Use `github.com` as the source (not `registry.terraform.io`):

```hcl
terraform {
  required_version = ">= 1.0"

  required_providers {
    jamfprotect = {
      source  = "github.com/smithjw/jamfprotect"
      version = "0.1.0"
    }
  }
}

provider "jamfprotect" {
  url           = "https://your-tenant.protect.jamfcloud.com"
  client_id     = var.jamfprotect_client_id
  client_secret = var.jamfprotect_client_secret
}
```

### Environment Variables

Alternatively, configure via environment variables:

```bash
export JAMFPROTECT_URL="https://your-tenant.protect.jamfcloud.com"
export JAMFPROTECT_CLIENT_ID="your-client-id"
export JAMFPROTECT_CLIENT_SECRET="your-client-secret"
```

Then omit provider configuration:

```hcl
provider "jamfprotect" {}
```

______________________________________________________________________

## Verification

Initialize Terraform:

```bash
terraform init
```

Expected output:

```
Initializing provider plugins...
- Finding github.com/smithjw/jamfprotect versions matching "0.1.0"...
- Installing github.com/smithjw/jamfprotect v0.1.0...
- Installed github.com/smithjw/jamfprotect v0.1.0 (unauthenticated)

Terraform has been successfully initialized!
```

Test the provider:

```bash
terraform plan
```

______________________________________________________________________

## Troubleshooting

### Error: "Failed to query available provider packages"

**Problem:**

```
Error: Failed to query available provider packages
Could not retrieve the list of available versions for provider github.com/smithjw/jamfprotect
```

**Solutions:**

1. Verify the provider binary is in the correct directory:

   ```bash
   # macOS/Linux
   ls ~/.terraform.d/plugins/github.com/smithjw/jamfprotect/0.1.0/*/

   # Windows
   dir %APPDATA%\terraform.d\plugins\github.com\smithjw\jamfprotect\0.1.0\
   ```

2. Ensure the binary is executable (macOS/Linux):

   ```bash
   chmod +x ~/.terraform.d/plugins/github.com/smithjw/jamfprotect/0.1.0/*/terraform-provider-*
   ```

3. Check the binary name matches the expected format:

   - Should be: `terraform-provider-jamfprotect_v0.1.0`

### Error: "Checksum verification failed"

**Problem:**

```
Error: Failed to install provider
Checksum verification failed for provider binary
```

**Solution:**
Re-download the provider binary. The file may have been corrupted.

### Error: Permission Denied (macOS)

**Problem:**

```
"terraform-provider-jamfprotect_v0.1.0" cannot be opened because the developer cannot be verified
```

**Solution:**
macOS Gatekeeper is blocking the binary. Allow it:

```bash
# Option 1: Remove quarantine attribute
xattr -d com.apple.quarantine ~/.terraform.d/plugins/github.com/smithjw/jamfprotect/0.1.0/*/terraform-provider-*

# Option 2: Allow in System Preferences
# System Preferences > Security & Privacy > General > "Allow Anyway"
```

### Wrong Platform Error

**Problem:**

```
Error: Incompatible provider version
Provider "github.com/smithjw/jamfprotect" v0.1.0 does not have a package available for your current platform, darwin_arm64
```

**Solution:**
You downloaded the wrong platform binary. Verify your platform:

```bash
uname -sm
# Darwin arm64   → use darwin_arm64
# Darwin x86_64  → use darwin_amd64
# Linux x86_64   → use linux_amd64
```

______________________________________________________________________

## Upgrading

To upgrade to a new version:

```bash
# Install new version
./scripts/install-provider.sh 0.2.0

# Update version in Terraform configuration
# version = "0.2.0"

# Upgrade
terraform init -upgrade
```

The old version remains installed and can be used by specifying its version.

______________________________________________________________________

## CI/CD Integration

### GitHub Actions

```yaml
name: Terraform

on: [push]

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.7.0

      - name: Install Jamf Protect Provider
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          curl -fsSL https://raw.githubusercontent.com/smithjw/terraform-provider-jamfprotect/main/scripts/install-provider.sh | bash -s -- 0.1.0

      - name: Terraform Init
        run: terraform init

      - name: Terraform Plan
        env:
          JAMFPROTECT_URL: ${{ secrets.JAMFPROTECT_URL }}
          JAMFPROTECT_CLIENT_ID: ${{ secrets.JAMFPROTECT_CLIENT_ID }}
          JAMFPROTECT_CLIENT_SECRET: ${{ secrets.JAMFPROTECT_CLIENT_SECRET }}
        run: terraform plan
```

______________________________________________________________________

## Private Repository Access

For private repositories, you need a GitHub Personal Access Token (PAT) with `repo` scope.

### Creating a PAT

1. Go to GitHub Settings > Developer settings > Personal access tokens > Tokens (classic)
2. Generate new token
3. Select scopes: `repo` (all repo sub-scopes)
4. Generate token and copy it

### Using the PAT

```bash
export GITHUB_TOKEN="ghp_your_token_here"
./scripts/install-provider.sh 0.1.0
```

Or download manually with authentication:

```bash
curl -L -H "Authorization: token ghp_your_token_here" \
    "https://github.com/smithjw/terraform-provider-jamfprotect/releases/download/v0.1.0/terraform-provider-jamfprotect_0.1.0_darwin_arm64.zip" \
    -o provider.zip
```

______________________________________________________________________

## Uninstalling

Remove the plugin directory:

```bash
# macOS/Linux
rm -rf ~/.terraform.d/plugins/github.com/smithjw/jamfprotect

# Windows
Remove-Item -Recurse -Force "$env:APPDATA\terraform.d\plugins\github.com\smithjw\jamfprotect"
```

______________________________________________________________________

## Support

- **Issues:** [GitHub Issues](https://github.com/smithjw/terraform-provider-jamfprotect/issues)
- **Documentation:** [README](https://github.com/smithjw/terraform-provider-jamfprotect/blob/main/README.md)
- **Examples:** [examples/](https://github.com/smithjw/terraform-provider-jamfprotect/tree/main/examples)
