# Private Provider Distribution Guide

This guide explains how to distribute the terraform-provider-jamfprotect privately without publishing to the Terraform Registry.

## Overview

You have several options for distributing a private Terraform provider:

1. **GitHub Releases (Private Repo)** - Release binaries via GitHub, users install manually
2. **Terraform Cloud/Enterprise Private Registry** - Enterprise feature
3. **Local Development Builds** - For development/testing only

This guide focuses on **Option 1: GitHub Releases** which works great for private distribution.

---

## ✅ Option 1: GitHub Releases with Manual Installation

### How It Works

1. ✅ Create GitHub releases with provider binaries (using GoReleaser)
2. ✅ Users download the appropriate binary for their platform
3. ✅ Users install the binary in Terraform's plugin directory
4. ✅ Repository stays private - only authorized users can download

### Step 1: Configure GoReleaser for GitHub-Only Releases

The provider is already configured! The `.goreleaser.yml` file will create GitHub releases automatically when you push a tag.

**What happens when you tag a release:**
1. GitHub Actions workflow builds binaries for all platforms
2. Creates SHA256 checksums and GPG signatures
3. Creates a GitHub Release with all artifacts attached
4. **DOES NOT** automatically publish to Terraform Registry (you control that separately)

### Step 2: Create a Release

```bash
# Update CHANGELOG
sed -i '' 's/## 0.1.0 (Unreleased)/## 0.1.0 (February 13, 2026)/' CHANGELOG.md
git add CHANGELOG.md
git commit -m "Release v0.1.0"
git push origin main

# Create and push tag
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions will automatically:
- Build binaries for darwin, linux, windows (amd64, arm64)
- Generate checksums
- Sign with GPG
- Create GitHub Release at: `https://github.com/smithjw/terraform-provider-jamfprotect/releases/tag/v0.1.0`

**Important:** Even though the repository is private, authorized users can download releases.

### Step 3: User Installation Instructions

Create `INSTALLATION.md` for your users:

````markdown
# Installing terraform-provider-jamfprotect (Private Distribution)

Since this provider is distributed privately via GitHub Releases, you need to install it manually.

## Prerequisites

- Terraform >= 1.0
- Access to the private GitHub repository

## Installation Steps

### 1. Determine Your Platform

```bash
# Check your platform
terraform version
# Shows: Terraform v1.x.x on darwin_arm64 (or linux_amd64, etc.)
```

### 2. Download the Provider Binary

Visit the [Releases page](https://github.com/smithjw/terraform-provider-jamfprotect/releases) and download the appropriate file for your platform:

- **macOS Intel:** `terraform-provider-jamfprotect_0.1.0_darwin_amd64.zip`
- **macOS Apple Silicon:** `terraform-provider-jamfprotect_0.1.0_darwin_arm64.zip`
- **Linux:** `terraform-provider-jamfprotect_0.1.0_linux_amd64.zip`
- **Windows:** `terraform-provider-jamfprotect_0.1.0_windows_amd64.zip`

### 3. Install the Provider

#### macOS / Linux

```bash
# Set version
VERSION="0.1.0"

# Determine your architecture
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Map architecture names
if [ "$ARCH" = "x86_64" ]; then
  ARCH="amd64"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
  ARCH="arm64"
fi

# Create plugin directory
mkdir -p ~/.terraform.d/plugins/github.com/smithjw/jamfprotect/${VERSION}/${OS}_${ARCH}

# Download and extract (replace with your actual GitHub download URL)
curl -L "https://github.com/smithjw/terraform-provider-jamfprotect/releases/download/v${VERSION}/terraform-provider-jamfprotect_${VERSION}_${OS}_${ARCH}.zip" \
  -o /tmp/terraform-provider-jamfprotect.zip

unzip /tmp/terraform-provider-jamfprotect.zip -d ~/.terraform.d/plugins/github.com/smithjw/jamfprotect/${VERSION}/${OS}_${ARCH}/

# Clean up
rm /tmp/terraform-provider-jamfprotect.zip

# Verify installation
ls -la ~/.terraform.d/plugins/github.com/smithjw/jamfprotect/${VERSION}/${OS}_${ARCH}/
```

#### Windows (PowerShell)

```powershell
$VERSION = "0.1.0"
$ARCH = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

# Create plugin directory
$PluginDir = "$env:APPDATA\terraform.d\plugins\github.com\smithjw\jamfprotect\$VERSION\windows_$ARCH"
New-Item -ItemType Directory -Force -Path $PluginDir

# Download and extract
$ZipPath = "$env:TEMP\terraform-provider-jamfprotect.zip"
Invoke-WebRequest -Uri "https://github.com/smithjw/terraform-provider-jamfprotect/releases/download/v$VERSION/terraform-provider-jamfprotect_${VERSION}_windows_${ARCH}.zip" -OutFile $ZipPath

Expand-Archive -Path $ZipPath -DestinationPath $PluginDir -Force

# Clean up
Remove-Item $ZipPath

# Verify
Get-ChildItem $PluginDir
```

### 4. Configure Terraform to Use the Provider

In your Terraform configuration, use the `github.com` source:

```hcl
terraform {
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

**Note:** Use `github.com/smithjw/jamfprotect` (NOT `registry.terraform.io/...`) as the source.

### 5. Verify Installation

```bash
terraform init
```

You should see:
```
Initializing provider plugins...
- Finding github.com/smithjw/jamfprotect versions matching "0.1.0"...
- Installing github.com/smithjw/jamfprotect v0.1.0...
- Installed github.com/smithjw/jamfprotect v0.1.0 (unauthenticated)
```

## Troubleshooting

### "Provider not found" Error

**Problem:**
```
Error: Failed to query available provider packages
Could not retrieve the list of available versions for provider github.com/smithjw/jamfprotect
```

**Solution:** Ensure the provider binary is in the correct directory:
- macOS/Linux: `~/.terraform.d/plugins/github.com/smithjw/jamfprotect/0.1.0/{OS}_{ARCH}/`
- Windows: `%APPDATA%\terraform.d\plugins\github.com\smithjw\jamfprotect\0.1.0\windows_{ARCH}\`

### "Checksum Mismatch" Error

**Solution:** Re-download the provider binary. The file may have been corrupted during download.

### Provider Binary Not Executable (macOS/Linux)

```bash
chmod +x ~/.terraform.d/plugins/github.com/smithjw/jamfprotect/0.1.0/{OS}_{ARCH}/terraform-provider-jamfprotect_v0.1.0
```

## Upgrading

To upgrade to a new version:

1. Download the new version from Releases
2. Install to a new version-specific directory (e.g., `0.2.0`)
3. Update your `version` in the Terraform configuration
4. Run `terraform init -upgrade`

## Automation

For CI/CD pipelines, you can automate installation:

```bash
#!/bin/bash
# install-jamfprotect-provider.sh

VERSION=${1:-"0.1.0"}
GITHUB_TOKEN=${GITHUB_TOKEN}  # Set this in your CI environment

# ... installation script from above, using curl with -H "Authorization: token $GITHUB_TOKEN"
```

Add to your CI workflow:
```yaml
- name: Install Jamf Protect Provider
  run: ./scripts/install-jamfprotect-provider.sh 0.1.0
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
````

---

## ✅ Option 2: Terraform Cloud Private Registry (Enterprise)

If you have Terraform Cloud for Business or Terraform Enterprise:

### Setup

1. Go to your Terraform Cloud organization
2. Navigate to **Settings** → **Provider Registry**
3. Click **Add a provider**
4. Connect your GitHub repository
5. Follow the wizard to set up private distribution

### Usage

```hcl
terraform {
  required_providers {
    jamfprotect = {
      source  = "app.terraform.io/{org}/jamfprotect"
      version = "0.1.0"
    }
  }
}
```

**Pros:**
- Automatic updates from GitHub releases
- Better versioning management
- Team access control via Terraform Cloud

**Cons:**
- Requires Terraform Cloud for Business ($20/user/month) or Enterprise
- Adds dependency on Terraform Cloud

---

## ✅ Option 3: Network Mirror (Advanced)

For enterprises with strict security requirements:

### Setup

1. Create a network mirror server (private HTTP server)
2. Host provider binaries on the mirror
3. Configure Terraform CLI to use the mirror

**`.terraformrc` configuration:**
```hcl
provider_installation {
  network_mirror {
    url = "https://terraform-mirror.internal.company.com/"
  }
}
```

**Pros:**
- Complete control over distribution
- No external dependencies
- Works in air-gapped environments

**Cons:**
- Requires infrastructure to maintain
- More complex setup

---

## Comparison Matrix

| Feature | GitHub Releases | Terraform Cloud Private | Network Mirror | Public Registry |
|---------|----------------|-------------------------|----------------|-----------------|
| **Repository Privacy** | ✅ Private | ✅ Private | ✅ Private | ❌ Public |
| **Setup Complexity** | 🟢 Easy | 🟡 Medium | 🔴 Hard | 🟢 Easy |
| **Cost** | ✅ Free | 💰 $20/user/month | 💰 Infrastructure | ✅ Free |
| **Access Control** | GitHub Teams | TFC Teams | Custom | Public |
| **Version Management** | Manual | Automatic | Manual | Automatic |
| **Discovery** | Manual docs | Built-in | Custom | Built-in |
| **Air-gap Support** | ❌ No | ❌ No | ✅ Yes | ❌ No |
| **Best For** | Small teams | Medium teams | Enterprises | Public use |

---

## Recommended Approach for Private Distribution

### Phase 1: Start with GitHub Releases (NOW)

**For v0.1.0:**
- ✅ Use GitHub Releases with manual installation
- ✅ Create `INSTALLATION.md` for users
- ✅ Keep repository private
- ✅ Control access via GitHub team permissions

**Benefits:**
- No additional cost
- Works immediately
- Full control over access
- Can switch to public registry later

### Phase 2: Evaluate Public Registry (LATER)

**After v0.1.0 feedback:**
- Gather feedback from internal users
- Decide if provider is ready for public use
- If yes: Make repo public and publish to registry
- If no: Continue with GitHub releases

### Phase 3: Enterprise Features (OPTIONAL)

**If needed:**
- Terraform Cloud private registry for better UX
- Network mirror for air-gapped environments

---

## Installation Script for Users

Create `scripts/install-provider.sh`:

```bash
#!/bin/bash
set -e

VERSION="${1:-0.1.0}"
GITHUB_ORG="smithjw"
PROVIDER_NAME="jamfprotect"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

echo "Installing terraform-provider-${PROVIDER_NAME} v${VERSION} for ${OS}_${ARCH}..."

# Plugin directory
PLUGIN_DIR="${HOME}/.terraform.d/plugins/github.com/${GITHUB_ORG}/${PROVIDER_NAME}/${VERSION}/${OS}_${ARCH}"
mkdir -p "${PLUGIN_DIR}"

# Download URL
DOWNLOAD_URL="https://github.com/${GITHUB_ORG}/terraform-provider-${PROVIDER_NAME}/releases/download/v${VERSION}/terraform-provider-${PROVIDER_NAME}_${VERSION}_${OS}_${ARCH}.zip"

# Download
if [ -n "$GITHUB_TOKEN" ]; then
  curl -L -H "Authorization: token ${GITHUB_TOKEN}" "${DOWNLOAD_URL}" -o /tmp/provider.zip
else
  curl -L "${DOWNLOAD_URL}" -o /tmp/provider.zip
fi

# Extract
unzip -o /tmp/provider.zip -d "${PLUGIN_DIR}"
rm /tmp/provider.zip

# Make executable
chmod +x "${PLUGIN_DIR}/"*

echo "✅ Successfully installed to ${PLUGIN_DIR}"
echo ""
echo "Usage in terraform:"
echo "  source = \"github.com/${GITHUB_ORG}/${PROVIDER_NAME}\""
echo "  version = \"${VERSION}\""
```

Make it executable:
```bash
chmod +x scripts/install-provider.sh
```

---

## Summary

**For v0.1.0 Private Distribution:**

1. ✅ **Push a tag to create GitHub Release** (already configured)
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

2. ✅ **Create INSTALLATION.md** with user instructions

3. ✅ **Share installation script** with your team

4. ✅ **Keep repository private** until you're ready for public release

**When Ready for Public:**
- Make repository public
- Add GPG key to Terraform Registry
- Provider auto-appears in registry within 15 minutes
- Users can switch from `github.com/smithjw/jamfprotect` to `registry.terraform.io/smithjw/jamfprotect`

---

**Would you like me to:**
1. Create the `INSTALLATION.md` file?
2. Create the installation script?
3. Update the `RELEASE_GUIDE.md` to include private distribution instructions?
