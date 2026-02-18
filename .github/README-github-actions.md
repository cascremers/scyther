# GitHub Actions Build System

This directory contains the GitHub Actions workflow for automated multi-platform builds of Scyther.

## Files

- **`workflows/build.yml`** - Main CI/CD workflow that builds binaries for all platforms
- **`scripts/package-release.sh`** - Script to package GUI + binaries into distribution archives

## How It Works

The workflow builds Scyther on four platforms in parallel:

1. **Linux** (Ubuntu latest) - builds both Linux and Windows (via MinGW cross-compilation)
2. **macOS Intel** (macOS 13) - builds for Intel Macs
3. **macOS ARM** (macOS latest) - builds for M1/M2 Macs

After all builds complete, it creates distribution packages containing:
- The Scyther binary for that platform
- Complete GUI (Python files, protocols, images)
- README with usage instructions

## Triggers

The workflow runs on:

1. **Tag push** (`v*` tags) - Automatically creates a GitHub Release with all platform binaries
2. **Manual dispatch** - Can be triggered manually from the Actions tab with optional tag specification

## Usage

### Automatic Release (Recommended)

1. Create and push a version tag:
   ```bash
   git tag v1.2.0
   git push origin v1.2.0
   ```

2. GitHub Actions will automatically:
   - Build for all platforms
   - Create distribution archives
   - Create a draft GitHub Release
   - Upload all binaries to the release

3. Review and publish the draft release on GitHub

### Manual Build

Go to Actions → "Build Scyther Binaries" → Run workflow

Optionally specify a tag name, or leave empty to build from current commit.

Download artifacts from the completed workflow run.

## Distribution Packages

The workflow creates these packages:

- `scyther-linux-{tag}.tgz` - Linux (64-bit)
- `scyther-macos-intel-{tag}.tgz` - macOS Intel
- `scyther-macos-arm-{tag}.tgz` - macOS ARM (M1/M2)
- `scyther-w32-{tag}.zip` - Windows (32-bit)

Each package contains everything needed to run Scyther GUI on that platform.

## Requirements

No additional setup needed - GitHub provides:
- Ubuntu runners with build tools
- macOS runners (both Intel and ARM)
- All required CI/CD features for public repositories

## Cost

For public repositories, GitHub Actions is free with generous limits.

Note: macOS runners consume 10× the minute quota of Linux runners.

## Troubleshooting

If a build fails:

1. Check the workflow run logs in the Actions tab
2. Common issues:
   - Missing dependencies (usually auto-installed)
   - CMake configuration errors
   - Binary not copied to `gui/Scyther/`
3. Test locally using the same platform:
   ```bash
   cd src && ./build.sh --platform={platform}
   ```

## Local Testing

Test the packaging script locally:

```bash
# Create mock artifacts directory
mkdir -p artifacts/scyther-linux
cp gui/Scyther/scyther-linux artifacts/scyther-linux/

# Run packaging
.github/scripts/package-release.sh v1.2.0

# Check output
ls -lh scyther-*.tgz
```
