#!/bin/bash
#
# Package Scyther GUI + binaries for distribution
# Used by GitHub Actions to create release archives
#
# Usage: package-release.sh <tag>
#

set -e

TAG=${1:-$(git describe --tags --always)}
echo "Creating release packages for version: $TAG"

# Directories
ARTIFACTS_DIR="artifacts"
DIST_DIR="dist-packages"
GUI_BASE="gui"

# Create distribution directory
mkdir -p "$DIST_DIR"

# Function to create a package
create_package() {
    local arch=$1
    local binary_name=$2
    local artifact_dir=$3
    local archive_type=$4  # tgz or zip
    
    local package_name="scyther-$arch-$TAG"
    local package_dir="$DIST_DIR/$package_name"
    
    echo "Creating package: $package_name"
    
    # Create package directory structure
    mkdir -p "$package_dir"
    
    # Copy GUI files (excluding build artifacts and git)
    echo "  Copying GUI files..."
    rsync -a --exclude='.git*' --exclude='__pycache__' --exclude='*.pyc' \
          --exclude='.venv' --exclude='venv' --exclude='.DS_Store' \
          "$GUI_BASE/" "$package_dir/"
    
    # Copy the binary
    echo "  Copying binary: $binary_name"
    mkdir -p "$package_dir/Scyther"
    cp "$artifact_dir/$binary_name" "$package_dir/Scyther/"
    chmod +x "$package_dir/Scyther/$binary_name"
    
    # Create version file
    echo "SCYTHER_GUI_VERSION = \"$TAG\"" > "$package_dir/Gui/Version.py"
    
    # Create README
    cat > "$package_dir/README.txt" << EOF
Scyther $TAG - $arch

To run Scyther:
1. Extract this archive
2. Run: python3 scyther-gui.py

Requirements:
- Python 3
- wxPython 4.0+ (will be auto-installed if missing)

For more information, see:
https://github.com/cascremers/scyther

EOF
    
    # Create archive
    cd "$DIST_DIR"
    if [ "$archive_type" = "zip" ]; then
        echo "  Creating ZIP archive..."
        zip -qr "../$package_name.zip" "$package_name"
        echo "Created: $package_name.zip"
    else
        echo "  Creating tarball..."
        tar czf "../$package_name.tgz" "$package_name"
        echo "Created: $package_name.tgz"
    fi
    cd ..
    
    # Cleanup
    rm -rf "$package_dir"
}

# Verify artifacts exist
if [ ! -d "$ARTIFACTS_DIR" ]; then
    echo "Error: Artifacts directory not found"
    exit 1
fi

# Package Linux
if [ -f "$ARTIFACTS_DIR/scyther-linux/scyther-linux" ]; then
    create_package "linux" "scyther-linux" "$ARTIFACTS_DIR/scyther-linux" "tgz"
else
    echo "Warning: Linux binary not found, skipping"
fi

# Package macOS Intel
if [ -f "$ARTIFACTS_DIR/scyther-macos-intel/scyther-mac" ]; then
    create_package "macos-intel" "scyther-mac" "$ARTIFACTS_DIR/scyther-macos-intel" "tgz"
else
    echo "Warning: macOS Intel binary not found, skipping"
fi

# Package macOS ARM
if [ -f "$ARTIFACTS_DIR/scyther-macos-arm/scyther-mac" ]; then
    create_package "macos-arm" "scyther-mac" "$ARTIFACTS_DIR/scyther-macos-arm" "tgz"
else
    echo "Warning: macOS ARM binary not found, skipping"
fi

# Package Windows
if [ -f "$ARTIFACTS_DIR/scyther-windows/scyther-w32.exe" ]; then
    create_package "w32" "scyther-w32.exe" "$ARTIFACTS_DIR/scyther-windows" "zip"
else
    echo "Warning: Windows binary not found, skipping"
fi

echo ""
echo "Release packaging complete!"
echo "Created packages:"
ls -lh scyther-*.{tgz,zip} 2>/dev/null || echo "No packages found"
