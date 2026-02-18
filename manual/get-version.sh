#!/bin/bash
#
# Extract Scyther version from git and write it to version.tex
#

# Try to get version from git
if [ -d ../.git ]; then
    VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "unknown")
else
    VERSION="unknown"
fi

# Clean up the version string (remove b' prefix if present from Python output)
VERSION=$(echo "$VERSION" | sed "s/^b'//; s/'$//")

# Write to version.tex
cat > version.tex << EOF
% Auto-generated version information
% Generated on $(date)
\newcommand{\scytherversion}{$VERSION}
EOF

echo "Version set to: $VERSION"
