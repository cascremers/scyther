#!/usr/bin/env bash

# Scyther Build Script
# Improved version with prerequisite checking, better error handling, and build options

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
BUILD_TYPE="Release"
PLATFORM=""
ARCH=""
VERBOSE=0
OUT_OF_TREE=0

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# Helper Functions
# =============================================================================

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build the Scyther protocol verifier for various platforms.

OPTIONS:
    --platform=PLATFORM   Target platform: linux, macos-arm, macos-intel, windows
                         (default: auto-detect)
    --debug              Build debug version instead of release
    --verbose            Show verbose build output
    --out-of-tree        Perform out-of-tree build in build/ directory
    --help               Show this help message

EXAMPLES:
    $0                          # Auto-detect platform and build
    $0 --debug                  # Build debug version
    $0 --platform=linux         # Build for Linux
    $0 --platform=macos-arm     # Build for macOS ARM (M1/M2)
    $0 --platform=windows       # Cross-compile for Windows (requires mingw)
    $0 --out-of-tree --verbose  # Out-of-tree build with verbose output

EOF
}

# =============================================================================
# Prerequisite Checking
# =============================================================================

check_command() {
    local cmd="$1"
    local package="$2"
    
    if ! command -v "$cmd" &> /dev/null; then
        print_error "Required command '$cmd' not found."
        if [ -n "$package" ]; then
            print_info "Install it with: $package"
        fi
        return 1
    fi
    return 0
}

check_prerequisites() {
    print_info "Checking build prerequisites..."
    
    local missing=0
    
    # Check CMake
    if ! check_command "cmake" "apt-get install cmake (on Ubuntu/Debian) or brew install cmake (on macOS)"; then
        missing=1
    else
        local cmake_version=$(cmake --version | head -n1 | awk '{print $3}')
        print_success "cmake found (version $cmake_version)"
    fi
    
    # Check flex
    if ! check_command "flex" "apt-get install flex (on Ubuntu/Debian) or brew install flex (on macOS)"; then
        missing=1
    else
        print_success "flex found"
    fi
    
    # Check bison
    if ! check_command "bison" "apt-get install bison (on Ubuntu/Debian) or brew install bison (on macOS)"; then
        missing=1
    else
        print_success "bison found"
    fi
    
    # Check compiler
    if command -v gcc &> /dev/null; then
        local gcc_version=$(gcc --version | head -n1)
        print_success "gcc found ($gcc_version)"
    elif command -v clang &> /dev/null; then
        local clang_version=$(clang --version | head -n1)
        print_success "clang found ($clang_version)"
    else
        print_error "No C compiler found (gcc or clang required)"
        print_info "Install with: apt-get install build-essential (Ubuntu/Debian) or xcode-select --install (macOS)"
        missing=1
    fi
    
    # Platform-specific checks
    if [ "$PLATFORM" = "windows" ]; then
        if ! check_command "i686-w64-mingw32-gcc" "apt-get install mingw-w64 (cross-compilation for Windows)"; then
            print_warning "MinGW not found. Cross-compilation to Windows will not work."
            print_info "To build for Windows from Linux, install: apt-get install mingw-w64"
        else
            print_success "MinGW found (for Windows cross-compilation)"
        fi
    fi
    
    if [ "$missing" -eq 1 ]; then
        print_error "Missing required prerequisites. Please install them and try again."
        exit 1
    fi
    
    print_success "All prerequisites satisfied"
    echo
}

# =============================================================================
# Platform Detection
# =============================================================================

detect_platform() {
    local os=$(uname)
    
    print_info "Detecting platform..."
    
    if [ "$os" = "Darwin" ]; then
        local arch=$(uname -m)
        if [ "$arch" = "arm64" ]; then
            PLATFORM="macos-arm"
        else
            PLATFORM="macos-intel"
        fi
    elif [ "$os" = "Linux" ]; then
        PLATFORM="linux"
    else
        print_warning "Unknown platform: $os"
        PLATFORM="unknown"
    fi
    
    print_info "Detected platform: $PLATFORM"
}

# =============================================================================
# Version Generation
# =============================================================================

generate_version() {
    print_info "Generating version information..."
    
    if [ -f "$SCRIPT_DIR/describe-version.py" ]; then
        cd "$SCRIPT_DIR"
        python3 describe-version.py
        print_success "Version information generated"
    else
        print_warning "describe-version.py not found, skipping version generation"
    fi
}

# =============================================================================
# Build Functions
# =============================================================================

build_for_platform() {
    local target_os=""
    local binary_name=""
    local output_name=""
    local cmake_flags="-D CMAKE_BUILD_TYPE:STRING=$BUILD_TYPE"
    
    # Determine CMake target and output files
    case "$PLATFORM" in
        linux)
            target_os="Unix"
            binary_name="scyther-linux"
            output_name="scyther-linux"
            ;;
        macos-arm)
            target_os="MacArm"
            binary_name="scyther-mac"
            output_name="scyther-mac-arm"
            ;;
        macos-intel)
            target_os="MacIntel"
            binary_name="scyther-mac"
            output_name="scyther-mac"
            ;;
        windows)
            target_os="Win32"
            binary_name="scyther-w32.exe"
            output_name="scyther-w32.exe"
            ;;
        *)
            print_error "Unknown or unsupported platform: $PLATFORM"
            print_info "Supported platforms: linux, macos-arm, macos-intel, windows"
            exit 1
            ;;
    esac
    
    print_info "Building for platform: $PLATFORM"
    print_info "Build type: $BUILD_TYPE"
    print_info "Target OS: $target_os"
    
    # Change to source directory
    cd "$SCRIPT_DIR"
    
    # Configure with CMake
    print_info "Running CMake configuration..."
    if [ "$VERBOSE" -eq 1 ]; then
        cmake $cmake_flags -D TARGETOS=$target_os . || {
            print_error "CMake configuration failed"
            exit 1
        }
    else
        cmake $cmake_flags -D TARGETOS=$target_os . > /dev/null || {
            print_error "CMake configuration failed (run with --verbose for details)"
            exit 1
        }
    fi
    print_success "CMake configuration complete"
    
    # Build
    print_info "Building $binary_name..."
    if [ "$VERBOSE" -eq 1 ]; then
        make || {
            print_error "Build failed"
            exit 1
        }
    else
        make 2>&1 | grep -E "error:|warning:" || make > /dev/null || {
            print_error "Build failed (run with --verbose for details)"
            exit 1
        }
    fi
    print_success "Build complete: $binary_name"
    
    # Copy to GUI directory
    local gui_dir="$SCRIPT_DIR/../gui/Scyther"
    if [ -d "$gui_dir" ]; then
        print_info "Copying binary to GUI directory..."
        cp "$binary_name" "$gui_dir/$output_name" || {
            print_error "Failed to copy binary to $gui_dir"
            exit 1
        }
        print_success "Binary copied to: $gui_dir/$output_name"
        
        # Also copy to ~/bin if it exists (Linux only)
        if [ "$PLATFORM" = "linux" ] && [ -d "$HOME/bin" ]; then
            cp "$binary_name" "$HOME/bin/" 2>/dev/null && \
                print_success "Binary also copied to: ~/bin/$binary_name"
        fi
    else
        print_warning "GUI directory not found: $gui_dir"
        print_info "Binary available at: $SCRIPT_DIR/$binary_name"
    fi
    
    echo
    echo "---------------------------------------------------------"
    print_success "Build completed successfully!"
    echo "---------------------------------------------------------"
    echo "  Platform:    $PLATFORM"
    echo "  Build type:  $BUILD_TYPE"
    echo "  Binary:      $SCRIPT_DIR/$binary_name"
    if [ -d "$gui_dir" ]; then
        echo "  GUI binary:  $gui_dir/$output_name"
    fi
    echo "---------------------------------------------------------"
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Parse arguments
    for arg in "$@"; do
        case $arg in
            --platform=*)
                PLATFORM="${arg#*=}"
                shift
                ;;
            --debug)
                BUILD_TYPE="Debug"
                shift
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            --out-of-tree)
                OUT_OF_TREE=1
                print_warning "Out-of-tree builds not yet fully implemented, using in-tree build"
                shift
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $arg"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Auto-detect platform if not specified
    if [ -z "$PLATFORM" ]; then
        detect_platform
    fi
    
    echo
    echo "========================================================="
    echo "  Scyther Build System"
    echo "========================================================="
    echo
    
    # Check prerequisites
    check_prerequisites
    
    # Generate version info
    generate_version
    echo
    
    # Build
    build_for_platform
}

# Run main function
main "$@"

