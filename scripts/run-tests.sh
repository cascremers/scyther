#!/usr/bin/env bash

# Scyther Test Runner
# Runs verification tests on a set of protocol models to validate the build

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Find the scyther binary
find_scyther_binary() {
    local binary=""
    
    # Check for various platform binaries in gui/Scyther
    if [ -f "$PROJECT_ROOT/gui/Scyther/scyther-linux" ]; then
        binary="$PROJECT_ROOT/gui/Scyther/scyther-linux"
    elif [ -f "$PROJECT_ROOT/gui/Scyther/scyther-mac-arm" ]; then
        binary="$PROJECT_ROOT/gui/Scyther/scyther-mac-arm"
    elif [ -f "$PROJECT_ROOT/gui/Scyther/scyther-mac" ]; then
        binary="$PROJECT_ROOT/gui/Scyther/scyther-mac"
    elif [ -f "$PROJECT_ROOT/src/scyther-linux" ]; then
        binary="$PROJECT_ROOT/src/scyther-linux"
    elif [ -f "$PROJECT_ROOT/src/scyther-mac" ]; then
        binary="$PROJECT_ROOT/src/scyther-mac"
    else
        print_error "Scyther binary not found!"
        print_info "Please build Scyther first using: make build"
        exit 1
    fi
    
    echo "$binary"
}

# Run a single test
run_test() {
    local protocol_file="$1"
    local protocol_name=$(basename "$protocol_file" .spdl)
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    # Run scyther with basic verification
    # Use limited bounds for quick smoke testing
    # Note: Scyther may return non-zero exit codes when it finds attacks,
    # so we just check that it runs without crashing or erroring out completely
    local output
    local exit_code=0
    
    # Run with a timeout and limited bounds for quick testing
    output=$(timeout 15s "$SCYTHER_BINARY" --max-runs=3 --auto-claims "$protocol_file" 2>&1) || exit_code=$?
    
    # Check if it didn't timeout (exit code 124) or crash (segfault, etc.)
    if [ "$exit_code" = "124" ]; then
        print_error "Test timed out: $protocol_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    elif [ "$exit_code" = "139" ] || [ "$exit_code" = "134" ]; then
        # Segfault or abort
        print_error "Test crashed: $protocol_name (exit code $exit_code)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    elif echo "$output" | grep -qi "parse error\|syntax error\|fatal"; then
        # Check if there was an actual error (parsing, etc.)
        print_error "Test failed with error: $protocol_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    else
        # Success - scyther ran and produced some output
        print_success "Test passed: $protocol_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

# Main test suite
run_test_suite() {
    print_info "Running Scyther test suite..."
    echo
    
    # Test basic well-known protocols from gui/Protocols
    # Using simpler protocols that verify quickly for build testing
    local test_protocols=(
        "$PROJECT_ROOT/gui/Protocols/needham-schroeder-lowe.spdl"
        "$PROJECT_ROOT/gui/Protocols/yahalom.spdl"
        "$PROJECT_ROOT/gui/Protocols/otwayrees.spdl"
    )
    
    print_info "Running quick smoke tests on sample protocols..."
    print_info "(For full protocol analysis, use the Scyther GUI)"
    echo
    
    for protocol in "${test_protocols[@]}"; do
        if [ -f "$protocol" ]; then
            run_test "$protocol"
        else
            print_warning "Skipped: $(basename "$protocol") (file not found)"
            TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        fi
    done
}

# Test that scyther binary runs and shows version/help
test_binary_sanity() {
    print_info "Testing binary sanity..."
    
    TESTS_RUN=$((TESTS_RUN + 1))
    if "$SCYTHER_BINARY" --help > /dev/null 2>&1 || "$SCYTHER_BINARY" --version > /dev/null 2>&1 || "$SCYTHER_BINARY" > /dev/null 2>&1; then
        print_success "Binary sanity check passed"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo
        return 0
    else
        print_error "Binary sanity check failed"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo
        return 1
    fi
}

# Print summary
print_summary() {
    echo
    echo "========================================================="
    echo "  Test Summary"
    echo "========================================================="
    echo "  Total tests:    $TESTS_RUN"
    echo -e "  ${GREEN}Passed:${NC}         $TESTS_PASSED"
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "  ${RED}Failed:${NC}         $TESTS_FAILED"
    else
        echo "  Failed:         $TESTS_FAILED"
    fi
    if [ $TESTS_SKIPPED -gt 0 ]; then
        echo "  Skipped:        $TESTS_SKIPPED"
    fi
    echo "========================================================="
    
    if [ $TESTS_FAILED -eq 0 ] && [ $TESTS_PASSED -gt 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    elif [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        return 1
    else
        echo -e "${YELLOW}No tests were run!${NC}"
        return 1
    fi
}

# Main
main() {
    echo
    echo "========================================================="
    echo "  Scyther Test Suite"
    echo "========================================================="
    echo
    
    # Find binary
    SCYTHER_BINARY=$(find_scyther_binary)
    print_info "Using binary: $SCYTHER_BINARY"
    echo
    
    # Run tests
    test_binary_sanity
    run_test_suite
    
    # Print summary
    print_summary
}

main "$@"
