# Scyther Makefile
# Main build orchestration for the Scyther protocol verifier

.PHONY: default all build clean manual test help

# Default target
default: build

# Build the Scyther backend
build:
	@echo "Building Scyther..."
	cd src && ./build.sh

# Build with all options
all: build manual

# Build the manual
manual:
	@echo "Building manual..."
	cd manual && make

# Run tests
test:
	@echo "Running Scyther protocol tests..."
	@if [ ! -f gui/Scyther/scyther-linux ] && [ ! -f gui/Scyther/scyther-mac ] && [ ! -f gui/Scyther/scyther-mac-arm ]; then \
		echo "Error: Scyther binary not found. Please run 'make build' first."; \
		exit 1; \
	fi
	@./scripts/run-tests.sh

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cd src && make clean
	@rm -f src/scyther-linux src/scyther-mac src/scyther-w32.exe
	@rm -f src/CMakeCache.txt src/cmake_install.cmake
	@rm -rf src/CMakeFiles
	@echo "Clean complete"

# Show help
help:
	@echo "Scyther Build System"
	@echo "===================="
	@echo ""
	@echo "Available targets:"
	@echo "  make           - Build Scyther for current platform (default)"
	@echo "  make build     - Build Scyther for current platform"
	@echo "  make all       - Build Scyther and manual"
	@echo "  make manual    - Build the PDF manual"
	@echo "  make test      - Run protocol verification tests"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make help      - Show this help message"
	@echo ""
	@echo "Build options (use with src/build.sh directly):"
	@echo "  ./src/build.sh --help           - Show build script help"
	@echo "  ./src/build.sh --debug          - Build debug version"
	@echo "  ./src/build.sh --verbose        - Verbose build output"
	@echo "  ./src/build.sh --platform=linux - Build for specific platform"
	@echo ""
	@echo "Examples:"
	@echo "  make                           # Build for current platform"
	@echo "  make test                      # Run tests"
	@echo "  cd src && ./build.sh --debug   # Build debug version"
	@echo ""


