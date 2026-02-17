# Scyther Makefile
# Main build orchestration for the Scyther protocol verifier

# Installation directories
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share/scyther
MANDIR ?= $(PREFIX)/share/doc/scyther
INSTALL_DIRS := $(DESTDIR)$(BINDIR) $(DESTDIR)$(DATADIR)/Protocols $(DESTDIR)$(DATADIR)/Images $(DESTDIR)$(MANDIR)

# Auto-detect platform binary
SCYTHER_BINARY := $(firstword $(wildcard gui/Scyther/scyther-linux gui/Scyther/scyther-mac-arm gui/Scyther/scyther-mac))

.PHONY: default all build clean manual test install uninstall help

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
	@if [ -z "$(SCYTHER_BINARY)" ]; then \
		echo "Error: Scyther binary not found. Please run 'make build' first."; \
		exit 1; \
	fi
	@./scripts/run-tests.sh

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cd src && make clean
	@rm -f src/scyther-linux src/scyther-mac src/scyther-mac-arm src/scyther-w32.exe
	@rm -f src/CMakeCache.txt src/cmake_install.cmake
	@rm -rf src/CMakeFiles
	@echo "Clean complete"

# Install Scyther system-wide
install:
	@echo "Installing Scyther to $(PREFIX)..."
	@install -d $(INSTALL_DIRS)
	@# Install binaries
	@if [ -z "$(SCYTHER_BINARY)" ]; then \
		echo "Error: No Scyther binary found. Run 'make' first as a regular user, then 'sudo make install'."; \
		exit 1; \
	fi
	@echo "Installing $(notdir $(SCYTHER_BINARY))..."
	@install -m 755 $(SCYTHER_BINARY) $(DESTDIR)$(BINDIR)/scyther
	@# Install GUI scripts and dependencies to data directory
	@echo "Installing GUI scripts..."
	@install -m 755 gui/scyther-gui.py $(DESTDIR)$(DATADIR)/scyther-gui.py
	@install -m 644 gui/requirements.txt $(DESTDIR)$(DATADIR)/requirements.txt
	@# Install protocol models
	@echo "Installing protocol models..."
	@cp -r gui/Protocols/. $(DESTDIR)$(DATADIR)/Protocols/
	@# Install images
	@echo "Installing images..."
	@cp -r gui/Images/. $(DESTDIR)$(DATADIR)/Images/
	@# Install Python modules
	@echo "Installing Python modules..."
	@cp -r gui/Scyther $(DESTDIR)$(DATADIR)/
	@cp -r gui/Gui $(DESTDIR)$(DATADIR)/
	@# Create wrapper script for GUI from template
	@echo "Creating GUI launcher wrapper..."
	@sed 's|@DATADIR@|$(DATADIR)|g' scripts/scyther-gui.in > $(DESTDIR)$(BINDIR)/scyther-gui
	@chmod 755 $(DESTDIR)$(BINDIR)/scyther-gui
	@# Install manual if available
	@if [ -f gui/scyther-manual.pdf ]; then \
		echo "Installing manual..."; \
		install -m 644 gui/scyther-manual.pdf $(DESTDIR)$(MANDIR)/; \
	fi
	@echo ""
	@echo "========================================================="
	@echo "Installation complete!"
	@echo "========================================================="
	@echo "  Binary:     $(BINDIR)/scyther"
	@echo "  GUI:        $(BINDIR)/scyther-gui"
	@echo "  Protocols:  $(DATADIR)/Protocols/"
	@echo "  Manual:     $(MANDIR)/scyther-manual.pdf"
	@echo ""
	@echo "Run 'scyther --help' or 'scyther-gui' to get started."
	@echo "========================================================="

# Uninstall Scyther
uninstall:
	@echo "Uninstalling Scyther from $(PREFIX)..."
	@rm -f $(DESTDIR)$(BINDIR)/scyther
	@rm -f $(DESTDIR)$(BINDIR)/scyther-gui
	@rm -rf $(DESTDIR)$(DATADIR)
	@rm -rf $(DESTDIR)$(MANDIR)
	@echo "Uninstall complete"

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
	@echo "  make install   - Install Scyther system-wide (may require sudo)"
	@echo "  make uninstall - Remove installed files"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make help      - Show this help message"
	@echo ""
	@echo "Installation options (set before 'make install'):"
	@echo "  PREFIX=/usr/local  - Installation prefix (default: /usr/local)"
	@echo "  DESTDIR=           - Staging directory for package builds"
	@echo ""
	@echo "Build options (use with src/build.sh directly):"
	@echo "  ./src/build.sh --help     - Show all build options"
	@echo "  ./src/build.sh --debug    - Build with debug symbols"
	@echo "  ./src/build.sh --verbose  - Verbose build output"
	@echo "  ./src/build.sh --platform=linux - Build for specific platform"
	@echo ""
	@echo "Examples:"
	@echo "  make                              # Build for current platform"
	@echo "  make test                         # Run tests"
	@echo "  make && sudo make install         # Build then install to /usr/local"
	@echo "  make install PREFIX=/opt/scyther  # Install to custom location (build first!)"
	@echo "  cd src && ./build.sh --debug      # Build debug version"
	@echo ""
	@echo "Note: Always run 'make' as a regular user before 'sudo make install'"
	@echo "      to avoid permission issues with build artifacts."
	@echo ""


