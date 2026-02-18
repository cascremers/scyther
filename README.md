The Scyther tool repository
===========================

This README describes the organization of the repository of the Scyther
tool for security protocol analysis. Its intended audience are
interested users and future developers of the Scyther tool, as well as
protocol modelers. For installation, usage instructions, and pre-built binaries of the
Scyther tool see:
<https://cispa.saarland/group/cremers/scyther/index.html>.

Installing from source
----------------------

We use Linux during the development of Scyther, but development on
Windows and macOS should be equally feasible. The build system
automatically detects your platform and configures the build accordingly.

Scyther is written partly in Python 3 (for the GUI, using wxPython) and
partly in C (for the backend). 

### Quick start

The simplest way to build Scyther is:

```bash
make
```

This will automatically check prerequisites, detect your platform, and build
the appropriate binary. The build system supports Linux, macOS (Intel and ARM),
and Windows cross-compilation.

### Build options

For advanced build options (debug builds, verbose output, cross-compilation), 
use the build script directly:

```bash
./src/build.sh --help            # Show all available options
./src/build.sh --debug           # Build debug version
./src/build.sh --verbose         # Show detailed build output
./src/build.sh --platform=linux  # Build for specific platform
```

Supported platforms: `linux`, `macos-arm`, `macos-intel`, `windows`

Note: `make` is a convenience wrapper that calls `build.sh` with auto-detection.
For advanced options, call `build.sh` directly as shown above.

### Available make targets

  * `make` or `make build` - Build Scyther for current platform
  * `make test` - Run automated protocol verification tests
  * `make clean` - Remove build artifacts
  * `make manual` - Build the PDF manual
  * `make help` - Show all available targets

### Prerequisites

The build process depends on the following tools:

  * `cmake` (version 3.5 or later)
  * `build-essential` (or equivalent C compiler)
  * `flex`
  * `bison`
  * `gcc-multilib` (Linux only, for 32-bit support)
  * `python3-minimal`

The build script automatically checks for these prerequisites and provides
installation instructions if anything is missing.

**Ubuntu/Debian:**
```bash
sudo apt-get install cmake build-essential flex bison gcc-multilib python3-minimal
```

**macOS:**
```bash
brew install cmake flex bison
xcode-select --install  # For compiler
```

**Windows cross-compilation (from Linux):**
```bash
sudo apt-get install mingw-w64
./src/build.sh --platform=windows
```

### Python GUI Requirements

The GUI requires Python 3 with wxPython 4.0 or later. You can install it:

**Option 1: Automatic (recommended)**
```bash
python3 gui/scyther-gui.py
# Will automatically set up a virtual environment if wxPython is not found
```

**Option 2: Manual system-wide installation**
```bash
pip3 install -r gui/requirements.txt
```

**Option 3: Manual virtual environment**
```bash
cd gui
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip3 install -r requirements.txt
```

### Running Scyther

After building, the binary is automatically copied to `./gui/Scyther/`. You can
run the graphical interface with:

```bash
python3 gui/scyther-gui.py
```

**Note:** If wxPython is not installed, the script will automatically detect this
and set up a virtual environment with all required dependencies. This is handled
transparently on first run.

### System-wide Installation

To install Scyther system-wide (typically to `/usr/local`):

```bash
make                    # Build as regular user first
sudo make install       # Then install as root
```

**Important:** Always build as a regular user before running `sudo make install`.
Running `make` with sudo will create root-owned files in the source tree, preventing
future builds as a regular user.

The install target will:
- Install the `scyther` binary to `$(PREFIX)/bin/`
- Install the GUI launcher `scyther-gui` to `$(PREFIX)/bin/`
- Install protocol models, Python modules, and images to `$(PREFIX)/share/scyther/`
- Create a user-local virtual environment for wxPython if needed (in `~/.local/share/scyther/venv`)

To customize the installation location:
```bash
make install PREFIX=/opt/scyther
```

To uninstall:
```bash
sudo make uninstall
```

### Testing

To verify your build works correctly, run:

```bash
make test
```

This runs automated smoke tests on sample protocols to ensure the verifier
is functioning properly.

Note that welcome all contributions, e.g., further protocol models. Just send
us a pull request.

Manual
------

The Scyther user manual can be found here:

  * [./gui/scyther-manual.pdf](gui/scyther-manual.pdf)


Protocol Models
---------------

The protocol models have the extension `.spdl` and can be found in the following directories:

  * [./gui/Protocols](gui/Protocols), containing the officially released models, and
  * [./testing](testing), containing models currently under development.

License
-------

Currently these Scyther sources are licensed under the GPL 2, as indicated in
the source code. Contact Cas Cremers if you have any questions.

