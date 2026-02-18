# Changelog

All notable changes to the Scyther tool will be documented in this file.

## [1.3.0] - 2026-02-18

This release focuses on documentation improvements, build system modernization, and platform support enhancements.

### Added
- Comprehensive manual improvements with updated documentation of command-line options and helper scripts
- Visual language descriptions and better explanations of attack graphs in the manual
- GitHub Actions workflow for automated multi-platform builds
- Cross-compilation support from Intel to ARM macOS
- System-wide installation targets (`make install` and `make uninstall`)
- Virtual environment script (`scyther-gui-venv.sh`) for automatic wxPython installation
- Improved build system interface with better platform detection

### Changed
- Manual is now considered stable (removed "draft" status)
- Modernized build system with cleaner interface and better testing
- Updated manual margins and formatting for better readability
- Updated bibliography and website references throughout documentation
- Improved .gitignore for better handling of build artifacts
- Updated copyright years and URLs to reflect current organization

### Fixed
- Fixed bug that could prevent showing claim results
- Fixed minimal Python version specification
- Fixed Windows path detection issues
- Fixed Linux shebang lines
- Various UI fixes including theming and confirm loss dialog
- Build scripts now fail on first failing command for better error detection

## [1.2.1] - 2020-02-05

### Changed
- Removed redundant comments and obsolete code clauses
- Updated copyright year to 2020

### Fixed
- Fixed Linux shebang lines
- Fixed Windows path detection
- Various minor bugfixes

## [1.2] - 2020-01-28

This release modernizes the dependencies and simplifies installation on modern versions of the three supported platforms.

### Added
- Python 3 support (replacing Python 2)
- wxPython 4.0 support and requirement
- Updated installation instructions
- Issue templates and reporting guidelines

### Changed
- Full conversion from Python 2 to Python 3 using 2to3
- Updated GUI to work with wxPython 4.0 (major upgrade from wxPython 2.8)
- Modernized shell command execution code
- Updated copyright notices to 2020
- Updated documentation regarding Python 3 and wxPython 4

### Removed
- Python 2 support (dropped)
- wxPython 2.8 support (superseded by wxPython 4.0)
- Obsolete Mac PPC compilation artifacts

### Fixed
- Fixed deprecated use of ElementTree XML objects' `getchildren` method
- Fixed wxPython 4 errors for highlighting SPDL errors
- Fixed several wxPython 4 compatibility issues
- Fixed GCC warnings with safer constructs
- Fixed Python reference to include version number for building from source

## [1.1.3] - 2013-05-03

### Changed
- Updated installation instructions
- Updated 'ffgg' protocol generator for new conventions
- Minor manual update

### Fixed
- Reverted use of shlex (was breaking abort backend thread functionality on Windows)
- Added hack to avoid manual Graphviz path setting on Windows in most cases

## [1.1.2] - 2012-11-26

### Fixed
- Fixed rare bug in some cases where hashes were used as symmetric keys
- Fixed invoking Scyther scripts from non-standard directories or using symlinks
- Improved compatibility with recent versions of Graphviz (>2.26)

### Added
- Weakagree and Alive claims now allow optional role parameter (useful for protocols with more than two roles)
- Python script to dump attack outputs for large sets of files
- GUI: Canceling verification now kills back-end thread

### Changed
- Reintroduced option for specifying alternative PKI

## [1.1.1] - 2012-09-24

Minor bugfix release (see v1.1.2 for details).

## [1.1] - 2012-09-13

Major feature release introducing powerful language extensions and new protocol models.

### Added
- **Language**: Support for `macro Term1 = Term2;` definitions, greatly simplifying specifications
- **Language**: Support for `match(T1,T2);` events in roles for delayed decryption modeling
- **Language**: Support for `not match(T1,T2);` events for protocol restrictions (e.g., `A != B`)
- **Language**: Support for `option "COMMANDLINE_OPTIONS";` in specifications for full access to command-line options
- **Backend**: `--one-role-per-agent` command-line option to disallow agents from performing multiple roles
- **Environment**: `SCYTHERCACHEDIR` environment variable to override internal cache path
- **Documentation**: First incomplete version of the new manual
- **Protocols**: IEEE 802.16e/WIMAX (PKMv2rsa and variants)
- **Protocols**: IKEv1 and IKEv2 protocol suites
- **Protocols**: ISO/IEC 9798 models
- Well-formedness check as described in the 2012 book

### Changed
- Dropped PPC support for Mac distributions (Intel only)
- Build system updates for Mac 10.8 with backward compatibility to 10.6 and 10.7

### Fixed
- Fixed compilation problem on Windows
- Fixed occurrence of multiple macro symbols in one tuple (could cause infinite loop)
- Fixed list-length code (uninitialized variable)
- Fixed compilation error when building outside of git
- Various typo corrections

## [1.0] - 2008-05-22

Initial stable release of Scyther.

### Added
- **Language**: Support for weak agreement claims
- **Language**: Support for non-injective data agreement through `Commit` and `Running` signals
- **GUI**: Mac support with universal binary
- **GUI**: Switched to Scintilla editor component with undo, line numbering, and error highlighting
- **Backend**: Detection when recv event cannot match with send event (helps catch specification errors)
- **Language**: Added claim parameter for Reachable claim (`Reachable,R` for role-specific trust)
- **Backend**: `--max-of-role=N` switch to narrow scenarios
- **Backend**: `--scan-claims` switch to retrieve list of claims
- **Scripting**: Added `verifyOne` and `scanClaims` methods to Scyther object

### Changed
- `--max-attacks=N` now defines maximum attacks per claim (was global maximum)
- Improved attack graph output
- Rewrote parts of GUI code for improved stability

### Fixed
- Fixed Python 2.5 compatibility with integrated (c)elementtree
- Fixed Windows Vista tmpfile() implementation issue (no attack output)
- Fixed Windows Vista support without breaking Windows XP
- Fixed bug in Python interface backend (e.g., with mpa.py)

---

## Version History Summary

### Major Version Differences

**v1.0 → v1.1**: Language Extensions & Protocol Models
- Introduced macro definitions, match/not match events, and flexible command-line options
- Added major protocol models (IKE, WIMAX, ISO/IEC 9798)
- Enhanced backend with role restrictions

**v1.1 → v1.2**: Platform Modernization
- Complete migration from Python 2 to Python 3
- Upgraded from wxPython 2.8 to wxPython 4.0
- Focused on compatibility with modern platforms

**v1.2 → v1.3**: Documentation & Build System
- Comprehensive manual overhaul (no longer draft)
- Modern build system with GitHub Actions
- Enhanced developer experience with better tooling

---

