################################################################
# Name:		SVNVersion.cmake
# Purpose:	Determine subversion revision id for Scyther
#		and write it into a macro in version.h
# Author:	Cas Cremers
################################################################

# TODO: Technically, this only needs to be redone each time a file
# changes, so this might be a target with dependencies on all files.

# Checkout version info
set_source_files_properties(version.h
	PROPERTIES
	GENERATED true)
find_program (SVNVERSION_EXECUTABLE NAMES svnversion)
if (SVNVERSION_EXECUTABLE)
	# svnversion found; we should always build this
	message (STATUS "Generating version.h using svnversion command")
	exec_program (${SVNVERSION_EXECUTABLE}
		OUTPUT_VARIABLE SVN_Version
	)
	message (STATUS "svnversion gave ${SVN_Version}")
	file (WRITE version.h
		"#define SVNVERSION \"${SVN_Version}\"\n"
	)
else (SVNVERSION_EXECUTABLE)
	# No svnversion. what do we write then? just empty...?
	message (STATUS "Generating empty version.h")
	file (WRITE version.h "")
endif (SVNVERSION_EXECUTABLE)

