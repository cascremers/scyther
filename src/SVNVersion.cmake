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
mark_as_advanced (SVNVERSION_EXECUTABLE)
mark_as_advanced (SVNVERSION_DYNAMIC)
set (SVNVERSION_DYNAMIC false)
if (SVNVERSION_EXECUTABLE)
	# svnversion found
	if (UNIX)
		# Unix system
		# test whether svnversion gives useful info
		exec_program (${SVNVERSION_EXECUTABLE}
			OUTPUT_VALUE SVN_Result
		)
		mark_as_advanced (SVN_Result)
		if (SVN_Result STREQUAL "exported")
			# svnversion gives useful stuff
			set (SVNVERSION_DYNAMIC true)
		endif (SVN_Result STREQUAL "exported")
		mark_as_advanced (SVNDIR)
	endif (UNIX)
endif (SVNVERSION_EXECUTABLE)

if (SVNVERSION_DYNAMIC)
	# add a command to generate version.h
	message (STATUS	"Generating version.h dynamically using svnversion command")
	add_custom_command (
		OUTPUT	version.h
		# The version number depends on all the files; if they
		# don't change, neither should the version number
		# (although this might be incorrect when updating the
		# current directory)
		DEPENDS	${Scyther_sources}
		DEPENDS .svn
		COMMAND	echo
		ARGS	"\\#define SVNVERSION \\\"`${SVNVERSION_EXECUTABLE}`\\\"" >version.h
		COMMENT	"Generating subversion version information in version.h using svnversion command"
	)
else (SVNVERSION_DYNAMIC)
	# Don't dynamically generate, simply empty every time
	file (WRITE version.h "#define SVNVERSION \"Unknown\"\n")
endif (SVNVERSION_DYNAMIC)

# add the version number to the sources
set (Scyther_sources ${Scyther_sources} version.h)

