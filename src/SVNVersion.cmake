################################################################
# Name:		SVNVersion.cmake
# Purpose:	Determine subversion revision id for Scyther
#		and write it into a macro in version.h
# Author:	Cas Cremers
################################################################

# Technically, this only needs to be redone each time a file
# changes, so this is a target with dependencies on all files.

# Checkout version info
find_program (SVNVERSION_EXECUTABLE NAMES svnversion)
mark_as_advanced (SVNVERSION_EXECUTABLE)
mark_as_advanced (SVNVERSION_DYNAMIC)
set (SVNVERSION_DYNAMIC false)
if (SVNVERSION_EXECUTABLE)
	# test whether svnversion gives useful info
	execute_process (
		COMMAND	${SVNVERSION_EXECUTABLE} --no-newline
		OUTPUT_VARIABLE SVN_Result
	)
	mark_as_advanced (SVN_Result)
	if (NOT ${SVN_Result} STREQUAL "exported")
		# svnversion gives useful stuff
		## write to file
		#file (WRITE version.h "#define SVNVERSION \"${SVN_Result}\"\n")
		set (SVNVERSION_DYNAMIC true)
	endif (NOT ${SVN_Result} STREQUAL "exported")
	mark_as_advanced (SVNDIR)
endif (SVNVERSION_EXECUTABLE)

# If dynamic generation is required, this means another target in the
# makefile
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
		COMMAND	./subbuild-version-information.sh
		COMMENT	"Generating subversion and tag version information in version.h using svnversion command"
	)
else (SVNVERSION_DYNAMIC)
	# Don't dynamically generate, simply empty every time
	file (WRITE version.h "#define SVNVERSION \"Unknown\"\n#define TAGVERSION \"Unknown\"")
endif (SVNVERSION_DYNAMIC)

# add the version number to the sources
set_source_files_properties(version.h
	PROPERTIES
	GENERATED true)
set (Scyther_sources ${Scyther_sources} version.h)

