################################################################
# Name:		UniversalBinary.cmake
# Purpose:	Add target to make a Mac universal binary
#		Needs pre-build mac versions first!
# Author:	Cas Cremers
################################################################

find_program(lipoexecutable lipo)
if (lipoexecutable)
	# Check whether we already have the binaries
	set (requiredfiles false)
	find_file (ppcfile "scyther-macppc" .)
	if (ppcfile)
		find_file (intelfile "scyther-macintel" .)
		if (intelfile)
			set (requiredfiles true)
		else (intelfile)
			message (FATAL_ERROR "Could not find scyther-macintel, which is required for the universal binary.")
		endif (intelfile)
	else (ppcfile)
		message (FATAL_ERROR "Could not find scyther-macppc, which is required for the universal binary.")
	endif (ppcfile)
	
	# Use information to proceed
	if (requiredfiles)
		message (STATUS "Adding target for Mac universal binary")
		add_custom_target (scyther-mac
			COMMAND	lipo -create ${ppcfile} ${intelfile} -output scyther-mac
		)
	else (requiredfiles)
		message (STATUS "No universal binary possible yet. Please do the following:")
		message (STATUS "  cmake -DTARGETOS=MacPPC   . && make")
		message (STATUS "  cmake -DTARGETOS=MacIntel . && make")
		message (STATUS "  cmake . && make scyther-mac")
	endif (requiredfiles)
else (lipoexecutable)
	message (FATAL_ERROR "Cannot find lipo program to create universal binaries")
endif (lipoexecutable)

