################################################################
# Name:		UniversalBinary.cmake
# Purpose:	Add target to make a Mac universal binary
#		Needs pre-build mac versions first!
# Author:	Cas Cremers
################################################################

find_program(lipoexecutable lipo)
if (lipoexecutable)
	# Check whether we already have the binaries
	set (UBrequiredfiles FALSE)
	set (ppcfile	"${CMAKE_CURRENT_BINARY_DIR}/scyther-macppc")
	set (intelfile	"${CMAKE_CURRENT_BINARY_DIR}/scyther-macintel")
	if (EXISTS "${ppcfile}")
		if (EXISTS "${intelfile}")
			set (UBrequiredfiles TRUE)
		else (EXISTS "${intelfile}")
			message (STATUS "Could not find scyther-macintel.")
		endif (EXISTS "${intelfile}")
	else (EXISTS "${ppcfile}")
		message (STATUS "Could not find scyther-macppc.")
	endif (EXISTS "${ppcfile}")
	
	# Use information to proceed
	if (UBrequiredfiles)
		message (STATUS "Adding target for Mac universal binary")
		add_custom_target (scyther-mac
			COMMAND	lipo -create "${ppcfile}" "${intelfile}" -output scyther-mac
			COMMENT	"Generating Mac universal binary"
			DEPENDS	scyther-macintel
			DEPENDS	scyther-macppc
		)
	else (UBrequiredfiles)
		message (STATUS "No universal binary possible yet. Please do the following:")
		message (STATUS "  cmake -DTARGETOS=MacPPC   . && make")
		message (STATUS "  cmake -DTARGETOS=MacIntel . && make")
		message (STATUS "  cmake . && make scyther-mac")
	endif (UBrequiredfiles)
else (lipoexecutable)
	message (FATAL_ERROR "Cannot find the 'lipo' program that is required for creating universal binaries")
endif (lipoexecutable)

