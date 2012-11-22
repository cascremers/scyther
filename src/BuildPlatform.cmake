################################################################
# Name:		BuildPlatform.cmake
# Purpose:	Make platform-dependant decisions
# Author:	Cas Cremers
################################################################

# Retrieve Source_OS, Destination_OS (from -DTARGET)
include (GetOS.cmake)

# From source_os and destination_os make a new name for the build script
if (Source_OS STREQUAL Destination_OS)
	set (BuildScriptName "Build${Source_OS}.cmake")
else (Source_OS STREQUAL Destination_OS)
	set (BuildScriptName "Build${Source_OS}-${Destination_OS}.cmake")
endif (Source_OS STREQUAL Destination_OS)
message (STATUS "Locating platform specific file ${BuildScriptName}")

# Locate the file. If it exists, start it
if (EXISTS ${BuildScriptName})
	# Execute the build script
	include (${BuildScriptName})
else (EXISTS ${BuildScriptName})
	# Could not find it!
	message (STATUS "Could not find ${BuildScriptName}")
	if (Source_OS STREQUAL Destination_OS)
		message (FATAL_ERROR "Don't know how to build on ${Source_OS}")
	else (Source_OS STREQUAL Destination_OS)
		message (FATAL_ERROR "Don't know how to build for ${Destination_OS} on ${Source_OS}")
	endif (Source_OS STREQUAL Destination_OS)
endif (EXISTS ${BuildScriptName})

