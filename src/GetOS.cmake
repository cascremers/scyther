################################################################
# Name:		GetOS.cmake
# Purpose:	Determine Source_OS and Destination_OS (-DTARGETOS)
# Author:	Cas Cremers
################################################################

# Supported types:
#
# Win32
# Unix
# MacIntel

# First we find out the current operating system
set (Source_OS)
if (WIN32)
	# Windows
	set (Source_OS "Win32")
else (WIN32)
	# Not windows, is it a mac?
	if (APPLE)
		if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "arm64" AND NOT DEFINED ENV{ARCH})
			# If Apple and Arm64, set Source_OS to MacArm
			set(Source_OS "MacArm")
		else(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "arm64" AND NOT DEFINED ENV{ARCH})
			# If not arm64, assume Intel for legacy reasons.
			set(Source_OS "MacIntel")
		endif(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "arm64" AND NOT DEFINED ENV{ARCH})
		
	else (APPLE)
		# Not a mac, not windows
		if (UNIX)
			set (Source_OS "Unix")
		else (UNIX)
			message (FATAL "Unrecognized source platform.")
		endif (UNIX)
	endif (APPLE)
endif (WIN32)
#message (STATUS "Source platform: ${Source_OS}")

# Destination? If target is unset, we just take the source
if (TARGETOS)
	set (Destination_OS "${TARGETOS}")
else (TARGETOS)
	set (Destination_OS "${Source_OS}")
endif (TARGETOS)
#message (STATUS "Destination platform: ${Destination_OS}")

