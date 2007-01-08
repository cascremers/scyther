################################################################
# Name:		CMakeLists.txt
# Purpose:	Input file for CMake for the Scyther tool
# Author:	Cas Cremers
################################################################

# Scyther project
project (Scyther)
# I need 2.4 for flex/etc although it does not run yet
#CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

# List all the source files
set (Scyther_sources
	arachne.c binding.c claim.c color.c compiler.c cost.c
	debug.c depend.c dotout.c error.c heuristic.c hidelevel.c
	intruderknowledge.c knowledge.c label.c list.c main.c mgu.c
	prune_bounds.c prune_theorems.c role.c 
	specialterm.c states.c switches.c symbol.c system.c tac.c
	termlist.c termmap.c term.c timer.c type.c warshall.c xmlout.c
	parser.c scanner.c
  )

# If we are in a debug mode we want to be strict
set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -DDEBUG")

# Determine version number
include (SVNVersion.cmake)

# Make scanner and parser
include (ScannerParser.cmake)

# By default, we build what we get
mark_as_advanced (CLEAR TARGETOS)
if (NOT TARGETOS)
	if (WIN32)
		set (TARGETOS "WIN32")
	else (WIN32)
		if (APPLE)
			set (TARGETOS "APPLE")
		else (APPLE)
			if (UNIX)
				set (TARGETOS "UNIX")
			endif (UNIX)
		endif (APPLE)
	endif (WIN32)
endif (NOT TARGETOS)

# Determine name and target from type
if (${TARGETOS} STREQUAL "UNIX")
	# Should for now only be done on the unix platform
	if (UNIX)
		message (STATUS "Building Linux version")
		set (scythername "scyther-linux")
		add_executable (${scythername} ${Scyther_sources})
	endif (UNIX)
endif (${TARGETOS} STREQUAL "UNIX")

if (${TARGETOS} STREQUAL "APPLE")
	if (APPLE)
		# Should for now only be done on the apple platform
		message (STATUS "Building Apple version")
		set (scythername "scyther-mac")
		add_executable (${scythername} ${Scyther_sources})
	endif (APPLE)
endif (${TARGETOS} STREQUAL "APPLE")

if (${TARGETOS} STREQUAL "WIN32")
	# This should work on win32 platform, but also when the compiler
	# is available anyway under linux
	set (CMAKE_C_COMPILER "i586-mingw32msvc-gcc")
	set (CMAKE_CXX_COMPILER "i586-mingw32msvc-g++")
	set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)	# to get rid of -rdynamic
	message (STATUS "Building W32 version")
	set (scythername "scyther-w32.exe")
	add_executable (${scythername} ${Scyther_sources})
endif (${TARGETOS} STREQUAL "WIN32")

# Make the Scyther linux binary
if (NOT scythername)
	message (FATAL_ERROR "Cannot determine target platform [${TARGETOS}]")
endif (NOT scythername)



