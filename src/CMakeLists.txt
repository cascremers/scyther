################################################################
# Name:		CMakeLists.txt
# Purpose:	Input file for CMake for the Scyther tool
# Author:	Cas Cremers
################################################################

CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

# Scyther project
project (Scyther)

# Try clang
#set (CMAKE_C_COMPILER "clang")

# List all the source files
set (Scyther_sources
	arachne.c binding.c claim.c color.c compiler.c cost.c
	debug.c depend.c dotout.c error.c heuristic.c hidelevel.c
	intruderknowledge.c knowledge.c label.c list.c main.c mgu.c
	prune_bounds.c prune_theorems.c role.c
	specialterm.c states.c switches.c symbol.c system.c tac.c
	tempfile.c
	termlist.c termmap.c term.c timer.c type.c warshall.c xmlout.c
	parser.c scanner.c
  )

# If we are in a debug mode we want to be strict
set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -DDEBUG -std=c11")

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-non-prototype -std=c11")

# Make scanner and parser
include (ScannerParser.cmake)

# Set build target settings according to platform
include (BuildPlatform.cmake)

