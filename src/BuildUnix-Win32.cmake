################################################################
# Name:		BuildUnix-Win32.cmake
# Purpose:	Build Win32 binary on Unix
# Author:	Cas Cremers
################################################################

message (STATUS "Building W32 version")

# This should work on win32 platform, but also when the compiler
# is available anyway under linux
set (CMAKE_C_COMPILER "i586-mingw32msvc-gcc")
set (CMAKE_CXX_COMPILER "i586-mingw32msvc-g++")
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)	# to get rid of -rdynamic
# Signal for windows
set (CMAKE_C_FLAGS "-DFORWINDOWS")

# Static where possible (i.e. only not on the APPLE)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static -m32")

set (scythername "scyther-w32.exe")
add_executable (${scythername} ${Scyther_sources})

