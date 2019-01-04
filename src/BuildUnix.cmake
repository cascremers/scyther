################################################################
# Name:		BuildUnix.cmake
# Purpose:	Build Unix binary on self
# Author:	Cas Cremers
################################################################

# We call it linux, because that is what de-facto is the case.

message (STATUS "Building Linux version")

# Static where possible (i.e. only not on the APPLE)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static")

set (scythername "scyther-linux")
add_executable (${scythername} ${Scyther_sources})

