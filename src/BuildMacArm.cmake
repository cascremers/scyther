################################################################
# Name:		BuildMacIntel.cmake
# Purpose:	Build MacIntel binary
# Author:	Cas Cremers
################################################################

message (STATUS "Building Apple Mac ARM version")
set (scythername "scyther-mac")
add_executable (${scythername} ${Scyther_sources})
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mmacosx-version-min=10.15")

