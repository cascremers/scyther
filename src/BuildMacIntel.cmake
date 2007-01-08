################################################################
# Name:		BuildMacIntel.cmake
# Purpose:	Build MacIntel binary on self
# Author:	Cas Cremers
################################################################

message (STATUS "Building Apple Mac Intel version")
set (scythername "scyther-macintel")
add_executable (${scythername} ${Scyther_sources})
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fnested-functions -arch i386")

