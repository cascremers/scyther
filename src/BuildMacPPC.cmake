################################################################
# Name:		BuildMacPPC.cmake
# Purpose:	Build MacPPC binary 
# Author:	Cas Cremers
################################################################

message (STATUS "Building Apple Mac PPC version")
set (scythername "scyther-macppc")
add_executable (${scythername} ${Scyther_sources})
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fnested-functions -arch ppc")

