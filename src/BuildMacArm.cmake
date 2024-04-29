################################################################
# Name:		BuildMacArm.cmake
# Purpose:	Build MacArm binary
# Author:	Sam Jakob M.
################################################################

message (STATUS "Building Apple Mac ARM (Apple Silicon) version")
set (scythername "scyther-mac")
add_executable (${scythername} ${Scyther_sources})
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mmacosx-version-min=10.15")
