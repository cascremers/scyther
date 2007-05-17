################################################################
# Name:		BuildUnix.cmake
# Purpose:	Build Unix binary on self
# Author:	Cas Cremers
################################################################

# We call it linux, because that is what de-facto is the case.

message (STATUS "Building Linux version")
set (scythername "scyther-linux")
add_executable (${scythername} ${Scyther_sources})

