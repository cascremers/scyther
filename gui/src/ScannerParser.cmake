################################################################
# Name:		ScannerParser.cmake
# Purpose:	If flex/bison are available, generate parser and scanner
# Author:	Cas Cremers
################################################################

# Make the scanner using flex, if it can be found
include(FindFLEX.cmake)
if (FLEX_FOUND)
	set_source_files_properties(scanner.c PROPERTIES GENERATED true)
	ADD_CUSTOM_COMMAND (
		OUTPUT	scanner.c
		DEPENDS scanner.l
		COMMAND	${FLEX_EXECUTABLE}
		# TODO: I should look up from which version the -o
		# switch works, might not be portable.
		ARGS	-oscanner.c scanner.l
		COMMENT	"Building scanner.c from scanner.l using flex"
	)
else (FLEX_FOUND)
	message (STATUS "Because flex is not found, we will use the existing scanner.c")
endif (FLEX_FOUND)

# Make the parser using bison, if it can be found
include(FindBISON.cmake)
if (BISON_FOUND)
	set_source_files_properties(parser.c PROPERTIES GENERATED true)
	ADD_CUSTOM_COMMAND (
		OUTPUT	parser.c
		DEPENDS parser.y
		COMMAND	${BISON_EXECUTABLE}
		# TODO: I should look up from which version the -o
		# switch works, might not be portable.
		ARGS	-d -oparser.c parser.y
		COMMENT	"Building parser.c from parser.y using bison"
	)
else (BISON_FOUND)
	message (STATUS "Because bison is not found, we will use the existing parser.c")
endif (BISON_FOUND)


