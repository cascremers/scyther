CC = @CC@
VERSION = @VERSION@
AM_CFLAGS = @CFLAGS@
YFLAGS = -d
BUILT_SOURCES = parser.h

bin_PROGRAMS = scyther
scyther_SOURCES = main.c \
		 scanner.l parser.y \
		 memory.c terms.c termlists.c symbols.c \
		 knowledge.c runs.c modelchecker.c \
		 report.c debug.c mgu.c substitutions.c \
		 match_basic.c match_clp.c constraints.c \
		 output.c latex.c varbuf.c tracebuf.c \
		 attackminimize.c tac.c \
		 compiler.c 
scyther_LDADD = @LEXLIB@

