CC = @CC@
VERSION = @VERSION@
AM_CFLAGS = @CFLAGS@
YFLAGS = -d
BUILT_SOURCES = parser.h

bin_PROGRAMS = scyther
scyther_SOURCES = main.c \
		 scanner.l parser.y \
		 memory.c memory.h \
		 terms.c terms.h \
		 termmaps.c termmaps.h \
		 termlists.c termlists.h \
		 symbols.c symbols.h \
		 knowledge.c knowledge.h \
		 runs.c runs.h \
		 claims.c claims.h \
		 modelchecker.c modelchecker.h \
		 report.c report.h \
		 error.c error.h \
		 debug.c debug.h \
		 mgu.c mgu.h \
		 substitutions.c substitutions.h \
		 match_basic.c match_basic.h \
		 match_clp.c match_clp.h \
		 constraints.c constraints.h \
		 output.c output.h \
		 latex.c latex.h \
		 varbuf.c varbuf.h \
		 tracebuf.c tracebuf.h \
		 attackminimize.c attackminimize.h \
		 tac.c tac.h \
		 compiler.c compiler.h \
		 pheading.h
scyther_LDADD = @LEXLIB@

