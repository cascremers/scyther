CC = @CC@
VERSION = @VERSION@
AM_CFLAGS = @CFLAGS@

bin_PROGRAMS = scyther
scyther_SOURCES = main.c \
		 memory.c terms.c termlists.c symbols.c \
		 knowledge.c runs.c modelchecker.c \
		 report.c debug.c mgu.c substitutions.c \
		 match_basic.c match_clp.c constraints.c \
		 output.c latex.c varbuf.c tracebuf.c \
		 attackminimize.c tac.c \
		 compiler.c \
		 scanner.l parser.y
scyther_LDADD = @LEXLIB@


