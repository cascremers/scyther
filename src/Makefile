#
#	Scyther Makefile
#

#
#	DEBUG or optimization settings: uncomment a single line:
#
CFLAGS = -g3 -D DEBUG		# default usage, for e.g. with valgrind
#CFLAGS = -g3 -D DEBUG -pg	# for code profiling with gprof
#CFLAGS = -O3 -static -finline-functions -fomit-frame-pointer

#
#	Compiler and linkage
#
CC = gcc
# Note that these paths must include the path to the argtable library.
CPPFLAGS = -I/scratch/ccremers/include -I/usr/local/include -Wall
LDFLAGS = -L/scratch/ccremers/lib -L/usr/local/lib
LOADLIBS = -lfl
LDLIBS = -largtable2
OPTIONS = ${CPPFLAGS} ${CFLAGS} ${LDFLAGS}

#
#	Module set for the modelchecker
#
MODULES=memory.o terms.o termlists.o symbols.o knowledge.o runs.o modelchecker.o \
report.o debug.o  mgu.o substitutions.o \
match_basic.o \
match_clp.o constraints.o \
output.o latex.o \
varbuf.o tracebuf.o attackminimize.o \
tac.o parser.o compiler.o 

#
#	Dependencies
#
MODELCHECKER = ${MODULES} main.o

all:		scyther tags

${Target}.o:	${Target}.c
		$(CC) $(OPTIONS) ${Target}.c -c

scanner.c:	scanner.lex
		flex scanner.lex
		cp lex.yy.c scanner.c

tok.h:		parser.c

parser.c:	parser.y
		bison -d -v parser.y
		cp parser.tab.c parser.c
		cmp -s parser.tab.h tok.h || cp parser.tab.h tok.h

tags:		*.c *.h
		ctags *.c *.h

modules:	$(MODULES)

scyther:	scanner.o $(MODELCHECKER)
		$(CC) $(OPTIONS) $(MODELCHECKER) -o scyther $(LOADLIBS) $(LDLIBS)

ptestmain.o scanner.o	: tok.h

#
#	Cleanup
#
clean:
		rm -f *.o
		rm -f scyther
		rm -f scanner.c
		rm -f parser.c
		rm -f tok.h
#
#	Clean and rebuild: 'make new'
#
new:
		make clean
		make all

