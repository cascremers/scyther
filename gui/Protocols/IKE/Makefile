CPPSRC= $(wildcard *.cpp)
DEST= $(CPPSRC:.cpp=.spdl)

default:	$(DEST)

%.spdl:	%.cpp
	cpp $< >$@

mpa:	$(DEST) make-mpa.py
	./make-mpa.py

