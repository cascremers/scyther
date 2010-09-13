
#objects=$(wildcard *.cpp)
objects= SMQV.cpp FHMQV.cpp

default:	$(objects:.cpp=.spdl)

%.spdl:	%.cpp
	cpp -C $< >$@


