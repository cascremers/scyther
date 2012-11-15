
outputs= isoiec-9798-3-6-1.spdl isoiec-9798-3-6-2.spdl \
	 isoiec-9798-3-7-1.spdl isoiec-9798-3-7-2.spdl

all:	$(outputs)

isoiec-9798-3-6-%.spdl:	isoiec-9798-3-6-%.cpp isoiec-9798-3-6.template
	cpp -C -P $< >$@

isoiec-9798-3-7-%.spdl:	isoiec-9798-3-7-%.cpp isoiec-9798-3-7.template
	cpp -C -P $< >$@

clean:
	\rm -f $(outputs)


