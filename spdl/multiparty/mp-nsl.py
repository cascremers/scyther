#!/usr/bin/python
#
# Generate Multi-party NSL protocol description for n parties
#

def llist (n):
	global P
	
	s = ""
	first = 1
	for i in range(0,P):
		if n != i:
			if first:
				first = 0
			else:
				s = s + ","
			s = s + "r%i" % (i)
	return s

def message1 (label):
	global P

	s = "{ "
	for i in range (0,label+1):
		if i>0:
			s = s + ","
		s = s + "n%i" % (i)
	s = s + ","
	s = s + llist((label+1) % P)
	s = s + " }pk(r%i)" % ((label+1) % P)
	return s

P = 4
print message1 (1)


