#!/usr/bin/env python
#
import sys
import json
import math

"""
Given a file of Scyther verification tests to do (json file), create a shell file to run them all using bsub.

Arguments:

  [1] Filename of json stuff
  [2] Step count: how many verification tasks go into one job
  [3] Additional commands to send to bsub (e.g. "-W 1:00")

"""

def countlines(fn):
	count = 0
	fh = open(fn,'r')
	for l in fh.xreadlines():
		count = count + 1
	fh.close()
	return count
	
def marker(jobcount,todo):
	left = todo - jobcount
	dperc = int((100 * jobcount) / todo)
	print "echo \"Sent %i out of %i jobs, hence %i left. %i%% done.\"" % (jobcount,todo,left,dperc)

def main(fn,step,optlist):

	todo = math.ceil(countlines(fn) / int(step))

	fh = open(fn,'r')
	ln = 1
	buf = 0
	s = ""
	jobcount = 0
	done = 0

	for l in fh.xreadlines():
		if buf == 0:
			s =  "bsub %s ./json-scyther.py %s" % (" ".join(optlist),fn)
		s += " %i" % (ln)
		buf = buf + 1
		done = done + 1
		if buf >= int(step):
			print (s)
			s = ""
			buf = 0
			jobcount = jobcount + 1
			if jobcount % 10 == 0:
				"""
				After ten jobs, display progress info
				"""
				marker(jobcount,todo)
			
		ln = ln + 1
	print (s)
	marker(jobcount,todo)
	fh.close()
	
	
if __name__ == '__main__':
	""" Usage: filename, step, options to send to bsub
	"""
	main(sys.argv[1],sys.argv[2],sys.argv[3:])

