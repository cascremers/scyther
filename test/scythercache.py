#!/usr/bin/python
#
#	Scyther caching mechanism
#
#	Uses md5 hashes to store previously calculated results.
#
#	(c)2005 Cas Cremers
#
#
#	TODO:
#
#	- Maybe it is an idea to time the output. If Scyther takes less
#	  than a second, we don't need to cache the output. That would
#	  reduce the required cache size significantly.
#

import md5
import commands
import os
import sys
from tempfile import NamedTemporaryFile, gettempdir

#----------------------------------------------------------------------------
# How to cal Scyther
#----------------------------------------------------------------------------

#	scyther should reside in $PATH
def scythercall (argumentstring, inputfile):
	clstring = "scyther " + argumentstring + " " + inputfile
	(status,scout) = commands.getstatusoutput(clstring)
	return (status,scout)

#----------------------------------------------------------------------------
# Cached evaluation
#----------------------------------------------------------------------------

#	cached results
#	input:	a large string (consisting of read input files)
#	argstring:	a smaller string
def evaluate (argumentstring, inputstring):

	def cacheid():
		m = md5.new()
	
		# # Determine scyther version
		# (status, scout) = scythercall ("--version", "")
		# if status == 1 or status < 0:
		# 	# some problem
		# 	print "Problem with determining scyther version!"
		# 	os.exit()
		# # Add version to hash
		# m.update (scout)

		# Add inputfile to hash
		m.update (inputstring)

		# Add arguments to hash
		m.update (argumentstring)

		# Return a readable ID (good for a filename)
		return m.hexdigest()

	# slashcutter
	# Takes 'str': cuts of the first 'depth' strings of length
	# 'width' and puts 'substr' in between
	def slashcutter(str,substr,width,depth):
		res = ""
		while len(str)>width and depth>0:
			res = res + str[0:width] + substr
			str = str[width:]
			depth = depth-1
		return res + str

	# Determine name
	def cachefilename(id):
		fn = gettempdir() + "/scyther/"
		fn = fn + slashcutter(id,"/",2,4)
		fn = fn + ".txt"
		return fn

	# Ensure directory
	def ensureDirectory (path):
		if not os.path.exists(path):
			os.mkdir(path)

	# Ensure directories for a file
	def ensureDirectories (filename):
		for i in range(1,len(filename)):
			if filename[i] == '/':
				np = i+1
				ensureDirectory(filename[:np])

	# Determine the unique filename for this test
	cachefile = cachefilename(cacheid())
	ensureDirectories(cachefile)

	# Does it already exist?
	if os.path.exists(cachefile):
		# Great: return the cached results
		f = open(cachefile,'r')
		res = f.read()
		f.close()
		return (0,res)
	else:
		# Hmm, we need to compute this result
		h = NamedTemporaryFile()
		h.write(inputstring)
		h.flush()
		(status, scout) = scythercall (argumentstring, h.name)
		h.close()

		# Write cache file even if it's wrong
		f = open(cachefile,'w')
		f.write(scout)
		f.close()

		return (status,scout)

#----------------------------------------------------------------------------
# Parsing Output
#----------------------------------------------------------------------------

# Parse output
def parse(scout):
	results = {}
	lines = scout.splitlines()
	for line in lines:
		data = line.split()
		if len(data) > 6 and data[0] == 'claim':
			claim = " ".join(data[1:4])
			tag = data[6]
			value = -1
			if tag == 'failed:':
				value = 0
			if tag == 'correct:':
				value = 1
		 	if value == -1:
				raise IOError, 'Scyther output for ' + commandline + ', line ' + line + ' cannot be parsed.'
			results[claim] = value
	return results

#----------------------------------------------------------------------------
# Default tests
#----------------------------------------------------------------------------

# Yield default protocol list (from any other one)
def default_protocols(plist):
	plist.sort()
	return ['../spdl/spdl-defaults.inc'] + plist


# Yield arguments, given a bound type:
# 	0: fast
# 	1: thorough
#
def default_arguments(plist,match,bounds):
	n = len(plist)
	# These bounds assume at least two protocols, otherwise
	# stuff breaks.
	if n < 2:
		nmin = 2
	else:
		nmin = n
	timer = 1
	maxruns = 2
	maxlength = 10
	if bounds == 0:
		timer = nmin**2
		maxruns = 2*nmin
		maxlength = 2 + maxruns * 3
	elif bounds == 1:
		timer = nmin**3
		maxruns = 3*nmin
		maxlength = 2 + maxruns * 4
	else:
		print "Don't know bounds method", bounds
		sys.exit()

	args = "--arachne --timer=%i --max-runs=%i --max-length=%i" % (timer, maxruns, maxlength)
	matching = "--match=" + str(match)
	allargs = "--summary " + matching + " " + args
	return allargs

# Yield test results
def default_test(plist, match, bounds):
	pl = default_protocols(plist)
	args = default_arguments(plist,match,bounds)

	input = ""
	for fn in pl:
		if len(fn) > 0:
			f = open(fn, "r")
			input = input + f.read()
			f.close()
	
	# Use Scyther
	(status,scout) = evaluate(args,input)
	return (status,scout)

# Test, check for status, yield parsed results
def default_parsed(plist, match, bounds):
	(status,scout) = default_test(plist, match, bounds)
	if status == 1 or status < 0:
		# Something went wrong
		print "*** Error when checking [", plist, match, bounds, "]"
		print
		sys.exit()
	return parse(scout)



