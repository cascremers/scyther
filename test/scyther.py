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
#	  If so, we only need to create directories for the cached files
#	  we actually create.
#

import md5
import commands
import os
import sys
import time
from tempfile import NamedTemporaryFile, gettempdir
from optparse import OptionParser

#----------------------------------------------------------------------------
# Global definitions
#----------------------------------------------------------------------------

# Minimum duration for something to get into the cache
CacheTimer = 0.1

#----------------------------------------------------------------------------
# How to call Scyther
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
		fn = fn + slashcutter(id,"/",3,2)
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

	# Does it already exist?
	if os.path.exists(cachefile):
		# Great: return the cached results
		f = open(cachefile,'r')
		res = f.read()
		f.close()
		# TODO technically, we should store the status in the
		# cache file as well. For now, we just return 0 status.
		return (0,res)
	else:
		# Hmm, we need to compute this result
		# Compute duration (in seconds)
		h = NamedTemporaryFile()
		h.write(inputstring)
		h.flush()
		starttime = time.time()
		(status, scout) = scythercall (argumentstring, h.name)
		duration = time.time() - starttime
		h.close()

		# Only cache if it took some time
		if duration >= CacheTimer:
			# Write cache file even if it's wrong
			ensureDirectories(cachefile)
			f = open(cachefile,'w')
			f.write(scout)
			f.close()

		return (status,scout)

#----------------------------------------------------------------------------
# Parsing Output
#----------------------------------------------------------------------------

# status
def error_status(status):
	if status == 1 or status < 0:
		return True
	else:
		return False

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
		maxlength = 2 + maxruns * 4
	elif bounds == 1:
		timer = nmin**3
		maxruns = 3*nmin
		maxlength = 2 + maxruns * 6
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
	if error_status(status):
		# Something went wrong
		print "*** Error when checking [", plist, match, bounds, "]"
		print
		sys.exit()
	return parse(scout)

# Some default options for the scyther wrapper
def default_options(parser):
	parser.add_option("-m","--match", dest="match",
			default = 0,
			help = "select matching method (0: no type flaws, 2: \
			full type flaws")
	parser.add_option("-b","--bounds", dest="bounds",
			default = 0,
			help = "bound type selection (0: quickscan, 1:thorough)")

#----------------------------------------------------------------------------
# Some default testing stuff
#----------------------------------------------------------------------------

def all_unless_given(plist):
	if plist == []:
		# Get the list
		import protocollist
		return protocollist.from_all()
	else:
		return plist

#	Scan for compilation errors or stuff like that

def scan_for_errors(options,args):
	# Select specific list
	plist = all_unless_given(args)
	# Now check all things in the list
	errorcount = 0
	for p in plist:
		# Test and gather output
		(status,scout) = default_test([p], 0, 0)
		error = False
		if error_status(status):
			error = True
		else:
			if scout.rfind("ERROR") != -1:
				error = True
			if scout.rfind("error") != -1:
				error = True
		if error:
			print "There is an error in the output for", p
			errorcount = errorcount + 1

	if errorcount > 0:
		print
	print "Scan complete. Found", errorcount, "error(s) in", len(plist), "files."

#	Scan for timeout protocols
#
#	The idea is that some things will generate a timeout, and we would like
#	to know which ones. However, this can just be a problem of the time
#	limit, and might not be caused by a loop at all. Therefore, some
#	scanning is needed.

def scan_for_timeouts(options,args):

	def parse_timeout(status,scout):
		if not error_status(status):
			if scout.rfind("time=") != -1:
				return True
		return False

	def check_for_timeout(p):
		# First a simple test
		(status,scout) = default_test([p], 0, 1)
		if not parse_timeout(status,scout):
			# Well if there is no timeout here...
			return False

		# More testing...
		
		return True

	# Select specific list
	plist = all_unless_given(args)
	# Now check all things in the list
	errorcount = 0
	for p in plist:
		# Test and gather output
		if check_for_timeout(p):
			print "There is a timeout for", p
			errorcount = errorcount + 1

	if errorcount > 0:
		print
	print "Scan complete. Found", errorcount, "timeout(s) in", len(plist), "files."

#----------------------------------------------------------------------------
# Standalone usage
#----------------------------------------------------------------------------

def main():
	parser = OptionParser()
	default_options(parser)
	parser.add_option("-e","--errors", dest="errors",
			default = "False",
			action = "store_true",
			help = "detect compilation errors for all protocols [in list_all]")
	parser.add_option("-t","--timeouts", dest="timeouts",
			default = "False",
			action = "store_true",
			help = "scan for timeout errors for all protocols [in list_all]")
	(options, args) = parser.parse_args()

	# Subcases
	if options.errors != "False":
		scan_for_errors(options,args)
	elif options.timeouts != "False":
		scan_for_timeouts(options,args)
	else:
		# Not any other switch: just test the list then
		if args == []:
			print "Scyther default test needs at least one input file."
			sys.exit()
		(status,scout) = default_test(args, options.match, options.bounds)
		print "Status:", status
		print scout

# Only if main stuff
if __name__ == '__main__':
	main()
