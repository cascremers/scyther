#!/usr/bin/python
#
#	Scyther caching mechanism
#
#	Uses md5 hashes to store previously calculated results.
#
#	(c)2005 Cas Cremers
#
#

import md5
import commands
import os
import sys
import time
from tempfile import NamedTemporaryFile, gettempdir

#----------------------------------------------------------------------------
# Global definitions
#----------------------------------------------------------------------------

# Minimum duration for a test to get into the cache (in seconds)
CacheTimer = 0.1
ScytherProgram = "scyther"

#----------------------------------------------------------------------------
# How to override Scyther program setting
#----------------------------------------------------------------------------

def scytheroverride (newprg):
	global ScytherProgram

	ScytherProgram = newprg
	if not os.path.exists(ScytherProgram):
		print "Cannot find any file at", ScytherProgram, " and it cannot be used as a Scyther executable."
		sys.exit()

#----------------------------------------------------------------------------
# How to call Scyther
#----------------------------------------------------------------------------

#	scyther should reside in $PATH
def scythercall (argumentstring, inputfile):
	global ScytherProgram

	clstring = ScytherProgram + " " + argumentstring + " " + inputfile
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

	def compute_and_cache(cachefile):
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

	def retrieve_from_cache(file):
		f = open(file,'r')
		res = f.read()
		f.close()
		# TODO technically, we should store the status in the
		# cache file as well. For now, we just return 0 status.
		return (0,res)

	# Determine the unique filename for this test
	cachefile = cachefilename(cacheid())
	if os.path.exists(cachefile):
		return retrieve_from_cache(cachefile)
	else:
		return compute_and_cache(cachefile)

#----------------------------------------------------------------------------
# Standalone usage
#----------------------------------------------------------------------------

def main():
	print "This module has currently no standalone functionality."

# Only if main stuff
if __name__ == '__main__':
	main()
