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
from tempfile import NamedTemporaryFile, gettempdir

#	scyther should reside in $PATH
def scythercall (argumentstring, inputfile):
	clstring = "scyther " + argumentstring + " " + inputfile
	(status,scout) = commands.getstatusoutput(clstring)
	return (status,scout)

#	cached results
#	input:	a large string (consisting of read input files)
#	argstring:	a smaller string
def eval (argumentstring, inputstring):

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
	id = cacheid()
	filename = "scyther/cache-" + id[:3] + "/res-" + id[3:] + ".txt"
	cachefile = gettempdir() + "/" + filename
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
		if not(status <= 0 or status == 1):
			# All is well
			f = open(cachefile,'w')
			f.write(scout)
			f.close()
		else:
			print status
			print scout
			print h.name

		sys.exit()
		return (status,scout)


