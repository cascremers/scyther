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

#	scyther should reside in $PATH
def scythercall (argumentstring, inputfile):
	clstring = "scyther " + argumentstring + " " + inputfile
	(status,scout) = commands.getstatusoutput(clstring)
	return (status,scout)

#	cached results
#	input:	a large string (consisting of read input files)
#	argstring:	a smaller string
def scythercache (argumentstring, inputstring):

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

	# Ensure directories for a file
	def ensureDirectories (filename):

		def ensureDir (plist):
			if len(plist) > 1:
				ensureDir (plist[:-1])
			path = plist.join("/")
			if not os.path.exists(path):
				os.mkdir(path)

		dir = os.path.dirname(filename)
		ensuredir (dir.split("/"))

	# Determine the unique filename for this test
	id = cacheid()
	filename = "scythercache/" + id[:2] + "/res-" + id[2:] + ".txt"
	cachefile = gettempdir() + "/" + filename
	ensureDirectories(cachefile)

	# Does it already exist?
	if os.path.exists(cachefile):
		# Great: return the cached results
		f = open(cachefile,"r")
		res = f.read()
		f.close()
		return (0,res)
	else:
		# Hmm, we need to compute this result
		h = NamedTemporaryFile()
		h.write(inputstring)
		(status, scout) = scythercall (argumentstring, h.name)
		h.close()
		f = open(cachefile,"w")
		f.write(scout)
		f.close()
		return (status,scout)


