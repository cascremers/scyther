#!/usr/bin/python
#
# Multi-protocol test using Scyther
#
# (c)2004 Cas Cremers
#
# Input of this script:
#
# 	- A number on the commandline of stuff to test
# 	- A list of files on stdin to be used (lines starting with '#' are
# 	ignored)
#
#
# Tips and tricks:
#
# Use e.g.
#	$ ulimit -v 100000
# to counteract memory problems
# 
# If you know where to look, use
#	$ ls s*.spdl t*.spdl -1 | ./multiprotocoltest.py 2
# To verify combos of protocols starting with s and t
#

# ***********************
# 	PARAMETERS
# ***********************

# Temporary files
TempFileList = "scyther-blap.tmp"
TempFileTuples = "scyther-blip.tmp"

# External programs
TupleProgram = "./tuples.py"
ScytherProgram = "../src/scyther"

# Scyther parameters
ScytherDefaults	= "--summary"
ScytherMethods	= "-m1 -a"
ScytherBounds	= "-r4 --max-depth=20 -l15"

# Build a large part of the command line (for Scyther) already
ScytherArgs = ScytherDefaults + " " + ScytherMethods + " " + ScytherBounds
CommandPrefix = ScytherProgram + " " + ScytherArgs

# Some default settings for Agents, untrusted e with sk(e) and k(a,e) etc.
IncludeProtocols = 'spdl-defaults.inc'

# Some protocols are causing troubles: this is a hard-coded filter to exclude
# the problem children. Unfair, yes. Practical, yes.
SkipList = [ 'gong-nonce.spdl', 'gong-nonce-b.spdl', 'splice-as-hc.spdl', 'kaochow-palm.spdl' ]

ClaimToResultMap = {}		# maps protocol claims to correctness in singular tests (0,1)
ProtocolToFileMap = {}		# maps protocol names to file names
ProtocolToStatusMap = {}	# maps protocol names to status: 0 all false, 1 all correct, otherwise (2) mixed
ProtocolToEffectsMap = {}	# maps protocols that help create multiple flaws, to the protocol names of the flaws they caused


# ***********************
# 	MODULES
# ***********************

import os
import sys
import string
import commands

# ***********************
# 	LIBS
# ***********************

# GetKeys
#
# Given a mapping f and a value x, returns a list of keys 
# k for which f(k) = x
def GetKeys (f, x):
	res = []
	for k in f.keys():
		if f[k] == x:
			res.append(k)
	return res

# GetListKeys
#
# Given a mapping f and a list l, returns a list of keys 
# k for which f(k) = x, x in l
def GetListKeys (f, l):
	res = []
	for x in l:
		for y in GetKeys (f, x):
			if y not in res:
				res.append(y)
	return res

# CommandLine
#
# Yield the commandline to test, given a list of protocols
def CommandLine (plist):
	linelist = " ".join(plist)
	return "cat " + IncludeProtocols + " " + linelist + " | " + CommandPrefix

# PrintProtStatus
#
# pretty-print the status of a protocol
def PrintProtStatus (file, prname):
	file.write (prname + ": ")
	if ProtocolToStatusMap[prname] == 0:
		file.write ("All-Flawed")
	elif ProtocolToStatusMap[prname] == 1:
		file.write ("All-Correct")
	else:
		file.write ("Mixed")

# ScytherEval
#
# Take the list of protocols in plist, and give them to Scyther.
# Returns a dictionary of claim -> bool; where 1 means that it is
# correct, and 0 means that it is false (i.e. there exists an attack)
def ScytherEval (plist):
	results = {}

	# Flush before trying (possibly fatal) external commands
	sys.stdout.flush()
	sys.stderr.flush()

	# Use Scyther
	(status,scout) = commands.getstatusoutput(CommandLine (plist))

	if status == 1 or status < 0:
		# Something went wrong
		print "*** Error when checking [" + CommandLine (plist) + "]\n"
		return results

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

# ScytherEval1
#
# The above, but do the preprocessing for a single protocol
def ScytherEval1 (protocol):
	results = ScytherEval ([protocol])

	# Add the claim to the list of ClaimToResultMap
	for claim in results.keys():
		if ClaimToResultMap.has_key(claim):
			# Claim occurs in two protocols; determine the
			# files
			file1 = ProtocolToFileMap[claim.split()[0]]
			file2 = protocol
			raise IOError, 'Claim occurs in two protocols: ' + claim + ", in files (" + file1 + ") and (" + file2 + ")"

		# Add the filename to the protocol mappings
		prname = claim.split()[0]
		if ProtocolToFileMap.has_key(prname):
			# We already wrote this down
			#
			# TODO The mapping should not conflict, but we don't
			# check that now (covered by claim duplication # in a sense)
			#
			# Compare previous result, maybe mixed
			if ProtocolToStatusMap[prname] <> results[claim]:
				ProtocolToStatusMap[prname] = 2
		else:
			# New one, store the first result
			ProtocolToFileMap[prname] = protocol
			ProtocolToStatusMap[prname] = results[claim]

	ClaimToResultMap.update (results)

# Show progress of i (0..n)
# 
LastProgress = {}
ProgressBarWidth = 50

def ShowProgress (i,n,txt):
	def IntegerPart (x):
		return int (( x * i ) / n)
	
	percentage = IntegerPart (100)
	factor = IntegerPart (ProgressBarWidth)

	showme = 0
	if LastProgress.has_key(n):
		if LastProgress[n]<>(factor,txt):
			showme = 1
	else:
		showme = 1
	if showme == 1:
		bar = "\r["
		i = 0
		while i < ProgressBarWidth:
			if i <= factor:
				bar = bar + "*"
			else:
				bar = bar + "."
			i = i+1
		bar = bar + "] %3d%% " % percentage + txt
		sys.stderr.write(bar)
		sys.stderr.flush()
	LastProgress[n] = (factor, txt)

def ClearProgress (n,txt):
	bar = " " * (1 + ProgressBarWidth + 2 + 5 + len(txt))
	sys.stderr.write("\r" + bar + "\r")
	sys.stderr.flush()


def DescribeContext (filep, protocols, claim):
	def DC_Claim(cl,v):
		if v == 0:
			filep.write ("- " + cl + " : false in both cases")
		elif v == 1:
			filep.write ("+ " + cl + " : correct in both cases")
		elif v == 2:
			filep.write ("* " + cl + " : newly false in multi-protocol test")
		else:
			filep.write ("???")
		filep.write ("\n")

	filep.write ("-- Attack description.\n\n")
	filep.write ("Involving the protocols:\n")

	for prfile in protocols:
		prnames = GetKeys (ProtocolToFileMap, prfile)
		filep.write ("- " + prfile + ": " + ",".join(prnames) + "\n")
	newprname = claim.split()[0]
	newprfile = ProtocolToFileMap[newprname]
	filep.write ("The new attack occurs in " + newprfile + ": " + newprname)

	filep.write ("\n\n")
	filep.write (" $ " + CommandLine (protocols) + "\n")
	filep.write ("\n")
	DC_Claim (claim, 2)

	# Determine, for each protocol name within the list of files,
	# which claims fall under it, and show their previous status
	
	for prname in ProtocolToFileMap:
		# Protocol name
		if ProtocolToFileMap[prname] in protocols:
			# prname is a protocol name within the scope
			# first print isolation correct files (skipping
			# the claim one, because that is obvious)
			
			# construct list of claims for this protocol
			cllist = []
			for cl in ClaimToResultMap.keys():
				if cl.split()[0] == prname:
					cllist.append( (cl,ClaimToResultMap[cl]) )

			# We want to show some details, in any case of
			# the protocol of the claim. However, if the
			# partner protocol is completely correct or
			# completely false, we summarize.
			summary = 0
			all = 0
			if claim.split()[0] <> prname:
				count = [0,0]
				for cl,v in cllist:
					count[v] = count[v]+1
				if count[0] == 0 and count[1] > 0:
					all = 1
					summary = 1
				if count[1] == 0 and count[0] > 0:
					all = 0
					summary = 1
				
			if summary == 1:
				DC_Claim (cl.split()[0] + " *ALL*", all)
			else:
				for cl,v in cllist:
					if v == 1 and cl <> claim:
						DC_Claim(cl,1)
				for cl,v in cllist:
					if v == 0 and cl <> claim:
						DC_Claim(cl,0)
	filep.write ("\n")



# ***********************
# 	MAIN CODE
# ***********************

# Pass std input to temporary file (list of protocol files)
#----------------------------------------------------------------------
# 
# Determines:
# 	TupleWidth
# 	ProtocolCount
# 	Protocol[0..count-1]
#
# Furthermore, TempFileList is created.

TupleWidth = sys.argv[1]

# Read stdin into list and count, send to file
loop = 1
ProtocolCount = 0
Protocol = []
outp = open(TempFileList, 'w')
while loop:
	line = sys.stdin.readline()
	if line != '':
		# not the end of the input
		cleanline = string.strip(line)
		if cleanline != '' and cleanline[0] != '#' and cleanline not in SkipList:
			# not a blank line, not forbidden
			Protocol.append(cleanline)
			ProtocolCount = ProtocolCount + 1
			outp.write(line)
	else:
		# end of the input
		loop = 0
outp.close()

# Caching of single-protocol results for speed gain.
#----------------------------------------------------------------------
#
# The script first computes the singular results for all the protocols
# and stores this in an array, or something like that.

print "Evaluating tuples of", TupleWidth, "for", ProtocolCount, "protocols, using the command '" + CommandPrefix + "'"
i = 0
safetxt = " " * 20
while i < ProtocolCount:
	ShowProgress (i, ProtocolCount,Protocol[i]+safetxt)
	ScytherEval1 ( Protocol[i] )
	i = i + 1
ClearProgress(ProtocolCount, safetxt)
print "Evaluated single results."

# Show classification
#----------------------------------------------------------------------
#
print "Correct protocols: ", GetKeys (ProtocolToStatusMap, 1)
print "Partly flawed protocols: ", GetKeys (ProtocolToStatusMap, 2)
print "Completely flawed protocols: ", GetKeys (ProtocolToStatusMap, 0)

# Computation of combined list.
#----------------------------------------------------------------------
#
# We use the tuple script to generate the list of tuples we need.
# We use a temporary file (again) to store that list.
# This requires that 'tuples.py' is in the same directory.

lstatus=os.system(TupleProgram + ' ' + TupleWidth + ' <' + TempFileList + ' >' + TempFileTuples)

inp = open(TempFileTuples, 'r')
TupleCount = 0
for x in inp:
	TupleCount = TupleCount + 1
inp.close()
print "Commencing test for", TupleCount, "protocol combinations."

# Testing of protocol tuples
#----------------------------------------------------------------------
#
# We take the list of tuples and test each combination.

inp = open(TempFileTuples, 'r')
processed = 0
newattacks = 0
for tline in inp:
	#
	# Get the next tuple
	#
	protocols = tline.split()
	ShowProgress (processed, TupleCount, " ".join(protocols) + safetxt)
	#
	# Process it
	#
	results = ScytherEval ( protocols )
	#
	# Now we have the results for this combination.
	# Check whether any of these claims is 'newly false'
	#
	for claim,value in results.items():
		if value == 0:
			# Apparently this claim is false now (there is
			# an attack)
			if ClaimToResultMap[claim] == 1:
				# Wooh! It was correct before
				ClearProgress (TupleCount, safetxt)
				newattacks = newattacks + 1
				print "-" * 40
				print "New attack [[", newattacks, "]] at", processed, "/", TupleCount, ":", claim, " using",CommandLine( protocols)
				for helper in GetListKeys (ProtocolToFileMap, protocols):
					clprname = claim.split()[0]
					if helper <> clprname:
						if helper not in ProtocolToEffectsMap.keys():
							# new
							ProtocolToEffectsMap[helper] = [clprname]
							print "% Detected a new flaw helper:", helper
						else:
							# already noted as helper, add destruction now
							if clprname not in ProtocolToEffectsMap[helper]:
								ProtocolToEffectsMap[helper].append(clprname)
				#
				# TODO
				#
				# Generate output to recreate/draw the
				# attack, and maybe add this to a big
				# error log thingy. Furthermore,
				# explicitly recreate the commandline
				# and the claim that is newly violated
				DescribeContext (sys.stdout, protocols, claim)
	
	# Next!
	processed = processed + 1
inp.close()

ClearProgress (TupleCount, safetxt)
print "Processed", processed,"tuple combinations in total."
print "Found", newattacks, "new attacks."
if newattacks > 0:
	print "  These were helped by:"
	for helper in ProtocolToEffectsMap.keys():
		sys.stdout.write ("  ")
		PrintProtStatus (sys.stdout, helper)
		sys.stdout.write (". This possibly breaks " + str(ProtocolToEffectsMap[helper]) + "\n")

sys.stdout.flush()
sys.stderr.flush()
