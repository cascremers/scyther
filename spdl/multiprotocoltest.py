#!/usr/bin/python
#
# Multi-protocol test
#
# Input of this script:
#
# 	- A number on the commandline of stuff to test
# 	- A list of files on stdin to be used

import os
import sys
import string
import commands

TempFileList = "scyther-blap.tmp"
TempFileTuples = "scyther-blip.tmp"

TupleProgram = "./tuples.py"

ScytherProgram = "../src/scyther"
ScytherDefaults	= "--summary"
ScytherMethods	= "-m0 -a"
ScytherBounds	= "-r4 -l40"

ReportInterval = 10

ScytherArgs = ScytherDefaults + " " + ScytherMethods + " " + ScytherBounds
CommandPrefix = ScytherProgram + " " + ScytherArgs

ProtocolClaims = {}

SkipList = [
	'gong-nonce.spdl',
	'gong-nonce-b.spdl',
	'splice-as-hc.spdl',
	'kaochow-palm.spdl'
	]

# ***********************
# 	LIBS
# ***********************

# ScytherEval
#
# Take the list of protocols in plist, and give them to Scyther.
# Returns a dictionary of claim -> bool; where 1 means that it is
# correct, and 0 means that it is false (i.e. there exists an attack)
def ScytherEval (plist):
	linelist = " ".join(plist)

	commandline = "cat " + linelist + " | " + CommandPrefix
	scout = commands.getoutput(commandline)
	lines = scout.splitlines()
	results = {}
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
				print "Scyther parse error for the input line: " + commandline
				print "On the output line: " + line
			results[claim] = value
	return results

# ScytherEval1
#
# The above, but do the preprocessing for a single protocol
def ScytherEval1 (protocol):
	results = ScytherEval ([protocol])
	ProtocolClaims.update (results)



# Show progress of i (0..n)
# 
LastProgress = {}
ProgressBarWidth = 50

def ShowProgress (i,n,txt):
	factor = int((ProgressBarWidth * i) / n)
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
		bar = bar + "] " + txt
		sys.stdout.write(bar)
		sys.stdout.flush()
	LastProgress[n] = (factor, txt)

def ClearProgress (n,txt):
	bar = " " * (1 + ProgressBarWidth + 2 + len(txt))
	sys.stdout.write("\r" + bar + "\r")
	sys.stdout.flush()







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
		if cleanline != '' and cleanline not in SkipList:
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
safetxt = '                                '
while i < ProtocolCount:
	ShowProgress (i, ProtocolCount,Protocol[i]+safetxt)
	ScytherEval1 ( Protocol[i] )
	i = i + 1
ClearProgress(ProtocolCount, safetxt)
print "Evaluated single results, proceeding to test tuples."

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
			if ProtocolClaims[claim] == 1:
				# Wooh! It was correct before
				ClearProgress (TupleCount, safetxt)
				newattacks = newattacks + 1
				print "We found a new flaw:", claim
	
	# Next!
	processed = processed + 1

ClearProgress (TupleCount, safetxt)
print "Processed", processed,"tuple combinations in total."

inp.close()
