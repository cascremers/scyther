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
ScytherMethods	= "-m1 -a"
ScytherBounds	= "-r4 -l40"

ScytherArgs = ScytherDefaults + " " + ScytherMethods + " " + ScytherBounds
CommandPrefix = ScytherProgram + " " + ScytherArgs

ProtocolClaims = {}

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
		if data[0] == 'claim':
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
	ProtocolClaims[protocol] = ScytherEval ([protocol])




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
		if cleanline != '':
			# not a blank line
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

i = 0
while i < ProtocolCount:
	ScytherEval1 ( Protocol[i] )
	i = i + 1

print ProtocolClaims

# Computation of combined list.
#----------------------------------------------------------------------
#
# We use the tuple script to generate the list of tuples we need.
# We use a temporary file (again) to store that list.
# This requires that 'tuples.py' is in the same directory.

lstatus=os.system(TupleProgram + ' ' + TupleWidth + ' <' + TempFileList + ' >' + TempFileTuples)

# Testing of protocol tuples
#----------------------------------------------------------------------
#
# We take the list of tuples and test each combination.


