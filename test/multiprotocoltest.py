#!/usr/bin/python
#
# Multi-protocol test using Scyther
#
# Typical big test: './multiprotocoltest.py -a -s -B' , go and drink some
# coffee. Drink some more. Go on holiday. Break leg. Return. Heal.
# Return to computer to find great results and/or system crash.
#
# (c)2004 Cas Cremers
#
# ***********************
# 	MODULES
# ***********************

import os
import sys
import string
import commands
import copy
from optparse import OptionParser

# My own stuff
import tuplesdo
import scythertest
import protocollist


# ***********************
# 	PARAMETERS
# ***********************

ClaimToResultMap = {}		# maps protocol claims to correctness in singular tests (0,1)
ProtocolToFileMap = {}		# maps protocol names to file names
ProtocolToStatusMap = {}	# maps protocol names to status: 0 all false, 1 all correct, otherwise (2) mixed
ProtocolToEffectsMap = {}	# maps protocols that help create multiple flaws, to the protocol names of the flaws they caused

ReportedAttackList = []			# stores attacks that have already been reported.
CommandPrefix = ""
ArgumentsList = []			# argument lists that have been displayed onscreen

# Ugly hack. Works.
safetxt = " " * 20

# ***********************
# 	LIBS
# ***********************

def GetKeys (f, x):
	"""Get the list of keys of a mapping to some value

	   in:
	   	f:	a mapping
		x:	an element of the range of f
	   out:
	   	A list, with elements from the domain of f, such that
		for each y in the list we have f(y)=x
	"""

	res = []
	for k in f.keys():
		if f[k] == x:
			res.append(k)
	return res


def GetListKeys (f, l):
	"""Get a list of keys for a list of elements (generalized GetKeys)

	   in:
	   	f:	a mapping
		l:	a list of elements from the range of f
	   out:
	   	A list, with elements from the domain of f, such that
		for each y in the list we have f(y) in l.
	"""
	   	
	res = []
	for x in l:
		for y in GetKeys (f, x):
			if y not in res:
				res.append(y)
	return res


def CommandLine (plist):
	"""Yield the commandline to test

	   in:
		a list of protocol file names
	   out:
		a command line string
	"""

	linelist = " ".join(plist)
	return "cat " + IncludeProtocols + " " + linelist + " | " + CommandPrefix


def PrintProtStatus (file, prname):
	"""Pretty-print the protocol status

	   in:
		file:			a file pointer to write to (e.g. stdout)
		prname:			a protocol name id
	   global:
	   	ProtocolStatusMap:	the pre-determined status of the protocols
	   out:
	   	output is written to file
	"""

	file.write (prname + ": ")
	if ProtocolToStatusMap[prname] == 0:
		file.write ("All-Flawed")
	elif ProtocolToStatusMap[prname] == 1:
		file.write ("All-Correct")
	else:
		file.write ("Mixed")


def ScytherEval (plist):
	"""Evaluate a protocol file list using Scyther

	   in:
	   	A list of protocol file names
	   global:
	   	options:	settings for scyther
		ArgumentsList:	already reported arguments list for
				scyther.
	   out:
	   	A dictionary of claim->bool, where true means correct
		(either complete or bounded) and false means attack.
		If the arguments list that is constructed was not
		reported before, it is now (to stdout).
	"""

	global options

	# Flush before trying (possibly fatal) external commands
	sys.stdout.flush()
	sys.stderr.flush()

	args = scythertest.default_arguments(plist, int(options.match), int(options.bounds))
	n = len(plist)
	if not (n,args) in ArgumentsList:
		ArgumentsList.append((n,args))
		print "Testing",n,"tuples using",args

	return scythertest.default_parsed(plist, int(options.match), int(options.bounds))


def ScytherEval1 (protocol):
	"""Evaluate a single protocol and store the results for later usage

	   in:
	   	a single protocol file name
	   global:
	   	ClaimToResultMap
		ProtocolToFileMap
		ProtocolToStatusMap
	   out:
	   	Globals have been updated to reflect the computed
		protocol status
	"""

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
ProgressBarWidth = 38

def ShowProgress (i,n,txt):
	global options

	def IntegerPart (x):
		return int (( x * i ) / n)
	
	if not options.progressbar:
		return
	percentage = IntegerPart (100)
	factor = IntegerPart (ProgressBarWidth)

	showme = False
	if LastProgress.has_key(n):
		if LastProgress[n]<>(factor,txt):
			showme = True
	else:
		showme = True
	if showme:
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
	global options

	if not options.progressbar:
		return
	bar = " " * (1 + ProgressBarWidth + 2 + 5 + len(txt))
	sys.stderr.write("\r" + bar + "\r")
	sys.stderr.flush()


def DescribeContextBrief (filep, protocols, claim, prefix):
	global ReportedAttackList

	# compute string
	outstr = "\t" + claim

	prlist = []
	for prfile in protocols:
		prnames = GetKeys (ProtocolToFileMap, prfile)
		prlist = prlist + prnames


	newprname = claim.split()[0]
	prlistclean = []
	for pn in prlist:
		if pn not in prlistclean:
			if pn != newprname:
				prlistclean.append(pn)
				outstr = outstr + "\t" + pn

	# determine whether we did that already
	if not outstr in ReportedAttackList:
		ReportedAttackList.append(outstr)
		# print
		filep.write (prefix)
		filep.write (outstr)
		filep.write ("\n")
		# a new attack!
		return 1
	else:
		# 0 new attacks
		return 0


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
			summary = False
			all = 0
			if claim.split()[0] <> prname:
				count = [0,0]
				for cl,v in cllist:
					count[v] = count[v]+1
				if count[0] == 0 and count[1] > 0:
					all = 1
					summary = True
				if count[1] == 0 and count[0] > 0:
					all = 0
					summary = True
				
			if summary:
				DC_Claim (cl.split()[0] + " *ALL*", all)
			else:
				for cl,v in cllist:
					if v == 1 and cl <> claim:
						DC_Claim(cl,1)
				for cl,v in cllist:
					if v == 0 and cl <> claim:
						DC_Claim(cl,0)
	filep.write ("\n")

#
# Determine whether the attack is really only for this combination of protocols (and not with less)
#
# returns 0 if it could be done with less also
# returns 1 if it really requires these protocols
#
def RequiresAllProtocols (protocols, claim):

	# check for single results
	if ClaimToResultMap[claim] == 0:
		# claim was always false (already attack on single prot.)
		return False
	# check for simple cases
	if TupleWidth <= 2:
		# nothing to remove
		return True

	# test the claims when removing some others
	# for TupleWidth size list, we can remove TupleWidth-1
	# protocols, and test
	clprname = claim.split()[0]
	claimfile = ProtocolToFileMap[clprname]
	for redundantfile in protocols:
		if redundantfile != claimfile:
			# for this particular option, construct a list
			simplercase = copy.copy(protocols)
			simplercase.remove(redundantfile)
			# now test the validity of the claim
			simplerresults = ScytherEval (simplercase)
			if claim in simplerresults.keys() and simplerresults[claim] == 0:
				# Redundant protocol was not necessary for attack!
				return False
	return True
			

			


#
# Signal that there is an attack, claim X using protocols Y
#
# Returns number of new attacks found
#
def SignalAttack (protocols, claim):
	if not RequiresAllProtocols (protocols, claim):
		return 0

	ClearProgress (TupleCount, safetxt)
	outs = "***\t" + str(newattacks)
	outs = outs + "\t" + str(processed) + "/" + str(TupleCount)
	for helper in GetListKeys (ProtocolToFileMap, protocols):
		clprname = claim.split()[0]
		if helper <> clprname:
			if helper not in ProtocolToEffectsMap.keys():
				# new
				ProtocolToEffectsMap[helper] = [clprname]
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
	return DescribeContextBrief (sys.stdout, protocols, claim, outs)

# ***********************
# 	MAIN CODE
# ***********************

# Pass std input to temporary file (list of protocol files)
#----------------------------------------------------------------------
# 
# Determines:
# 	ProtocolCount
# 	ProtocolFileList[0..count-1]
#
# Furthermore, TempFileList is created.

def multiprotocol_test(ProtocolFileList, width, match):
	global options
	global processed, newattacks
	global TupleWidth, TupleCount
	global ClaimToResultMap, ProtocolToFileMap, ProtocolToStatusMap, ProtocolToEffectsMap

	TupleWidth = width
	ProtocolCount = len(ProtocolFileList)
	ScytherMethods = "--match=" + str(match)

	# Reset mem
	ClaimToResultMap = {}		
	ProtocolToFileMap = {}		
	ProtocolToStatusMap = {}	
	ProtocolToEffectsMap = {}	

	# Caching of single-protocol results for speed gain.
	#----------------------------------------------------------------------
	#
	# The script first computes the singular results for all the protocols
	# and stores this in an array, or something like that.

	TupleCount = tuplesdo.tuples_count(ProtocolCount, TupleWidth)
	print "Evaluating", TupleCount, "tuples of", TupleWidth, "for", ProtocolCount, "protocols."
	i = 0
	while i < ProtocolCount:
		ShowProgress (i, ProtocolCount,ProtocolFileList[i]+safetxt)
		ScytherEval1 ( ProtocolFileList[i] )
		i = i + 1
	ClearProgress(ProtocolCount, safetxt)
	print "Evaluated single results."

	# Show classification
	#----------------------------------------------------------------------
	#
	print "Correct protocols: ", GetKeys (ProtocolToStatusMap, 1)
	print "Partly flawed protocols: ", GetKeys (ProtocolToStatusMap, 2)
	print "Completely flawed protocols: ", GetKeys (ProtocolToStatusMap, 0)

	# Testing of protocol tuples
	#----------------------------------------------------------------------
	#
	# We take the list of tuples and test each combination.

	processed = 0
	newattacks = 0

	#
	# Check all these protocols
	#
	def process(protocols):
		global processed, newattacks

		#
		# Get the next tuple
		#
		ShowProgress (processed, TupleCount, " ".join(protocols) + safetxt)
		#
		# Determine whether there are valid claims at all in
		# this set of file names
		#
		has_valid_claims = False
		for prname in GetListKeys (ProtocolToFileMap, protocols):
			if ProtocolToStatusMap[prname] != 0:
				has_valid_claims = True
		if has_valid_claims:
			#
			# Use Scyther to verify the claims
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
					newattacks = newattacks + SignalAttack (protocols, claim)
			
		# Next!
		processed = processed + 1

	tuplesdo.tuples_do(process,ProtocolFileList,TupleWidth)

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

#	Yell some stuff

def banner(str):
	print
	print "*" * 40
	print "\t" + str
	print "*" * 40
	print

#	Magical recursive unfolding of tests

def the_great_houdini(list,width,match):
	global options

	# Empty list
	if list == []:
		the_great_houdini(protocollist.select(int(options.protocols)),width,match)
	# Unfold sequence of tuple widths
	elif options.sequence:
		options.sequence = False
		banner ("Testing multiple tuple widths")
		for n in range(2,4):
			banner ("Testing tuple width %i" % n)
			the_great_houdini(list,n,match)
		options.sequence = True
	# Unfold matching methods
	elif options.allmatch:
		options.allmatch = False
		banner ("Testing multiple match methods")
		for m in range(0,3):
			options.match = m
			banner ("Testing match %i" % m)
			the_great_houdini(list,width,m)
		options.allmatch = True
	# Last but not least: test
	else:
		multiprotocol_test(list,width,match)
	

def main():
	global options
	global processed, newattacks
	global TestCount

	parser = OptionParser()
	scythertest.default_options(parser)
	parser.add_option("-t","--tuplewidth", dest="tuplewidth",
			default = 2,
			help = "number of concurrent protocols to test, >=2")
	parser.add_option("-s","--sequence", dest="sequence",
			default = False,
			action = "store_true",
			help = "test for two and three tuples")
	parser.add_option("-a","--allmatch", dest="allmatch",
			default = False,
			action = "store_true",
			help = "test for all matching methods")
	parser.add_option("-p","--protocols", dest="protocols",
			default = 0,
			help = "protocol selection (0: all, 1:literature only, 2:literature without know attacks)")
	parser.add_option("-B","--disable-progressbar", dest="progressbar",
			default = "True",
			action = "store_false",
			help = "suppress a progress bar")

	(options, args) = parser.parse_args()
	scythertest.process_default_options(options)

	the_great_houdini(args, int(options.tuplewidth), int(options.match))


if __name__ == '__main__':
	main()
