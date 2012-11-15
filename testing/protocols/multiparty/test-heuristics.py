#!/usr/bin/python
#
#
#	Idea:
#
#	We test all options for the heuristics [0..31] to compare,
#	and sincerely hope on gives a complete proof.
#	we slowly refine the tests.
#
import commands

def startset():
	mainlist = [11, 15]
	print "Starting with", mainlist
	return mainlist

def tuplingchoice(heur,variant,P,runs,latupling):
	#	variant is in range [0..64>,
	#	where we use the highest bid to signify the
	#	associativity of the tupling.

	extraflags = ""
	if latupling:
		extraflags += " --la-tupling"

	# Choose heuristics
	extraflags += " --goal-select=%i" % (heur)

	# Time limit
	extraflags += " --timer=20"

	s = "./multinsl-generator.py"
	s += " %i %i" % (P,variant)
	s += " | scyther -a -r%i -m2 --summary %s" % (runs, extraflags)

	## Old stuff
	#s += " | scyther -a -r%i --summary" % runs

	# Show what we're doing
	print s

	#s += " | grep \"complete\""
	out = commands.getoutput(s)
	if out == "":
		#print "Okay"
		return False
	else:
		print out
		return True

def testvariant(h,v,p,r):
	if tuplingchoice (h,v,p,r, False):
		return True
	else:
		return tuplingchoice (h,v,p,r, True)

def scan(testlist, P, runs):
	print "Testing using P %i and %i runs." % (P,runs)
	for i in testlist:
		print "Testing protocol %i." % (i)
		for h in range (0,32):
			print "Heuristic %i:" % (h)
			testvariant (h,i,P,runs)

def main():
	candidates = startset()
	scan(candidates,3,5)

main()
