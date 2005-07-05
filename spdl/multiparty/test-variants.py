#!/usr/bin/python
#
#
#	Idea:
#
#	We test all variants [0..31] until we are sure they work. Thus,
#	we slowly refine the tests.
#
import commands

def testvariant(variant,P,runs):
	s = "./multinsl-generator.py"
	s += " %i %s" % (P,variant)
	s += " | scyther -a -r%i -m2 --summary" % runs
	#s += " | scyther -a -r%i --summary" % runs
	#print s
	s += " | grep \"failed:\""
	out = commands.getoutput(s)
	if out == "":
		#print "Okay"
		return True
	else:
		#print out
		return False

def removeattacks (testlist, P, runs):
	okaylist = []
	for v in testlist:
		if testvariant (v, P, runs):
			okaylist.append(v)
	return okaylist

def scan(testlist, P, runs):
	print "Testing using P %i and %i runs." % (P,runs)
	results = removeattacks (testlist, P, runs)
	if len(results) < len(testlist):
		attacked = []
		for i in range(0,len(testlist)):
			if testlist[i] not in results:
				attacked.append(testlist[i])
		print "Using P %i and %i runs, we find attacks on %s" % (P,runs, str(attacked))
		print "Therefore, we are left with %i candidates: " % (len(testlist)), results 

	return results

def main():
	candidates = range(0,32)
	for P in range(2,7):
		for runs in range(P-1,P+2):
			candidates = scan(candidates,P,runs)
	print
	print "Good variants:"
	print candidates
		

main()
