#!/usr/bin/python
#
#
import commands

def testvariant(variant):
	s = "./multinsl-generator.py"
	s += " 4 %s" % (variant)
	s += " | scyther -a -r5 -m2 --summary"
	print s
	s += " | grep \"failed:\""
	out = commands.getoutput(s)
	if out == "":
		print "Okay"
		return True
	else:
		print out
		return False

def main():
	good = []
	for i in range (0,32):
		print i
		if testvariant (i):
			good.append(i)
	print
	print "Good variants:"
	print good
		

main()
