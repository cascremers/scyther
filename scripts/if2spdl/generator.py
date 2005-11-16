#!/usr/bin/python

import pprint

def unfold(arg):
	for x in arg:
		pprint.pprint(x)

def intruderKnowledge(x):
	print "Intruder knowledge"
	print x[0], str(x[1])

def scenario(x):
	print "Scenario",x,"ignoring for now"

def initialState(arg):
	arg = arg[0]	# One level deeper (has no implication rule)
	print "Initial State"
	print len(arg)
	for x in arg:
		if x[0] == "h":
			print "Some stupid semi time thing"
		if x[0] == "i":
			intruderKnowledge(x),"ignoring for now"
		elif x[0] == "w":
			scenario(x)

# Ignore for now
def protocolRules(arg):
	return
	
# Goals: ignored for now
def goal(arg):
	return

def labeledRule(lr):
	type = None
	label = None
	if lr[0] == "lb":
		label = lr[1]
	if lr[2] == "type":
		type = lr[3]
	arg = lr[4]

	if type == "Init":
		initialState(arg)
	elif type == "Protocol_Rules":
		protocolRules(arg)
	elif type == "Goal":
		goal(arg)

def generateSpdl(ll):
	if ll[0] == "option":
		print "Option [" + ll[1] + "]"
		for i in ll[2]:
			labeledRule(i)
		return

	print "Not understood element: "
	print ll[0]
