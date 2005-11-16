#!/usr/bin/python

def unfold(arg):
	for x in arg:
		print x

def initialState(arg):
	print "Initial State"
	unfold(arg)

def protocolRules(arg):
	print "Protocol Rules"
	unfold(arg)
	
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
