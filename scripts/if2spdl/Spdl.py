#!/usr/bin/python
#
#	Spdl generator
#
import If
from misc import *

def action(protocol, actiontype, rule, fact):
	res = actiontype + "_"
	res += str(fact.step)
	res += fact.spdl()
	res += ";\n"
	return res

def processRole(protocol, role):

	res = ""
	print "Role", role
	# initial knowledge
	for rule in protocol:
		if role in rule.getActors():
			for fact in rule.left:
				if type(fact) == If.PrincipalFact:
					print fact


	# derive message sequence
	for rule in protocol:
		if role in rule.getActors():
			for fact in rule.left:
				if type(fact) == If.MessageFact:
					res += action(protocol, "read", rule, fact)

			for fact in rule.right:
				if type(fact) == If.MessageFact:
					res += action(protocol, "send", rule, fact)


	print res
	return ""


def getRoles(protocol):
	roles = []
	for rule in protocol:
		roles += rule.getActors()
	return uniq(roles)

def generator(protocol):
	roles = getRoles(protocol)
	print "Found",len(protocol),"rules."
	print "Roles:", roles
	res = ""
	for role in roles:
		res += processRole(protocol,role)
	return res

