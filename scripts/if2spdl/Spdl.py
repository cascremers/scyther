#!/usr/bin/python
#
#	Spdl generator
#
import If
from misc import *

def processRole(rulelist, role):

	print "Role", role
	for rule in rulelist:
		if role in rule.getActors():
			for fact in rule.getFacts():
				if type(fact) == If.MessageFact:
					print fact.spdl()

	print
	return ""


def getRoles(rulelist):
	roles = []
	for rule in rulelist:
		roles += rule.getActors()
	return uniq(roles)

def generator(rulelist):
	roles = getRoles(rulelist)
	print "Found",len(rulelist),"rules."
	print "Roles:", roles
	res = ""
	for role in roles:
		res += processRole(rulelist,role)
	return res

