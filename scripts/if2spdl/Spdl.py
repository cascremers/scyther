#!/usr/bin/python
#
#	Spdl generator
#
import If

def processRole(rulelist, role):

	print "Role", role
	for rule in rulelist:
		if rule.getActor() == role:
			print rule

	print
	return ""


def getRoles(rulelist):
	roles = []
	for rule in rulelist:
		actor = rule.getActor()
		if actor != None:
			if actor not in roles:
				roles.append(actor)
	return roles

def generator(rulelist):
	roles = getRoles(rulelist)
	print "Found",len(rulelist),"rules."
	print "Roles:", roles
	res = ""
	for role in roles:
		res += processRole(rulelist,role)
	return res

