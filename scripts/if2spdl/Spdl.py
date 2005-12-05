#!/usr/bin/python
#
#	Spdl generator
#
import If
from misc import *

def action(actiontype, fact):
	res = actiontype + "_"
	res += str(fact.step)
	res += fact.spdl()
	return res


def getRoles(protocol):
	roles = []
	for rule in protocol:
		roles += rule.getActors()
	return uniq(roles)

class Role(object):
	""" Containts a list of rules, to be executed sequentially """
	def __init__(self,name,actor):
		self.name = name
		self.rules = []
		self.actor = actor
	
	def prependRule(self,rule):
		self.rules = [rule] + self.rules

	def getLength(self):
		return len(self.rules)

	def getFirst(self):
		if self.getLength() > 0:
			return self.rules[0]
		else:
			return None

	def getFirstStep(self):
		return self.getFirst().getStepFrom()

	def getActor(self):
		return self.actor

	def __str__(self):
		res = "Role " + self.name + "\n\n"
		for rule in self.rules:
			res += str(rule)
			res += "\n\n"
		return res

	def spdl(self):
		res = ""
		if len(self.rules) == 0:
			return res
		res += "role " + self.name + " ("
		# TODO Insert parameter agents
		res += ")\n"
		res += "{\n"
		# TODO declare constants, variables
		res += "\n"
		# Message sequence
		res += "\t// Knowledge before: " + str(self.rules[0].before.knowledge) + "\n"
		for rule in self.rules:
			# Read
			if rule.readFact != None:
				res += "\t" + action("read",rule.readFact) + ";\n"
			# Show knowledge extending for this read
			res += "\t// Knowledge delta: " + str(rule.before.runknowledge) + " -> " + str(rule.after.runknowledge) + "\n"



			# Send
			if rule.sendFact != None:
				res += "\t" + action("send",rule.sendFact) + ";\n"
		# TODO claims
		# Close up
		res += "}\n\n"
		return res

	def __cmp__(self,other):
		return cmp(self.name, other.name)

def extractRoles(protocol):
	""" Extract the roles of a protocol description. This yields a
	list of Role objects """

	# Construct full list of rules to do
	rulestodo = []
	for rule in protocol:
		if type(rule) == If.MessageRule:
			rulestodo.append(rule)
	
	# Now process them until none are left
	# First, we have no rolenames yet
	rolenames = []
	roles = []
	while len(rulestodo) > 0:
		# Pick one hrule (with the highest step number, maybe)
		highest = rulestodo[0].getStepFrom()
		hrule = rulestodo[0]
		for rule in rulestodo:
			step = rule.getStepFrom()
			step = max(step,rule.getStepTo())
			if step >= highest:
				highest = step
				hrule = rule
		# hrule has been picked. Work back from here
		# first make up a name
		if len(hrule.getActors()) != 1:
			print "Warning: weird actor list for hrule:", hrule.getActors()
			name = "X"
			actor = None
		else:
			actor = hrule.getActors()[0]
			name = str(actor)
			# Remove variable x prefix
			if len(name) > 1 and name[0] == 'x':
				name = name[1:]

		# This name is maybe already taken
		if name in rolenames:
			# Append counter
			counter = 2
			while name + str(counter) in rolenames:
				counter = counter+1
			name = name + str(counter)

		rolenames.append(name)
		role = Role(name,actor)
		roles.append(role)

		# Transfer to rule
		role.prependRule(hrule)
		rulestodo.remove(hrule)

		# Scan for preceding events until none is found
		scan = True
		while scan and role.getFirstStep() != -1:
			scan = False
			for rule in rulestodo:
				if actor in rule.getActors() and rule.getStepTo() == role.getFirstStep():
					# This one works
					role.prependRule(rule)
					rulestodo.remove(rule)
					scan = True

	return roles

def generator(protocol):
	roles = extractRoles(protocol)
	roles.sort()
	res = ""
	print "Found",len(roles),"roles."
	for role in roles:
		res += role.spdl()
	return res

