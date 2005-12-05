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

class Event(object):
	""" SPDL role event """
	def substitute(self, msgfrom, msgto):
		pass

	def spdl(self):
		return str(self)

class CommEvent(Event):
	""" SPDL message event """
	def __init__(self,type,label,fromrole,torole,message):
		self.type = type
		self.label = label
		self.fromrole = fromrole
		self.torole = torole
		self.message = message

	def substitute(self, msgfrom, msgto):
		self.message = self.message.substitute(msgfrom, msgto)
	
	def spdl(self):
		res = str(self.type) + "_"
		res += str(self.label)
		res += "("
		res += self.fromrole.spdl()
		res += ","
		res += self.torole.spdl()
		res += ", "
		res += self.message.spdl(False)
		res += " )"
		return res

	def inTerms(self):
		l = []
		l += self.fromrole.inTerms()
		l += self.torole.inTerms()
		l += self.message.inTerms()
		return l

class Role(object):
	""" Containts a list of rules, to be executed sequentially """
	def __init__(self,name,actor):
		self.name = name
		self.rules = []
		self.actor = actor
		self.events = []
		self.knowledge = If.MsgList([])
		self.constants = If.MsgList([])
		self.variables = If.MsgList([])
		self.asymmetric = If.MsgList([])	# Asymmetric keys 
	
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

	def appendEvent(self, event):
		self.event += [event]
	
	def substitute(self, msgfrom, msgto):
		def subst(o):
			o = o.substitute(msgfrom, msgto)

		subst(self.events)
		subst(self.knowledge)
		subst(self.constants)
		subst(self.variables)
		subst(self.asymmetric)

	def inTerms(self):
		l = []
		for ev in self.events:
			l += ev.inTerms()
		return l

	def spdl(self):
		pf = "\t\t"
		pfc = pf + "// "

		# Start output
		res = ""
		if len(self.rules) == 0:
			return res
		res += "\trole " + self.name + "\n"
		res += "\t{\n"

		res += pfc + "Rule list based messages\n\n"
		res += pfc + "Asymmetric keys: " + str(self.asymmetric) + "\n"

		# Message sequence (based on rules)
		res += pfc + "Knowledge before: " + str(self.rules[0].before.knowledge) + "\n"
		for rule in self.rules:
			# Read
			if rule.readFact != None:
				res += pfc + action("read",rule.readFact) + ";\n"
			# Show knowledge extending for this read
			res += pfc + "Knowledge delta: " + str(rule.before.runknowledge) + " -> " + str(rule.after.runknowledge) + "\n"

			# Send
			if rule.sendFact != None:
				res += pfc + action("send",rule.sendFact) + ";\n"
		res += "\n"

		# TODO declare constants, variables
		res += pfc + "Constants and variables\n"
		if len(self.constants) > 0:
			res += pf + "const " + self.constants.spdl() + ";\n"
		if len(self.variables) > 0:
			res += pf + "var   " + self.variables.spdl() + ";\n"
		res += "\n"

		# Message sequence (based on event list)
		res += pfc + "Event list based messages\n"
		for event in self.events:
			res += pf + event.spdl() + ";\n"
		res += "\n"

		# TODO claims
		
		# Close up
		res += "\t}\n\n"
		return res

	def __cmp__(self,other):
		return cmp(self.name, other.name)

def sanitizeRole(protocol, role):
	""" Get rid of If artefacts, and construct role.events """
	rules = role.rules

	# Create events for each rule
	ruleevents = []
	role.events = []
	for rule in role.rules:
		events = []
		if rule.readFact != None:
			f = rule.readFact
			events.append(CommEvent("read", f.step, f.claimsender, f.recipient, f.message))
		if rule.sendFact != None:
			f = rule.sendFact
			events.append(CommEvent("send", f.step, f.claimsender, f.recipient, f.message))
		ruleevents.append(events)
		role.events += events
	
	# Try to substitute stuff until sane
	# First check whether knowledge lists actually agree in length,
	# otherwise this does not make sense at all.
	for n in range(0,len(rules)-1):
		knowbefore = rules[n].after.runknowledge
		knowafter = rules[n+1].before.runknowledge
		if len(knowbefore) != len(knowafter):
			raise "KnowledgeDeltaLenDiff", n
		else:
			# The after items should be substituted by the
			# before items
			for i in range(0,len(knowbefore)):
				# Substitute this item
				msgfrom = knowafter[i]
				msgto = knowbefore[i]
				if msgfrom != msgto:
					### TEST
					print "Substituting %s by %s" % (str(msgfrom), str(msgto))
					# In all subsequent terms... TODO or
					# just the next one?
					for j in range(n+1, len(rules)):
						events = ruleevents[j]
						for ev in events:
							ev.substitute(msgfrom, msgto)


	# Extract knowledge etc
	role.knowledge = role.rules[0].before.knowledge
	role.constants = If.MsgList([])
	role.variables = If.MsgList([])
	l = uniq(role.inTerms())
	replacelist = []
	noncecounter = 0
	for t in l:
		if t not in role.knowledge:
			if t.isVariable():
				role.variables.append(t)
			else:
				# For now, we say local constants from the intermediate
				# format are simply replaced by
				# local constants from the
				# operational semantics. This is
				# not necessarily correct. TODO
				### constants.append(t)
				cname = "n"
				rname = role.name.lower()
				if rname.startswith("x"):
					rname = rname[1:]
				cname += rname
				cname += str(noncecounter)
				msg = If.Constant("nonce",cname)
				noncecounter = noncecounter + 1
				replacelist.append( (t,msg) )
				role.constants.append(msg)
				### TEST
				print "Substituting %s by %s" % (str(t), str(msg))
	# Apply replacelist
	if len(replacelist) > 0:
		for ev in role.events:
			for (f,t) in replacelist:
				ev.substitute(f,t)

	# Extract keys
	akeys = []
	for ev in role.events:
		akeys += ev.message.aKeys()
	role.asymmetric = uniq(akeys)


		

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
	while (len(rulestodo) > 0):
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

		# This name is maybe already taken
		if name in rolenames:
			# Append counter
			counter = 2
			while (name + str(counter) in rolenames):
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
		while (scan and role.getFirstStep() != -1):
			scan = False
			for rule in protocol:
				if actor in rule.getActors() and rule.getStepTo() == role.getFirstStep():
					# Remove if not yet covered
					scan = True
					if rule in rulestodo:
						rulestodo.remove(rule)
					# Loop detection
					if rule in role.rules:
						# This is a loop TODO
						print "Warning: loop detected for role", role.name
						scan = False	# Current setting: stop scan
					else:
						# No loop, prepend
						role.prependRule(rule)

		# Role done, sanitize
		sanitizeRole( protocol, role)

	return roles

def generator(protocol):
	roles = extractRoles(protocol)
	roles.sort()
	res = ""
	res += "protocol " + protocol.getName() + " ("
	namelist = []
	for role in roles:
		namelist += [role.name]
	res += ", ".join(namelist)
	res += ")\n"
	res += "{\n"
	for role in roles:
		res += role.spdl()
	res += "}\n"
	return res

