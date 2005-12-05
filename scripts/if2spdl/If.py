#!/usr/bin/python
#
#	If.py
#
#	Objects and stuff for the intermediate format
#
import copy	# To copy objects
import os	# For path functions


class Message(object):
	def __cmp__(self,other):
		return cmp(str(self),str(other))

	def inTerms(self):
		return [self]

	def isVariable(self):
		return False

	def substitute(self, msgfrom, msgto):
		if self == msgfrom:
			return msgto
		else:
			return self
	
	def aKeys(self):
		return []

class Constant(Message):
	def __init__ (self,type,s,optprime=""):
		self.type = type
		self.prime = optprime
		self.str = s
	
	def __str__(self):
		return self.str + self.prime

	def spdl(self,braces=True):
		return self.str + self.prime

	def __repr__(self):
		return str(self)

class Variable(Constant):
	def isVariable(self):
		return True

class PublicKey(Constant):
	pass

class Composed(Message):
	def __init__ (self,m1,m2):
		self.left = m1
		self.right = m2
	
	def __str__(self):
		return "(" + str(self.left) + "," + str(self.right) + ")"

	def spdl(self,braces=True):
		res = ""
		if braces:
			res += "("
		res += self.left.spdl(False) + "," + self.right.spdl(False)
		if braces:
			res += ")"
		return res

	def inTerms(self):
		return self.left.inTerms() + self.right.inTerms()

	def substitute(self, msgfrom, msgto):
		if self == msgfrom:
			return msgto
		else:
			new = copy.copy(self)
			new.left = self.left.substitute(msgfrom, msgto)
			new.right = self.right.substitute(msgfrom, msgto)
			return new

	def aKeys(self):
		return self.left.aKeys() + self.right.aKeys()

class SPCrypt(Message):
	def __init__ (self,key,message):
		self.key = key
		self.message = message

	def __str__(self):
		return "{" + str(self.message) + "}" + str(self.key) + " "
	
	def spdl(self,braces=True):
		return "{" + self.message.spdl(False) + "}" + self.key.spdl() + " "

	def inTerms(self):
		return self.key.inTerms() + self.message.inTerms()

	def substitute(self, msgfrom, msgto):
		if self == msgfrom:
			return msgto
		else:
			new = copy.copy(self)
			new.key = self.key.substitute(msgfrom, msgto)
			new.message = self.message.substitute(msgfrom, msgto)
			return new

	def aKeys(self):
		return self.message.aKeys() + self.key.aKeys()

class PublicCrypt(SPCrypt):
	def aKeys(self):
		return self.message.aKeys() + [self.key]

class SymmetricCrypt(SPCrypt):
	pass

class XOR(Composed):
	def __str__(self):
		return str(self.left) + " xor " + str(self.right)

	def spdl(self,braces=True):
		# This is not possible yet!
		raise Error


class MsgList(list):
	def inTerms(self):
		l = []
		for m in self:
			l = l + m.inTerms()
		return l

	def __str__(self):
		return "[ " + ", ".join(map(str,self)) + " ]"

	def spdl(self):
		first = True
		res = ""
		for m in self:
			if not first:
				res += ", "
			else:
				first = False
			res += m.spdl()
		return res

	def getList(self):
		l = []
		for e in self:
			l.append(e)
		return l

	def substitute(self, msgfrom, msgto):
		newl = []
		for m in self:
			newl.append(m.substitute(msgfrom, msgto))
		return MsgList(newl)

class Fact(list):
	def __repr__(self):
		return "Fact<" + list.__repr__(self) + ">"

	def getActor(self):
		return None

class GoalFact(Fact):
	def __repr__(self):
		return "Goal " + Fact.__repr__(self)

class PrincipalFact(Fact):
	def __init__(self,t):
		self.step = t[0]
		self.readnextfrom = t[1]
		self.actor = t[2]
		self.runknowledge = t[3]
		self.knowledge = t[4]
		self.bool = t[5]
		self.session = t[6]

	def __str__(self):
		res = "Principal Fact:"
		res += "\nStep         " + str(self.step)
		res += "\nReadNextFrom " + str(self.readnextfrom)
		res += "\nActor        " + str(self.actor)
		res += "\nRunKnowledge " + str(self.runknowledge)
		res += "\nKnowledge    " + str(self.knowledge)
		#res += "\nBool         " + str(self.bool)
		res += "\nSession      " + str(self.session)
		return res + "\n"

	def __repr__(self):
		return str(self)

	def getActor(self):
		return self.actor

class TimeFact(Fact):
	def __repr__(self):
		return "Time " + Fact.__repr__(self)

class MessageFact(Fact):
	def __init__(self,t):
		self.step = t[0]
		self.realsender = t[1]
		self.claimsender = t[2]
		self.recipient = t[3]
		self.message = t[4]
		self.session = t[5]

	def __str__(self):
		res = "Message Fact:"
		res += "\nStep         " + str(self.step)
		res += "\nRealSender   " + str(self.realsender)
		res += "\nClaimSender  " + str(self.claimsender)
		res += "\nRecipient    " + str(self.recipient)
		res += "\nMessage      " + str(self.message)
		res += "\nSession      " + str(self.session)
		return res + "\n"

	def __repr__(self):
		return str(self)

	def spdl(self):
		res = ""
		res += "(" + str(self.claimsender)
		res += "," + str(self.recipient)
		res += ", " + str(self.message)
		res += " )"
		return res

class State(list):
	def __repr__(self):
		return "State<" + list.__repr__(self) + ">"

class Label(object):
	def __init__(self, name, category):
		self.name = name
		self.category = category
	
	def __str__(self):
		return "lb=" + self.name + ",type=" + self.category

	def __repr__(self):
		return str(self)

class Rule(object):
	def __init__(self,left=[],right=[]):
		def sanitize(x):
			if x == None:
				return []
			elif type(x) != list:
				return [x]
			else:
				return x

		self.left = sanitize(left)
		self.right = sanitize(right)
		self.label = None
		self.actors = []
	
	def setLabel(self,label):
		self.label = label
	
	def __str__(self):
		res = "Rule:"
		if self.label != None:
			res += " (" + str(self.label) +")"
		res += "\n"
		if len(self.left) > 0:
			res += str(self.left) + "\n"
		if len(self.right) > 0:
			if len(self.left) > 0:
				res += "=>\n"
			res += str(self.right) + "\n"
		res += ".\n"
		return res

	def __repr__(self):
		return str(self)

	def getActors(self):
		return self.actors

	def getFacts(self):
		return self.left + self.right


class InitialRule(Rule):

	def __str__(self):
		return "Initial " + Rule.__str__(self)


class MessageRule(Rule):

	def __init__(self,left=[],right=[]):
		Rule.__init__(self,left,right)
		self.actors = []
		# Add actors
		for fact in self.getFacts():
			actor = fact.getActor()
			if actor != None and actor not in self.actors:
				self.actors.append(actor)
		# Read/Send, before/after
		self.readFact = None
		self.before = None
		for fact in self.left:
			if type(fact) == MessageFact:
				self.readFact = fact
			elif type(fact) == PrincipalFact:
				self.before = fact
		self.sendFact = None
		self.after = None
		for fact in self.right:
			if type(fact) == MessageFact:
				self.sendFact = fact
			elif type(fact) == PrincipalFact:
				self.after = fact

		if self.before == None or self.after == None:
			print "Warning: rule does not have both principal facts."
			print self

	def __str__(self):
		return "Message " + Rule.__str__(self)

	def getStepFrom(self):
		if self.before != None:
			return self.before.step
		else:
			return -1

	def getStepTo(self):
		if self.after != None:
			return self.after.step
		else:
			return -1


class GoalRule(Rule):
	def __str__(self):
		return "Goal " + Rule.__str__(self)

class CorrespondenceRule(GoalRule):
	def __init__(self, l):
		GoalRule.__init__(self,l,None)
	
	def __str__(self):
		return "Correspondence " + GoalRule.__str__(self)

class SecrecyRule(GoalRule):
	def __init__(self, l):
		GoalRule.__init__(self,l,None)
	
	def __str__(self):
		return "Secrecy " + GoalRule.__str__(self)

class STSecrecyRule(GoalRule):
	def __init__(self, l):
		GoalRule.__init__(self,l,None)
	
	def __str__(self):
		return "Short-term Secrecy " + GoalRule.__str__(self)

class AuthenticateRule(GoalRule):
	def __init__(self, l):
		GoalRule.__init__(self,l,None)
	
	def __str__(self):
		return "Authenticate " + GoalRule.__str__(self)

class Protocol(list):
	def setFilename(self, filename):
		self.path = os.path.dirname(filename)
		self.filename = os.path.basename(filename)

	# Get head of filename (until first dot)
	def getBaseName(self):
		parts = self.filename.split(".")
		if parts[0] == "":
			return "None"
		else:
			return parts[0]

	# Construct protocol name from filename
	def getName(self):
		return self.getBaseName()
		

