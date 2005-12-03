#!/usr/bin/python
#
#	If.py
#
#	Objects and stuff for the intermediate format
#
firstone = True

class Atomic(object):
	def __init__ (self,type,s,optprime=""):
		self.type = type
		self.str = s + optprime
	
	def __str__(self):
		return self.str

	def __repr__(self):
		return str(self)

class Variable(Atomic):
	pass

class TypedConstant(Atomic):
	pass

class Special(Atomic):
	def __init__ (self,x):
		Atomic.__init__(self, "special", x)

class Message(list):
	def subType(self):
		return "(generic)"

	def __str__(self):
		if self[0] == "crypt":
			return "{" + str(self[2]) + "}" + str(self[1]) + " "
		else:
			res = ""
			for s in self:
				if res != "":
					res += ","
				res += str(s)
			return res

	def __repr__(self):
		return "Message" + self.subType() + "<" + str(self) + ">"


class MsgList(list):
	def __repr__(self):
		return "Msglist<" + list.__repr__(self) + ">"

class Fact(list):
	def __repr__(self):
		return "Fact<" + list.__repr__(self) + ">"

class GoalFact(Fact):
	def __repr__(self):
		return "Goal " + Fact.__repr__(self)

class PrincipalFact(Fact):
	def __str__(self):
		res = "Principal Fact:"
		res += "\nStep         " + str(self[0])
		res += "\nReadNextFrom " + str(self[1])
		res += "\nActor        " + str(self[2])
		res += "\nRunKnowledge " + str(self[3])
		res += "\nKnowledge    " + str(self[4])
		#res += "\nBool         " + str(self[5])
		res += "\nSession      " + str(self[6])
		return res + "\n"

	def __repr__(self):
		return str(self)

class TimeFact(Fact):
	def __repr__(self):
		return "Time " + Fact.__repr__(self)

class MessageFact(Fact):
	def __str__(self):
		res = "Message Fact:"
		res += "\nStep         " + str(self[0])
		res += "\nRealSender   " + str(self[1])
		res += "\nClaimSender  " + str(self[2])
		res += "\nRecipient    " + str(self[3])
		res += "\nMessage      " + str(self[4])
		res += "\nSession      " + str(self[5])
		return res + "\n"

	def __repr__(self):
		return str(self)

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
	def __init__(self,left=None,right=None):
		self.left = left
		self.right = right
		self.label = None
	
	def setLabel(self,label):
		self.label = label
	
	def __str__(self):
		res = "Rule:"
		if self.label != None:
			res += " (" + str(self.label) +")"
		res += "\n"
		if self.left != None:
			res += str(self.left) + "\n"
		if self.right != None:
			if self.left != None:
				res += "=>\n"
			res += str(self.right) + "\n"
		res += ".\n"
		return res

	def __repr__(self):
		return str(self)

class InitialRule(Rule):
	def __str__(self):
		return "Initial " + Rule.__str__(self)

class MessageRule(Rule):
	def __init__(self,l,r):
		global firstone

		Rule.__init__(self,l,r)
		if firstone:
			print str(self)
			firstone = False


	def __str__(self):
		return "Message " + Rule.__str__(self)

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


