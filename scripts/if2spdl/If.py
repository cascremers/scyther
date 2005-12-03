#!/usr/bin/python
#
#	If.py
#
#	Objects and stuff for the intermediate format
#
firstone = True

class Atomic(list):
	def __init__ (self,l,type=""):
		list.__init__(self,l)
		self.type = type
	
	def getType(self):
		return self.type

	def __str__(self):
		return  "".join(self)

	def __repr__(self):
		return "Constant<" + str(self) + ">"

class Special(Atomic):
	def __init__ (self,x):
		Atomic.__init__(self,[x],"special")

class Message(list):
	def __str__(self):
		#return "".join(self)
		res = ""
		for s in self:
			if res != "":
				res += ","
			res += str(s)
		return res

	def subType(self):
		return "(generic)"

	def __repr__(self):
		return "Message" + self.subType() + "<" + str(self) + ">"

class MsgList(list):
	def __repr__(self):
		return "Msglist<" + list.__repr__(self) + ">"

class Fact(list):
	def __repr__(self):
		return "Fact<" + list.__repr__(self) + ">"

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
		res += str(self.left) + "\n"
		res += "=>\n"
		res += str(self.right) + "\n"
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


