#!/usr/bin/python

# requires python-pyparsing module
# http://pyparsing.sourceforge.net/

from pyparsing import Word, alphanums, alphas, nums, oneOf, restOfLine, OneOrMore, \
	ParseResults, Forward, Combine, Or, Optional,MatchFirst, \
	ZeroOrMore, StringEnd, LineEnd, delimitedList, Group, Literal

def ifParse (str):
	# Tokens
	lbr = Literal("(").suppress()
	rbr = Literal(")").suppress()
	com = Literal(",").suppress()
	hash = Literal("#").suppress()
	equ = Literal("=").suppress()
	implies = Literal("=>").suppress()

	# Functions to construct tuples etc
	def bracket(x):
		return lbr + x + rbr

	def ntup(n):
		x = Message
		while n > 1:
			x = x + com + Message
			n = n - 1
		return x

	def btup(n):
		return bracket(ntup(n))

	def funcy(x,y):
		return x + bracket(y)

	def ftup(x,n):
		return funcy(x, ntup(n))

	# Message section
	Alfabet= alphas+nums+"_$"
	Variable = Word("x",Alfabet).setName("variable")
	Constant = Word(alphas,Alfabet).setName("constant")
	Number = Word(nums).setName("number")
	Basic = MatchFirst([ Variable, Constant, Number ])

	Message = Forward()
	TypeInfo = oneOf ("mr nonce pk sk fu table")
	TypeMsg = Group(TypeInfo + lbr + Message + rbr).setName("typeinfo")
	CryptOp = oneOf ("crypt scrypt c funct rcrypt tb")
	CryptMsg = Group(CryptOp + lbr + Message + com + Message + rbr).setName("crypt")
	SMsg = Group(Literal("s") + lbr + Message + rbr)
	Message << Or ([TypeMsg, CryptMsg, SMsg, Basic]) + Optional(Literal("'")) 

	# Fact section
	Request = Group("request" + btup(4))
	Witness = Group("witness" + btup(4))
	Give = Group("give" + lbr + Message + com + ftup(Literal("f"),
		1) + rbr)
	Secret = Group("secret" + lbr + Message + com +
			ftup(Literal("f"),1) + rbr)
	TimeFact = Group(ftup (Literal("h"), 1))
	IntruderKnowledge = Group(ftup (Literal("i"), 1))
	MessageFact = Group(ftup(Literal("m"),6))
	Principal = Group(ftup(Literal("w"), 7))

	Fact = Principal | MessageFact | IntruderKnowledge | TimeFact | Secret | Give | Witness | Request

	#State = Fact + OptioZeroOrMore ("." + Fact)
	State = delimitedList (Fact, ".")

	# Rules and labels
	rulename = Word (alphanums + "_")
	rulecategory = oneOf("Protocol_Rules Invariant_Rules Decomposition_Rules Intruder_Rules Init Goal")
	label = hash + "lb" + equ + rulename + com + "type" + equ + rulecategory
	rule = State + Optional(implies + State)
	labeledrule = Group(label + rule)
	typeflag = hash + "option" + equ + oneOf ("untyped","typed")

	# A complete file
	iffile = typeflag + OneOrMore(labeledrule) 

	parser = iffile
	parser.ignore("##" + restOfLine)

	return parser.parseString(str)


