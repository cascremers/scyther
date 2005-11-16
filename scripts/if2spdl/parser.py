#!/usr/bin/python

# requires python-pyparsing module
# http://pyparsing.sourceforge.net/

from pyparsing import Word, alphanums, alphas, nums, oneOf, restOfLine, OneOrMore, \
	ParseResults, Forward, Combine, Or, Optional,MatchFirst, \
	ZeroOrMore, StringEnd, LineEnd, delimitedList, Group, Literal

def parse (str):
	# Tokens
	lbr = Literal("(").suppress()
	rbr = Literal(")").suppress()
	com = Literal(",").suppress()

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
	Variable = Word("x",Alfabet)
	Constant = Word(alphas,Alfabet)
	Number = Word(nums)
	Basic = MatchFirst([ Variable, Constant, Number ])

	Message = Forward()
	TypeInfo = oneOf ("mr nonce pk sk fu table")
	TypeMsg = TypeInfo + lbr + Message + rbr
	CryptOp = oneOf ("crypt scrypt c funct rcrypt tb")
	CryptMsg = CryptOp + lbr + Message + com + Message + rbr
	SMsg = Literal("s") + lbr + Message + rbr
	Message << Or ([TypeMsg, CryptMsg, SMsg, Basic]) + Optional(Literal("'")) 

	# Fact section

	Request = "request" + btup(4)
	Witness = "witness" + btup(4)
	Give = "give" + lbr + Message + com + ftup(Literal("f"), 1) + rbr
	Secret = "secret" + lbr + Message + com + ftup(Literal("f"),1) + rbr
	TimeFact = ftup (Literal("h"), 1)
	IntruderKnowledge = ftup (Literal("i"), 1)
	MessageFact = ftup(Literal("m"),6)
	Principal = ftup(Literal("w"), 7)

	Fact = Principal | MessageFact | IntruderKnowledge | TimeFact | Secret | Give | Witness | Request

	#State = Fact + OptioZeroOrMore ("." + Fact)
	State = delimitedList (Fact, ".")

	# Rules and labels
	rulename = Word (alphanums + "_")
	rulecategory = oneOf("Protocol_Rules Invariant_Rules Decomposition_Rules Intruder_Rules Init Goal")
	label = "# lb=" + rulename + "," + "type=" + rulecategory
	rule = State + Optional("\n" + "=>" + "\n" + State)
	labeledrule = Group(label + rule)
	typeflag = "# option=" + oneOf ("untyped","typed")

	# A complete file
	iffile = typeflag + OneOrMore(labeledrule) 

	parser = iffile
	parser.ignore("##" + restOfLine)

	return parser.parseString(str)

file = open("NSPK_LOWE.if", "r")
res = parse ("".join(file.readlines() ) )
print res

