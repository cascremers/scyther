#!/usr/bin/python

# requires python-pyparsing module
# http://pyparsing.sourceforge.net/

from pyparsing import Literal, alphas, nums, Word, oneOf, Or, Group, \
	restOfLine, Forward, Optional, delimitedList
import Term

typedversion = False

# Generate atom parser
#
# Takes a list of tokens, returns 
def atomsParser ():
	global typedversion

	# ------------------------------------------------------
	# Atomic
	# ------------------------------------------------------

	# Tokens
	lbr = Literal("(").suppress()
	rbr = Literal(")").suppress()
	comma = Literal(",").suppress()
	hash = Literal("#").suppress()
	equ = Literal("=").suppress()
	implies = Literal("=>").suppress()
	dot = Literal(".").suppress()
	eol = Literal("\n").suppress()

	# Basic constructors
	Alfabet= alphas+nums+"_$"
	Number = Word(nums)
	Number.setParseAction(lambda s,l,t: [ "number", Term.TermConstant(t[0]) ])

	# Typeinfo/Constant
	TypeInfo = oneOf ("mr nonce pk sk fu table")
	TypeInfo.setParseAction(lambda s,l,t: [ "typeinfo", Term.TermConstant(t[0]) ])
	Const = Word(alphas,Alfabet)
	Const.setParseAction(lambda s,l,t: [ "constant", Term.TermConstant(t[0]) ])

	# Time
	nTime = Group(Number)
	nTime.setParseAction(lambda s,l,t: ["n", t[0] ])
	xTime = Literal("xTime")
	xTime.setParseAction(lambda s,l,t: ["x", 0 ])
	sTime = Literal("s").suppress() + lbr + Group(Number) + rbr
	sTime.setParseAction(lambda s,l,t: ["s", t[0] ])
	Time = Or([nTime,xTime,sTime])
	Time.setParseAction(lambda s,l,t: ["time", t[0],t[1] ])

	# Two versions
	Variable = Word("x",Alfabet)
	Variable.setParseAction(lambda s,l,t: [ "v", Term.TermVariable(t[0],None) ])
	if typedversion:
		Variable = TypeInfo + "(" + Variable + ")"

	# Atomic
	Atomic = Or([ TypeInfo + lbr + Const + rbr, Variable])

	### TEST
	print Time.parseString("s(25)")

	# ------------------------------------------------------
	# Messages
	# ------------------------------------------------------
	
	# Base forward declaration
	Message = Forward()

	# Optional prime
	optprime = Optional(Literal("'"))

	# Agents etc
	Agent = Or ([Literal("mr") + lbr + Const + rbr, Variable])
	KeyTable = Or ([Literal("table") + lbr + Const + rbr, Variable])
	KeyTableApp = Literal("tb") + lbr + KeyTable + comma + Agent + rbr + optprime

	# Crypto
	pkterm = Literal("pk") + lbr + Const + rbr + optprime
	varterm = Variable + optprime
	Invertible = Or( [pkterm, KeyTableApp, varterm])
	PublicCypher = Literal("crypt") + lbr + Invertible + comma + Message + rbr
	XOR = Literal("rcrypt") + lbr + Message + comma + Message + rbr
	SymmetricCypher = Literal("scrypt") + lbr + Message + comma + Message + rbr
	futerm = Or([ Literal("fu") + lbr + Const + rbr, Variable ])
	Function = Literal("funct") + lbr + futerm + comma + Message + rbr
	
	# Message composition
	Concatenation = Literal("c") + lbr + Message + comma + Message + rbr
	Composed = Or([ Concatenation, SymmetricCypher, XOR,
			PublicCypher, Function, KeyTable, KeyTableApp ])
	Message = Or ([Composed, Atomic])

	# ------------------------------------------------------
	# Model of honest agents
	# ------------------------------------------------------
	
	Boolean = Or ([ Literal("true"), Literal("false"), Variable ])
	Session = Forward()
	Session = Or ([ Literal("s") + lbr + Session + rbr, Number, Variable ])
	MsgList = Forward()
	MsgEtc = Literal("etc")
	MsgComp = Literal("c") + lbr + Message + comma + MsgList + rbr
	MsgList = Or ([ MsgEtc, Variable, MsgComp ])
	Step = Or ([ Number, Variable ])

	### TEST
	print Message.parseString("xKb")
	print MsgList.parseString("etc")
	print MsgComp.parseString("c(xKb,etc)")
	print MsgList.parseString("c(xA,c(xB,c(xKa,c(xKa',c(xKb,etc)))))")

	# Principal fact
	Principal = Literal("w") + lbr + Step + comma + Agent + comma + Agent + comma + MsgList + comma + MsgList + comma + Boolean + comma + Session + rbr

	# Message fact
	MessageFact = Literal("m") + lbr + Step + comma + Agent + comma + Agent + comma + Agent + comma + Message + comma + Session + rbr

	# Goal fact
	GoalFact = Literal ("nogniet")
	GoalState = Literal ("nogniet")

	# Facts and states
	Fact = Or ([ Principal, MessageFact ])
	State = Group(delimitedList (Fact, "."))

	# Rules
	mr1 = Literal("h") + lbr + Literal("s") + lbr + Literal("xTime") + rbr + rbr + dot + State
	mr2 = implies
	mr3 = Literal("h") + lbr + Literal("xTime") + rbr + dot + MessageFact + dot + Principal + dot + GoalFact + eol
	MessageRule = mr1 + eol + mr2 + eol + mr3 + eol
	InitialState = Literal("h") + lbr + Literal("xTime") + rbr + dot + State + eol

	# Intruder
	IntruderRule = Literal("nogniet")

	# Simplification
	SimplificationRule = Literal("nogniet")

	# Compose all rules
	Rule = Or([ InitialState, MessageRule, IntruderRule, GoalState, SimplificationRule ])


	print Rule.parseFile("test.if")
	




def ifParse (str):
	# Tokens
	lbr = Literal("(").suppress()
	rbr = Literal(")").suppress()
	comma = Literal(",").suppress()
	hash = Literal("#").suppress()
	equ = Literal("=").suppress()
	implies = Literal("=>").suppress()

	# Functions to construct tuples etc
	def bracket(x):
		return lbr + x + rbr

	def ntup(n):
		x = Message
		while n > 1:
			x = x + comma + Message
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
	Variable = Word("x",Alfabet).setParseAction(lambda s,l,t: [ Term.TermVariable(t[0],None) ])
	Constant = Word(alphas,Alfabet).setParseAction(lambda s,l,t: [ Term.TermConstant(t[0]) ])
	Number = Word(nums).setParseAction(lambda s,l,t: [ Term.TermConstant(t[0]) ])

	Basic = MatchFirst([ Variable, Constant, Number ])

	# Message definition is recursive
	Message = Forward()

	def parseType(s,l,t):
		if t[0][0] == "pk":
			# Public key thing, that's not really a type for
			# us but a function
			return [Term.TermEncrypt(t[0][1], t[0][0]) ]

		term = t[0][1]
		term.setType(t[0][0])
		return [term]

	TypeInfo = oneOf ("mr nonce pk sk fu table").setParseAction(lambda s,l,t: [ Term.TermConstant(t[0]) ])
	TypeMsg = Group(TypeInfo + lbr + Message + rbr).setParseAction(parseType)

	def parseCrypt(s,l,t):
		# Crypto types are ignored for now
		type = t[0][0]
		if type == "c":
			return [Term.TermTuple( t[0][1],t[0][2] ) ]
		return [Term.TermEncrypt(t[0][2],t[0][1])]

	CryptOp = oneOf ("crypt scrypt c funct rcrypt tb")
	CryptMsg = Group(CryptOp + lbr + Message + comma + Message + rbr).setParseAction(parseCrypt)

	def parseSMsg(s,l,t):
		return [Term.TermEncrypt(t[0][1],Term.Termconstant("succ") )]

	SMsg = Group(Literal("s") + lbr + Message + rbr)

	def parsePrime(s,l,t):
		# for now, we simply ignore the prime (')
		return [t[0][0]]

	Message << Group(Or ([TypeMsg, CryptMsg, SMsg, Basic]) + Optional(Literal("'"))).setParseAction(parsePrime)

	# Fact section
	Request = Group("request" + btup(4))
	Witness = Group("witness" + btup(4))
	Give = Group("give" + lbr + Message + comma + ftup(Literal("f"),
		1) + rbr)
	Secret = Group("secret" + lbr + Message + comma +
			ftup(Literal("f"),1) + rbr)
	TimeFact = Group(ftup (Literal("h"), 1))
	IntruderKnowledge = Group(ftup (Literal("i"), 1))
	MessageFact = Group(ftup(Literal("m"),6))
	Principal = Group(ftup(Literal("w"), 7))

	Fact = Principal | MessageFact | IntruderKnowledge | TimeFact | Secret | Give | Witness | Request

	#State = Fact + OptioZeroOrMore ("." + Fact)
	State = Group(delimitedList (Fact, "."))

	# Rules and labels
	rulename = Word (alphanums + "_")
	rulecategory = oneOf("Protocol_Rules Invariant_Rules Decomposition_Rules Intruder_Rules Init Goal")
	label = hash + "lb" + equ + rulename + comma + "type" + equ + rulecategory
	rule = Group(State + Optional(implies + State))
	labeledrule = Group(label + rule)
	typeflag = hash + "option" + equ + oneOf ("untyped","typed")

	# A complete file
	iffile = typeflag + Group(OneOrMore(labeledrule))

	parser = iffile
	parser.ignore("##" + restOfLine)

	return parser.parseString(str)

def main():
	global typedversion

	typedversion = False
	atomsParser()

if __name__ == '__main__':
	main()

