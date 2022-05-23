#!/usr/bin/python

# requires python-pyparsing module
# http://pyparsing.sourceforge.net/

from pyparsing import Literal, alphas, nums, Word, oneOf, Or, Group, \
	restOfLine, Forward, Optional, delimitedList, alphanums,\
	OneOrMore
import Term
import If

typedversion = False

# Markers:
#
# 	TODO	stuff that still needs to be done.
# 	DEVIANT	stuff that deviates from the original BNF specs in the
# 		paper.
# 	TEST	test things, remove later

# Generate parser
#
# Takes a list of tokens, returns 
def ruleParser ():
	global typedversion

	# ------------------------------------------------------
	# Atomic
	# ------------------------------------------------------

	# Tokens
	lbr = Literal("(")
	rbr = Literal(")")
	comma = Literal(",")
	hash = Literal("#")
	equ = Literal("=")
	implies = Literal("=>")
	dot = Literal(".")
	eol = Literal("\n").suppress()

	# Basic constructors
	Alfabet= alphas+nums+"_$"
	Number = Word(nums)
	Number.setParseAction(lambda s,l,t: [ "number", Term.TermConstant(t[0]) ])

	# Typeinfo/Constant
	TypeInfo = oneOf ("mr nonce pk sk fu table")
	TypeInfo.setParseAction(lambda s,l,t: [ "typeinfo", Term.TermConstant(t[0]) ])
	Constant = Word(alphas,Alfabet)
	Constant.setParseAction(lambda s,l,t: [ Term.TermConstant(t[0]) ])

	# Time
	nTime = Number
	xTime = Literal("xTime")
	sTime = Literal("s").suppress() + lbr + Group(Number) + rbr
	Time = Or([nTime,xTime,sTime])

	# Const
	Const = Forward()
	ConstC = Literal("c") + lbr + Constant + comma + Time + rbr
	ConstF = Literal("c(ni,ni)")
	Const << Or ([ Constant, ConstC, ConstF ])

	Const.setParseAction(lambda s,l,t: [ If.Constant("".join(t)) ])

	# Two versions
	Variable = Word("x",Alfabet)
	Variable.setParseAction(lambda s,l,t: [ Term.TermVariable(t[0]+"V",None) ])
	if typedversion:
		Variable = TypeInfo + lbr + Variable + rbr

	# Optional prime
	optprime = Optional(Literal("'"))

	# Atomic
	## DEVIANT : below there is an optprime after the atom. This
	## is not in the BNF.
	Atomic = Or([ TypeInfo + lbr + Const + rbr, Variable]) + optprime

	### TEST
	#print Time.parseString("s(25)")
	#print Variable.parseString("xCas")
	#print Atomic.parseString("nonce(Koen)")

	# ------------------------------------------------------
	# Messages
	# ------------------------------------------------------
	
	# Base forward declaration
	Message = Forward()


	# Agents etc
	Agent = Or ([Literal("mr") + lbr + Const + rbr, Variable])
	KeyTable = Or ([Literal("table") + lbr + Const + rbr, Variable])
	KeyTableApp = Literal("tb") + lbr + KeyTable + comma + Agent + rbr + optprime

	# Crypto
	pkterm = Literal("pk") + lbr + Const + rbr + optprime
	varterm = Variable + optprime
	Invertible = Or( [pkterm, KeyTableApp, varterm])
	PublicCypher = Literal("crypt") + lbr + Invertible + comma + Message + rbr
	PublicCypher.setParseAction(lambda s,l,t: [ Term.TermEncrypt(t[2],t[1]) ])
	XOR = Literal("rcrypt") + lbr + Message + comma + Message + rbr
	SymmetricCypher = Literal("scrypt") + lbr + Message + comma + Message + rbr
	futerm = Or([ Literal("fu") + lbr + Const + rbr, Variable ])
	Function = Literal("funct") + lbr + futerm + comma + Message + rbr
	
	# Message composition
	Concatenation = Literal("c") + lbr + Message + comma + Message + rbr
	Concatenation.setParseAction(lambda s,l,t: [ Term.TermTuple(t[1],t[2]) ])
	Composed = Or([ Concatenation, SymmetricCypher, XOR,
			PublicCypher, Function, KeyTable, KeyTableApp ])
	Message << Or ([Composed, Atomic])

	### TEST
	#print Message.parseString("nonce(c(Na,xTime))")

	# ------------------------------------------------------
	# Model of honest agents
	# ------------------------------------------------------
	
	Boolean = Or ([ Literal("true"), Literal("false"), Variable ])
	Session = Forward()
	Session << Or ([ Literal("s") + lbr + Session + rbr, Number, Variable ])
	MsgEtc = Literal("etc")

	MsgList = Forward()
	MsgComp = Literal("c") + lbr + Message + comma + MsgList + rbr
	MsgList << Or ([ MsgEtc, Variable, MsgComp ])

	Step = Or ([ Number, Variable ])

	### TEST
	#print Message.parseString("xKb")
	#print MsgList.parseString("etc")
	#print MsgList.parseString("c(xKb,etc)")
	#print MsgList.parseString("c(xA,c(xB,c(xKa,c(xKa',c(xKb,etc)))))")

	# Principal fact
	Principal = Literal("w") + lbr + Step + comma + Agent + comma + Agent + comma + MsgList + comma + MsgList + comma + Boolean + comma + Session + rbr
	Principal.setParseAction(lambda s,l,t: [ "Principal", t])

	# Message fact
	MessageFact = Literal("m") + lbr + Step + comma + Agent + comma + Agent + comma + Agent + comma + Message + comma + Session + rbr

	# Goal fact
	Correspondence = Principal + dot + Principal
	Secret = Literal("secret") + lbr + Message + Literal("f") + lbr + Session + rbr + rbr
	Secrecy = Literal("secret") + lbr + Literal("xsecret") + comma + Literal("f") + lbr + Session + rbr + rbr + dot + Literal("i") + lbr + Literal("xsecret") + rbr
	Give = Literal("give") + lbr + Message + Literal("f") + lbr + Session + rbr + rbr
	STSecrecy = Literal("give(xsecret,f(xc)).secret(xsecret,f(xc))") + implies + Literal("i(xsecret)")
	Witness = Literal("witness") + lbr + Agent + comma + Agent + comma + Constant + comma + Message + rbr
	Request = Literal("request") + lbr + Agent + comma + Agent + comma + Constant + comma + Message + rbr
	Authenticate = Literal("request") + lbr + Agent + comma + Agent + comma + Constant + comma + Message + rbr
	GoalState = Or ([ Correspondence, Secrecy, STSecrecy, Authenticate ])
	GoalFact = Or ([ Secret, Give, Witness, Request ])

	# TimeFact
	TimeFact = Literal("h") + lbr + Message + rbr

	# Intruder knowledge
	IntruderKnowledge = Literal("i") + lbr + Message + rbr
	
	# Facts and states
	Fact = Or ([ Principal, MessageFact, IntruderKnowledge, TimeFact, Secret, Give, Witness, Request ])
	State = Group(delimitedList (Fact, "."))	## From initial part of document, not in detailed BNF

	# Rules
	MFPrincipal = Or ([ MessageFact + dot + Principal, Principal ])
	mr1 = Literal("h") + lbr + Literal("s") + lbr + Literal("xTime") + rbr + rbr + dot + MFPrincipal
	mr2 = implies
	mr3 = Literal("h") + lbr + Literal("xTime") + rbr + dot + MFPrincipal + Optional(dot + delimitedList(GoalFact, "."))
	MessageRule = Group(mr1) + mr2 + Group(mr3)		## DEVIANT : BNF requires newlines
	InitialState = Literal("h") + lbr + Literal("xTime") + rbr + dot + State 	## DEVIANT : BNF requires newlines

	# Intruder
	IntruderRule = Literal("nogniet")

	# Simplification
	f_simplif = Literal("f") + lbr + Literal("s") + lbr + Literal ("xc") + rbr + rbr + implies + Literal("f") + lbr + Literal("xc") + rbr	## DEVIANT : EOL removed
	matching_request = Witness + dot + Request + implies
	no_auth_intruder = Request + implies
	SimplificationRule = Or ([ f_simplif, matching_request, no_auth_intruder ])

	# Compose all rules
	Rule = Or([ InitialState, MessageRule, IntruderRule, GoalState, SimplificationRule ])

	return Rule

# IFParser
# Does not work for the first line (typed/untyped)
# Depends on ruleParser
def ifParser():
	
	comma = Literal(",").suppress()
	hash = Literal("#").suppress()
	equal = Literal("=").suppress()

	# Rules and labels
	rulename = Word (alphanums + "_")
	rulecategory = oneOf("Protocol_Rules Invariant_Rules Decomposition_Rules Intruder_Rules Init Goal")
	label = hash + Literal("lb") + equal + rulename + comma + Literal("type") + equal + rulecategory
	labeledrule = Group(label) + Group(ruleParser())

	def labeledruleAction(s,l,t):
		if t[0][3] == "Protocol_Rules":
			print("-----------------")
			print("- Detected rule -")
			print("-----------------")

			print(t[0])
			print(t[1])
			print()

	labeledrule.setParseAction(labeledruleAction)

	# A complete file
	parser = OneOrMore(labeledrule)
	parser.ignore("##" + restOfLine)

	return parser

# Determine (un)typedness from this line
def typeSwitch(line):
	try:
		global typedversion

		typeflag = Literal("#") + "option" + Literal("=") + oneOf ("untyped","typed")
		res = typeflag.parseString(line)
		if res[3] == "untyped":
			typedversion = False
		elif res[3] == "typed":
			typeversion = True
		else:
			print("Cannot determine whether typed or untyped.")
			raise ParseException
	
	except:
		print("Unexpected error while determining (un)typedness of the line", line)

	str = "Detected "
	if not typedversion:
		str += "un"
	str += "typed version."
	print(str)

# Parse an entire file, including the first one
def linesParse(lines):

	typeSwitch(lines[0])

	parser = ifParser()
	result = parser.parseString("".join( lines[1:]))

# Main code
def main():
	file = open("NSPK_LOWE.if", "r")
	linesParse(file.readlines())
	file.close()


if __name__ == '__main__':
	main()

