#!/usr/bin/python

# requires python-pyparsing module
# http://pyparsing.sourceforge.net/

from pyparsing import Literal, alphas, nums, Word, oneOf, Or, Group, \
	restOfLine, Forward, Optional, delimitedList, alphanums,\
	OneOrMore
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
	lbrX = Literal("(")
	rbrX = Literal(")")
	commaX = Literal(",")
	lbr = Literal("(").suppress()
	rbr = Literal(")").suppress()
	comma = Literal(",").suppress()
	hash = Literal("#")
	equ = Literal("=")
	implies = Literal("=>").suppress()
	dot = Literal(".").suppress()
	eol = Literal("\n").suppress()

	# Basic constructors
	Alfabet= alphas+nums+"_$"
	Number = Word(nums)

	# Typeinfo/Constant
	TypeInfo = oneOf ("mr nonce pk sk fu table")
	Constant = Word(alphas,Alfabet)

	# Time
	nTime = Number
	xTime = Literal("xTime")
	sTime = Literal("s") + lbrX + Number + rbrX
	Time = Or([nTime,xTime,sTime])

	# Const
	Const = Forward()
	ConstC = Literal("c") + lbrX + Constant + commaX + Time + rbrX
	ConstF = Literal("c(ni,ni)")
	Const << Or ([ Constant, ConstC, ConstF ])

	def stringize(s,l,t):
		return [ "".join(t) ]

	Const.setParseAction(stringize)

	# Optional prime
	def optprimeaction(s,l,t):
		if len(t) == 0:
			return [ "" ]
		else:
			return t
	optprime = Optional(Literal("'"))
	optprime.setParseAction(optprimeaction)

	# Two versions
	if typedversion:
		Variable = Word("x",Alfabet)
		Variable = TypeInfo + lbr + Variable + rbr + optprime
		Variable.setParseAction(lambda s,l,t: [
				If.Variable(t[0],t[1],t[2]) ])
	else:
		Variable = Word("x",Alfabet) + optprime
		Variable.setParseAction(lambda s,l,t: [
				If.Variable("untyped",t[0],t[1]) ])

	# Atomic
	## DEVIANT : below there is an optprime after the atom. This
	## is not in the BNF.
	TypedConstant = TypeInfo + lbr + Const + rbr + optprime
	TypedConstant.setParseAction(lambda s,l,t: [
				If.Constant(t[0],t[1],t[2]) ])
	Atomic = Or(TypedConstant, Variable)

	### TEST
	#print Atomic.parseString("mr(Cas)'")
	#print Atomic.parseString("nonce(Koen)")

	# ------------------------------------------------------
	# Messages
	# ------------------------------------------------------
	
	# Base forward declaration
	Message = Forward()


	# Agents etc
	AgentMr = Literal("mr") + lbr + Const + rbr
	AgentMr.setParseAction(lambda s,l,t: [ If.Constant(t[0],t[1]) ])
	Agent = Or ([AgentMr, Variable])

	# TODO Not implemented yet
	KeyTable = Or ([Literal("table") + lbr + Const + rbr, Variable])
	KeyTableApp = Literal("tb") + lbr + KeyTable + comma + Agent + rbr + optprime

	# Crypto
	pkterm = Literal("pk") + lbr + Const + rbr + optprime
	pkterm.setParseAction(lambda s,l,t: [ If.PublicKey(t[0],t[1],t[2]) ])
	##varterm = Variable + optprime		### Variable already has an optprime
	varterm = Variable		

	Invertible = Or( [pkterm, KeyTableApp, varterm])
	PublicCypher = Literal("crypt") + lbr + Invertible + comma + Message + rbr
	PublicCypher.setParseAction(lambda s,l,t: [ If.PublicCrypt(t[1],t[2]) ])
	XOR = Literal("rcrypt") + lbr + Message + comma + Message + rbr
	XOR.setParseAction(lambda s,l,t: [ If.XOR(t[1],t[2]) ])
	SymmetricCypher = Literal("scrypt") + lbr + Message + comma + Message + rbr
	SymmetricCypher.setParseAction(lambda s,l,t: [ If.SymmetricCrypt(t[1],t[2]) ])

	# TODO Not implemented yet
	futerm = Or([ Literal("fu") + lbr + Const + rbr, Variable ])
	Function = Literal("funct") + lbr + futerm + comma + Message + rbr
	
	Concatenation = Literal("c").suppress() + lbr + Message + comma + Message + rbr
	Concatenation.setParseAction(lambda s,l,t: [ If.Composed(t[0],t[1]) ])

	# Message composition
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
	MsgEtc.setParseAction(lambda s,l,t: [ If.MsgList([If.Constant("special","etc") ]) ])
	MsgVar = Group(Variable)
	MsgVar.setParseAction(lambda s,l,t: [ If.MsgList(t) ])

	MsgList = Forward()
	MsgComp = Literal("c") + lbr + Message + comma + MsgList + rbr
	MsgComp.setParseAction(lambda s,l,t: [ If.MsgList([t[1]] + t[2].getList()) ])
	MsgList << Or ([ MsgEtc, Variable, MsgComp ])

	Step = Or ([ Number, Variable ])

	### TEST
	#print Message.parseString("xKb")
	#print Message.parseString("mr(Cas)")
	#print MsgList.parseString("etc")
	#print MsgList.parseString("c(xKb,etc)")
	#print MsgList.parseString("c(xA,c(xB,c(xKa,c(xKa',c(xKb,etc)))))")

	# Principal fact
	Principal = Literal("w") + lbr + Step + comma + Agent + comma + Agent + comma + MsgList + comma + MsgList + comma + Boolean + comma + Session + rbr
	Principal.setParseAction(lambda s,l,t: [ If.PrincipalFact(t[1:]) ])

	# Message fact
	MessageFact = Literal("m") + lbr + Step + comma + Agent + comma + Agent + comma + Agent + comma + Message + comma + Session + rbr
	MessageFact.setParseAction(lambda s,l,t: [ If.MessageFact(t[1:]) ])

	# Goal fact
	Secret = Literal("secret") + lbr + Message + Literal("f") + lbr + Session + rbr + rbr
	Give = Literal("give") + lbr + Message + Literal("f") + lbr + Session + rbr + rbr
	Witness = Literal("witness") + lbr + Agent + comma + Agent + comma + Constant + comma + Message + rbr
	Request = Literal("request") + lbr + Agent + comma + Agent + comma + Constant + comma + Message + rbr
	GoalFact = Or ([ Secret, Give, Witness, Request ])
	GoalFact.setParseAction(lambda s,l,t: [ If.GoalFact(t) ])
	# Goal State
	# It actually yields a rule (not a state per se)
	Correspondence = Principal + dot + Principal
	Correspondence.setParseAction(lambda s,l,t: [
			If.CorrespondenceRule(t) ])
	Secrecy = Literal("secret") + lbr + Literal("xsecret") + comma + Literal("f") + lbr + Session + rbr + rbr + dot + Literal("i") + lbr + Literal("xsecret") + rbr
	Secrecy.setParseAction(lambda s,l,t: [ If.SecrecyRule(t) ])
	STSecrecy = Literal("give(xsecret,f(xc)).secret(xsecret,f(xc))") + implies + Literal("i(xsecret)")
	STSecrecy.setParseAction(lambda s,l,t: [
		If.STSecrecyRule(t) ])
	Authenticate = Literal("request") + lbr + Agent + comma + Agent + comma + Constant + comma + Message + rbr
	Authenticate.setParseAction(lambda s,l,t: [ If.AuthenticateRule(t) ])
	GoalState = Or ([ Correspondence, Secrecy, STSecrecy, Authenticate ])

	# TimeFact
	TimeFact = Literal("h") + lbr + Message + rbr
	TimeFact.setParseAction(lambda s,l,t: [ If.TimeFact(t[1]) ])

	# Intruder knowledge
	IntruderKnowledge = Literal("i") + lbr + Message + rbr
	
	# Facts and states
	Fact = Or ([ Principal, MessageFact, IntruderKnowledge, TimeFact, Secret, Give, Witness, Request ])
	Fact.setParseAction(lambda s,l,t: [ If.Fact(t) ])
	State = Group(delimitedList (Fact, "."))	## From initial part of document, not in detailed BNF
	State.setParseAction(lambda s,l,t: [ If.State(t) ])

	# Rules
	MFPrincipal = Or ([ MessageFact + dot + Principal, Principal ])
	mr1 = Literal("h") + lbr + Literal("s") + lbr + Literal("xTime") + rbr + rbr + dot + MFPrincipal
	mr2 = implies
	mr3 = Literal("h") + lbr + Literal("xTime") + rbr + dot + MFPrincipal + Optional(dot + delimitedList(GoalFact, "."))
	MessageRule = Group(mr1) + mr2 + Group(mr3)		## DEVIANT : BNF requires newlines
	MessageRule.setParseAction(lambda s,l,t: [
			If.MessageRule(t[0][3:],t[1][2:]) ])
	InitialState = Literal("h") + lbr + Literal("xTime") + rbr + dot + State 	## DEVIANT : BNF requires newlines
	InitialState.setParseAction(lambda s,l,t: [ If.InitialRule(t[2]) ])

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
	
	comma = Literal(",")
	hash = Literal("#")
	equal = Literal("=")

	# Rules and labels
	rulename = Word (alphanums + "_")
	rulecategory = oneOf("Protocol_Rules Invariant_Rules Decomposition_Rules Intruder_Rules Init Goal")
	label = hash + Literal("lb") + equal + rulename + comma + Literal("type") + equal + rulecategory
	label.setParseAction(lambda s,l,t: [ If.Label(t[3],t[7]) ])
	labeledrule = label + ruleParser()

	def labeledruleAction(s,l,t):
		rule = t[1]
		rule.setLabel(t[0])
		return [rule]

	labeledrule.setParseAction(labeledruleAction)

	# A complete file
	parser = OneOrMore(labeledrule)
	parser.ignore("##" + restOfLine)
	return parser

# Determine (un)typedness from this line
def typeSwitch(line):
	global typedversion

	typeflag = Literal("#") + "option" + Literal("=") + oneOf ("untyped","typed")
	res = typeflag.parseString(line)
	if res[3] == "untyped":
		typedversion = False
	elif res[3] == "typed":
		typeversion = True
	else:
		print "Cannot determine whether typed or untyped."
		raise ParseException
	
	str = "Detected "
	if not typedversion:
		str += "un"
	str += "typed version."
	print str

# Parse a number of lines, including the first line with the type switch
def linesParse(lines):

	typeSwitch(lines[0])
	parser = ifParser()
	return If.Protocol(parser.parseString("".join( lines[1:])))

# Parse an entire file
#
# Return a protocol
def fileParse(filename):
	file = open(filename, "r")
	protocol = linesParse(file.readlines())
	file.close()
	protocol.setFilename(filename)
	return protocol

# Main code
def main():
	print "Testing Ifparser module"
	print
	print fileParse("NSPK_LOWE.if")

if __name__ == '__main__':
	main()

