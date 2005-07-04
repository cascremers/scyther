#!/usr/bin/python
#
# Generate Multi-party NSL protocol description for n parties
#
# Input: P variant
#
# variant uses some bits:
#	bit	mask	meaning if set to '1'
#			message type 1
# 	0	1	agents in reverse 
# 	1	2	nonces after agents
# 	2	4	nonces in reverse 
# 	3	8	interleaved variant
# 			message type 2
# 	4	16	nonces in reverse in message 2
#
import sys

def role (r):
	global P

	return "R%i" % (r % P)

def nonce (r):
	global P

	return "n%i" % (r % P)

def extend (s1, s2):
	if s1 == "":
		return s2
	else:
		return s1 + "," + s2

def weavel (l1,l2,reverse1,swap,reverse2,interleave):
	""" l1 is typically a list of nonces, l2 might be empty (names) """
	global variant

	if reverse1:
		l1.reverse()
	if l2 == []:
		return l1
	else:
		if reverse2:
			l2.reverse()
		if swap:
			# swap
			l3 = l1
			l1 = l2
			l2 = l3
		if interleave:
			rl = []
			largest = max(len(l1),len(l2))
			for i in range (0,largest):
				if i < len(l1):
					rl.append(l1[i])
				if i < len(l2):
					rl.append(l2[i])
			return rl
		else:
			return l1 + l2

def message1 (label):
	global P,variant

	noncelist = []
	for i in range(0,label+1):
		noncelist.append(nonce(i))
	rolelist = []
	for i in range(0,P):
		if i != (label+1) % P:
			rolelist.append(role(i))

	return ",".join(weavel(noncelist,rolelist,
		(variant & 1 != 0),
		(variant & 2 != 0),
		(variant & 4 != 0),
		(variant & 8 != 0)
		))

def message2 (label):
	global P,variant

	noncelist = []
	for i in range (((label + 1) % P),P):
		noncelist.append(nonce(i))

	return ",".join(weavel(noncelist,[],
		(variant & 16 != 0),
		False,
		False,
		False
		))

def message (label):
	global P

	s = "{ "
	if label < P:
		s = s + message1 (label)
	else:
		s = s + message2 (label)

	s = s + " }pk(%s)" % role(label+1)
	return s

def action (event,label):
	s = "\t\t%s_%i(%s,%s, " % (event,label, role(label),
			role(label+1))
	s += message (label)
	s += " );\n"
	return s

def read (label):
	return action ("read", label)


def send (label):
	return action ("send", label)

def roledef (r):
	global P

	s = ""
	s += "\trole " + role(r) + "\n\t{\n"

	# constants for this role
	
	s += "\t\tconst " + nonce (r) + ": Nonce;\n"

	# variables
	
	s += "\t\tvar "
	nr = 0
	for i in range (0,P):
		if r != i:
			if nr > 0:
				s += ","
			s += nonce(i)
			nr += 1

	s += ": Nonce;\n"
		
	# actions
	
	s += "\n"
	if r > 0:
		# Initial read
		s += read(r-1)
	s += send(r)
	s += read(P+r-1)
	if r < (P-1):
		# Final send
		s += send(P+r)
	
	# claims
	
	s += "\t\tclaim_%sa( %s, Secret, %s );\n" % (role(r), role(r),
			nonce(r))
	s += "\t\tclaim_%sb( %s, Nisynch );\n" % (role(r), role(r))

	# close
	s += "\t}\n\n"
	return s


def protocol (pset,vset):
	global P,variant

	P = pset
	variant = vset

	s = ""
	s += "// Generalized Needham-Schroeder-Lowe for %i parties\n\n" % P
	s += "// Variant %i\n" % variant
	s += "const pk: Function;\n"
	s += "secret sk: Function;\n"
	s += "inversekeys (pk,sk);\n\n"

	s += "protocol mnsl%iv%i(" % (P,variant)
	for i in range (0,P):
		if i > 0:
			s += ","
		s += role(i)
	s += ")\n{\n"

	for i in range (0,P):
		s += roledef(i)
	
	s += "}\n\n"

	s += "const Alice, Bob: Agent;\n\n"

	s += "const Eve: Agent;\n"
	s += "untrusted Eve;\n"
	s += "const ne: Nonce;\n"
	s += "compromised sk(Eve);\n"

	s += "\n"
	return s

def main():
	if len(sys.argv) < 3:
		print "We need at least 2 arguments: number of parties, and variant"
		print "Note that variant is in [0..31]"
		print ""
		print "E.g. './multinsl-generator.py 2 0' yields a default NSL protocol"
	else:
		print protocol(int (sys.argv[1]), int(sys.argv[2]))

# Only if main stuff
if __name__ == '__main__':
	main()
else:
	print protocol (2,0)
