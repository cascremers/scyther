#!/usr/bin/python
#
#	Process the main results
#
import sys

class buffer:

	def __init__(self, name="unnamed", prefix=">>>"):
		self.claims = {}
		self.count = 0
		self.name = name
		self.prefix = prefix
	
	def reset(self):
		self.count = 0
		self.claims = {}

	def size(self):
		return self.count

	def add(self,(cl, hl), match=-1):
		# cleanup cl
	 	usloc = cl.rfind("_")
		if usloc != -1:
			# cut off any underscore stuff (ignore for now)
			cl = cl[:usloc]

		# possibly add
		if not (cl,hl) in self.claims.keys():
			if match >= 0:
				self.claims[(cl,hl)] = [match]
			else:
				self.claims[(cl,hl)] = []
			self.count = self.count + 1
		elif match >= 0 and match not in self.claims[(cl,hl)]:
			self.claims[(cl,hl)].append(match)

	def dump(self):
		if self.size() == 0:
			return

		print "Dumping buffer " + self.name
		print
		counted = 0
		for (cl,hl) in self.claims.keys():
			# Determine whether to print
			#
			toprint = True
			if cl.rfind("Nisynch") != -1:
				# Nisynch claim
				# Construct comparable Niagree claim
				newcl = cl.replace("Nisynch","Niagree")
				# Now check whether this one occurs
				if (newcl,hl) in self.claims.keys():
					toprint = False

			if toprint:
				res = self.prefix
				res = res + "\t" + cl
				res = res + "\t" + str(self.claims[(cl,hl)])
				res = res + "\t" + str(hl)
				print res
				counted = counted + 1
		print
		print "Count: " + str(counted) + " in " + self.name 
		print
		self.reset()


def ignore_this(data):
	if (data[3].rfind(" SV") != -1):
		# Server role!
		return True
	else:
		# Not including the server role
		return False

def main():

	buf_big = buffer("[Global]",">>>G")
	buf_small = buffer("[Local]", ">>>L")
	match = -1

	line = sys.stdin.readline()
	while line != "":
		# Clean input
		line = line.strip()
		data = line.split("\t")

		# Is it an attack thing?
		if data[0] != "***":
			# Nope
			buf_small.dump()
			print line
			# Maybe it reports the match type?
			matchprefix = "Testing match "
			loc = line.rfind(matchprefix)
			if loc != -1:
				match = int(line[loc + len(matchprefix)])
				print "Detected match type", match
		else:
			if not ignore_this(data):
				# Yes!
				claim = data[3]
				helpers = "\t".join(data[4:])
				buf_big.add((claim,helpers), match)
				buf_small.add((claim,helpers), match)

		# Proceed to next line
		line = sys.stdin.readline()

	buf_small.dump()
	buf_big.dump()


main()
