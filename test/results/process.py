#!/usr/bin/python
#
#	Process the main results
#
import sys

class buffer:

	def __init__(self, name="unnamed", prefix=">>>"):
		self.list = []
		self.count = 0
		self.name = name
		self.prefix = prefix
	
	def reset(self):
		self.count = 0
		self.list = []

	def size(self):
		return self.count

	def add(self,(cl, hl)):
		# cleanup cl
	 	usloc = cl.rfind("_")
		if usloc != -1:
			# cut off any underscore stuff (ignore for now)
			cl = cl[:usloc]

		# possibly add
		if not (cl,hl) in self.list:
			self.list.append((cl,hl))
			self.count = self.count + 1

	def dump(self):
		if self.size() == 0:
			return

		print "Dumping buffer " + self.name
		print
		counted = 0
		for (cl,hl) in self.list:
			# Determine whether to print
			#
			toprint = True
			if cl.rfind("Nisynch") != -1:
				# Nisynch claim
				# Construct comparable Niagree claim
				newcl = cl.replace("Nisynch","Niagree")
				# Now check whether this one occurs
				if (newcl,hl) in self.list:
					toprint = False

			if toprint:
				res = self.prefix + "\t"
				res = res + cl + "\t" + str(hl)
				print res
				counted = counted + 1
		print
		print "Count: " + str(counted) + " in " + self.name 
		print
		self.reset()


def main():

	buf_big = buffer("[Global]",">>>G")
	buf_small = buffer("[Local]", ">>>L")

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
		else:
			# Yes!
			claim = data[3]
			helpers = "\t".join(data[4:])
			buf_big.add((claim,helpers))
			buf_small.add((claim,helpers))

		# Proceed to next line
		line = sys.stdin.readline()

	buf_small.dump()
	buf_big.dump()


main()
