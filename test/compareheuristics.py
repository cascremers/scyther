#!/usr/bin/python
#
#	Compare heuristics
#
import sys
from optparse import OptionParser

import scythertest

# Parse
def parse(scout):
	ra = 0
	rb = 0
	rp = 0
	nc = 0
	st = 0
	for l in scout.splitlines():
		data = l.split()
		if len(data) > 6 and data[0] == 'claim':
			tag = data[6]
			if tag == 'failed:':
				ra = ra + 1
				nc = nc + 1
			elif tag == 'correct:':
				nc = nc + 1
				if l.rfind("complete_proof") != -1:
					rp = rp + 1
				else:
					rb = rb + 1
		elif data[0] == 'states':
			st = int(data[1])
	return (ra,rb,rp,nc,st)


# Test with a goal selector
def test_goal_selector(goalselector, options):
	import protocollist

	scythertest.set_extra_parameters("--goal-select=" + str(goalselector))
	result = str(goalselector)
	plist = protocollist.from_literature()
	np = len(plist)

	attacks = 0
	bounds = 0
	proofs = 0
	claims = 0
	states = 0
	for p in plist:
		(status,scout) = scythertest.default_test([p], \
				int(options.match), \
				int(options.bounds))
		(ra,rb,rp,nc,st) = parse(scout)
		attacks = attacks + ra
		bounds = bounds + rb
		proofs = proofs + rp
		claims = claims + nc
		states = states + st
	
	return (attacks,bounds,proofs,claims,np,states)

# Max
class maxor:
	def __init__(self,dir=0,mymin=99999999, mymax=-99999999):
		self.dir = dir
		self.min = mymin
		self.max = mymax
	
	def reg(self,data):
		res = ""
		if self.min >= data:
			self.min = data
			if (self.dir & 2):
				res = res + "-"
		if self.max <= data:
			self.max = data
			if (self.dir & 1):
				res = res + "+"
		if res == "":
			return res
		else:
			return "[" + res + "]"

# Main code
def main():
	parser = OptionParser()
	scythertest.default_options(parser)
	(options, args) = parser.parse_args()
	scythertest.process_default_options(options)

	print "G-sel\tAttack\tBound\tProof\tClaims\tScore1\tScore2"
	print 

	ramax = maxor(1)
	rbmax = maxor(2)
	rpmax = maxor(1)
	score1max = maxor(1)
	score2max = maxor(1)
	statesmax = maxor(2)

	for g in range(1,31):
		if (g & 8) == 0:
			(ra,rb,rp,nc,np,st) = test_goal_selector(g, options)

			# Scores: bounds are negative
			score1 = ra + rp - rb
			score2 = ra + (3 * rp) - (2 * rb)

			res = str(g)

			def shows (res, mx, data):
				return res + "\t" + str(data) + mx.reg(data)

			res = shows (res, ramax, ra)
			res = shows (res, rbmax, rb)
			res = shows (res, rpmax, rp)
			res = res + "\t" + str(nc)
			res = shows (res, score1max, score1)
			res = shows (res, score2max, score2)
			res = shows (res, statesmax, st)

			print res
	print
	print "Goal selector scan completed."

# Only if main stuff
if __name__ == '__main__':
	main()
