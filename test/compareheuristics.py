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
	return (ra,rb,rp,nc)


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
	for p in plist:
		(status,scout) = scythertest.default_test([p], \
				int(options.match), \
				int(options.bounds))
		(ra,rb,rp,nc) = parse(scout)
		attacks = attacks + ra
		bounds = bounds + rb
		proofs = proofs + rp
		claims = claims + nc
	
	return (attacks,bounds,proofs,claims,np)


# Main code
def main():
	parser = OptionParser()
	scythertest.default_options(parser)
	(options, args) = parser.parse_args()
	scythertest.process_default_options(options)

	print "G-sel\tAttack\tBound\tProof\tClaims\tScore1\tScore2"
	print 
	score1max = 0
	score2max = 0

	for g in range(1,31):
		(ra,rb,rp,nc,np) = test_goal_selector(g, options)

		# Scores: bounds are negative
		score1 = ra + rp - rb
		score2 = ra + rp - (2 * rb)

		res = str(g)
		res = res + "\t" + str(ra) + "\t" + str(rb)
		res = res + "\t" + str(rp) + "\t" + str(nc)
		res = res + "\t" + str(score1)
		if score1 >= score1max:
			score1max = score1
			res = res + "*"
		res = res + "\t" + str(score2)
		if score2 >= score2max:
			score2max = score2
			res = res + "*"
		print res
	print
	print "Goal selector scan completed."

# Only if main stuff
if __name__ == '__main__':
	main()
