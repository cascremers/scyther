#!/usr/bin/python
#
#	protocol list
#
#
def list_ppfix(list, prefix, postfix):
	newlist = []
	for i in list:
		newlist.append(prefix + i + postfix)
	return newlist

def from_good_literature():
	list = [ \
	"bke.spdl",
	"boyd.spdl",
	"ccitt509-ban.spdl",
	"gong-nonce-b.spdl",
	"gong-nonce.spdl",
	"isoiec11770-2-13.spdl",
	"kaochow-v2.spdl",
	"kaochow-v3.spdl",
	"nsl3.spdl",
	"ksl.spdl",
	"soph.spdl",
	"splice-as-hc-cj.spdl",
	"woolam-pi-f.spdl",
	"yahalom-lowe.spdl",
	"yahalom-paulson.spdl",
	"yahalom.spdl" ]

	return list_ppfix(list, "../spdl/","")

def from_bad_literature():
	list = [ \
	"andrew-ban.spdl",
	"andrew-lowe-ban.spdl",
	"denning-sacco-shared.spdl",
	"kaochow.spdl",
	"ns3.spdl",
	"ns-symmetric-amended.spdl",
	"ns-symmetric.spdl",
	"otwayrees.spdl",
	"splice-as-hc.spdl",
	"splice-as.spdl",
	"tmn.spdl",
	"wmf-brutus.spdl",
	"woolam-cmv.spdl",
	"yahalom-ban.spdl" ]

	return list_ppfix(list, "../spdl/","")

def from_literature():
	return from_good_literature() + from_bad_literature()

def from_others():
	list = [ \
	"bke-broken.spdl",
	"bke-one.spdl",
	"bkepk-ce2.spdl",
	"bkepk-ce.spdl",
	"broken1.spdl",
	"carkey-broken-limited.spdl",
	"carkey-broken.spdl",
	"carkey-ni2.spdl",
	"carkey-ni.spdl",
	"five-run-bound.spdl",
	"helloworld.spdl",
	"kaochow-palm.spdl",
	"ns3-brutus.spdl",
	"nsl3-nisynch-rep.spdl",
	"nsl7.spdl",
	"onetrace.spdl",
	"samasc-broken.spdl",
	"simplest.spdl",
	"soph-keyexch.spdl",
	"speedtest.spdl",
	"woolam-ce.spdl",
	"unknown2.spdl"]

	return list_ppfix(list, "../spdl/","")

def from_all():
	return from_literature() + from_others()

def select(type):
	n = int(type)
	if n == 0:
		# 0 means all protocols
		return from_all()
	elif n == 1:
		# 1 means from literature
		return from_literature()
	elif n == 2:
		# 2 means from literature, no known attacks
		return from_good_literature()
	else:
		# Otherwise empty list
		return []




def main():
	for l in [from_literature(), from_others()]:
		for p in l:
			print p
		print

if __name__ == '__main__':
	main()
