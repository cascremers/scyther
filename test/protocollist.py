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

def from_literature():
	list = [ \
	"andrew-ban.spdl",
	"andrew-lowe-ban.spdl",
	"bkepk.spdl",
	"bke.spdl",
	"boyd.spdl",
	"ccitt509-ban.spdl",
	"denning-sacco-shared.spdl",
	"gong-nonce-b.spdl",
	"gong-nonce.spdl",
	"isoiec11770-2-13.spdl",
	"kaochow-palm.spdl",
	"kaochow.spdl",
	"kaochow-v2.spdl",
	"kaochow-v3.spdl",
	"ns3.spdl",
	"nsl3.spdl",
	"nsl7.spdl",
	"ns-symmetric-amended.spdl",
	"ns-symmetric.spdl",
	"otwayrees.spdl",
	"soph-keyexch.spdl",
	"soph.spdl",
	"splice-as-hc-cj.spdl",
	"splice-as-hc.spdl",
	"splice-as.spdl",
	"tmn.spdl",
	"wmf-brutus.spdl",
	"woolam-ce.spdl",
	"woolam-cmv.spdl",
	"woolam-pi-f.spdl",
	"yahalom-ban.spdl",
	"yahalom-lowe.spdl",
	"yahalom-paulson.spdl",
	"yahalom.spdl" ]

	return list_ppfix(list, "../spdl/","")

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
	"ns3-brutus.spdl",
	"nsl3-nisynch-rep.spdl",
	"onetrace.spdl",
	"samasc-broken.spdl",
	"simplest.spdl",
	"speedtest.spdl",
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
