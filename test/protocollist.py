#
#	protocol list
#
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
	"yahalom-ban.spdl",
	"yahalom-lowe.spdl",
	"yahalom-paulson.spdl",
	"yahalom.spdl" ]

	return list

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
	return list

def select(type):
	list = from_literature()
	if int(type) == 0:
		# 0 means all protocols
		list = list + from_others()

	# modify path 
	for i in range(0, len(list)):
		list[i] = "../spdl/" + list[i]
	return list

		
