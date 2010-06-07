#!/bin/sh

IGN=""
MDS=" --models=7rules"
DEF=" --PSH $MDS \
      --max-runs=0 \
      "
DEFOUT="protocol-security-hierarchy.pdf"

APROTS=""
APROTS="$APROTS ns3.spdl nsl3.spdl"
APROTS="$APROTS Protocols/ccitt509-1.spdl Protocols/ccitt509-1c.spdl Protocols/ccitt509-3.spdl"

SPROTS=""
SPROTS="$SPROTS \
	Protocols/BKE.spdl \
	Protocols/AdversaryModels/JKL-TS1.spdl \
	Protocols/AdversaryModels/JKL-TS2.spdl \
	Protocols/AdversaryModels/JKL-TS3.spdl \
	Protocols/AdversaryModels/BCNP-1.spdl \
	Protocols/AdversaryModels/BCNP-2.spdl \
	Protocols/AdversaryModels/naxos.spdl \
	Protocols/AdversaryModels/2DH-ISO.spdl \
	Protocols/AdversaryModels/DHKE-1.spdl \
	"

./test-adversary-models.py $DEF --secrecy        $SPROTS $IGN
cp $DEFOUT psh-CSL-secrecy.pdf
./test-adversary-models.py $DEF --authentication $APROTS $IGN
cp $DEFOUT psh-CSL-authentication.pdf

