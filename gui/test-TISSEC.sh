#!/bin/sh
#
# Script to recreate test result for TISSEC journal paper on compromise
#

DEFOUT="protocol-security-hierarchy.pdf"

# Define protocol sets
# Protocols for secrecy
SPROTS=""
SPROTS="$SPROTS \
        Protocols/AdversaryModels/2DH-ISO-C.spdl \
        Protocols/AdversaryModels/2DH-ISO.spdl \
	Protocols/AdversaryModels/BCNP-1.spdl \
	Protocols/AdversaryModels/BCNP-2.spdl \
        Protocols/AdversaryModels/BKE.spdl \
        Protocols/AdversaryModels/DHKE-1.spdl \
        Protocols/AdversaryModels/HMQV-C.spdl \
        Protocols/AdversaryModels/HMQV-twopass.spdl \
	Protocols/AdversaryModels/JKL-TS1-2004.spdl \
	Protocols/AdversaryModels/JKL-TS1-2008.spdl \
	Protocols/AdversaryModels/JKL-TS2-2004.spdl \
	Protocols/AdversaryModels/JKL-TS2-2008.spdl \
	Protocols/AdversaryModels/JKL-TS3-2004.spdl \
	Protocols/AdversaryModels/JKL-TS3-2008.spdl \
        Protocols/AdversaryModels/kea-plus.spdl \
        Protocols/AdversaryModels/MQV-twopass.spdl \
        Protocols/AdversaryModels/naxos.spdl \
        Protocols/AdversaryModels/naxos-MTencr.spdl \
        Protocols/AdversaryModels/naxos-C.spdl \
        Protocols/AdversaryModels/ns3.spdl \
        Protocols/AdversaryModels/nsl3.spdl \
	Protocols/AdversaryModels/UM.spdl \
        Protocols/AdversaryModels/yahalom-ban-paulson-modified.spdl \
        Protocols/AdversaryModels/yahalom-ban-paulson.spdl \
	Protocols/AdversaryModels/CF.spdl \
	"
# Protocols for authentication
APROTS=""
APROTS="$APROTS ns3.spdl nsl3.spdl"
APROTS="$APROTS Protocols/ccitt509-1.spdl Protocols/ccitt509-1c.spdl Protocols/ccitt509-3.spdl"


# Simpler testing (cf. ESORICS)
IGN=""
#MDS=" --models=7rules"
MDS=" --models=paper"
DEF=" --PSH $MDS \
      --max-runs=4 \
      "
./test-adversary-models.py $DEF --secrecy        $SPROTS $IGN
cp $DEFOUT psh-TISSEC-simple.pdf


# Full testing (cf. CSL)
IGN=""
MDS=" --models=7rules"
DEF=" --PSH $MDS \
      --max-runs=4 \
      "
./test-adversary-models.py $DEF --secrecy        $SPROTS $IGN
cp $DEFOUT psh-TISSEC-secrecy.pdf
./test-adversary-models.py $DEF --authentication $APROTS $IGN
cp $DEFOUT psh-TISSEC-authentication.pdf

