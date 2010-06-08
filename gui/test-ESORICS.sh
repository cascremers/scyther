#!/bin/sh
#
# Script to recreate test result for Esorics 2010 paper.
#

DEFOUT="protocol-security-hierarchy.pdf"

IGN=""
#MDS=" --models=7rules"
MDS=" --models=paper"
DEF=" --PSH $MDS \
      "
SPROTS=" \
        Protocols/AdversaryModels/2DH-ISO-C.spdl \
        Protocols/AdversaryModels/2DH-ISO.spdl \
        Protocols/AdversaryModels/BKE.spdl \
        Protocols/AdversaryModels/DHKE-1.spdl \
        Protocols/AdversaryModels/HMQV-C.spdl \
        Protocols/AdversaryModels/HMQV-twopass.spdl \
        Protocols/AdversaryModels/kea-plus.spdl \
        Protocols/AdversaryModels/MQV-twopass.spdl \
        Protocols/AdversaryModels/naxos.spdl \
        Protocols/AdversaryModels/ns3.spdl \
        Protocols/AdversaryModels/nsl3.spdl \
        Protocols/AdversaryModels/yahalom-ban-paulson-modified.spdl \
        Protocols/AdversaryModels/yahalom-ban-paulson.spdl \
	"

./test-adversary-models.py $DEF --secrecy        $SPROTS $IGN
cp $DEFOUT psh-ESORICS-secrecy.pdf


