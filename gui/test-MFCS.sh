#!/bin/sh

#IGN=" --ignore=ksl-lowe --ignore=Okamoto"
IGN=" --ignore=Okamoto --ignore=ksl --ignore=SKEME"
MDS=" --models=7rules"
DEF=" --PSH $MDS \
      --max-runs=0 \
      "
APROTS="Protocols/*.spdl"
SPROTS="$APROTS Protocols/AdversaryModels/*.spdl"
DEFOUT="protocol-security-hierarchy.pdf"

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
	"

./test-adversary-models.py $DEF --secrecy        $SPROTS $IGN
cp $DEFOUT psh-MFCS-secrecy.pdf
./test-adversary-models.py $DEF --authentication $APROTS $IGN
cp $DEFOUT psh-MFCS-authentication.pdf

