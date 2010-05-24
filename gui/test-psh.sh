#!/bin/sh

#IGN=" --ignore=ksl-lowe --ignore=Okamoto"
IGN=" --ignore=Okamoto --ignore=ksl-lowe --ignore=SKEME"
MDS=" --models=7rules"
DEF=" --PSH $MDS"
APROTS="Protocols/*.spdl"
SPROTS="$APROTS Protocols/AdversaryModels/*.spdl"
DEFOUT="protocol-security-hierarchy.pdf"

./test-adversary-models.py $DEF --secrecy        $SPROTS $IGN
cp $DEFOUT psh-secrecy.pdf
./test-adversary-models.py $DEF --authentication $APROTS $IGN
cp $DEFOUT psh-authentication.pdf

