#!/bin/sh

#IGN=" --ignore=ksl-lowe --ignore=Okamoto"
IGN=" \
	--ignore=Okamoto \
	--ignore=ksl \
	--ignore=SKEME \
	--ignore=onetrace \
	--ignore=unknown \
	--ignore=bke \
	--ignore=HSDDM \
	--ignore=tls-BM \
	--ignore=palm \
	--ignore=andrew \
	--ignore=ban \
	"
MDS=" --models=7rules"
DEF=" --PSH $MDS"

APROTS=""
#APROTS="$APROTS ../protocols/*.spdl"
#APROTS="$APROTS ../protocols/misc/*.spdl"
#APROTS="$APROTS ../protocols/misc/tls/*.spdl"
APROTS="$APROTS Protocols/*.spdl"
SPROTS="$APROTS"

DEFOUT="protocol-security-hierarchy.pdf"

#./test-adversary-models.py $DEF --secrecy        $SPROTS $IGN
#cp $DEFOUT psh-secrecy.pdf
./test-adversary-models.py $DEF --authentication $APROTS $IGN
cp $DEFOUT psh-ALT-authentication.pdf

