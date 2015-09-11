#!/bin/sh
#
# Script to recreate test result for relation KCI and (w)PFS.
#
# Selecting only two-message protocols

DEFOUT="protocol-security-hierarchy.pdf"

# Define protocol sets
# Protocols for secrecy
SPROTS=""
SPROTS="$SPROTS \
        Protocols/AdversaryModels/naxos.spdl \
        Protocols/AdversaryModels/sig-naxos.spdl \
	Protocols/AdversaryModels/BCNP-1.spdl \
	Protocols/AdversaryModels/UM.spdl \
	Protocols/AdversaryModels/UM-3pass.spdl \
	Protocols/AdversaryModels/UM-3pass-reduced.spdl \
	Protocols/AdversaryModels/UM-2pass-variant.spdl \
	"

# Run test
IGN=""
MDS=" --models=kcipfs"
DEF=" --PSH $MDS \
      --max-runs=4 \
      "
./test-adversary-models.py $DEF --secrecy        $SPROTS $IGN
cp $DEFOUT psh-KCI_PFS.pdf

