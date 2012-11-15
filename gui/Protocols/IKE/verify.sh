#############################################################################
#
# NAME
#	verify - batch protocol verifier script for scyther
#
# SYNOPSIS
#	./verify.sh [option]... [file]...
#
# DESCRIPTION
#	Verify protocol specifications using scyther.
#
# OPTIONS
#
#	-d	Debug mode [false]
#	-e	Execution environment [cluster]
#	-h	Help
#	-i	Skip attack patterns of the form Alice talking to Alice
#	-l	lower bound of claims to check [1]
#	-m	Adversary-compromise model [ext]
#	-o	Output directory (attack graphs) [./graphs/]
#	-r	number of runs [6]
#	-t	timeout in s
#	-u	upper bound of claims to check [1]
#
# EXAMPLE
#	./verify.sh -m br -o . *.spdl
#
#############################################################################


#!/bin/bash

# Default values
CLAIM[0]=1
CLAIM[1]=1
DEBUG=false
ENV='cluster'
FILES="*.spdl"
INITUNIQUE=
MODEL='ext'
OUTDIR='./graphs'
RUNS='-r 6'
SCYTHER='../scyther/Scyther/scyther-linux'
TIMEOUT=

# Adversary-compromise models
# EXT
MODELS[0]=
# INT
MODELS[1]='--LKRothers 1'
# CA
MODELS[2]='--LKRactor 1'
# AF
MODELS[3]='--LKRafter 1'
# AFC
MODELS[4]='--LKRaftercorrect 1'
# BR
MODELS[5]='--LKRothers 1 --SKR 1 --SKRinfer' # (inferred session keys)
MODELS[6]='--LKRothers 1 --SKR 1'
# CKw
MODELS[7]='--LKRothers 1 --LKRactor 1 --LKRaftercorrect 1 --SKR 1 --SKRinfer --SSR 1'
MODELS[8]='--LKRothers 1 --LKRactor 1 --LKRaftercorrect 1 --SKR 1 --SSR 1'
# CK
MODELS[9]='--LKRothers 1 --LKRafter 1 --LKRaftercorrect 1 --SKR 1 --SKRinfer --SSR 1'
MODELS[10]='--LKRothers 1 --LKRafter 1 --LKRaftercorrect 1 --SKR 1 --SSR 1'
# eCK-1
MODELS[11]='--LKRothers 1 --SKR 1 --SKRinfer --RNR 1'
MODELS[12]='--LKRothers 1 --SKR 1 --RNR 1'
# eCK-2
MODELS[13]='--LKRothers 1 --LKRactor 1 --LKRaftercorrect 1 --SKR 1 --SKRinfer'
MODELS[14]='--LKRothers 1 --LKRactor 1 --LKRaftercorrect 1 --SKR 1'


# Parse command line arguments
while getopts “de:hil:m:o:r:t:u:” FLAG;
do
	case $FLAG in
		d) DEBUG=true;;
		e) ENV=$OPTARG;;
		i) INITUNIQUE='--init-unique';;
		l) CLAIM[0]=$OPTARG;;
		m) MODEL=$OPTARG;;
		o) OUTDIR=$OPTARG;;
		r) RUNS="-r $OPTARG";;
		t) TIMEOUT="-T $OPTARG";;
		u) CLAIM[1]=$OPTARG;;
		h|?)
			printf "Usage: %s: [-l num][-u num][-d][-e [cluster|remote|local]][-h][-m model][-o value][-r num][-t sec]file[...]\n" $(basename $0) >&2 
			exit 1;;
	esac
done
shift $(($OPTIND - 1))

# Remaining arguments treated as specification files
if [ -n "$*" ]; then
	FILES="$*"
	# mkdir -p "$OUTDIR$TSTAMP"
fi


# Parse model identifiers
mflags=
case $MODEL in
	int)	mflags=${MODELS[1]};;
	ca) 	mflags=${MODELS[2]};;
	af) 	mflags=${MODELS[3]};;
	afc)	mflags=${MODELS[4]};;
	bri)	mflags=${MODELS[5]};;
	br) 	mflags=${MODELS[6]};;
	ckwi)	mflags=${MODELS[7]};;
	ckw)	mflags=${MODELS[8]};;
	cki)	mflags=${MODELS[9]};;
	ck)		mflags=${MODELS[10]};;
	eck1i)	mflags=${MODELS[11]};;
	eck1)	mflags=${MODELS[12]};;
	eck2i)	mflags=${MODELS[13]};;
	eck2)	mflags=${MODELS[14]};;
esac


# Verify
for file in $FILES;
do
	EXT=`echo "$file" | sed 's/^.*\.//'`
	if [ "$EXT" == 'spdl' ]; then
		# Extract protocol name
		tmp=`basename $file .spdl`
		p=`basename $tmp .pp`

		# Execute scyther for selected models and claim
		for (( c=${CLAIM[0]}; c<=${CLAIM[1]}; c++ ));
		do
			init="$SCYTHER $TIMEOUT --force-regular $INITUNIQUE $RUNS $mflags $file -d -o $OUTDIR/${p}_adv-${MODEL}_I$c.dot --filter=$p,I$c"
			resp="$SCYTHER $TIMEOUT --force-regular $INITUNIQUE $RUNS $mflags $file -d -o $OUTDIR/${p}_adv-${MODEL}_R$c.dot --filter=$p,R$c"
			if $DEBUG; then
				echo $init
				echo $resp
			elif [ $ENV = "cluster" ]; then
				bsub -W 08:00 -R "rusage[mem=4096]" $init
				bsub -W 08:00 -R "rusage[mem=4096]" $resp
			else # $ENV = local
				time $init
				time $resp
			fi
		done
	else
		printf "WARNING: %s could not be processed." $file
	fi
done
