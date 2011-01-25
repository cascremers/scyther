#!/bin/sh

bsub -W 8:00 -N ./test-mpa.py -m 2 --plain                  --latex iso-aa-t ~/papers/iso/*.spdl
bsub -W 8:00 -N ./test-mpa.py -m 2 --plain -b               --latex iso-aa-b ~/papers/iso/*.spdl
bsub -W 8:00 -N ./test-mpa.py -m 2 --plain -u               --latex iso-aa-u ~/papers/iso/*.spdl
bsub -W 8:00 -N ./test-mpa.py -m 2 --plain    --extravert   --latex iso-ex-t ~/papers/iso/*.spdl
bsub -W 8:00 -N ./test-mpa.py -m 2 --plain -b --extravert   --latex iso-ex-b ~/papers/iso/*.spdl
bsub -W 8:00 -N ./test-mpa.py -m 2 --plain -u --extravert   --latex iso-ex-u ~/papers/iso/*.spdl
bsub -W 8:00 -N ./test-mpa.py -m 2 --plain    --init-unique --latex iso-iu-t ~/papers/iso/*.spdl
bsub -W 8:00 -N ./test-mpa.py -m 2 --plain -b --init-unique --latex iso-iu-b ~/papers/iso/*.spdl
bsub -W 8:00 -N ./test-mpa.py -m 2 --plain -u --init-unique --latex iso-iu-u ~/papers/iso/*.spdl
