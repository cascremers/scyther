#!/bin/sh

bsub -W 8:00 -Jd "ike1-aa-t" -N ./test-mpa.py -m 2 --plain                  --latex ike1-aa-t ~/src/ikev2/pp-results/mpa/ikev1*.spdl
bsub -W 8:00 -Jd "ike1-aa-b" -N ./test-mpa.py -m 2 --plain -b               --latex ike1-aa-b ~/src/ikev2/pp-results/mpa/ikev1*.spdl
bsub -W 8:00 -Jd "ike1-aa-u" -N ./test-mpa.py -m 2 --plain -u               --latex ike1-aa-u ~/src/ikev2/pp-results/mpa/ikev1*.spdl
bsub -W 8:00 -Jd "ike1-ex-t" -N ./test-mpa.py -m 2 --plain    --extravert   --latex ike1-ex-t ~/src/ikev2/pp-results/mpa/ikev1*.spdl
bsub -W 8:00 -Jd "ike1-ex-b" -N ./test-mpa.py -m 2 --plain -b --extravert   --latex ike1-ex-b ~/src/ikev2/pp-results/mpa/ikev1*.spdl
bsub -W 8:00 -Jd "ike1-ex-u" -N ./test-mpa.py -m 2 --plain -u --extravert   --latex ike1-ex-u ~/src/ikev2/pp-results/mpa/ikev1*.spdl
bsub -W 8:00 -Jd "ike1-iu-t" -N ./test-mpa.py -m 2 --plain    --init-unique --latex ike1-iu-t ~/src/ikev2/pp-results/mpa/ikev1*.spdl
bsub -W 8:00 -Jd "ike1-iu-b" -N ./test-mpa.py -m 2 --plain -b --init-unique --latex ike1-iu-b ~/src/ikev2/pp-results/mpa/ikev1*.spdl
bsub -W 8:00 -Jd "ike1-iu-u" -N ./test-mpa.py -m 2 --plain -u --init-unique --latex ike1-iu-u ~/src/ikev2/pp-results/mpa/ikev1*.spdl

