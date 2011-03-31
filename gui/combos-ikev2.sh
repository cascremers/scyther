#!/bin/sh

bsub -W 8:00 -Jd "ike2-aa-t" -N ./test-mpa.py -m 2 --plain                  --latex ike2-aa-t ~/src/ikev2/pp-results/mpa/ikev2*.spdl
bsub -W 8:00 -Jd "ike2-aa-b" -N ./test-mpa.py -m 2 --plain -b               --latex ike2-aa-b ~/src/ikev2/pp-results/mpa/ikev2*.spdl
bsub -W 8:00 -Jd "ike2-aa-u" -N ./test-mpa.py -m 2 --plain -u               --latex ike2-aa-u ~/src/ikev2/pp-results/mpa/ikev2*.spdl
bsub -W 8:00 -Jd "ike2-ex-t" -N ./test-mpa.py -m 2 --plain    --extravert   --latex ike2-ex-t ~/src/ikev2/pp-results/mpa/ikev2*.spdl
bsub -W 8:00 -Jd "ike2-ex-b" -N ./test-mpa.py -m 2 --plain -b --extravert   --latex ike2-ex-b ~/src/ikev2/pp-results/mpa/ikev2*.spdl
bsub -W 8:00 -Jd "ike2-ex-u" -N ./test-mpa.py -m 2 --plain -u --extravert   --latex ike2-ex-u ~/src/ikev2/pp-results/mpa/ikev2*.spdl
bsub -W 8:00 -Jd "ike2-iu-t" -N ./test-mpa.py -m 2 --plain    --init-unique --latex ike2-iu-t ~/src/ikev2/pp-results/mpa/ikev2*.spdl
bsub -W 8:00 -Jd "ike2-iu-b" -N ./test-mpa.py -m 2 --plain -b --init-unique --latex ike2-iu-b ~/src/ikev2/pp-results/mpa/ikev2*.spdl
bsub -W 8:00 -Jd "ike2-iu-u" -N ./test-mpa.py -m 2 --plain -u --init-unique --latex ike2-iu-u ~/src/ikev2/pp-results/mpa/ikev2*.spdl


