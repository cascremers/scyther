#!/bin/sh

bsub -W 8:00 -Jd "ike0-aa-t" -N ./test-mpa.py -m 2 --plain                  --latex ike0-aa-t ~/src/ikev2/pp-results/mpa/ikev*.spdl
bsub -W 8:00 -Jd "ike0-aa-b" -N ./test-mpa.py -m 2 --plain -b               --latex ike0-aa-b ~/src/ikev2/pp-results/mpa/ikev*.spdl
bsub -W 8:00 -Jd "ike0-aa-u" -N ./test-mpa.py -m 2 --plain -u               --latex ike0-aa-u ~/src/ikev2/pp-results/mpa/ikev*.spdl
bsub -W 8:00 -Jd "ike0-ex-t" -N ./test-mpa.py -m 2 --plain    --extravert   --latex ike0-ex-t ~/src/ikev2/pp-results/mpa/ikev*.spdl
bsub -W 8:00 -Jd "ike0-ex-b" -N ./test-mpa.py -m 2 --plain -b --extravert   --latex ike0-ex-b ~/src/ikev2/pp-results/mpa/ikev*.spdl
bsub -W 8:00 -Jd "ike0-ex-u" -N ./test-mpa.py -m 2 --plain -u --extravert   --latex ike0-ex-u ~/src/ikev2/pp-results/mpa/ikev*.spdl
bsub -W 8:00 -Jd "ike0-iu-t" -N ./test-mpa.py -m 2 --plain    --init-unique --latex ike0-iu-t ~/src/ikev2/pp-results/mpa/ikev*.spdl
bsub -W 8:00 -Jd "ike0-iu-b" -N ./test-mpa.py -m 2 --plain -b --init-unique --latex ike0-iu-b ~/src/ikev2/pp-results/mpa/ikev*.spdl
bsub -W 8:00 -Jd "ike0-iu-u" -N ./test-mpa.py -m 2 --plain -u --init-unique --latex ike0-iu-u ~/src/ikev2/pp-results/mpa/ikev*.spdl

