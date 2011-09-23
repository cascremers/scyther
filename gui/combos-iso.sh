#!/bin/sh

bsub -W 8:00 -Jd "iso-aa-t" -N ./test-mpa.py -m 2 --plain                  --latex iso-aa-t ~/papers/iso9798/scyther-models/*.spdl
bsub -W 8:00 -Jd "iso-aa-b" -N ./test-mpa.py -m 2 --plain -b               --latex iso-aa-b ~/papers/iso9798/scyther-models/*.spdl
bsub -W 8:00 -Jd "iso-aa-u" -N ./test-mpa.py -m 2 --plain -u               --latex iso-aa-u ~/papers/iso9798/scyther-models/*.spdl
bsub -W 8:00 -Jd "iso-ex-t" -N ./test-mpa.py -m 2 --plain    --extravert   --latex iso-ex-t ~/papers/iso9798/scyther-models/*.spdl
bsub -W 8:00 -Jd "iso-ex-b" -N ./test-mpa.py -m 2 --plain -b --extravert   --latex iso-ex-b ~/papers/iso9798/scyther-models/*.spdl
bsub -W 8:00 -Jd "iso-ex-u" -N ./test-mpa.py -m 2 --plain -u --extravert   --latex iso-ex-u ~/papers/iso9798/scyther-models/*.spdl
bsub -W 8:00 -Jd "iso-iu-t" -N ./test-mpa.py -m 2 --plain    --init-unique --latex iso-iu-t ~/papers/iso9798/scyther-models/*.spdl
bsub -W 8:00 -Jd "iso-iu-b" -N ./test-mpa.py -m 2 --plain -b --init-unique --latex iso-iu-b ~/papers/iso9798/scyther-models/*.spdl
bsub -W 8:00 -Jd "iso-iu-u" -N ./test-mpa.py -m 2 --plain -u --init-unique --latex iso-iu-u ~/papers/iso9798/scyther-models/*.spdl
