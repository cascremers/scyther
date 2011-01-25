#!/bin/sh

bsub -W 8:00 -Jd "book-aa-t" -N ./test-mpa.py -m 2 --plain                  --latex book-aa-t Protocols/MultiProtocolAttacks/*.spdl
bsub -W 8:00 -Jd "book-aa-b" -N ./test-mpa.py -m 2 --plain -b               --latex book-aa-b Protocols/MultiProtocolAttacks/*.spdl
bsub -W 8:00 -Jd "book-aa-u" -N ./test-mpa.py -m 2 --plain -u               --latex book-aa-u Protocols/MultiProtocolAttacks/*.spdl
bsub -W 8:00 -Jd "book-ex-t" -N ./test-mpa.py -m 2 --plain    --extravert   --latex book-ex-t Protocols/MultiProtocolAttacks/*.spdl
bsub -W 8:00 -Jd "book-ex-b" -N ./test-mpa.py -m 2 --plain -b --extravert   --latex book-ex-b Protocols/MultiProtocolAttacks/*.spdl
bsub -W 8:00 -Jd "book-ex-u" -N ./test-mpa.py -m 2 --plain -u --extravert   --latex book-ex-u Protocols/MultiProtocolAttacks/*.spdl
bsub -W 8:00 -Jd "book-iu-t" -N ./test-mpa.py -m 2 --plain    --init-unique --latex book-iu-t Protocols/MultiProtocolAttacks/*.spdl
bsub -W 8:00 -Jd "book-iu-b" -N ./test-mpa.py -m 2 --plain -b --init-unique --latex book-iu-b Protocols/MultiProtocolAttacks/*.spdl
bsub -W 8:00 -Jd "book-iu-u" -N ./test-mpa.py -m 2 --plain -u --init-unique --latex book-iu-u Protocols/MultiProtocolAttacks/*.spdl
