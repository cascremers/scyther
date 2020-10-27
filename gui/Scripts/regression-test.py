#!/usr/bin/env python

"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2013 Cas Cremers

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

def testSet(blacklist=[]):
    import os

    prefix = "../Protocols/"
    dl = os.listdir(prefix)
    fl = []
    for fn in dl:
        if fn.endswith(".spdl"):
            okay = True
            for fb in blacklist:
                if fn.startswith(fb):
                    okay = False
                    break
            if okay:
                fl.append((prefix,fn))
    return fl

def evaluate(fn,prefix=""):
    import subprocess
    import tempfile

    cmd = "../Scyther/scyther-linux"
    args = [cmd,"--max-runs=4","--plain",fn]

    fstdout = tempfile.TemporaryFile()
    fstderr = tempfile.TemporaryFile()

    subprocess.call(args,stdout=fstdout,stderr=fstderr)

    fstdout.seek(0)
    fstderr.seek(0)

    res = ""
    for l in fstdout:
        res += prefix + l.strip() + "\n"
    #for l in fstderr.xreadlines():
    #    print l

    fstdout.close()
    fstderr.close()
    return res


def main():
    dest = "regression-test.txt"
    output = "regression-test.txt.tmp"

    fp = open(output, 'w')

    fl = testSet(blacklist=['ksl'])
    cnt = 1
    tres = ""
    for (prefix,fn) in sorted(fl):
        print("Evaluating %s (%i/%i)" % (fn,cnt,len(fl)))
        res = evaluate(prefix+fn, "%s\t" % (fn))
        fp.write(res)
        tres += res
        cnt += 1
    fp.close()

    fp = open(dest, 'w')
    fp.write(tres)
    fp.close()

    print(res)



if __name__ == '__main__':
    main()
