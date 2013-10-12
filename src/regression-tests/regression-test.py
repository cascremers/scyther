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

"""
regression-test.py

Regression tests for changes to the Scyther executable.
"""

"""
For each file, we run a test with some parameters, and check the result.

We do this for a large set of protocols, but also for some subset with 'special' parameters.
The tests are described in "tests.txt"

Each line is considered a sequence of arguments.
The output is written to test-X.out, where X is a sanitized version of the argument line.
"""

def sanitize(arg):
    """
    Take an argument line and sanitize it.

    Return argument may well be empty, which causes an error
    """
    from string import printable

    l = ""
    for c in arg:
        if c in printable:
            l = l + c
    l = l.strip()

    removes = "\\\"'`{}$"
    for x in removes:
        l = l.replace(x,"")
    
    l = l.replace("\t"," ")
    #ol = l 
    #l = ol + "x"
    #while l != ol:
    #    l = ol.replace("  "," ")

    #l = l.replace(" ","_")
    l = l.replace("/","-")

    l = l.strip()
    assert(len(l) > 0)
    return l


def runTest(arg,destdir="."):
    """
    Run a test and store the result.

    Time measurement is super coarse and depends, among other things, on me
    browsing in the background during the tests.
    """
    import subprocess
    import time
    from os.path import join

    nm = sanitize(arg)
    outfile = join(destdir,"test-%s.out" % (nm))
    errfile = join(destdir,"test-%s.err" % (nm))
    clkfile = join(destdir,"test-%s.time" % (nm))

    starttime = time.time()         # Time in seconds

    cmd = "../scyther-linux ../../%s --output=\"%s\" --errors=\"%s\"" % (arg,outfile,errfile)
    subprocess.call(cmd,shell=True)

    delta = time.time() - starttime # Duration in seconds

    fp = open(clkfile,'w')
    fp.write("Passed wall time in seconds:\n%i\n" % (delta))
    fp.close()


def runTests(fn,destdir="."):

    fp = open(fn,'r')
    tests = []
    clen = 0
    for l in fp.xreadlines():
        if l.startswith("#") or l.startswith("%"):
            continue
        d = l.strip()
        if len(d) > 0:
            tests.append(d)
            if not d.startswith("="):
                # We skip the 'global' settings
                clen = clen + 1
    fp.close()

    print "Running %i tests." % (clen)
    print "Destination: %s" % (destdir)
    cnt = 1
    setting = ""
    for l in tests:
        if l.startswith("="):

            setting = l[1:]
            if len(setting.strip()) == 0:
                setting = ""

            print "Changing global setting to \"%s\"" % (setting)

        else:
            print "%i/%i: Evaluating %s" % (cnt,clen,l+setting)
            runTest(l+setting,destdir)
            cnt = cnt + 1


def main():
    runTests("tests.txt","results")


if __name__ == "__main__":
    main()



