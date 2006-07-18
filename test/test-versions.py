#!/usr/bin/python

"""
    Huge oldversions difference tester, optionally diff with the one in
    $PATH as well.

    Arguments will be passed on to Scyther for all the protocols in the
    set. (protocollist.py?)
"""

import os
import os.path
import commands
import protocollist

oldversionspath="../oldversions"
oldversionsprefix="scyther"

def get_versions(step=1):
    global oldversionspat
    global oldversionsprefix

    l = os.listdir(oldversionspath)
    rl = []
    i = 0
    for fn in l:
        if fn.startswith(oldversionsprefix):
            if i == 0:
                rl.append(fn[len(oldversionsprefix):])
            i = (i+1) % step
    rl.sort()
    rl.append(-1)   # denoting the current version
    return rl

def run_version(version,args):
    global oldversionspat
    global oldversionsprefix

    if version == -1:
        prg = "scyther"
    else:
        prg = "%s/%s%s" % (oldversionspath, oldversionsprefix, version)

    out = commands.getoutput("%s %s" % (prg,args))
    return out

def test_all_protocols(version, args):
    print "Testing version %s" % version
    l = protocollist.from_all()
    res = {}
    for fn in l:
        res[fn] = run_version(version, "%s %s" % (args,fn))
    return res

def test_all(versions,args):
    res = {}
    for v in versions:
        res[v] = test_all_protocols(v,args)
    return res

def main():
    vl = get_versions(150)
    res = test_all(vl,"-r2")
    l = protocollist.from_all()
    changes = {}
    for p in l:
        ln = len(vl)
        for i in range(0,(ln-1)):
            v1 = vl[i]
            v2 = vl[i+1]
            if str(res[v1][p]) != str(res[v2][p]):

                if v2 in changes.keys():
                    changes[v2].append(p)
                else:
                    changes[v2] = [p]

                print "*" * 80
                print "Found difference for protocol %s, between versions %s and %s" % (p,v1,v2)
                print 
                print "<" * 80
                print res[v1][p]
                print "=" * 80
                print res[v2][p]
                print ">" * 80

    print
    for x in changes.keys():
        print "For version %s, %i protocols changed." % (x,len(changes[x]))



if __name__ == '__main__':
    main()

