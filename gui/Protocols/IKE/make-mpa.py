#!/usr/bin/env python

import os

def getProtocolFiles(path=".",extension=""):
    allfiles = os.listdir(path)
    spfl = []
    for fn in allfiles:
        if fn.endswith(extension):
            spfl.append(fn)
    return spfl

def scanThis(fn,f,rewritelist,cnt):

    s = ""
    mapping = []
    for lhs in rewritelist:
        rhs = "%s%i" % (lhs,cnt)
        mapping.append((lhs,rhs))

    fp = open(fn,"r")
    for rl in fp:
        l = rl
        if f != None:
            l = f(l)
        for (lhs,rhs) in mapping:
            l = l.replace(lhs,rhs)
        s = s + l
    fp.close()
    return s

def convertEm(f=None,path=".",rewritelist=[],newdir=".",oldext="",newext=None):
    fl = getProtocolFiles(path=path,extension=oldext)
    cnt = 1
    for fn in fl:
        ffn = os.path.join(path,fn)
        print("Processing",ffn)
        s = scanThis(ffn,f,rewritelist,cnt)
        if newext == None:
            fn2 = fn
        else:
            fn2 = fn.replace(oldext,newext)
        ffn2 = os.path.join(newdir,fn2)
        fp = open(ffn2,"w")
        fp.write(s)
        fp.close()
        print("Produced",ffn2)
        cnt = cnt+1

def preprocess(s):
    s = s.replace("@oracle","@OracleA")
    s = s.replace("@ora ",  "@OracleB ")
    s = s.replace("@ora(",  "@OracleB(")
    return s

def main():
    convertEm(f=preprocess,rewritelist=["@OracleA","@executability","@OracleB"],path=".",newdir="mpa",oldext=".spdl")
    print("Done.")

if __name__ == '__main__':
    main()


