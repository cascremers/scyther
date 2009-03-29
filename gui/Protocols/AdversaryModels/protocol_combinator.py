#!/usr/bin/python

import os


def writer(fh,fn):
    fh2 = open(fn,'r')
    for l in fh2.xreadlines():
        fh.write(l)
    fh2.close()


def createCouple(ext,sep,n1,n2):

    fn1 = n1 + ext
    fn2 = n2 + ext
    fn3 = n1 + sep + n2 + ext
    print fn1,"+",fn2,"->",fn3
    fh = open(fn3,'w')
    writer(fh, fn1)
    writer(fh, fn2)
    fh.close()


def produceCouples(dir):

    sep = "_and_"
    ext = ".spdl"
    files = os.listdir(dir)
    
    spdlfiles = []
    for fn in files:
        if fn.endswith(ext):
            if fn.find(sep) < 0:
                spdlfiles.append(fn[:-len(ext)])

    for n1 in spdlfiles:
        for n2 in spdlfiles:
            if n1 != n2:
                createCouple(ext,sep,n1,n2)



def main():
    produceCouples(".")

if __name__ == '__main__':
    main()
