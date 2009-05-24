#!/usr/bin/python

import os

def main():

    fn = "test.log"
    fh = open(fn,'r')
    last = None
    for l in fh.readlines():
        last = l
    fh.close()
    data = last.split("\t")
    print "Continuing from %s: '%s'" % (data[0],data[1].rstrip())

    cmd = "nice %s" % (data[1].rstrip())
    os.system(cmd)

if __name__ == '__main__':
    main()
