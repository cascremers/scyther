#!/usr/bin/python

import commands
import sys


def findfunctions(excludes):
    """
    Extract functions from tags file
    """
    fh = open("tags",'r')
    dict = {}
    for l in fh.readlines():
        data = l.strip().split('\t')
        if len(data) >= 4:
            fn = data[0]
            sourcefile = data[1]
            etype = data[3]
            if not fn.startswith("!_TAG_"):
                if sourcefile not in excludes:
                    if etype in ['f']:
                        dict[fn] = sourcefile
    return dict

def main():
    args = []
    if len(sys.argv) > 0:
        args = sys.argv[1:]

    mincount = 0
    if len(args) > 0:
        mincount = int(args[0])

    """ Force indent """
    cmd = "indent *.c *.h"
    output = commands.getoutput(cmd)

    """ Force ctags """
    cmd = "ctags *.c *.h"
    output = commands.getoutput(cmd)

    excludes = ['scanner.c','scanner.h','parser.c','parser.h']
    fnames = findfunctions(excludes)
    for fname in fnames.keys():
        """
        The ..* construct makes sure that function definitions are
        skipped (based on the indent settings
        """
        cmd = "grep '..*%s' *.c" % (fname)
        #print cmd
        output = commands.getoutput(cmd).splitlines()
        if len(output) <= mincount:
            print "%s\t%s" % (fnames[fname],fname)
            if len(output) > 0:
                print output

if __name__ == '__main__':
    main()

