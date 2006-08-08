#!/usr/bin/python
#
# python wrapper for the Scyther command-line tool
#

#---------------------------------------------------------------------------

""" Import externals """
import sys

#---------------------------------------------------------------------------

""" Import scyther components """
import Scyther.Scyther as Scyther

#---------------------------------------------------------------------------

def usage():
    x = Scyther.Scyther()
    x.xml = False
    x.options = "--help"
    x.verify()
    return x

def simpleRun(args):
    x = Scyther.Scyther()
    x.options = args
    x.verify()
    return x

if __name__ == '__main__':
    pars = sys.argv[1:]
    if len(pars) == 0:
        print usage()
    else:
        print simpleRun(" ".join(pars))


