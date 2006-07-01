#!/usr/bin/python

import os

def analyze(file):

    claim = 0
    correct = 0
    attack = 0
    boundokay = 0
    notoccurs = 0

    if os.path.isfile(file):
        fp = open(file,'r')
        for l in fp.readlines():
            if l.startswith("claim"):
                claim = claim + 1
                if l.find("\tFail\t") >= 0:
                    attack = attack + 1
                else:
                    if l.find("bounds") >= 0:
                        boundokay = boundokay + 1
                    else:
                        if l.find("proof") >= 0:
                            correct = correct + 1
                        else:
                            if l.find("does not occur") >= 0:
                                notoccurs = notoccurs + 1
                            else:
                                print "Huh? ", l.strip()


        fp.close()

    if claim > 0:
        ratio = (100.0 * (attack+correct)) / claim
        print "[%s]\t%i\t%i\t%i\t%s%%" % (file, claim,attack,correct, str(ratio))

def timed(file):

    if os.path.isfile(file):
        fp = open(file,'r')
        for l in fp.readlines():
            l = l.strip()
            if l.find("User time (seconds)") >= 0:
                x = l.find(":")
                time = float(l[(x+1):])
                print file, time
                return
    print file, " no time found"

def all():
    for i in range(1,8):
        analyze("boundruns%i.txt" % (i))
    for i in range(1,8):
        timed("boundtime%i.txt" % (i))

all()




