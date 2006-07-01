#!/usr/bin/python

import os

firstbroken = {}

def analyze(file,bound):

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
    
                dt = l.split('\t')
                claimid = "%s,%s" % (dt[1],dt[2])

                if l.find("\tFail\t") >= 0:
                    attack = attack + 1

                    if claimid not in firstbroken.keys():
                        firstbroken[claimid] = bound

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
        analyze("boundruns%i.txt" % (i),i)
    for i in range(1,8):
        timed("boundtime%i.txt" % (i))

    for i in range(1,8):
        l = []
        for k in firstbroken.keys():
            if firstbroken[k] == i:
                l.append(k)
        print "Attack with %i runs:" % i
        print l

all()




