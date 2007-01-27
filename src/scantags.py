#!/usr/bin/python

import commands
import sys

class Tag(object):
    """
    Object for tag (ctag line)
    """

    def __init__(self,tagline):
        tl = tagline.strip().split('\t')
        self.id = tl[0]
        self.filename = tl[1]

    def __str__(self):
        return self.id

class GrepRes(object):
    """
    Object for a result line from grep
    """

    def __init__(self,line):
        self.line = line
        x = line.find(":")
        if x:
            self.filename = line[:x]
            self.text = line[x:].strip()
        else:
            self.filename = None
            self.text = None

    def __str__(self):
        return self.line


def outToRes(out,filter=[]):
    """
    filter grep output and make a list of GrepRes objects. Filter out
    any that come from the filenames in the filter list. Also return the
    count of all results (not taking the filter into account).
    """

    reslist = []
    count = 0
    for l in out.splitlines():
        gr = GrepRes(l)
        if gr.filename not in filter:
            reslist.append(gr)
        count = count+1
    return (reslist,count)

def gettags():
    """
    Get all the tags in a list
    """

    f = open("tags","r")
    tags = []
    for l in f.readlines():
        if not l.startswith("!"):
            tags.append(Tag(l))
    f.close()
    return tags

def tagoccurs(problems,tag,filter=[]):
    """
    Check tag occurrences in certain files and show interesting ones.
    """

    cmd = "grep \"\\<%s\\>\" *.[chly]" % tag
    (reslist,count) = outToRes(commands.getoutput(cmd),[tag.filename])
    if (len(reslist) == 0) and (count < 2):
        if tag.filename not in filter:
            # this might be a problem, store it
            if tag.filename not in problems.keys():
                problems[tag.filename] = {}
            problems[tag.filename][tag.id] = count

    return problems


def tagreport(problems):
    for fn in problems.keys():
        print "file: %s" % fn
        for t in problems[fn].keys():
            print "\t%i\t%s" % (problems[fn][t],t)


def main():
    # Generate tags
    print "Generating tags using 'ctags'"
    cmd = "ctags *.c *.h *.l *.y"
    commands.getoutput(cmd)

    # Analyze results
    print "Analyzing results"
    filter = ["scanner.c","parser.c"]
    tags = gettags()
    problems = {}
    total = len(tags)
    count = 0
    steps = 20
    print "_ " * (steps)

    for t in tags:
        problems = tagoccurs(problems,t,filter)
        count = count + 1
        if count % (total / steps) == 0:
            print "^",
            sys.stdout.flush()
    print
    print

    tagreport (problems)

main()

