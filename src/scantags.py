#!/usr/bin/python

import commands

class Tag(object):
    """
    Object for tag (ctag line)
    """

    def __init__(self,tagline):
        tl = tagline.strip().split('\t')
        self.tag = tl[0]
        self.filename = tl[1]

    def __str__(self):
        return self.tag

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

def tagoccurs(tag):
    """
    Check tag occurrences in .c and .h files and show interesting ones.
    """

    cmd = "grep \"\\<%s\\>\" *.[ch]" % tag
    (reslist,count) = outToRes(commands.getoutput(cmd),[tag.filename])
    if (len(reslist) == 0) and (count < 2):
        print "\"%s\" seems to occur only %i times in %s" % (tag,count,tag.filename)


def main():
    tags = gettags()
    for t in tags:
        tagoccurs(t)

main()
