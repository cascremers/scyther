#!/usr/bin/python
#
#    protocol list
#
#
import os;

def basedir():
    return os.path.expanduser("~/svn/ecss/protocols/spdl/")

def spdldir():
    return basedir() + "SPORE/"
    
def index(directory):
    # like os.listdir, but traverses directory trees
    stack = [directory]
    files = []
    while stack:
        directory = stack.pop()
        for file in os.listdir(directory):
            fullname = os.path.join(directory, file)
            files.append(fullname)
            if os.path.isdir(fullname) and not os.path.islink(fullname):
                stack.append(fullname)
    return files

def known_problems():
    return ['needham-schroeder-lowe.spdl', 'kaochow-v2.spdl', 'needham-schroeder-sk.spdl', 'ccitt509-3.spdl', 'denning-sacco-lowe.spdl', 'kaochow-v3.spdl', 'ksl.spdl', 'ksl-lowe.spdl', 'denning-sacco.spdl', 'needham-schroeder-sk-amend.spdl', 'needham-schroeder-sk.spdl', 'andrew-ban-concrete.spdl', 'wmf.spdl', 'yahalom.spdl', 'wmf-lowe.spdl', 'needham-schroeder.spdl']

def known_good_ones():
    list = [ \
    "ccitt509-1c.spdl",
    "ccitt509-1.spdl",
    "ccitt509-3.spdl",
    "ccitt509-ban3.spdl",
    "denning-sacco-lowe.spdl",
    "denning-sacco.spdl",
    "kaochow.spdl",
    "kaochow-v2.spdl",
    "kaochow-v3.spdl",
    "ksl-lowe.spdl",
    "ksl.spdl",
    "needham-schroeder-lowe.spdl",
    "needham-schroeder-sk-amend.spdl",
    "needham-schroeder-sk.spdl",
    "neumannstub-hwang.spdl",
    "neumannstub.spdl",
    "otwayrees.spdl",
    "smartright.spdl",
    "splice-as-cj.spdl",
    "splice-as-hc.spdl",
    "splice-as.spdl",
    "woo-lam-pi-f.spdl",
    "woo-lam-pi.spdl",
    "woo-lam.spdl",
    "yahalom-lowe.spdl",
    "yahalom-paulson.spdl" ]

    return [  "/" + i for i in list ]

def spdlextension (fn):
    return fn.endswith(".spdl")

def make_lists():
    """
        Returns (from_good_lit, from_bad_lit, others)

        Note that from_good_lit and from_bad_lit together form the spdl directory
    """

    good = []
    bad = []
    others = []

    # Precompute good names
    knowngood = known_good_ones()

    l = index(basedir())
    for file in l:
        if spdlextension(file):
            # its a protocol!
            if file.startswith(spdldir()):
                # SPORE type
                goodflag = False
                for goody in knowngood:
                    if file.endswith(goody):
                        goodflag = True
                if goodflag:
                    good += [file]
                else:
                    bad += [file]
            else:
                # not SPORE
                others += [file]

    return (good, bad, others)

def from_others():
    (good, bad, others) = make_lists()
    return others

def from_good_literature():
    (good, bad, others) = make_lists()
    return good

def from_bad_literature():
    (good, bad, others) = make_lists()
    return bad

def from_literature():
    (good, bad, others) = make_lists()
    return good + bad

def from_all():
    (good, bad, others) = make_lists()
    return good + bad + others

def from_literature_no_problems():
    bl = from_literature()
    pl = known_problems()
    dl = []
    for p in bl:
        test = True
        for pbad in pl:
            if p.endswith(pbad):
                test = False
        if test:
            dl += [p]
    return dl

def select(type):

    (good, bad, others) = make_lists()

    n = int(type)
    if n == 0:
        # 0 means all protocols
        return from_all()
    elif n == 1:
        # 1 means from literature
        return from_literature()
    elif n == 2:
        # 2 means from literature, no known attacks
        return from_good_literature()
    elif n == 3:
        # 3 means from litature, without the problem cases
        return from_good_literature_no_problems()
    else:
        # Otherwise empty list
        return []



def main():
    l = from_all()
    for f in l:
        print f
        

if __name__ == '__main__':
    main()
