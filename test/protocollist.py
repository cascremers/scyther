#!/usr/bin/python
#
#    protocol list
#
#
import os;

def list_ppfix(list, prefix, postfix):
    return [ prefix + i + postfix for i in list]

def from_good_literature():
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

    return list_ppfix(list, "/home/cas/svn/ecss/protocols/spdl/SPORE/","")

def from_bad_literature():
    list = [ \
    "andrew-ban-concrete.spdl",
    "andrew-ban.spdl",
    "andrew-lowe-ban.spdl",
    "andrew.spdl",
    "needham-schroeder.spdl",
    "tmn.spdl",
    "wmf-lowe.spdl",
    "wmf.spdl",
    "woo-lam-pi-1.spdl",
    "woo-lam-pi-2.spdl",
    "woo-lam-pi-3.spdl",
    "yahalom-ban.spdl",
    "yahalom.spdl" ]

    return list_ppfix(list, "/home/cas/svn/ecss/protocols/spdl/SPORE/","")

def from_literature():

    def spdlfiletype (fn):
        return fn.endswith(".spdl")

    spdldir = "/home/cas/svn/ecss/protocols/spdl/SPORE/"
    sl = os.listdir (spdldir)
    sld = [ spdldir + i for i in filter (spdlfiletype, sl)]
    ##print sld
    return sld

def from_others():
    list = [ \
            ]

    return list_ppfix(list, "../spdl/","")

def from_all():
    return from_literature() + from_others()

def select(type):
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
    else:
        # Otherwise empty list
        return []




def main():
    for l in [from_literature(), from_others()]:
        for p in l:
            print p
        print

if __name__ == '__main__':
    main()
