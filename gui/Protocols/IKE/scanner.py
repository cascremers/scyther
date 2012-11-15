#!/usr/bin/env python

import sys

ALLPROTS = set()
ALLCLAIMS = set()   # prot x role x claim
PREFIX = None       # Required prefix
FFUNC = (lambda p: True)        # Filter function

def reset():

    global ALLPROTS
    global ALLCLAIMS
    global PREFIX
    global FFUNC

    ALLPROTS = set()
    ALLCLAIMS = set()
    PREFIX = None
    FFUNC = (lambda p: True) 

def skipLine(l):
    if len(l) == 0:
        return True

    skippable = ["%","\\begin","\\end","Protocol"]
    for skstr in skippable:
        if l.startswith(skstr):
            return True

    return False

def stripRowEnd(l):
    # Assume ends with \\, split by dtl
    endstr = "\\\\"
    if not l.endswith(endstr):
        print "Error: some line does not end with \\\\"
        print ">>%s<<" % (l)
        sys.exit(-1)

    return l[:-len(endstr)]

def splitStrip(l,sp):

    dtl = l.split(sp)
    for i in range(0,len(dtl)):
        dtl[i] = dtl[i].strip()
    return dtl

def roleClaim(dtl):
    rcdt = dtl.split()
    assert(rcdt[0].endswith(":"))
    role = rcdt[0][:-1]
    claim = rcdt[1]
    return (role,claim[:20])

def scanAttackFile(fn):

    global ALLPROTS

    fp = open("gen-%s-mpaattacks.tex" % (fn),"r")
    attackmap = {}
    prot = None
    role = None
    claim = None
    for rawline in fp.xreadlines():

        l = rawline.strip()

        if skipLine(l):
            continue

        l = stripRowEnd(l)

        dtl = splitStrip(l,"&")

        # New protocol
        if len(dtl[0]) > 0:
            prot = dtl[0]

        # New role
        if len(dtl[1]) > 0:
            (role,claim) = roleClaim(dtl[1])

        # Claims list
        # Assume starts with '[' and ends with ']'
        assert(dtl[2].startswith("["))
        assert(dtl[2].endswith("]"))
        attl = ((dtl[2])[1:-1]).split(",")
        for i in range(0,len(attl)):
            x = attl[i].strip()
            assert(x.startswith("'"))
            assert(x.endswith("'"))
            attl[i] = x[1:-1]

        ak = (prot,role,claim)
        if ak not in attackmap.keys():
            attackmap[ak] = set()
        attackmap[ak].add(tuple(attl))

        # Add to allprots set
        ALLPROTS.add(prot)
        for p in attl:
            ALLPROTS.add(prot)

    fp.close()

    return attackmap


def shorten(prot):
    """
    Shorten protocol name
    """
    cutting = ["isoiec-","9798-"]
    for ct in cutting:
        if prot.startswith(ct):
            prot = prot[len(ct):]
    return prot.replace("-udkey","-ud")


def prettyclaim(cl):
    """
    Rewrite if needed
    """
    return cl.replace("Commit","Agreement")


def mpaTable(attackmap):
    """
    construct table for MPA attacks
    """
    counter = 1
    s = ""

    s += "\\begin{longtable}{|l|lll|l|}\n" 
    s += "\\hline\n"
    for kk in sorted(ALLCLAIMS):
        if kk not in attackmap.keys():
            continue
        (prot,role,claim) = kk

        ats = str(attackmap[kk])
        sl = "%i & %s & %s & %s & %s \\\\ \n" % (counter,prot,role,claim,ats)

        s += sl
        counter = counter + 1

    s += "\\hline\n"
    s += "\\end{longtable}\n"

    return s


def rotated(headl):
    """
    Add rotated headers
    """
    for i in range(0,len(headl)):
        headl[i] = "\\begin{sideways} %s \\end{sideways}\n" % (headl[i])
    return " & ".join(headl)


def baseprot(prot):
    return shorten(prot)[:5]


def mpaTable2(attackmap,tabtype="tabular",options=""):
    """
    construct table for MPA attacks

    Second attempt
    """

    # To find the number of columns, we first need to find all protocols involved in two-protocol attacks
    involved = set()
    for kk in attackmap.keys():
        for atl in attackmap[kk]:
            # convert tuple back to list
            att = list(atl)
            if len(att) == 1:
                # This attack involves one *additional* protocol, so is a two-protocol attack
                involved.add(att[0])
    colheads = sorted(involved)
    attcols = ""
    last = None
    for hd in colheads:
        prm = baseprot(hd)
        if last == prm:
            attcols += "@{\hspace{2mm}}c"
        else:
            last = prm
            attcols += "|c"


    #attcols = "c" * len(involved)

    counter = 1
    s = ""

    #s += "\\clearpage \n"

    s += "\\begin{%s}%s{|l|ll|%s|}\n" % (tabtype,options,attcols)
    s += "\\hline\n"
    s += rotated(["No","Prot","Claim"])
    for hd in colheads:
        s += "& \\begin{sideways}%s\\end{sideways} " % (shorten(hd))
    s += "\\\\ \n"

    s += "\\hline\n"
    last = None
    for kk in sorted(ALLCLAIMS):
        if kk not in attackmap.keys():
            continue
        (prot,role,claim) = kk
        
        prm = baseprot(prot)
        if last != prm:
            last = prm
            s += "\\hline\n"

        sl = ""
        sl += "%i & %s & %s %s " % (counter,shorten(prot),role,claim)
        for ch in colheads:
            se = tuple([ch])
            if se in attackmap[kk]:
                sl += "& $\\bullet$ "
            else:
                sl += "& $\\circ$  "

        sl += "\\\\ \n"

        s += sl
        counter = counter + 1

    s += "\\hline\n"
    s += "\\end{%s}\n" % (tabtype)

    return s


def mpaTable3(attackmaps,tabtype="tabular",options=""):
    """
    construct table for MPA attacks

    attmaps = sequence of (attackmap, symbol)

    Symbol of the first matching is displayed

    Second attempt
    """

    global FFUNC
    # To find the number of columns, we first need to find all protocols involved in two-protocol attacks
    # Also populate "allkeys"
    involved = set()
    allkeys = set()
    for (attackmap,symbs) in attackmaps:
        for kk in attackmap.keys():
            allkeys.add(kk)
            for atl in attackmap[kk]:
                # convert tuple back to list
                att = list(atl)
                if len(att) == 1:
                    # This attack involves one *additional* protocol, so is a two-protocol attack
                    if FFUNC:
                        if not FFUNC(att[0]):
                            continue

                    involved.add(att[0])

    colheads = sorted(involved)
    attcols = ""
    last = None
    for hd in colheads:
        prm = baseprot(hd)
        if last == prm:
            attcols += "@{\hspace{2mm}}c"
        else:
            last = prm
            attcols += "|c"


    #attcols = "c" * len(involved)

    counter = 1
    s = ""

    #s += "\\clearpage \n"

    s += "\\begin{%s}%s{|l|ll|%s|}\n" % (tabtype,options,attcols)
    s += "\\hline\n"
    s += rotated(["No","Prot","Claim"])
    for hd in colheads:
        s += "& \\begin{sideways}%s\\end{sideways} " % (shorten(hd))
    s += "\\\\ \n"

    s += "\\hline\n"
    last = None
    for kk in sorted(ALLCLAIMS):
        if kk not in attackmap.keys():
            continue
        (prot,role,claim) = kk
        
        prm = baseprot(prot)
        if last != prm:
            last = prm
            s += "\\hline\n"

        sl = ""
        sl += "%i & %s & %s %s " % (counter,shorten(prot),role,prettyclaim(claim))
        for ch in colheads:
            se = tuple([ch])
            sl += "& "
            for (attackmap,symb) in attackmaps:
                if kk in attackmap.keys():
                    if se in attackmap[kk]:
                        sl += symb
                        break

        sl += "\\\\ \n"

        s += sl
        counter = counter + 1

    s += "\\hline\n"
    s += "\\end{%s}\n" % (tabtype)

    return s


def scanClaimList(fn):
    """
    Simply gather claims
    """

    global ALLPROTS
    global ALLCLAIMS
    global FFUNC

    fp = open("gen-%s-claims.txt" % (fn),"r")

    claimmap = {}
    for rawline in fp.xreadlines():

        l = rawline.strip()

        if skipLine(l):
            continue

        dtl = splitStrip(l,"; ")

        filename = dtl[0]
        prot = dtl[1]
        if FFUNC:
            if not FFUNC(prot):
                continue

        label = dtl[2]
        (role,claim) = roleClaim(dtl[3])

        ALLCLAIMS.add((prot,role,claim))
        ALLPROTS.add(prot)

    fp.close()

    return claimmap

def scanClaimFile(fn):
    """
    Construct claimmap

    prot -> roles -> claims
    """

    global ALLPROTS
    global ALLCLAIMS
    global FFUNC

    fp = open("gen-%s-correctclaims.tex" % (fn),"r")

    claimmap = {}
    for rawline in fp.xreadlines():

        l = rawline.strip()

        if skipLine(l):
            continue

        l = stripRowEnd(l)

        dtl = splitStrip(l,"&")

        prot = dtl[0]
        if FFUNC:
            if not FFUNC(prot):
                continue

        if prot not in claimmap.keys():
            claimmap[prot] = {}

        cll = splitStrip(dtl[1],";")

        for dt in cll:
            (role,claim) = roleClaim(dt)

            if role not in claimmap[prot].keys():
                claimmap[prot][role] = set()

            claimmap[prot][role].add(claim)

            ALLCLAIMS.add((prot,role,claim))

        ALLPROTS.add(prot)

    fp.close()

    return claimmap

def getRoleClaims(rcmap):

    rc = set()
    for role in rcmap.keys():
        for claim in rcmap[role]:
            rc.add((role,claim))

    return rc

def typeScanMatrix(cml,onlyChanged = False):

    global ALLPROTS

    """
    Scan for the influence of typing.

    Input:

    [(txt1,cm1),(txt2,cm2),...]

    """
    s = ""

    s += "\\begin{longtable}{|l|lll|%s|}\n" % ("c" * len(cml))
    s += "\\hline\n"

    s += "No & Prot & Role & Claim "
    for (txt,cm) in cml:
        s += "& %s " % (txt)
    s += "\\\\\n"
    s += "\\hline\n"

    goodverdict = "$\\circ$"
    badverdict = "$\\bullet$"

    counter = 1
    for (prot,role,claim) in sorted(ALLCLAIMS):
        # Header
        sl = "%i & %s & %s & %s " % (counter,prot,role,claim)
        alltrue = True
        for (txt,cm) in cml:
            verdict = badverdict
            if prot in cm.keys():
                if role in cm[prot].keys():
                    if claim in cm[prot][role]:
                        verdict = goodverdict
            if verdict == badverdict:
                alltrue = False

            sl += "& %s " % (verdict)
        sl += "\\\\\n"

        if alltrue == True:
            if onlyChanged == True:
                continue

        s += sl
        counter = counter + 1

    s += "\\hline\n"
    s += "\\end{longtable}\n"
    return s

def typeScanMatrix2(cml,onlyChanged = False,additive = False):

    global ALLPROTS

    """
    Scan for the influence of typing.

    Input:

    [(txt1,cm1),(txt2,cm2),...]

    """
    s = ""

    s += "\\begin{longtable}{|l|lll||c|}\n" 
    s += "\\hline\n"

    s += "No & Prot & Claim & Attacks"
    s += "\\\\\n"
    s += "\\hline\n"
    s += "\\hline\n"

    goodverdict = "$\\circ$"
    badverdict = "$\\bullet$"

    last = None
    counter = 1
    for (prot,role,claim) in sorted(ALLCLAIMS):
        if baseprot(prot) != last:
            last = baseprot(prot)
            s += "\\hline\n"

        # Header
        sl = "%i & %s & %s %s " % (counter,prot,role,prettyclaim(claim))
        alltrue = True
        res = ""
        for (txt,cm) in cml:
            verdict = badverdict
            if prot in cm.keys():
                if role in cm[prot].keys():
                    if claim in cm[prot][role]:
                        verdict = goodverdict
            if verdict == badverdict:
                alltrue = False
                if additive:
                    res += txt
                else:
                    res = txt

        sl += "& %s " % (res)
        sl += "\\\\\n"

        if alltrue == True:
            if onlyChanged == True:
                continue

        s += sl
        counter = counter + 1

    s += "\\hline\n"
    s += "\\end{longtable}\n"
    return s

def typeScanMatrix3(hd1,hd2,cml,f,onlyChanged = False,tabletype="longtable"):

    global ALLPROTS

    """
    Scan for the influence of typing.

    Input:

    f is given as input a sequence of Bool (attack = False) of length len(cml), should return string.

    """
    s = ""

    s += "\\begin{%s}{|l|ll||%s|}\n" % (tabletype,hd1)
    s += "\\hline\n"

    s += rotated(["No","Protocol","Claim"]) + " & " + rotated(hd2)
    s += "\\\\\n"
    s += "\\hline\n"
    s += "\\hline\n"

    goodverdict = "$\\circ$"
    badverdict = "$\\bullet$"

    last = None
    counter = 1
    for (prot,role,claim) in sorted(ALLCLAIMS):
        if baseprot(prot) != last:
            last = baseprot(prot)
            s += "\\hline\n"

        # Header
        sl = "%i & %s & %s %s " % (counter,prot,role,prettyclaim(claim))
        alltrue = True
        res = ""
        resl = []
        for cm in cml:
            verdict = badverdict
            if prot in cm.keys():
                if role in cm[prot].keys():
                    if claim in cm[prot][role]:
                        verdict = goodverdict
            if verdict == badverdict:
                alltrue = False
                resl.append(False)
            else:
                resl.append(True)

        sl += "& %s " % (f(resl))
        sl += "\\\\\n"

        if alltrue == True:
            if onlyChanged == True:
                continue

        s += sl
        counter = counter + 1

    s += "\\hline\n"
    s += "\\end{%s}\n" % (tabletype)
    return s

def docWrapper(s,title=None,author=None):

    pref = ""
    pref += "\\documentclass{article}\n"
    pref += "\\usepackage{a4}\n"
    pref += "\\usepackage{geometry}\n"
    pref += "\\usepackage{longtable}\n"
    pref += "\\usepackage{rotating}\n"
    pref += "\\begin{document}\n"
    if title or author:
        if title:
            pref += "\\title{%s}\n" % (title)
        if author:
            pref += "\\author{%s}\n" % (author)
        pref += "\\maketitle\n"
    post = ""
    post += "\\end{document}\n"

    return pref + s + post

def secWrapper(s,title,level=0):
    """
    level : 

    0 section
    1 subsection
    2 subsub...
    """
    pref = "\\" + "sub" * level + "section{" + title + "}\n\n"
    post = "\n"
    return pref + s + post


def sizeWrapper(s, width="!", height="!"):

    if (width != "!") or (height != "!"):
        s = "\\resizebox{%s}{%s}{ \n%s}\n" % (width,height,s)
    return s


def fileWrite(fn,s):

    fp = open("%s.tex" % (fn), "w")
    fp.write(s)
    fp.close()


def docWrite(fn,tex,author=None,title=None):

    fileWrite(fn, docWrapper(tex,author=author,title=title))


def docMake(fn,tex,author=None,title=None):

    import commands

    docWrite(fn,tex,author,title)
    cmd = "pdflatex %s" % (fn)
    commands.getoutput(cmd)

def f1(resl):
    txtl = []
    for t in resl:
        if t == True:
            txtl.append(" ")
        else:
            txtl.append("$\\bullet$")
    return " & ".join(txtl)

def pb(tl,width):
    nl = []
    for t in tl:
        nl.append("\\parbox{%s}{%s}" % (width,t))
    return nl

def makeReport(fn,includefiles=False):
    scanClaimList(fn + "-aa-t")

    cISOaat = scanClaimFile(fn + "-aa-t")
    cISOaab = scanClaimFile(fn + "-aa-b")
    cISOaau = scanClaimFile(fn + "-aa-u")
    cISOiut = scanClaimFile(fn + "-iu-t")
    cISOiub = scanClaimFile(fn + "-iu-b")
    cISOiuu = scanClaimFile(fn + "-iu-u")
    cISOext = scanClaimFile(fn + "-ex-t")
    cISOexb = scanClaimFile(fn + "-ex-b")
    cISOexu = scanClaimFile(fn + "-ex-u")

    tex = ""
    #tex += secWrapper(typeScanMatrix([("typed",cISOaat),("basic",cISOaab),("untyped",cISOaau)],onlyChanged = False),title="Normal mode (Alice-Alice communication allowed)")
    #tex += secWrapper(typeScanMatrix([("typed",cISOiut),("basic",cISOiub),("untyped",cISOiuu)],onlyChanged = True),title="Disallow Alice-Alice initiators")
    #tex += secWrapper(typeScanMatrix([("typed",cISOext),("basic",cISOexb),("untyped",cISOexu)],onlyChanged = True),title="Disallow Alice-Alice communications")

    orders = [cISOaab,
              cISOaat,
              cISOiub,
              cISOiut]

    sectex = typeScanMatrix3("c|c|c|c",pb(["No type checks\\\\Alice-talks-to-Alice initators","Type checks\\\\Alice-talks-to-Alice initators","No type checks\\\\No Alice-talks-to-Alice initators","Type checks\\\\No Alice-talks-to-Alice initators"],"49mm"), orders,f1,onlyChanged = True)

    mpatex = sizeWrapper(mpaTable3([
        (scanAttackFile(fn + "-ex-t"),"$\\bullet$"),
        (scanAttackFile(fn + "-aa-b"),"$\\circ$")
        ]),width="\\textwidth")

    if includefiles == True:
        fileWrite("../gen-att-" + fn,sectex)
        fileWrite("../gen-mpa-" + fn,mpatex)

    tex += secWrapper(sectex,title="Attacks found")
    tex += secWrapper(mpatex,title="MPA attacks")
    docMake(fn,tex,author="Cas Cremers",title="test report %s" % (fn))


def filterPrefix(prot):
    """
    Returns true iff the protocol name is okay to be considered
    """
    if PREFIX:
        if not prot.startswith(PREFIX):
            return False
    return True

def filterPrefixBD(prot):
    """
    Returns true iff the protocol name is okay to be considered
    """
    if PREFIX:
        if not prot.startswith(PREFIX):
            return False
    if prot.endswith("-ud"):
        return False
    if prot.endswith("-udkey"):
        return False
    return True


def filterCombo(prot):
    """
    Returns true iff the protocol name is okay to be considered
    """
    if prot.find("-sig-child") >= 0:
        return False
    
    return True


def filterISOsymmBD(prot):
    """
    Returns true iff the protocol name is okay to be considered
    """
    if prot.endswith("-ud"):
        return False
    if prot.endswith("-udkey"):
        return False

    if prot.startswith("isoiec-9798-2"):
        return True
    if prot.startswith("isoiec-9798-4"):
        return True

    return False



if __name__ == "__main__":
    
    #reset()
    #PREFIX = "isoiec-9798-2"
    #makeReport(PREFIX)

    includefiles = True

    reset()
    FFUNC = filterCombo
    PREFIX = "ike1"
    makeReport(PREFIX,includefiles=includefiles)

    reset()
    FFUNC = filterCombo
    PREFIX = "ike2"
    makeReport(PREFIX,includefiles=includefiles)

    reset()
    FFUNC = filterCombo
    PREFIX = "ike0"
    makeReport(PREFIX,includefiles=includefiles)





