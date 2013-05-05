#!/usr/bin/env python
#
# cpp2macro.py
#
# Author:   Cas Cremers
# Date:     April 2013
#
# Convert a .cpp file for Scyther, that was intended to become a .spdl file,
# into a pure .spdl file using the new 'macro' construct.
#
# This removes in many cases the need for the cpp preprocessor.
#
# Caveats:
#
#   * No fancy cpp features are supported, such as ifdef or undef.
#   * Only the most basic cases have been tested.
#
# Assumptions:
# 1.   '#define' starts at the beginning of the line (possibly whitespace prefix)
# 2.   lines with macros contain nothing else
# 3.   macros are defined on a single line
#
import sys
from optparse import OptionParser

CPPDEF = "#define"

def parseArgs():
    usage = "usage: %s [options] [inputfiles]" % sys.argv[0]
    description = "cpp2macro.py is a program to convert scyther spdl descriptions specified as .cpp files into pure .spdl files."
    parser = OptionParser(usage=usage,description=description)

    # command
    parser.add_option("-R","--replace",dest="replace",default=False,action="store_true",
            help="By default we generate .mspdl files. If this option is specified, we generate .spdl files and overwrite any existing ones.")
    parser.add_option("-G","--git",dest="git",default=False,action="store_true",
            help="Try to propagate changes to git by performing 'git rm X.cpp' and 'git add X.spdl'. Implies '--replace'.")

    return parser.parse_args()

def tempName(ext=""):

    import tempfile
    import os.path

    dir = tempfile.gettempdir()
    if ext != "":
        if not ext.startswith("."):
            ext = "-" + ext

    fn = os.path.join(dir,"scyther-cpp-temp" + ext)
    return fn


def checkConsistent(fn1,fn2):

    import subprocess
    import os

    fnull = open(os.devnull, 'w') 
    out1 = subprocess.check_output(["scyther-linux", "--report-compromise", fn1],stderr=fnull)
    out2 = subprocess.check_output(["scyther-linux", "--report-compromise", fn2],stderr=fnull)
    return (out1 == out2)


def isMacroLine(l):
    global CPPDEF

    dt = l.strip()
    return dt.startswith(CPPDEF)

def getMacroDef(l):
    """
    Return the start of the macro definition, if any
    """
    import string 

    global CPPDEF

    i = l.find(CPPDEF)
    if i < 0:
        return -1

    state = 0   # 0: Looking for white space, 1: Found white space
    j = i + len(CPPDEF)
    sv = True
    while state < 2 and j < len(l):
        v = l[j] in string.whitespace
        if v == sv:
            # State 0: exit state when we find whitespace
            # State 1: exit state when we find non-whitespace
            state += 1
            j += 1
            sv = not sv

    return j

def parseMacro(l):
    """
    Parse a macro

    Return (name, list of args,def,realarg)
    or     (None, [],"","")

    Note: this should have returned a MacroDef object,... bla bla
    """
    global CPPDEF

    dt = l.split()
    if len(dt) < 3:
        return (None,[],"","")

    if dt[0] != CPPDEF:
        return (None,[],"","")

    nameargs = dt[1]
    # len(nameargs) > 0 by construction from split
    if nameargs[-1] != ")":
        # Simple case: no args
        return (nameargs,[]," ".join(dt[2:]),"")

    # We take some arguments
    i = nameargs.find("(")
    assert(i != -1) # Should not happen with correct macro definitions

    name = nameargs[:i]
    sargs = nameargs[i+1:-1]

    return (name,sargs.split(",")," ".join(dt[2:]),sargs)



def findMacros(spdl):
    """
    Given a list of lines, find all macro names and return them.
    Returns (name,args,def,realarg) tuples.
    """

    res = []

    for l in spdl:
        (name,args,mdef,realarg) = parseMacro(l)
        if name != None:
            #print "Detected macro:", name,args,mdef
            res.append((name,args,mdef,realarg))
    return res


def findMacroUse(spdl,macros):
    """
    Find the use of macros with multiple arguments, so we can unfold them in another pass
    """
    #print "Scanning for macro usage."

    # First, determine macros with arguments
    aml = []
    seenargs = {}
    for (mn,ml,md,ra) in macros:
        if len(ml) > 0:
            aml.append((mn,ml))
            seenargs[mn] = []
        else:
            seenargs[mn] = []

    for l in spdl:
        if not isMacroLine(l):
            for (mn,ml) in aml:
                i = 0
                while i >= 0 and i < len(l):
                    i = l.find(mn,i)
                    if i >= 0:
                        # Find args
                        j1 = i + len(mn) + 1
                        assert(j1 < len(l))
                        j2 = l.find(")",j1)
                        assert(j2 >= 0)
                        args = l[j1:j2]
                        if args not in seenargs[mn]:
                            seenargs[mn].append(args)
                        i += 1

    #print seenargs
    return seenargs


def macroInstance(mn,ra):
    """
    Expand a macro name to something sensible
    """
    dt = ra.split(",")
    if len(dt) == 0:
        return mn

    for i in range(0,len(dt)):
        dt[i] = dt[i].strip()

    return mn + "-" + "-".join(dt)


def rewriteOneUsage(l,mn,ml,md,argl):
    """
    Rewrite line wrt one macro usage
    """
    found = False
    i = -1
    while not found:
        i = l.find(mn,i+1)
        if i < 0:
            return (False,l)
        found = True
        if i + len(mn) >= len(l):
            return (False,l)
        if l[i+len(mn)] != "(":
            found = False

    #print mn,l

    # Find args
    j1 = i + len(mn) + 1
    assert(j1 < len(l))
    j2 = l.find(")",j1)
    assert(j2 >= 0)

    if len(argl) < 2:
        # Not used twice, so no renaming
        return (True, l[:j1-1] + l[j2+1:])

    # Rename
    nn = macroInstance(mn,l[j1:j2])
    return (True, l[:i] + nn + l[j2+1:])
    



def rewriteUsage(l,macros,seenargs,context=None):
    """
    Rewrite a line with macros
    """
    for (mn,ml,md,ra) in macros:
        if mn != context:
            if len(ml) > 0:
                flag = True
                while flag == True:
                    (flag,l) = rewriteOneUsage(l,mn,ml,md,seenargs[mn])

    return l


def replaceOcc(l,x,y):
    """
    Replace in l the occurrence of x to y
    """
    import string
    import re

    NAMECH = string.ascii_letters + '-'

    def xrepl(matchobj):
        i = matchobj.start()
        j = matchobj.end()
        if i > 0:
            if l[i-1] in NAMECH:
                return x
        if j < len(l) - 1:
            if l[j] in NAMECH:
                return x
        return y

    rex = re.escape(x)
    return re.sub(rex,xrepl,l)




def replaceArgs(md,mn,ra,anew):
    """
    Replace in md the arguments to mn from ml to mlnew.
    """

    import re

    mpat = mn + '\(\s*' + ra + '\s*\)'
    repl = mn + '(' + anew + ')'

    return re.sub(mpat,repl,md)



def rewriteSPDL(spdl,macros,seenargs):
    """
    Rewrite the spdl file
    """
    res = []
    for l in spdl:
        if isMacroLine(l):
            # Macro
            (mn,ml,md,ra) = parseMacro(l)
            if len(seenargs[mn]) == 0:
                if len(ml) == 0:
                    nl = "macro %s = %s;\n" % (mn,rewriteUsage(md,macros,seenargs,mn))
                else:
                    nl = "// macro %s does not seem to occur.\n" % (mn)
            elif len(seenargs[mn]) == 1:
                newd = replaceOcc(md,ra,seenargs[mn][0])
                nl = "macro %s = %s;\n" % (mn,rewriteUsage(newd,macros,seenargs,mn))
            else:
                # Macro with multiple instantiations of the parameters
                nl = ""
                for ranew in seenargs[mn]:
                    newd = replaceOcc(md,ra,ranew)
                    nl += "macro %s = %s;\n" % (macroInstance(mn,ranew),rewriteUsage(newd,macros,seenargs,mn))

            res.append(nl)
        else:
            # Non-macro
            res.append(rewriteUsage(l,macros,seenargs))
    return res


def checkSameResult(fncpp,fnspdl):

    import subprocess
    import os.path

    result = False
    out = subprocess.check_output(["cpp",fncpp])

    fn = tempName("checksame-"+ os.path.basename(fncpp))
    tf = open(fn,"w")
    tf.write(out)
    tf.close()

    x = checkConsistent(fn,fnspdl)
    if x:
        print "Ok."
        #print "The spdl file %s yields the same result as running cpp on the original file %s." % (fnspdl,fncpp)
        result = True
    else:
        print "Mismatch!"
        print "The spdl file %s does not yield the same result as running cpp on the original file %s." % (fnspdl,fncpp)

    tf.close()
    return result


def convertOne(opts,fn):
    import os.path
    import subprocess

    i = fn.rfind(".")
    if i >= 0:
        fn2 = fn[:i]
    else:
        fn2 = fn
    fn2 = fn2 + ".mspdl"

    trycpp = True

    if trycpp:
        # Use CPP
        out = subprocess.check_output(["cpp","-fdirectives-only",fn])
        spdl = []
        for l in out.splitlines():
            if l.startswith("# 1 "):
                continue
            if l.startswith("#define _"):
                continue
            if l.startswith("#define ") and l.endswith(" 1"):
                continue
            spdl.append(l + "\n")

        out = "".join(spdl)
        #print out

        fn1 = tempName(os.path.basename(fn))
        fp = open(fn1,'w')
        fp.write(out)
        fp.close()
    else:
        # Not using CPP
        fn1 = fn
        spdl = []
        fp = open(fn1,'r')
        for l in fp.xreadlines():
            spdl.append(l)
        fp.close()

    macros = findMacros(spdl)
    seenargs = findMacroUse(spdl,macros)
    spdl = rewriteSPDL(spdl,macros,seenargs)

    fp = open(fn2,"w")
    for l in spdl:
        fp.write(l)
    fp.close()

    result = False
    try:
        result = checkSameResult(fn1,fn2)
    except:
        print "Failed at comparing", fn1, "to", fn2
        pass

    fp.close()

    if result and opts.replace:
        # Move fn2 to the .spdl file.
        oldext = ".mspdl"
        newext = ".spdl"
        if fn2.endswith(oldext):
            dest = fn2[:-len(oldext)] + newext
            subprocess.check_call(["mv",fn2,dest])

            if opts.git:
                # Propagate to git
                subprocess.check_call(["git","rm",fn])
                subprocess.check_call(["git","add",dest])

    return result


def main():

    # Parse arguments
    (opts,args) = parseArgs()

    # Git switch implies replace
    if opts.git:
        opts.replace = True

    good = []
    bad = []
    for fn in args:
        res = False
        try:
            res = convertOne(opts,fn)
        except:
            res = False
            pass

        if res:
            good.append(fn)
        else:
            bad.append(fn)

    if opts.replace:
        action = "replacement"
    else:
        action = "conversion"

    print "Successful %s: %s" % (action, good)
    if len(bad) > 0:
        print "Failed %s: %s" % (action, bad)



if __name__ == '__main__':
    main()

