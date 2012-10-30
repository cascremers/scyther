"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2012 Cas Cremers

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

#
# EString
# printf-like strings with terms, with possible pre-processing of terms EStrings when converting to a string
#
# Signature of pre-processors: Term union ... -> ... (Maybe also EString later)
#

import Term

def EStringDebugMarkers(t):
    return EString("<" + str(t) + ">")

ESINS = "%s"
#PROCESS = [EStringDebugMarkers]
PROCESS = []

def PushEStringProcess(f):
    global PROCESS

    PROCESS += [f]
    return PROCESS

def PopEStringProcess():
    global PROCESS

    assert(len(PROCESS) > 0)
    PROCESS = PROCESS[:-1]

class EString(object):
    """
    Extended string
    """
    global ESINS

    def __init__(self,string="",termlist=[]):
        # Detect shorthand where termlist length is one and string is empty
        if (string == "") and (len(termlist) > 0):
            string = "%s" * len(termlist)
        if len(termlist) == 0:
            # Detect shorthand where string is already an EString and termlist is empty
            if isinstance(string,EString):
                es = string
                string = es.string
                termlist = es.termlist
            # Detect shorthand where termlist is omitted and first parameter is a term instance
            if isinstance(string,Term.Term):
                termlist = [string]
                string = "%s"

        self.string = string
        self.termlist = termlist

        # Sanity check
        self.check()

        # If some things in the termlist are EStrings themselves, 
        # we should normalize.
        self.normalize()

    def check(self):
        # Sanity check
        n = self.string.count(ESINS)
        if n != len(self.termlist):
            print "Error: EString does not have the correct number of insertion markers wrt termlist length."
            print self.string
            print self.termlist
            assert(False)

    def findEsIns(self,n):
        # Find (n+1)-th occurrence from index i onwards, or None
        # Numbering corresponds to termlist index
        i = 0
        while (i < len(self.string)):
            if self.string[i:].startswith(ESINS):
                if (n == 0):
                    return i
                n -= 1
                i += len(ESINS)
            else:
                i += 1
        return None

    def replace(self,n,news,newtl):
        # Replace the n'th (0...) occurrence of the marker by 'news' and the corresponding term by the termlist 'newtl'
        i = self.findEsIns(n)
        assert(i != None)
        lefts = self.string[:i]
        leftt = self.termlist[:n]
        rights = self.string[(i+len(ESINS)):]
        rightt = self.termlist[(n+1):]
        self.string = lefts + news + rights
        self.termlist = leftt + newtl + rightt
        
    def rewriteterms(self,f):
        # Rewrite any terms, return result
        dest = EString()
        dest.string = self.string
        dest.termlist = [f(t) for t in self.termlist]
        return dest

    def normalize(self):
        # Unfold recursive EStrings recursively
        # I.e. find first EString in termlist, replace, iterate
        for n in range(0,len(self.termlist)):
            t = self.termlist[n]
            if isinstance(t,EString):
                # Found one: replace
                #print "Detected EString '%s' in '%s'" % (t,self)
                #print self.string
                #print self.termlist
                self.replace(n,t.string,t.termlist)
                # Iterate
                self.normalize()
                return
            elif isinstance(t,basestring):
                # Found one: replace
                #print "Detected basestring '%s' in '%s'" % (t,self)
                #print self.string
                #print self.termlist
                self.replace(n,str(t),[])
                # Iterate
                self.normalize()
                return
        return

    def __str__(self):
        global PROCESS

        i = 0
        j = 0
        res = ""
        while i < len(self.string):
            if self.string[i:].startswith(ESINS):
                # Replace and skip
                if j >= len(self.termlist):
                    assert(False,"Too many parameter-marker occurrences in EString or too few term arguments.")
                t = self.termlist[j]
                for f in PROCESS:
                    t = f(t)
                res += str(t)
                j += 1
                i += len(ESINS)
            else:
                res += self.string[i]
                i += 1
        return res

    def __add__(self,other):
        if isinstance(other,basestring):
            return EString(self.string + str(other), self.termlist)
        else:
            return EString(self.string + other.string, self.termlist + other.termlist)

    def joinlist(self,eslist,sep=""):
        for es in eslist:
            if len(str(self)) > 0:
                self.string += sep
            self += es
        return self

    def __len__(self):
        return len(str(self))

    def terms(self):
        return self.termlist



#---------------------------------------------------------------------------

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
