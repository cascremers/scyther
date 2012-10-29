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
# Dot-like graphs, but using printf-like EStrings with terms
#

import Term
from sets import Set
from Misc import *
from EString import *
from Abbreviations import AbbrevContext
import copy

def seqstr(seq,postfix="\n",prefix="",debug=False,comment=None):
    res = ""
    i = 1
    if (comment != None) and (len(seq) > 0):
        res += "%s%s" % (prefix,comment)
    if debug:
        res += "%s/* Start of sequence: %i elements */\n" % (prefix,len(seq))
    for x in seq:
        if debug:
            if "\n" in postfix:
                res += "%s/* Element %i of %i: %s */\n" % (prefix,i,len(S),x)
                i += 1
        res += "%s%s%s" % (prefix,x,postfix)
    if debug:
        res += "%s/* End of sequence */\n" % (prefix)
    return res

def seqterms(seq):
    l = []
    for x in seq:
        if not isinstance(x,basestring):
            l += x.terms()
    return l

class Dot(object):

    def __init__(self,graphs=[]):

        self.graphs = graphs

    def __str__(self):
        for g in self.graphs:
            return str(g)

class Graph(object):
    """
    Clustering based on node attribute "cluster"
    """

    def __init__(self,name="Unknown"):

        self.edges = []
        self.nodes = []
        self.clusters = []
        self.attr = []
        self.name = name
        self.lines = []
        self.abbreviations = {}
        self.mapper = {}

    def abbrevTerms(abbrev):
        print abbrev
        #self.abbreviations = abbrev
        return self.terms()

    def ComputeAbbreviations(self):
        """
        Compute abbreviations

        Stores the result in self.abbreviations
        Returns (edges,cluster) to display
        """

        AC = AbbrevContext()
        self.abbreviations = AC.abbreviateAll(self.terms())

        comments = EString()
        if len(self.abbreviations.keys()) > 0:
            comments += "Abbreviations:\n"
        for k in sorted(self.abbreviations.keys()):
            comments += EString("%s = %s\n" , [k, self.abbreviations[k]])

        # Legend
        ## If it exists...
        if len(comments) > 0:
            legendname = "comments"
            edges = []
            ## Ensure bottom
            for c in self.clusters:
                if len(c.nodes) > 0:
                    prev = c.nodes[-1].name
                    edges.append(Edge(prev,legendname,[Attribute("style","invis")]))

            ## Explain
            CL = Cluster("Cluster_comments")
            cattr = []
            cattr.append(Attribute("rank","sink"))
            cattr.append(Attribute("style","invis"))
            CL.attr = cattr

            attr = [ Attribute("shape","box") ]
            
            cms = EString(comments)
            cms.string = cms.string.replace("\n","\\l")
            attr.append(Attribute("label",cms))

            ce = Node(legendname)
            ce.attr = copy.copy(attr)
            CL.nodes = [ce]
        else:
            CL = None

        return (edges,CL)


        # For debugging
        #res = ""
        #for t in ss:
        #    res += "%s; " % str(t)
        #res += "\n"
        #self.comments += res

    def ComputeMapper(self):
        """
        Maybe this should be in Abbreviations.py
        """
        self.mapper = {}
        for k in self.abbreviations.keys():
            dest = self.abbreviations[k]
            mk = str(dest)
            assert (not mk in self.mapper.keys())
            self.mapper[mk] = Term.TermConstant(k)


    def __str__(self,abbreviate=True):

        if abbreviate:
            (CLedges,CL) = self.ComputeAbbreviations()
        else:
            CL = None
            CLedges = []
        
        self.ComputeMapper()
        PushEStringProcess((lambda t: t.replace(self.mapper)))

        res = "digraph %s {\n" % (self.name)
        # Attributes
    
        # Edges, nodes, clusters
        res += seqstr(self.lines,postfix=";\n")
        res += seqstr(self.attr,postfix=";\n")
        res += seqstr(self.clusters)
        res += seqstr(self.nodes)
        res += seqstr(self.edges)

        res += seqstr(CLedges)

        # Done with mapping
        PopEStringProcess()

        # Comments are *not* mapped
        if CL != None:
            res += str(CL)

        res += "}\n"

        #print "All terms in graph:"
        #print [str(t) for t in self.terms()]

        return res

    def terms(self):
        l = seqterms(self.attr)
        l += seqterms(self.lines)
        l += seqterms(self.clusters)
        l += seqterms(self.nodes)
        l += seqterms(self.edges)
        return l

class Attribute(object):
    """
    Attribute with extended string
    """
    def __init__(self,name,estring):
        self.name = name
        self.text = estring

    def __str__(self):
        res = "%s=\"%s\"" % (self.name,self.text)
        return res

    def terms(self):
        if isinstance(self.text,EString):
            return self.text.terms()
        elif isinstance(self.text,Term.Term):
            return [self.text]
        else:
            return []

class Cluster(object):
    """
    A cluster contains a bunch of nodes
    """

    def __init__(self,name):
        self.name = name
        self.nodes = []
        self.edges = []
        self.attr = []
        self.display = True
        self.lines = []

    def __str__(self):

        res = ""
        res += "/* Start of cluster '%s' */\n" % (self.name)
        if self.display:
            res += "subgraph %s {\n" % (self.name)
            comment = "/* Cluster attributes */\n"
            res += seqstr(self.attr,prefix="\t",postfix=";\n",comment=comment)
        else:
            res += "\t/* Not displaying this cluster, hence skipping attributes */\n"

        comment = "/* Cluster misc. lines */\n"
        res += seqstr(self.lines,prefix="\t",postfix=";\n",comment=comment)
        comment = "/* Cluster nodes */\n"
        res += seqstr(self.nodes,prefix="\t",comment=comment)
        comment = "/* Cluster edges */\n"
        res += seqstr(self.edges,prefix="\t",comment=comment)

        if self.display:
            res += "}\n"
        #res += "/* End of cluster '%s' */\n" % (self.name)
        return res
        
    def terms(self):
        l = seqterms(self.attr)
        l += seqterms(self.lines)
        l += seqterms(self.nodes)
        l += seqterms(self.edges)
        return l

class Node(object):
    """
    A node
    """
    def __init__(self,name,attrlist=[]):
        self.name = name
        self.attr = attrlist

    def __str__(self):
        res = ""
        if len(self.attr) == 0:
            res = str(self.name)
        else:
            l = []
            for x in self.attr:
                l.append(str(x))
            res = "%s [%s]" % (self.name,",".join(l))
        res += ";"
        return res

    def terms(self):
        return seqterms(self.attr)

class Edge(object):
    """
    An edge
    """
    def __init__(self,name,target,attrlist=[]):
        self.name = name
        self.target = target
        self.attr = attrlist

    def __str__(self):
        res = "%s -> %s" % (self.name, self.target)
        if len(self.attr) > 0:
            l = []
            for x in self.attr:
                l.append(str(x))
            res += " [%s]" % (",".join(l))
        res += ";"
        return res

    def terms(self):
        return seqterms(self.attr)


    


#---------------------------------------------------------------------------

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
