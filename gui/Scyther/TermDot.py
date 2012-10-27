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
# Dot-like graphs, but using printf-like strings with terms
#

import Term
from sets import Set
from Misc import *

def seqstr(seq,postfix="\n",debug=False):
    res = ""
    i = 1
    for x in seq:
        if debug:
            if "\n" in postfix:
                res += "// Element %i of %i: %s\n" % (i,len(S),x)
                i += 1
        res += "%s%s" % (x,postfix)
    return res

class Dot(object):

    def __init__(self,graphs):

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

    def __str__(self):

        res = "digraph %s {\n" % (self.name)
        # Attributes
    
        # Edges, nodes, clusters
        res += seqstr(self.attr)
        res += seqstr(self.lines)
        res += seqstr(self.clusters)
        res += seqstr(self.nodes)
        res += seqstr(self.edges)

        res += "}\n"
        return res

class EString(object):
    """
    Extended string
    """
    def __init__(self,string,termlist=[]):
        self.string = string
        self.termlist = termlist

    def __str__(self):
        i = 0
        j = 0
        res = ""
        macro = "%%"
        while i < len(self.string):
            if self.string[i:].startswith(macro):
                # Replace and skip
                if j >= len(self.termlist):
                    assert(False,"Too many macro occurrences in EString or too few term arguments.")
                res += "<<%s>>" % (self.termlist[j])
                j += 1
                i += len(macro)
            else:
                res += self.string[i]
                i += 1
        return res

    def __add__(self,other):
        return Estring(self.string + other.string, self.termlist + other.termlist)


class Attribute(object):
    """
    Attribute with extended string
    """
    def __init__(self,name,estring):
        self.name = name
        self.text = estring

    def __str__(self):
        return "%s=\"%s\"" % (self.name,self.text)


class Cluster(object):
    """
    A cluster contains a bunch of nodes
    """

    def __init__(self,name,nodes=[],edges=[],attrlist=[],display=True):
        self.name = name
        self.nodes = nodes
        self.edges = edges
        self.attr = attrlist
        self.display = display
        self.lines = []

    def __str__(self):

        res = ""
        res += "// Start of cluster '%s'\n" % (self.name)
        if self.display:
            res += "subgraph %s {\n" % (self.name)
            res += "// Cluster attributes\n"
            res += seqstr(self.attr)
        else:
            res += "// Not displaying cluster, hence skipping attributes\n"

        res += "// Cluster nodes\n"
        res += seqstr(self.nodes)
        res += "// Cluster edges\n"
        res += seqstr(self.edges)
        res += "// Cluster misc. lines\n"
        res += seqstr(self.lines)

        if self.display:
            res += "}\n"
        res += "// End of cluster '%s'\n" % (self.name)
        return res
        

class Node(object):
    """
    A node
    """
    def __init__(self,name,attrlist=[]):
        self.name = name
        self.attr = attrlist

    def __str__(self):
        if len(self.attr) == 0:
            return str(self.name)
        else:
            l = []
            for x in self.attr:
                l.append(str(x))
            return "%s [%s]" % (self.name,",".join(l))

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
        return res

    


#---------------------------------------------------------------------------

# vim: set ts=4 sw=4 et list lcs=tab\:>-:
