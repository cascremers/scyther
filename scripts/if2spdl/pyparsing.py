# module pyparsing.py
#
# Copyright (c) 2003,2004,2005  Paul T. McGuire
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#  Todo:
#  - add pprint() - pretty-print output of defined BNF
#


__doc__ = \
"""
pyparsing module - Classes and methods to define and execute parsing grammars

The pyparsing module is an alternative approach to creating and executing simple grammars, 
vs. the traditional lex/yacc approach, or the use of regular expressions.  With pyparsing, you
don't need to learn a new syntax for defining grammars or matching expressions - the parsing module 
provides a library of classes that you use to construct the grammar directly in Python.

Here is a program to parse "Hello, World!" (or any greeting of the form "<salutation>, <addressee>!")::

    from pyparsing import Word, alphas
    
    # define grammar of a greeting
    greet = Word( alphas ) + "," + Word( alphas ) + "!" 
    
    hello = "Hello, World!"
    print hello, "->", greet.parseString( hello )

The program outputs the following::

    Hello, World! -> ['Hello', ',', 'World', '!']

The Python representation of the grammar is quite readable, owing to the self-explanatory 
class names, and the use of '+', '|' and '^' operators.

The parsed results returned from parseString() can be accessed as a nested list, a dictionary, or an 
object with named attributes.

The pyparsing module handles some of the problems that are typically vexing when writing text parsers:
 - extra or missing whitespace (the above program will also handle "Hello,World!", "Hello  ,  World  !", etc.)
 - quoted strings
 - embedded comments
"""
__version__ = "1.3.3"
__versionTime__ = "12 September 2005 22:50"
__author__ = "Paul McGuire <ptmcg@users.sourceforge.net>"

import string
import copy,sys
import warnings
#~ sys.stderr.write( "testing pyparsing module, version %s, %s\n" % (__version__,__versionTime__ ) )

def _ustr(obj):
    """Drop-in replacement for str(obj) that tries to be Unicode friendly. It first tries
       str(obj). If that fails with a UnicodeEncodeError, then it tries unicode(obj). It
       then < returns the unicode object | encodes it with the default encoding | ... >.
    """
    try:
        # If this works, then _ustr(obj) has the same behaviour as str(obj), so
        # it won't break any existing code.
        return str(obj)
        
    except UnicodeEncodeError as e:
        # The Python docs (http://docs.python.org/ref/customization.html#l2h-182)
        # state that "The return value must be a string object". However, does a
        # unicode object (being a subclass of basestring) count as a "string
        # object"?
        # If so, then return a unicode object:
        return str(obj)
        # Else encode it... but how? There are many choices... :)
        # Replace unprintables with escape codes?
        #return unicode(obj).encode(sys.getdefaultencoding(), 'backslashreplace_errors')
        # Replace unprintables with question marks?
        #return unicode(obj).encode(sys.getdefaultencoding(), 'replace')
        # ...

def _str2dict(strg):
    return dict( [(c,0) for c in strg] )

alphas     = string.lowercase + string.uppercase
nums       = string.digits
hexnums    = nums + "ABCDEFabcdef"
alphanums  = alphas + nums    

class ParseBaseException(Exception):
    """base exception class for all parsing runtime exceptions"""
    __slots__ = ( "loc","msg","pstr","parserElement" )
    # Performance tuning: we construct a *lot* of these, so keep this
    # constructor as small and fast as possible        
    def __init__( self, pstr, loc, msg, elem=None ):
        self.loc = loc
        self.msg = msg
        self.pstr = pstr
        self.parserElement = elem

    def __getattr__( self, aname ):
        """supported attributes by name are:
            - lineno - returns the line number of the exception text
            - col - returns the column number of the exception text
            - line - returns the line containing the exception text
        """
        if( aname == "lineno" ):
            return lineno( self.loc, self.pstr )
        elif( aname in ("col", "column") ):
            return col( self.loc, self.pstr )
        elif( aname == "line" ):
            return line( self.loc, self.pstr )
        else:
            raise AttributeError(aname)

    def __str__( self ):
        return "%s (at char %d), (line:%d, col:%d)" % ( self.msg, self.loc, self.lineno, self.column )
    def __repr__( self ):
        return _ustr(self)
    def markInputline( self, markerString = ">!<" ):
        """Extracts the exception line from the input string, and marks 
           the location of the exception with a special symbol.
        """
        line_str = self.line
        line_column = self.column - 1
        if markerString:
            line_str = "".join( [line_str[:line_column], markerString, line_str[line_column:]])
        return line_str.strip()

class ParseException(ParseBaseException):
    """exception thrown when parse expressions don't match class"""
    """supported attributes by name are:
        - lineno - returns the line number of the exception text
        - col - returns the column number of the exception text
        - line - returns the line containing the exception text
    """
    pass
    
class ParseFatalException(ParseBaseException):
    """user-throwable exception thrown when inconsistent parse content
       is found; stops all parsing immediately"""
    pass
    
class RecursiveGrammarException(Exception):
    """exception thrown by validate() if the grammar could be improperly recursive"""
    def __init__( self, parseElementList ):
        self.parseElementTrace = parseElementList
    
    def __str__( self ):
        return "RecursiveGrammarException: %s" % self.parseElementTrace

class ParseResults(object):
    """Structured parse results, to provide multiple means of access to the parsed data:
       - as a list (len(results))
       - by list index (results[0], results[1], etc.)
       - by attribute (results.<resultsName>)
       """
    __slots__ = ( "__toklist", "__tokdict", "__doinit", "__name", "__parent", "__modal" )
    def __new__(cls, toklist, name=None, asList=True, modal=True ):
        if isinstance(toklist, cls):
            return toklist
        retobj = object.__new__(cls)
        retobj.__doinit = True
        return retobj
        
    # Performance tuning: we construct a *lot* of these, so keep this
    # constructor as small and fast as possible
    def __init__( self, toklist, name=None, asList=True, modal=True ):
        if self.__doinit:
            self.__doinit = False
            self.__name = None
            self.__parent = None
            self.__modal = modal
            if isinstance(toklist, list):
                self.__toklist = toklist[:]
            else:
                self.__toklist = [toklist]
            self.__tokdict = dict()

        if name:
            if not self.__name:
                self.__modal = self.__modal and modal
            if isinstance(name,int):
                name = _ustr(name) # will always return a str, but use _ustr for consistency
            self.__name = name
            if toklist:
                if isinstance(toklist,str):
                    toklist = [ toklist ]
                if asList:
                    if isinstance(toklist,ParseResults):
                        self[name] = (toklist.copy(),-1)
                    else:
                        self[name] = (ParseResults(toklist[0]),-1)
                    self[name].__name = name
                else:
                    try:
                        self[name] = toklist[0]
                    except TypeError:
                        self[name] = toklist

    def __getitem__( self, i ):
        if isinstance( i, (int,slice) ):
            return self.__toklist[i]
        else:
            if self.__modal:
                return self.__tokdict[i][-1][0]
            else:
                return ParseResults([ v[0] for v in self.__tokdict[i] ])

    def __setitem__( self, k, v ):
        if isinstance(v,tuple):
            self.__tokdict[k] = self.__tokdict.get(k,list()) + [v]
            sub = v[0]
        else:
            self.__tokdict[k] = self.__tokdict.get(k,list()) + [(v,0)]
            sub = v
        if isinstance(sub,ParseResults):
            sub.__parent = self
        
    def __delitem__( self, i ):
        del self.__toklist[i]

    def __contains__( self, k ):
        return k in self.__tokdict
        
    def __len__( self ): return len( self.__toklist )
    def __iter__( self ): return iter( self.__toklist )
    def keys( self ): 
        """Returns all named result keys."""
        return list(self.__tokdict.keys())
    
    def items( self ): 
        """Returns all named result keys and values as a list of tuples."""
        return [(k,v[-1][0]) for k,v in list(self.__tokdict.items())]
    
    def values( self ): 
        """Returns all named result values."""
        return [ v[-1][0] for v in list(self.__tokdict.values()) ]

    def __getattr__( self, name ):
        if name not in self.__slots__:
            if name in self.__tokdict:
                if self.__modal:
                    return self.__tokdict[name][-1][0]
                else:
                    return ParseResults([ v[0] for v in self.__tokdict[name] ])
            else:
                return ""
        return None

    def __iadd__( self, other ):
        if other.__tokdict:
            offset = len(self.__toklist)
            addoffset = ( lambda a: (a<0 and offset) or (a+offset) )
            otherdictitems = [(k,(v[0],addoffset(v[1])) ) for (k,vlist) in list(other.__tokdict.items()) for v in vlist]
            for k,v in otherdictitems:
                self[k] = v
                if isinstance(v[0],ParseResults):
                    v[0].__parent = self
        self.__toklist += other.__toklist
        del other
        return self
       
    def __repr__( self ):
        return "(%s, %s)" % ( repr( self.__toklist ), repr( self.__tokdict ) )

    def __str__( self ):
        out = "["
        sep = ""
        for i in self.__toklist:
            if isinstance(i, ParseResults):
                out += sep + _ustr(i)
            else:
                out += sep + repr(i)
            sep = ", "
        out += "]"
        return out

    def _asStringList( self, sep='' ):
        out = []
        for item in self.__toklist:
            if out and sep:
                out.append(sep)
            if isinstance( item, ParseResults ):
                out += item._asStringList()
            else:
                out.append( _ustr(item) )
        return out

    def asList( self ):
        """Returns the parse results as a nested list of matching tokens, all converted to strings."""
        out = []
        for res in self.__toklist:
            if isinstance(res,ParseResults):
                out.append( res.asList() )
            else:
                out.append( res )
        return out

    def asDict( self ):
        """Returns the named parse results as dictionary."""
        return dict( list(self.items()) )

    def copy( self ):
        """Returns a new copy of a ParseResults object."""
        ret = ParseResults( self.__toklist )
        ret.__tokdict = self.__tokdict.copy()
        ret.__parent = self.__parent
        ret.__modal = self.__modal
        ret.__name = self.__name
        return ret
        
    def asXML( self, doctag=None, namedItemsOnly=False, indent="", formatted=True ):
        """Returns the parse results as XML. Tags are created for tokens and lists that have defined results names."""
        nl = "\n"
        out = []
        namedItems = dict( [ (v[1],k) for (k,vlist) in list(self.__tokdict.items()) for v in vlist ] )
        nextLevelIndent = indent + "  "
        
        # collapse out indents if formatting is not desired
        if not formatted:
            indent = ""
            nextLevelIndent = ""
            nl = ""
            
        selfTag = None
        if doctag is not None:
            selfTag = doctag
        else:
            if self.__name:
                selfTag = self.__name
        
        if not selfTag:
            if namedItemsOnly:
                return ""
            else:
                selfTag = "ITEM"
                
        out += [ nl, indent, "<", selfTag, ">" ]
        
        worklist = self.__toklist
        for i,res in enumerate(worklist):
            if isinstance(res,ParseResults):
                if i in namedItems:
                    out += [ res.asXML(namedItems[i], namedItemsOnly and doctag is None, nextLevelIndent,formatted)]
                else:
                    out += [ res.asXML(None, namedItemsOnly and doctag is None, nextLevelIndent,formatted)]
            else:
                # individual token, see if there is a name for it
                resTag = None
                if i in namedItems:
                    resTag = namedItems[i]
                if not resTag:
                    if namedItemsOnly:
                        continue
                    else:
                        resTag = "ITEM"
                out += [ nl, nextLevelIndent, "<", resTag, ">", _ustr(res), "</", resTag, ">" ]
        
        out += [ nl, indent, "</", selfTag, ">" ]
        return "".join(out)


    def __lookup(self,sub):
        for k,vlist in list(self.__tokdict.items()):
            for v,loc in vlist:
                if sub is v:
                    return k
        return None
            
    def getName(self):
        """Returns the results name for this token expression."""
        if self.__name:
            return self.__name
        elif self.__parent:
            par = self.__parent
            if par:
                return par.__lookup(self)
            else:
                return None
        elif (len(self) == 1 and 
               len(self.__tokdict) == 1 and
               list(self.__tokdict.values())[0][0][1] in (0,-1)):
            return list(self.__tokdict.keys())[0]
        else:
            return None

def col (loc,strg):
    """Returns current column within a string, counting newlines as line separators
   The first column is number 1.
   """
    return loc - strg.rfind("\n", 0, loc)

def lineno(loc,strg):
    """Returns current line number within a string, counting newlines as line separators
   The first line is number 1.
   """
    return strg.count("\n",0,loc) + 1

def line( loc, strg ):
    """Returns the line of text containing loc within a string, counting newlines as line separators
       The first line is number 1.
       """
    lastCR = strg.rfind("\n", 0, loc)
    nextCR = strg.find("\n", loc)
    if nextCR > 0:
        return strg[lastCR+1:nextCR]
    else:
        return strg[lastCR+1:]

def _defaultStartDebugAction( instring, loc, expr ):
    print("Match",expr,"at loc",loc,"(%d,%d)" % ( lineno(loc,instring), col(loc,instring) ))

def _defaultSuccessDebugAction( instring, startloc, endloc, expr, toks ):
    print("Matched",expr,"->",toks.asList())
    
def _defaultExceptionDebugAction( instring, loc, expr, exc ):
    print("Exception raised:", exc)

def nullDebugAction(*args):
    """'Do-nothing' debug action, to suppress debugging output during parsing."""
    pass

class ParserElement(object):
    """Abstract base level parser element class."""
    DEFAULT_WHITE_CHARS = " \n\t\r"

    def setDefaultWhitespaceChars( chars ):
        """Overrides the default whitespace chars
        """
        ParserElement.DEFAULT_WHITE_CHARS = chars
    setDefaultWhitespaceChars = staticmethod(setDefaultWhitespaceChars)
    
    def __init__( self, savelist=False ):
        self.parseAction = None
        #~ self.name = "<unknown>"  # don't define self.name, let subclasses try/except upcall
        self.strRepr = None
        self.resultsName = None
        self.saveAsList = savelist
        self.skipWhitespace = True
        self.whiteChars = ParserElement.DEFAULT_WHITE_CHARS
        self.mayReturnEmpty = False
        self.keepTabs = False
        self.ignoreExprs = []
        self.debug = False
        self.streamlined = False
        self.mayIndexError = True
        self.errmsg = ""
        self.modalResults = True
        self.debugActions = ( None, None, None )

    def copy( self ):
        """Make a copy of this ParseElement.  Useful for defining different parse actions
           for the same parsing pattern, using copies of the original parse element."""
        cpy = copy.copy( self )
        cpy.whiteChars = ParserElement.DEFAULT_WHITE_CHARS
        return cpy

    def setName( self, name ):
        """Define name for this expression, for use in debugging."""
        self.name = name
        self.errmsg = "Expected " + self.name
        return self

    def setResultsName( self, name, listAllMatches=False ):
        """Define name for referencing matching tokens as a nested attribute 
           of the returned parse results.
           NOTE: this returns a *copy* of the original ParseElement object;
           this is so that the client can define a basic element, such as an
           integer, and reference it in multiple places with different names.
        """
        newself = self.copy()
        newself.resultsName = name
        newself.modalResults = not listAllMatches
        return newself

    def setParseAction( self, fn ):
        """Define action to perform when successfully matching parse element definition.
           Parse action fn is a callable method with the arguments (s, loc, toks) where:
            - s   = the original string being parsed
            - loc = the location of the matching substring
            - toks = a list of the matched tokens, packaged as a ParseResults object
           If the function fn modifies the tokens, it can return them as the return
           value from fn, and the modified list of tokens will replace the original.
           Otherwise, fn does not need to return any value.
        """
        self.parseAction = fn
        return self

    def skipIgnorables( self, instring, loc ):
        exprsFound = True
        while exprsFound:
            exprsFound = False
            for e in self.ignoreExprs:
                try:
                    while 1:
                        loc,dummy = e.parse( instring, loc )
                        exprsFound = True
                except ParseException:
                    pass
        return loc

    def preParse( self, instring, loc ):
        if self.ignoreExprs:
            loc = self.skipIgnorables( instring, loc )
        
        if self.skipWhitespace:
            wt = self.whiteChars
            instrlen = len(instring)
            while loc < instrlen and instring[loc] in wt:
                loc += 1
                
        return loc

    def parseImpl( self, instring, loc, doActions=True ):
        return loc, []

    def postParse( self, instring, loc, tokenlist ):
        return tokenlist

    #~ @profile
    def parse( self, instring, loc, doActions=True, callPreParse=True ):
        debugging = ( self.debug ) #and doActions )

        if debugging:
            #~ print "Match",self,"at loc",loc,"(%d,%d)" % ( lineno(loc,instring), col(loc,instring) )
            if (self.debugActions[0] ):
                self.debugActions[0]( instring, loc, self )
            if callPreParse:
                loc = self.preParse( instring, loc )
            tokensStart = loc
            try:
                try:
                    loc,tokens = self.parseImpl( instring, loc, doActions )
                except IndexError:
                    raise ParseException( instring, len(instring), self.errmsg, self)
            except ParseException as err:
                #~ print "Exception raised:", err
                if (self.debugActions[2] ):
                    self.debugActions[2]( instring, tokensStart, self, err )
                raise
        else:
            if callPreParse:
                loc = self.preParse( instring, loc )
            tokensStart = loc
            if self.mayIndexError or loc >= len(instring):
                try:
                    loc,tokens = self.parseImpl( instring, loc, doActions )
                except IndexError:
                    raise ParseException( instring, len(instring), self.errmsg, self)
            else:
                loc,tokens = self.parseImpl( instring, loc, doActions )
        
        tokens = self.postParse( instring, loc, tokens )

        retTokens = ParseResults( tokens, self.resultsName, asList=self.saveAsList, modal=self.modalResults )
        if self.parseAction and doActions:
            if debugging:
                try:
                    tokens = self.parseAction( instring, tokensStart, retTokens )
                    if tokens is not None:
                        if isinstance(tokens,tuple):
                            tokens = tokens[1]
                        retTokens = ParseResults( tokens, 
                                                  self.resultsName, 
                                                  asList=self.saveAsList and isinstance(tokens,(ParseResults,list)), 
                                                  modal=self.modalResults )
                except ParseException as err:
                    #~ print "Exception raised in user parse action:", err
                    if (self.debugActions[2] ):
                        self.debugActions[2]( instring, tokensStart, self, err )
                    raise
            else:
                tokens = self.parseAction( instring, tokensStart, retTokens )
                if tokens is not None:
                    if isinstance(tokens,tuple):
                        tokens = tokens[1]
                    retTokens = ParseResults( tokens, 
                                              self.resultsName, 
                                              asList=self.saveAsList and isinstance(tokens,(ParseResults,list)), 
                                              modal=self.modalResults )

        if debugging:
            #~ print "Matched",self,"->",retTokens.asList()
            if (self.debugActions[1] ):
                self.debugActions[1]( instring, tokensStart, loc, self, retTokens )

        return loc, retTokens

    def tryParse( self, instring, loc ):
        return self.parse( instring, loc, doActions=False )[0]

    def parseString( self, instring ):
        """Execute the parse expression with the given string.
           This is the main interface to the client code, once the complete 
           expression has been built.
        """
        if not self.streamlined:
            self.streamline()
            self.saveAsList = True
        for e in self.ignoreExprs:
            e.streamline()
        if self.keepTabs:
            loc, tokens = self.parse( instring, 0 )
        else:
            loc, tokens = self.parse( instring.expandtabs(), 0 )
        return tokens

    def scanString( self, instring ):
        """Scan the input string for expression matches.  Each match will return the matching tokens, start location, and end location."""
        if not self.streamlined:
            self.streamline()
        for e in self.ignoreExprs:
            e.streamline()
        
        if not self.keepTabs:
            instring = instring.expandtabs()
        instrlen = len(instring)
        loc = 0
        preparseFn = self.preParse
        parseFn = self.parse
        while loc < instrlen:
            try:
                loc = preparseFn( instring, loc )
                nextLoc,tokens = parseFn( instring, loc, callPreParse=False )
            except ParseException:
                loc += 1
            else:
                yield tokens, loc, nextLoc
                loc = nextLoc
        
    def transformString( self, instring ):
        """Extension to scanString, to modify matching text with modified tokens that may
           be returned from a parse action.  To use transformString, define a grammar and 
           attach a parse action to it that modifies the returned token list.  
           Invoking transformString() on a target string will then scan for matches, 
           and replace the matched text patterns according to the logic in the parse 
           action.  transformString() returns the resulting transformed string."""
        out = []
        lastE = 0
        # force preservation of <TAB>s, to minimize unwanted transformation of string, and to
        # keep string locs straight between transformString and scanString
        self.keepTabs = True
        for t,s,e in self.scanString( instring ):
            out.append( instring[lastE:s] )
            if t:
                if isinstance(t,ParseResults):
                    out += t.asList()
                elif isinstance(t,list):
                    out += t
                else:
                    out.append(t)
            lastE = e
        out.append(instring[lastE:])
        return "".join(out)

    def __add__(self, other ):
        """Implementation of + operator - returns And"""
        if isinstance( other, str ):
            other = Literal( other )
        return And( [ self, other ] )

    def __radd__(self, other ):
        """Implementation of += operator"""
        if isinstance( other, str ):
            other = Literal( other )
        return other + self

    def __or__(self, other ):
        """Implementation of | operator - returns MatchFirst"""
        if isinstance( other, str ):
            other = Literal( other )
        return MatchFirst( [ self, other ] )

    def __ror__(self, other ):
        """Implementation of |= operator"""
        if isinstance( other, str ):
            other = Literal( other )
        return other | self

    def __xor__(self, other ):
        """Implementation of ^ operator - returns Or"""
        if isinstance( other, str ):
            other = Literal( other )
        return Or( [ self, other ] )

    def __rxor__(self, other ):
        """Implementation of ^= operator"""
        if isinstance( other, str ):
            other = Literal( other )
        return other ^ self

    def __and__(self, other ):
        """Implementation of & operator - returns Each"""
        if isinstance( other, str ):
            other = Literal( other )
        return Each( [ self, other ] )

    def __rand__(self, other ):
        """Implementation of right-& operator"""
        if isinstance( other, str ):
            other = Literal( other )
        return other & self

    def __invert__( self ):
        """Implementation of ~ operator - returns NotAny"""
        return NotAny( self )

    def suppress( self ):
        """Suppresses the output of this ParseElement; useful to keep punctuation from
           cluttering up returned output.
        """
        return Suppress( self )

    def leaveWhitespace( self ):
        """Disables the skipping of whitespace before matching the characters in the 
           ParserElement's defined pattern.  This is normally only used internally by
           the pyparsing module, but may be needed in some whitespace-sensitive grammars.
        """
        self.skipWhitespace = False
        return self

    def setWhitespaceChars( self, chars ):
        """Overrides the default whitespace chars
        """
        self.skipWhitespace = True
        self.whiteChars = chars
        
    def parseWithTabs( self ):
        """Overrides default behavior to expand <TAB>s to spaces before parsing the input string.
           Must be called before parseString when the input grammar contains elements that 
           match <TAB> characters."""
        self.keepTabs = True
        return self
        
    def ignore( self, other ):
        """Define expression to be ignored (e.g., comments) while doing pattern 
           matching; may be called repeatedly, to define multiple comment or other
           ignorable patterns.
        """
        if isinstance( other, Suppress ):
            if other not in self.ignoreExprs:
                self.ignoreExprs.append( other )
        else:
            self.ignoreExprs.append( Suppress( other ) )
        return self

    def setDebugActions( self, startAction, successAction, exceptionAction ):
        """Enable display of debugging messages while doing pattern matching."""
        self.debugActions = (startAction or _defaultStartDebugAction, 
                             successAction or _defaultSuccessDebugAction, 
                             exceptionAction or _defaultExceptionDebugAction)
        self.debug = True
        return self

    def setDebug( self, flag=True ):
        """Enable display of debugging messages while doing pattern matching."""
        if flag:
            self.setDebugActions( _defaultStartDebugAction, _defaultSuccessDebugAction, _defaultExceptionDebugAction )
        else:
            self.debug = False
        return self

    def __str__( self ):
        return self.name

    def __repr__( self ):
        return _ustr(self)
        
    def streamline( self ):
        self.streamlined = True
        self.strRepr = None
        return self
        
    def checkRecursion( self, parseElementList ):
        pass
        
    def validate( self, validateTrace=[] ):
        """Check defined expressions for valid structure, check for infinite recursive definitions."""
        self.checkRecursion( [] )

    def parseFile( self, file_or_filename ):
        """Execute the parse expression on the given file or filename.
           If a filename is specified (instead of a file object),
           the entire file is opened, read, and closed before parsing.
        """
        try:
            file_contents = file_or_filename.read()
        except AttributeError:
            f = open(file_or_filename, "rb")
            file_contents = f.read()
            f.close()
        return self.parseString(file_contents)


class Token(ParserElement):
    """Abstract ParserElement subclass, for defining atomic matching patterns."""
    def __init__( self ):
        super(Token,self).__init__( savelist=False )
        self.myException = ParseException("",0,"",self)

    def setName(self, name):
        s = super(Token,self).setName(name)
        self.errmsg = "Expected " + self.name
        s.myException.msg = self.errmsg
        return s


class Empty(Token):
    """An empty token, will always match."""
    def __init__( self ):
        super(Empty,self).__init__()
        self.name = "Empty"
        self.mayReturnEmpty = True
        self.mayIndexError = False


class NoMatch(Token):
    """A token that will never match."""
    def __init__( self ):
        super(NoMatch,self).__init__()
        self.name = "NoMatch"
        self.mayReturnEmpty = True
        self.mayIndexError = False
        self.errmsg = "Unmatchable token"
        s.myException.msg = self.errmsg
        
    def parseImpl( self, instring, loc, doActions=True ):
        exc = self.myException
        exc.loc = loc
        exc.pstr = instring
        raise exc


class Literal(Token):
    """Token to exactly match a specified string."""
    def __init__( self, matchString ):
        super(Literal,self).__init__()
        self.match = matchString
        self.matchLen = len(matchString)
        try:
            self.firstMatchChar = matchString[0]
        except IndexError:
            warnings.warn("null string passed to Literal; use Empty() instead", 
                            SyntaxWarning, stacklevel=2)
        self.name = '"%s"' % self.match
        self.errmsg = "Expected " + self.name
        self.mayReturnEmpty = False
        self.myException.msg = self.errmsg
        self.mayIndexError = False

    # Performance tuning: this routine gets called a *lot*
    # if this is a single character match string  and the first character matches,
    # short-circuit as quickly as possible, and avoid calling startswith
    #~ @profile
    def parseImpl( self, instring, loc, doActions=True ):
        if (instring[loc] == self.firstMatchChar and
            (self.matchLen==1 or instring.startswith(self.match,loc)) ):
            return loc+self.matchLen, self.match
        #~ raise ParseException, ( instring, loc, self.errmsg )
        exc = self.myException
        exc.loc = loc
        exc.pstr = instring
        raise exc

class Keyword(Token):
    """Token to exactly match a specified string as a keyword, that is, it must be 
       immediately followed by a non-keyword character.  Compare with Literal::
         Literal("if") will match the leading 'if' in 'ifAndOnlyIf'.
         Keyword("if") will not; it will only match the leading 'if in 'if x=1', or 'if(y==2)'
       Accepts two optional constructor arguments in addition to the keyword string:
       identChars is a string of characters that would be valid identifier characters,
       defaulting to all alphanumerics + "_" and "$"; caseless allows case-insensitive
       matching, default is False.
    """
    DEFAULT_KEYWORD_CHARS = alphanums+"_$"
    
    def __init__( self, matchString, identChars=DEFAULT_KEYWORD_CHARS, caseless=False ):
        super(Keyword,self).__init__()
        self.match = matchString
        self.matchLen = len(matchString)
        try:
            self.firstMatchChar = matchString[0]
        except IndexError:
            warnings.warn("null string passed to Keyword; use Empty() instead", 
                            SyntaxWarning, stacklevel=2)
        self.name = '"%s"' % self.match
        self.errmsg = "Expected " + self.name
        self.mayReturnEmpty = False
        self.myException.msg = self.errmsg
        self.mayIndexError = False
        self.caseless = caseless
        if caseless:
            self.caselessmatch = matchString.upper()
            identChars = identChars.upper()
        self.identChars = _str2dict(identChars)

    def parseImpl( self, instring, loc, doActions=True ):
        if self.caseless:
            if ( (instring[ loc:loc+self.matchLen ].upper() == self.caselessmatch) and
                 (loc >= len(instring)-self.matchLen or instring[loc+self.matchLen].upper() not in self.identChars) ):
                return loc+self.matchLen, self.match
        else:
            if (instring[loc] == self.firstMatchChar and
                (self.matchLen==1 or instring.startswith(self.match,loc)) and
                (loc >= len(instring)-self.matchLen or instring[loc+self.matchLen] not in self.identChars) ):
                return loc+self.matchLen, self.match
        #~ raise ParseException, ( instring, loc, self.errmsg )
        exc = self.myException
        exc.loc = loc
        exc.pstr = instring
        raise exc
        
    def copy(self):
        c = super(Keyword,self).copy()
        c.identChars = Keyword.DEFAULT_KEYWORD_CHARS
        return c
        
    def setDefaultKeywordChars( chars ):
        """Overrides the default Keyword chars
        """
        Keyword.DEFAULT_KEYWORD_CHARS = chars
    setDefaultKeywordChars = staticmethod(setDefaultKeywordChars)        


class CaselessLiteral(Literal):
    """Token to match a specified string, ignoring case of letters.
       Note: the matched results will always be in the case of the given
       match string, NOT the case of the input text.
    """
    def __init__( self, matchString ):
        super(CaselessLiteral,self).__init__( matchString.upper() )
        # Preserve the defining literal.
        self.returnString = matchString
        self.name = "'%s'" % self.returnString
        self.errmsg = "Expected " + self.name
        self.myException.msg = self.errmsg

    def parseImpl( self, instring, loc, doActions=True ):
        if instring[ loc:loc+self.matchLen ].upper() == self.match:
            return loc+self.matchLen, self.returnString
        #~ raise ParseException, ( instring, loc, self.errmsg )
        exc = self.myException
        exc.loc = loc
        exc.pstr = instring
        raise exc


class Word(Token):
    """Token for matching words composed of allowed character sets.
       Defined with string containing all allowed initial characters,
       an optional string containing allowed body characters (if omitted,
       defaults to the initial character set), and an optional minimum,
       maximum, and/or exact length.
    """
    def __init__( self, initChars, bodyChars=None, min=1, max=0, exact=0 ):
        super(Word,self).__init__()
        self.initCharsOrig = initChars
        self.initChars = _str2dict(initChars)
        if bodyChars :
            self.bodyCharsOrig = bodyChars
            self.bodyChars = _str2dict(bodyChars)
        else:
            self.bodyCharsOrig = initChars
            self.bodyChars = _str2dict(initChars)
            
        self.maxSpecified = max > 0

        self.minLen = min

        if max > 0:
            self.maxLen = max
        else:
            self.maxLen = sys.maxsize

        if exact > 0:
            self.maxLen = exact
            self.minLen = exact

        self.name = _ustr(self)
        self.errmsg = "Expected " + self.name
        self.myException.msg = self.errmsg
        self.mayIndexError = False
        
    def parseImpl( self, instring, loc, doActions=True ):
        if not(instring[ loc ] in self.initChars):
            #~ raise ParseException, ( instring, loc, self.errmsg )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc
        start = loc
        loc += 1
        bodychars = self.bodyChars
        maxloc = start + self.maxLen
        maxloc = min( maxloc, len(instring) )
        while loc < maxloc and instring[loc] in bodychars:
            loc += 1
            
        throwException = False
        if loc - start < self.minLen:
            throwException = True
        if self.maxSpecified and loc < len(instring) and instring[loc] in bodychars:
            throwException = True

        if throwException:
            #~ raise ParseException, ( instring, loc, self.errmsg )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc

        return loc, instring[start:loc]

    def __str__( self ):
        try:
            return super(Word,self).__str__()
        except:
            pass

            
        if self.strRepr is None:
            
            def charsAsStr(s):
                if len(s)>4:
                    return s[:4]+"..."
                else:
                    return s
            
            if ( self.initCharsOrig != self.bodyCharsOrig ):
                self.strRepr = "W:(%s,%s)" % ( charsAsStr(self.initCharsOrig), charsAsStr(self.bodyCharsOrig) )
            else:
                self.strRepr = "W:(%s)" % charsAsStr(self.initCharsOrig)

        return self.strRepr


class CharsNotIn(Token):
    """Token for matching words composed of characters *not* in a given set.
       Defined with string containing all disallowed characters, and an optional 
       minimum, maximum, and/or exact length.
    """
    def __init__( self, notChars, min=1, max=0, exact=0 ):
        super(CharsNotIn,self).__init__()
        self.skipWhitespace = False
        self.notChars = notChars
        
        self.minLen = min

        if max > 0:
            self.maxLen = max
        else:
            self.maxLen = sys.maxsize

        if exact > 0:
            self.maxLen = exact
            self.minLen = exact
        
        self.name = _ustr(self)
        self.errmsg = "Expected " + self.name
        self.mayReturnEmpty = ( self.minLen == 0 )
        self.myException.msg = self.errmsg
        self.mayIndexError = False

    def parseImpl( self, instring, loc, doActions=True ):
        if instring[loc] in self.notChars:
            #~ raise ParseException, ( instring, loc, self.errmsg )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc
            
        start = loc
        loc += 1
        notchars = self.notChars
        maxlen = min( start+self.maxLen, len(instring) )
        while loc < maxlen and \
              (instring[loc] not in notchars):
            loc += 1

        if loc - start < self.minLen:
            #~ raise ParseException, ( instring, loc, self.errmsg )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc

        return loc, instring[start:loc]

    def __str__( self ):
        try:
            return super(CharsNotIn, self).__str__()
        except:
            pass

        if self.strRepr is None:
            if len(self.notChars) > 4:
                self.strRepr = "!W:(%s...)" % self.notChars[:4]
            else:
                self.strRepr = "!W:(%s)" % self.notChars
        
        return self.strRepr

class White(Token):
    """Special matching class for matching whitespace.  Normally, whitespace is ignored
       by pyparsing grammars.  This class is included when some whitespace structures
       are significant.  Define with a string containing the whitespace characters to be
       matched; default is " \\t\\n".  Also takes optional min, max, and exact arguments,
       as defined for the Word class."""
    whiteStrs = {
        " " : "<SPC>",
        "\t": "<TAB>",
        "\n": "<LF>",
        "\r": "<CR>",
        "\f": "<FF>",
        }
    def __init__(self, ws=" \t\r\n", min=1, max=0, exact=0):
        super(White,self).__init__()
        self.matchWhite = ws
        self.whiteChars = "".join([c for c in self.whiteChars if c not in self.matchWhite])
        #~ self.leaveWhitespace()
        self.name = ("".join([White.whiteStrs[c] for c in self.matchWhite]))
        self.mayReturnEmpty = True
        self.errmsg = "Expected " + self.name
        self.myException.msg = self.errmsg

        self.minLen = min

        if max > 0:
            self.maxLen = max
        else:
            self.maxLen = sys.maxsize

        if exact > 0:
            self.maxLen = exact
            self.minLen = exact
            
    def parseImpl( self, instring, loc, doActions=True ):
        if not(instring[ loc ] in self.matchWhite):
            #~ raise ParseException, ( instring, loc, self.errmsg )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc
        start = loc
        loc += 1
        maxloc = start + self.maxLen
        maxloc = min( maxloc, len(instring) )
        while loc < maxloc and instring[loc] in self.matchWhite:
            loc += 1

        if loc - start < self.minLen:
            #~ raise ParseException, ( instring, loc, self.errmsg )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc

        return loc, instring[start:loc]


class PositionToken(Token):
    def __init__( self ):
        super(PositionToken,self).__init__()
        self.name=self.__class__.__name__
        self.mayReturnEmpty = True

class GoToColumn(PositionToken):
    """Token to advance to a specific column of input text; useful for tabular report scraping."""
    def __init__( self, colno ):
        super(GoToColumn,self).__init__()
        self.col = colno

    def preParse( self, instring, loc ):
        if col(loc,instring) != self.col:
            instrlen = len(instring)
            if self.ignoreExprs:
                loc = self.skipIgnorables( instring, loc )
            while loc < instrlen and instring[loc].isspace() and col( loc, instring ) != self.col :
                loc += 1
        return loc

    def parseImpl( self, instring, loc, doActions=True ):
        thiscol = col( loc, instring )
        if thiscol > self.col:
            raise ParseException( instring, loc, "Text not in expected column", self)
        newloc = loc + self.col - thiscol
        ret = instring[ loc: newloc ]
        return newloc, ret

class LineStart(PositionToken):
    """Matches if current position is at the beginning of a line within the parse string"""
    def __init__( self ):
        super(LineStart,self).__init__()
        self.whiteChars = " \t"
        self.errmsg = "Expected start of line"
        self.myException.msg = self.errmsg

    def preParse( self, instring, loc ):
        loc = super(LineStart,self).preParse(instring,loc)
        if instring[loc] == "\n":
            loc += 1
        return loc

    def parseImpl( self, instring, loc, doActions=True ):
        if not( loc==0 or ( loc<len(instring) and instring[loc-1] == "\n" ) ): #col(loc, instring) != 1:
            #~ raise ParseException, ( instring, loc, "Expected start of line" )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc
        return loc, []

class LineEnd(PositionToken):
    """Matches if current position is at the end of a line within the parse string"""
    def __init__( self ):
        super(LineEnd,self).__init__()
        self.whiteChars = " \t"
        self.errmsg = "Expected end of line"
        self.myException.msg = self.errmsg
    
    def parseImpl( self, instring, loc, doActions=True ):
        if loc<len(instring):
            if instring[loc] == "\n":
                return loc+1, "\n"
            else:
                #~ raise ParseException, ( instring, loc, "Expected end of line" )
                exc = self.myException
                exc.loc = loc
                exc.pstr = instring
                raise exc
        else:
            return loc, []

class StringStart(PositionToken):
    """Matches if current position is at the beginning of the parse string"""
    def __init__( self ):
        super(StringStart,self).__init__()
        self.errmsg = "Expected start of text"
        self.myException.msg = self.errmsg
    
    def parseImpl( self, instring, loc, doActions=True ):
        if loc != 0:
            # see if entire string up to here is just whitespace and ignoreables
            if loc != self.preParse( instring, 0 ):
                #~ raise ParseException, ( instring, loc, "Expected start of text" )
                exc = self.myException
                exc.loc = loc
                exc.pstr = instring
                raise exc
        return loc, []

class StringEnd(PositionToken):
    """Matches if current position is at the end of the parse string"""
    def __init__( self ):
        super(StringEnd,self).__init__()
        self.errmsg = "Expected end of text"
        self.myException.msg = self.errmsg
    
    def parseImpl( self, instring, loc, doActions=True ):
        if loc < len(instring):
            #~ raise ParseException, ( instring, loc, "Expected end of text" )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc
        return loc, []


class ParseExpression(ParserElement):
    """Abstract subclass of ParserElement, for combining and post-processing parsed tokens."""
    def __init__( self, exprs, savelist = False ):
        super(ParseExpression,self).__init__(savelist)
        if isinstance( exprs, list ):
            self.exprs = exprs
        elif isinstance( exprs, str ):
            self.exprs = [ Literal( exprs ) ]
        else:
            self.exprs = [ exprs ]

    def __getitem__( self, i ):
        return self.exprs[i]

    def append( self, other ):
        self.exprs.append( other )
        self.strRepr = None
        return self

    def leaveWhitespace( self ):
        """Extends leaveWhitespace defined in base class, and also invokes leaveWhitespace on
           all contained expressions."""
        self.skipWhitespace = False
        self.exprs = [ copy.copy(e) for e in self.exprs ]
        for e in self.exprs:
            e.leaveWhitespace()
        return self

    def ignore( self, other ):
        if isinstance( other, Suppress ):
            if other not in self.ignoreExprs:
                super( ParseExpression, self).ignore( other )
                for e in self.exprs:
                    e.ignore( self.ignoreExprs[-1] )
        else:
            super( ParseExpression, self).ignore( other )
            for e in self.exprs:
                e.ignore( self.ignoreExprs[-1] )
        return self

    def __str__( self ):
        try:
            return super(ParseExpression,self).__str__()
        except:
            pass
            
        if self.strRepr is None:
            self.strRepr = "%s:(%s)" % ( self.__class__.__name__, _ustr(self.exprs) )
        return self.strRepr

    def streamline( self ):
        super(ParseExpression,self).streamline()

        for e in self.exprs:
            e.streamline()

        # collapse nested And's of the form And( And( And( a,b), c), d) to And( a,b,c,d )
        # but only if there are no parse actions or resultsNames on the nested And's
        # (likewise for Or's and MatchFirst's)
        if ( len(self.exprs) == 2 ):
            other = self.exprs[0]
            if ( isinstance( other, self.__class__ ) and
                  other.parseAction is None and
                  other.resultsName is None and
                  not other.debug ):
                self.exprs = other.exprs[:] + [ self.exprs[1] ]
                self.strRepr = None

            other = self.exprs[-1]
            if ( isinstance( other, self.__class__ ) and
                  other.parseAction is None and
                  other.resultsName is None and
                  not other.debug ):
                self.exprs = self.exprs[:-1] + other.exprs[:]
                self.strRepr = None

        return self

    def setResultsName( self, name, listAllMatches=False ):
        ret = super(ParseExpression,self).setResultsName(name,listAllMatches)
        #~ ret.saveAsList = True
        return ret
    
    def validate( self, validateTrace=[] ):
        tmp = validateTrace[:]+[self]
        for e in self.exprs:
            e.validate(tmp)
        self.checkRecursion( [] )


class And(ParseExpression):
    """Requires all given ParseExpressions to be found in the given order.
       Expressions may be separated by whitespace.
       May be constructed using the '+' operator.
    """
    def __init__( self, exprs, savelist = True ):
        super(And,self).__init__(exprs, savelist)
        self.mayReturnEmpty = True
        for e in exprs:
            if not e.mayReturnEmpty:
                self.mayReturnEmpty = False
                break
        self.skipWhitespace = exprs[0].skipWhitespace
        self.whiteChars = exprs[0].whiteChars

    def parseImpl( self, instring, loc, doActions=True ):
        loc, resultlist = self.exprs[0].parse( instring, loc, doActions )
        for e in self.exprs[1:]:
            loc, exprtokens = e.parse( instring, loc, doActions )
            if exprtokens or list(exprtokens.keys()):
                resultlist += exprtokens
        return loc, resultlist

    def __iadd__(self, other ):
        if isinstance( other, str ):
            other = Literal( other )
        return self.append( other ) #And( [ self, other ] )
        
    def checkRecursion( self, parseElementList ):
        subRecCheckList = parseElementList[:] + [ self ]
        for e in self.exprs:
            e.checkRecursion( subRecCheckList )
            if not e.mayReturnEmpty:
                break

    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        if self.strRepr is None:
            self.strRepr = "{" + " ".join( [ _ustr(e) for e in self.exprs ] ) + "}"
        
        return self.strRepr
    

class Or(ParseExpression):
    """Requires that at least one ParseExpression is found.
       If two expressions match, the expression that matches the longest string will be used.
       May be constructed using the '^' operator.
    """
    def __init__( self, exprs, savelist = False ):
        super(Or,self).__init__(exprs, savelist)
        self.mayReturnEmpty = False
        for e in exprs:
            if e.mayReturnEmpty:
                self.mayReturnEmpty = True
                break
    
    def parseImpl( self, instring, loc, doActions=True ):
        maxExcLoc = -1
        maxMatchLoc = -1
        for e in self.exprs:
            try:
                loc2 = e.tryParse( instring, loc )
            except ParseException as err:
                if err.loc > maxExcLoc:
                    maxException = err
                    maxExcLoc = err.loc
            except IndexError as err:
                if len(instring) > maxExcLoc:
                    maxException = ParseException(instring,len(instring),e.errmsg,self)
                    maxExcLoc = len(instring)
            else:
                if loc2 > maxMatchLoc:
                    maxMatchLoc = loc2
                    maxMatchExp = e
        
        if maxMatchLoc < 0:
            raise maxException

        return maxMatchExp.parse( instring, loc, doActions )

    def __ixor__(self, other ):
        if isinstance( other, str ):
            other = Literal( other )
        return self.append( other ) #Or( [ self, other ] )

    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        if self.strRepr is None:
            self.strRepr = "{" + " ^ ".join( [ _ustr(e) for e in self.exprs ] ) + "}"
        
        return self.strRepr
    
    def checkRecursion( self, parseElementList ):
        subRecCheckList = parseElementList[:] + [ self ]
        for e in self.exprs:
            e.checkRecursion( subRecCheckList )


class MatchFirst(ParseExpression):
    """Requires that at least one ParseExpression is found.
       If two expressions match, the first one listed is the one that will match.
       May be constructed using the '|' operator.
    """
    def __init__( self, exprs, savelist = False ):
        super(MatchFirst,self).__init__(exprs, savelist)
        self.mayReturnEmpty = False
        for e in exprs:
            if e.mayReturnEmpty:
                self.mayReturnEmpty = True
                break
    
    def parseImpl( self, instring, loc, doActions=True ):
        maxExcLoc = -1
        for e in self.exprs:
            try:
                ret = e.parse( instring, loc, doActions )
                return ret
            except ParseException as err:
                if err.loc > maxExcLoc:
                    maxException = err
                    maxExcLoc = err.loc
            except IndexError as err:
                if len(instring) > maxExcLoc:
                    maxException = ParseException(instring,len(instring),e.errmsg,self)
                    maxExcLoc = len(instring)

        # only got here if no expression matched, raise exception for match that made it the furthest
        else:
            raise maxException

    def __ior__(self, other ):
        if isinstance( other, str ):
            other = Literal( other )
        return self.append( other ) #MatchFirst( [ self, other ] )

    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        if self.strRepr is None:
            self.strRepr = "{" + " | ".join( [ _ustr(e) for e in self.exprs ] ) + "}"
        
        return self.strRepr
    
    def checkRecursion( self, parseElementList ):
        subRecCheckList = parseElementList[:] + [ self ]
        for e in self.exprs:
            e.checkRecursion( subRecCheckList )


class Each(ParseExpression):
    """Requires all given ParseExpressions to be found, but in any order.
       Expressions may be separated by whitespace.
       May be constructed using the '&' operator.
    """
    def __init__( self, exprs, savelist = True ):
        super(Each,self).__init__(exprs, savelist)
        self.mayReturnEmpty = True
        for e in exprs:
            if not e.mayReturnEmpty:
                self.mayReturnEmpty = False
                break
        self.skipWhitespace = True
        self.optionals = [ e.expr for e in exprs if isinstance(e,Optional) ]
        self.multioptionals = [ e.expr for e in exprs if isinstance(e,ZeroOrMore) ]
        self.multirequired = [ e.expr for e in exprs if isinstance(e,OneOrMore) ]
        self.required = [ e for e in exprs if not isinstance(e,(Optional,ZeroOrMore,OneOrMore)) ]
        self.required += self.multirequired

    def parseImpl( self, instring, loc, doActions=True ):
        tmpLoc = loc
        tmpReqd = self.required[:]
        tmpOpt  = self.optionals[:]
        matchOrder = []

        keepMatching = True
        while keepMatching:
            tmpExprs = tmpReqd + tmpOpt + self.multioptionals + self.multirequired
            failed = []
            for e in tmpExprs:
                try:
                    tmpLoc = e.tryParse( instring, tmpLoc )
                except ParseException:
                    failed.append(e)
                else:
                    matchOrder.append(e)
                    if e in tmpReqd:
                        tmpReqd.remove(e)
                    elif e in tmpOpt:
                        tmpOpt.remove(e)
            if len(failed) == len(tmpExprs):
                keepMatching = False
        
        if tmpReqd:
            missing = ", ".join( [ str(e) for e in tmpReqd ] )
            raise ParseException(instring,loc,"Missing one or more required elements (%s)" % missing )

        resultlist = []
        for e in matchOrder:
            loc,results = e.parse(instring,loc,doActions)
            resultlist.append(results)
            
        finalResults = ParseResults([])
        for r in resultlist:
            dups = {}
            for k in list(r.keys()):
                if k in list(finalResults.keys()):
                    tmp = ParseResults(finalResults[k])
                    tmp += ParseResults(r[k])
                    dups[k] = tmp
            finalResults += ParseResults(r)
            for k,v in list(dups.items()):
                finalResults[k] = v
        return loc, finalResults

    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        if self.strRepr is None:
            self.strRepr = "{" + " & ".join( [ _ustr(e) for e in self.exprs ] ) + "}"
        
        return self.strRepr
    
    def checkRecursion( self, parseElementList ):
        subRecCheckList = parseElementList[:] + [ self ]
        for e in self.exprs:
            e.checkRecursion( subRecCheckList )


class ParseElementEnhance(ParserElement):
    """Abstract subclass of ParserElement, for combining and post-processing parsed tokens."""
    def __init__( self, expr, savelist=False ):
        super(ParseElementEnhance,self).__init__(savelist)
        if isinstance( expr, str ):
            expr = Literal(expr)
        self.expr = expr
        self.strRepr = None
        if expr is not None:
            self.mayIndexError = expr.mayIndexError
            self.skipWhitespace = expr.skipWhitespace
            self.whiteChars = expr.whiteChars

    def parseImpl( self, instring, loc, doActions=True ):
        if self.expr is not None:
            return self.expr.parse( instring, loc, doActions )
        else:
            raise ParseException(instring,loc,"",self)

    def leaveWhitespace( self ):
        self.skipWhitespace = False
        self.expr = copy.copy(self.expr)
        if self.expr is not None:
            self.expr.leaveWhitespace()
        return self

    def ignore( self, other ):
        if isinstance( other, Suppress ):
            if other not in self.ignoreExprs:
                super( ParseElementEnhance, self).ignore( other )
                if self.expr is not None:
                    self.expr.ignore( self.ignoreExprs[-1] )
        else:
            super( ParseElementEnhance, self).ignore( other )
            if self.expr is not None:
                self.expr.ignore( self.ignoreExprs[-1] )
        return self

    def streamline( self ):
        super(ParseElementEnhance,self).streamline()
        if self.expr is not None:
            self.expr.streamline()
        return self

    def checkRecursion( self, parseElementList ):
        if self in parseElementList:
            raise RecursiveGrammarException( parseElementList+[self] )
        subRecCheckList = parseElementList[:] + [ self ]
        if self.expr is not None:
            self.expr.checkRecursion( subRecCheckList )
        
    def validate( self, validateTrace=[] ):
        tmp = validateTrace[:]+[self]
        if self.expr is not None:
            self.expr.validate(tmp)
        self.checkRecursion( [] )
    
    def __str__( self ):
        try:
            return super(ParseElementEnhance,self).__str__()
        except:
            pass
            
        if self.strRepr is None and self.expr is not None:
            self.strRepr = "%s:(%s)" % ( self.__class__.__name__, _ustr(self.expr) )
        return self.strRepr


class FollowedBy(ParseElementEnhance):
    """Lookahead matching of the given parse expression.  FollowedBy
    does *not* advance the parsing position within the input string, it only 
    verifies that the specified parse expression matches at the current 
    position.  FollowedBy always returns a null token list."""
    def __init__( self, expr ):
        super(FollowedBy,self).__init__(expr)
        self.mayReturnEmpty = True
        
    def parseImpl( self, instring, loc, doActions=True ):
        self.expr.tryParse( instring, loc )
        return loc, []


class NotAny(ParseElementEnhance):
    """Lookahead to disallow matching with the given parse expression.  NotAny
    does *not* advance the parsing position within the input string, it only 
    verifies that the specified parse expression does *not* match at the current 
    position.  Also, NotAny does *not* skip over leading whitespace. NotAny 
    always returns a null token list.  May be constructed using the '~' operator."""
    def __init__( self, expr ):
        super(NotAny,self).__init__(expr)
        #~ self.leaveWhitespace()
        self.skipWhitespace = False  # do NOT use self.leaveWhitespace(), don't want to propagate to exprs
        self.mayReturnEmpty = True
        self.errmsg = "Found unexpected token, "+_ustr(self.expr)
        self.myException = ParseException("",0,self.errmsg,self)
        
    def parseImpl( self, instring, loc, doActions=True ):
        try:
            self.expr.tryParse( instring, loc )
        except (ParseException,IndexError):
            pass
        else:
            #~ raise ParseException, (instring, loc, self.errmsg )
            exc = self.myException
            exc.loc = loc
            exc.pstr = instring
            raise exc
        return loc, []

    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        if self.strRepr is None:
            self.strRepr = "~{" + _ustr(self.expr) + "}"
        
        return self.strRepr


class ZeroOrMore(ParseElementEnhance):
    """Optional repetition of zero or more of the given expression."""
    def __init__( self, expr ):
        super(ZeroOrMore,self).__init__(expr)
        self.mayReturnEmpty = True
    
    def parseImpl( self, instring, loc, doActions=True ):
        tokens = []
        try:
            loc, tokens = self.expr.parse( instring, loc, doActions )
            hasIgnoreExprs = ( len(self.ignoreExprs) > 0 )
            while 1:
                if hasIgnoreExprs:
                    loc = self.skipIgnorables( instring, loc )
                loc, tmptokens = self.expr.parse( instring, loc, doActions )
                if tmptokens or list(tmptokens.keys()):
                    tokens += tmptokens
        except (ParseException,IndexError):
            pass

        return loc, tokens

    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        if self.strRepr is None:
            self.strRepr = "[" + _ustr(self.expr) + "]..."
        
        return self.strRepr
    
    def setResultsName( self, name, listAllMatches=False ):
        ret = super(ZeroOrMore,self).setResultsName(name,listAllMatches)
        ret.saveAsList = True
        return ret
    

class OneOrMore(ParseElementEnhance):
    """Repetition of one or more of the given expression."""
    def parseImpl( self, instring, loc, doActions=True ):
        # must be at least one
        loc, tokens = self.expr.parse( instring, loc, doActions )
        try:
            hasIgnoreExprs = ( len(self.ignoreExprs) > 0 )
            while 1:
                if hasIgnoreExprs:
                    loc = self.skipIgnorables( instring, loc )
                loc, tmptokens = self.expr.parse( instring, loc, doActions )
                if tmptokens or list(tmptokens.keys()):
                    tokens += tmptokens
        except (ParseException,IndexError):
            pass

        return loc, tokens

    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        if self.strRepr is None:
            self.strRepr = "{" + _ustr(self.expr) + "}..."
        
        return self.strRepr
    
    def setResultsName( self, name, listAllMatches=False ):
        ret = super(OneOrMore,self).setResultsName(name,listAllMatches)
        ret.saveAsList = True
        return ret
    

class Optional(ParseElementEnhance):
    """Optional matching of the given expression.
       A default return string can also be specified, if the optional expression
       is not found.
    """
    def __init__( self, exprs, default=None ):
        super(Optional,self).__init__( exprs, savelist=False )
        self.defaultValue = default
        self.mayReturnEmpty = True

    def parseImpl( self, instring, loc, doActions=True ):
        try:
            loc, tokens = self.expr.parse( instring, loc, doActions )
        except (ParseException,IndexError):
            if self.defaultValue is not None:
                tokens = [ self.defaultValue ]
            else:
                tokens = []

        return loc, tokens

    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        if self.strRepr is None:
            self.strRepr = "[" + _ustr(self.expr) + "]"
        
        return self.strRepr


class SkipTo(ParseElementEnhance):
    """Token for skipping over all undefined text until the matched expression is found.
       If include is set to true, the matched expression is also consumed.  The ignore
       argument is used to define grammars (typically quoted strings and comments) that 
       might contain false matches.
    """
    def __init__( self, other, include=False, ignore=None ):
        super( SkipTo, self ).__init__( other )
        if ignore is not None:
            self.expr = copy.copy( self.expr )
            self.expr.ignore(ignore)
        self.mayReturnEmpty = True
        self.mayIndexError = False
        self.includeMatch = include
        self.errmsg = "No match found for "+_ustr(self.expr)
        self.myException = ParseException("",0,self.errmsg,self)

    def parseImpl( self, instring, loc, doActions=True ):
        startLoc = loc
        instrlen = len(instring)
        expr = self.expr
        while loc < instrlen:
            try:
                expr.tryParse(instring, loc)
                if self.includeMatch:
                    skipText = instring[startLoc:loc]
                    loc,mat = expr.parse(instring,loc)
                    if mat:
                        return loc, [ skipText, mat ]
                    else:
                        return loc, [ skipText ]
                else:
                    return loc, [ instring[startLoc:loc] ]
            except (ParseException,IndexError):
                loc += 1
        exc = self.myException
        exc.loc = loc
        exc.pstr = instring
        raise exc

class Forward(ParseElementEnhance):
    """Forward declaration of an expression to be defined later -
       used for recursive grammars, such as algebraic infix notation.
       When the expression is known, it is assigned to the Forward variable using the '<<' operator.
    """
    def __init__( self, other=None ):
        super(Forward,self).__init__( other, savelist=False )

    def __lshift__( self, other ):
        self.expr = other
        self.mayReturnEmpty = other.mayReturnEmpty
        self.strRepr = None
        return self

    def leaveWhitespace( self ):
        self.skipWhitespace = False
        return self

    def streamline( self ):
        if not self.streamlined:
            self.streamlined = True
            if self.expr is not None: 
                self.expr.streamline()
        return self

    def validate( self, validateTrace=[] ):
        if self not in validateTrace:
            tmp = validateTrace[:]+[self]
            if self.expr is not None: 
                self.expr.validate(tmp)
        self.checkRecursion([])        
        
    def __str__( self ):
        if hasattr(self,"name"):
            return self.name
            
        strmethod = self.__str__
        self.__class__ = _ForwardNoRecurse
        if self.expr is not None: 
            retString = _ustr(self.expr)
        else:
            retString = "None"
        self.__class__ = Forward
        return "Forward: "+retString

class _ForwardNoRecurse(Forward):
    def __str__( self ):
        return "..."
        
class TokenConverter(ParseElementEnhance):
    """Abstract subclass of ParseExpression, for converting parsed results."""
    def __init__( self, expr, savelist=False ):
        super(TokenConverter,self).__init__( expr )#, savelist )


class Upcase(TokenConverter):
    """Converter to upper case all matching tokens."""
    def __init__(self, *args):
        super(Upcase,self).__init__(*args)
        warnings.warn("Upcase class is deprecated, use upcaseTokens parse action instead", 
                       DeprecationWarning,stacklevel=2)
    
    def postParse( self, instring, loc, tokenlist ):
        return list(map( string.upper, tokenlist ))


class Combine(TokenConverter):
    """Converter to concatenate all matching tokens to a single string.
       By default, the matching patterns must also be contiguous in the input string;
       this can be disabled by specifying 'adjacent=False' in the constructor.
    """
    def __init__( self, expr, joinString="", adjacent=True ):
        super(Combine,self).__init__( expr )
        # suppress whitespace-stripping in contained parse expressions, but re-enable it on the Combine itself
        if adjacent:
            self.leaveWhitespace()
        self.adjacent = adjacent
        self.skipWhitespace = True
        self.joinString = joinString

    def ignore( self, other ):
        if self.adjacent:
            ParserElement.ignore(self, other)
        else:
            super( Combine, self).ignore( other )
        return self

    def postParse( self, instring, loc, tokenlist ):
        retToks = tokenlist.copy()
        del retToks[:]
        retToks += ParseResults([ "".join(tokenlist._asStringList(self.joinString)) ], modal=self.modalResults)

        if self.resultsName and len(list(retToks.keys()))>0:
            return [ retToks ]
        else:
            return retToks


class Group(TokenConverter):
    """Converter to return the matched tokens as a list - useful for returning tokens of ZeroOrMore and OneOrMore expressions."""
    def __init__( self, expr ):
        super(Group,self).__init__( expr )
        self.saveAsList = True

    def postParse( self, instring, loc, tokenlist ):
        return [ tokenlist ]
        
class Dict(TokenConverter):
    """Converter to return a repetitive expression as a list, but also as a dictionary.
       Each element can also be referenced using the first token in the expression as its key.
       Useful for tabular report scraping when the first column can be used as a item key.
    """
    def __init__( self, exprs ):
        super(Dict,self).__init__( exprs )
        self.saveAsList = True

    def postParse( self, instring, loc, tokenlist ):
        for i,tok in enumerate(tokenlist):
            ikey = _ustr(tok[0]).strip()
            if len(tok)==1:
                tokenlist[ikey] = ("",i)
            elif len(tok)==2 and not isinstance(tok[1],ParseResults):
                tokenlist[ikey] = (tok[1],i)
            else:
                dictvalue = tok.copy() #ParseResults(i)
                del dictvalue[0]
                if len(dictvalue)!= 1 or (isinstance(dictvalue,ParseResults) and list(dictvalue.keys())):
                    tokenlist[ikey] = (dictvalue,i)
                else:
                    tokenlist[ikey] = (dictvalue[0],i)

        if self.resultsName:
            return [ tokenlist ]
        else:
            return tokenlist


class Suppress(TokenConverter):
    """Converter for ignoring the results of a parsed expression."""
    def postParse( self, instring, loc, tokenlist ):
        return []
    
    def suppress( self ):
        return self

#
# global helpers
#
def delimitedList( expr, delim=",", combine=False ):
    """Helper to define a delimited list of expressions - the delimiter defaults to ','.
       By default, the list elements and delimiters can have intervening whitespace, and 
       comments, but this can be overridden by passing 'combine=True' in the constructor.
       If combine is set to True, the matching tokens are returned as a single token
       string, with the delimiters included; otherwise, the matching tokens are returned
       as a list of tokens, with the delimiters suppressed.
    """
    if combine:
        return Combine( expr + ZeroOrMore( delim + expr ) ).setName(_ustr(expr)+_ustr(delim)+"...")
    else:
        return ( expr + ZeroOrMore( Suppress( delim ) + expr ) ).setName(_ustr(expr)+_ustr(delim)+"...")

def oneOf( strs, caseless=False ):
    """Helper to quickly define a set of alternative Literals, and makes sure to do 
       longest-first testing when there is a conflict, regardless of the input order, 
       but returns a MatchFirst for best performance.
    """
    if caseless:
        isequal = ( lambda a,b: a.upper() == b.upper() )
        masks = ( lambda a,b: b.upper().startswith(a.upper()) )
        parseElementClass = CaselessLiteral
    else:
        isequal = ( lambda a,b: a == b )
        masks = ( lambda a,b: b.startswith(a) )
        parseElementClass = Literal
    
    symbols = strs.split()
    i = 0
    while i < len(symbols)-1:
        cur = symbols[i]
        for j,other in enumerate(symbols[i+1:]):
            if ( isequal(other, cur) ):
                del symbols[i+j+1]
                break
            elif ( masks(cur, other) ):
                del symbols[i+j+1]
                symbols.insert(i,other)
                cur = other
                break
        else:
            i += 1
    
    return MatchFirst( [ parseElementClass(sym) for sym in symbols ] )

def dictOf( key, value ):
    """Helper to easily and clearly define a dictionary by specifying the respective patterns
       for the key and value.  Takes care of defining the Dict, ZeroOrMore, and Group tokens
       in the proper order.  The key pattern can include delimiting markers or punctuation,
       as long as they are suppressed, thereby leaving the significant key text.  The value
       pattern can include named results, so that the Dict results can include named token 
       fields.
    """
    return Dict( ZeroOrMore( Group ( key + value ) ) )

_bslash = "\\"
printables = "".join( [ c for c in string.printable if c not in string.whitespace ] )
empty      = Empty().setName("empty")

_escapedPunc = Word( _bslash, r"\[]-*.$+^?()~ ", exact=2 ).setParseAction(lambda s,l,t:t[0][1])
_printables_less_backslash = "".join([ c for c in printables if c not in  r"\]" ])
_escapedHexChar = Combine( Suppress(_bslash + "0x") + Word(hexnums) ).setParseAction(lambda s,l,t:chr(int(t[0],16)))
_escapedOctChar = Combine( Suppress(_bslash) + Word("0","01234567") ).setParseAction(lambda s,l,t:chr(int(t[0],8)))
_singleChar = _escapedPunc | _escapedHexChar | _escapedOctChar | Word(_printables_less_backslash,exact=1)
_charRange = Group(_singleChar + Suppress("-") + _singleChar)
_reBracketExpr = "[" + Optional("^").setResultsName("negate") + Group( OneOrMore( _charRange | _singleChar ) ).setResultsName("body") + "]"

_expanded = lambda p: (isinstance(p,ParseResults) and ''.join([ chr(c) for c in range(ord(p[0]),ord(p[1])+1) ]) or p)
        
def srange(s):
    r"""Helper to easily define string ranges for use in Word construction.  Borrows
       syntax from regexp '[]' string range definitions::
          srange("[0-9]")   -> "0123456789"
          srange("[a-z]")   -> "abcdefghijklmnopqrstuvwxyz"
          srange("[a-z$_]") -> "abcdefghijklmnopqrstuvwxyz$_"
       The input string must be enclosed in []'s, and the returned string is the expanded 
       character set joined into a single string.
       The values enclosed in the []'s may be::
          a single character
          an escaped character with a leading backslash (such as \- or \])
          an escaped hex character with a leading '\0x' (\0x21, which is a '!' character)
          an escaped octal character with a leading '\0' (\041, which is a '!' character)
          a range of any of the above, separated by a dash ('a-z', etc.)
          any combination of the above ('aeiouy', 'a-zA-Z0-9_$', etc.)
    """
    try:
        return "".join([_expanded(part) for part in _reBracketExpr.parseString(s).body])
    except:
        return ""

def replaceWith(replStr):
    """Helper method for common parse actions that simply return a literal value.  Especially 
       useful when used with transformString().
    """
    def _replFunc(*args):
        return replStr
    return _replFunc

def removeQuotes(s,l,t):
    """Helper parse action for removing quotation marks from parsed quoted strings.
       To use, add this parse action to quoted string using::
         quotedString.setParseAction( removeQuotes )
    """
    return t[0][1:-1]

def upcaseTokens(s,l,t):
    """Helper parse action to convert tokens to upper case."""
    return list(map( str.upper, t ))

def downcaseTokens(s,l,t):
    """Helper parse action to convert tokens to lower case."""
    return list(map( str.lower, t ))

def _makeTags(tagStr, xml):
    """Internal helper to construct opening and closing tag expressions, given a tag name"""
    tagAttrName = Word(alphanums)
    if (xml):
        tagAttrValue = dblQuotedString.copy().setParseAction( removeQuotes )
        openTag = "<" + Keyword(tagStr) + Dict(ZeroOrMore(Group( tagAttrName + Suppress("=") + tagAttrValue ))) + Optional("/",default="").setResultsName("empty") + ">"
    else:
        printablesLessRAbrack = "".join( [ c for c in string.printable if c not in ">" ] )
        tagAttrValue = quotedString.copy().setParseAction( removeQuotes ) | Word(printablesLessRAbrack)
        openTag = "<" + Keyword(tagStr,caseless=True) + Dict(ZeroOrMore(Group( tagAttrName.setParseAction(downcaseTokens) + Suppress("=") + tagAttrValue ))) + Optional("/",default="").setResultsName("empty") + ">"
    closeTag = "</" + Keyword(tagStr,caseless=not xml) + ">"
    
    openTag = openTag.setResultsName("start"+tagStr.title()).setName("<"+tagStr+">")
    closeTag = closeTag.setResultsName("end"+tagStr.title()).setName("</"+tagStr+">")
    
    return openTag, closeTag

def makeHTMLTags(tagStr):
    """Helper to construct opening and closing tag expressions for HTML, given a tag name"""
    return _makeTags( tagStr, False )

def makeXMLTags(tagStr):
    """Helper to construct opening and closing tag expressions for XML, given a tag name"""
    return _makeTags( tagStr, True )

alphas8bit = srange(r"[\0xc0-\0xd6\0xd8-\0xf6\0xf8-\0xfe]")

_escapables = "tnrfbacdeghijklmopqsuvwxyz " + _bslash + "'" + '"'
_octDigits = "01234567"
_escapedChar = ( Word( _bslash, _escapables, exact=2 ) |
                 Word( _bslash, _octDigits, min=2, max=4 ) )
_sglQuote = Literal("'")
_dblQuote = Literal('"')
dblQuotedString = Combine( _dblQuote + ZeroOrMore( CharsNotIn('\\"\n\r') | _escapedChar | '""' ) + _dblQuote ).streamline().setName("string enclosed in double quotes")
sglQuotedString = Combine( _sglQuote + ZeroOrMore( CharsNotIn("\\'\n\r") | _escapedChar | "''" ) + _sglQuote ).streamline().setName("string enclosed in single quotes")
quotedString = ( dblQuotedString | sglQuotedString ).setName("quotedString using single or double quotes")

# it's easy to get these comment structures wrong - they're very common, so may as well make them available
cStyleComment = Combine( Literal("/*") +
                         ZeroOrMore( CharsNotIn("*") | ( "*" + ~Literal("/") ) ) +
                         Literal("*/") ).streamline().setName("cStyleComment enclosed in /* ... */")
htmlComment = Combine( Literal("<!--") + ZeroOrMore( CharsNotIn("-") | 
                                                   (~Literal("-->") + Literal("-").leaveWhitespace() ) ) + 
                        Literal("-->") ).streamline().setName("htmlComment enclosed in <!-- ... -->")
restOfLine = Optional( CharsNotIn( "\n\r" ), default="" ).setName("rest of line up to \\n").leaveWhitespace()
dblSlashComment = "//" + restOfLine
cppStyleComment = FollowedBy("/") + ( dblSlashComment | cStyleComment )
javaStyleComment = cppStyleComment
pythonStyleComment = "#" + restOfLine
_noncomma = "".join( [ c for c in printables if c != "," ] )
_commasepitem = Combine(OneOrMore(Word(_noncomma) + 
                                  Optional( Word(" \t") + 
                                            ~Literal(",") + ~LineEnd() ) ) ).streamline().setName("commaItem")
commaSeparatedList = delimitedList( Optional( quotedString | _commasepitem, default="") ).setName("commaSeparatedList")


if __name__ == "__main__":

    def test( teststring ):
        print(teststring,"->", end=' ')
        try:
            tokens = simpleSQL.parseString( teststring )
            tokenlist = tokens.asList()
            print(tokenlist)
            print("tokens = ",        tokens)
            print("tokens.columns =", tokens.columns)
            print("tokens.tables =",  tokens.tables)
            print(tokens.asXML("SQL",True))
        except ParseException as err:
            print(err.line)
            print(" "*(err.column-1) + "^")
            print(err)
        print()

    selectToken    = CaselessLiteral( "select" )
    fromToken      = CaselessLiteral( "from" )

    ident          = Word( alphas, alphanums + "_$" )
    columnName     = Upcase( delimitedList( ident, ".", combine=True ) )
    columnNameList = Group( delimitedList( columnName ) )#.setName("columns")
    tableName      = Upcase( delimitedList( ident, ".", combine=True ) )
    tableNameList  = Group( delimitedList( tableName ) )#.setName("tables")
    simpleSQL      = ( selectToken + \
                     ( '*' | columnNameList ).setResultsName( "columns" ) + \
                     fromToken + \
                     tableNameList.setResultsName( "tables" ) )
    
    test( "SELECT * from XYZZY, ABC" )
    test( "select * from SYS.XYZZY" )
    test( "Select A from Sys.dual" )
    test( "Select AA,BB,CC from Sys.dual" )
    test( "Select A, B, C from Sys.dual" )
    test( "Select A, B, C from Sys.dual" )
    test( "Xelect A, B, C from Sys.dual" )
    test( "Select A, B, C frox Sys.dual" )
    test( "Select" )
    test( "Select ^^^ frox Sys.dual" )
    test( "Select A, B, C from Sys.dual, Table2   " )
