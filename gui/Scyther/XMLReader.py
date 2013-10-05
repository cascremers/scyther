"""
	Scyther : An automatic verifier for security protocols.
	Copyright (C) 2007-2013 Cas Cremers

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
# XMLReader
#
# Note:
# This requires python elementtree to work
# See: http://effbot.org/zone/element-index.htm
#
# On Fedora Core you can install this by installing the python-elementtree rpm
# Things will be a lot faster and consume less memory if you install the
# cElementTree module
#
# In python 2.5 cElementTree is in the core, so you don't need to install
# extra packages
#

import sys

# Check for cElementTree presence. Otherwise use ElementTree.
useiter = True
try:
    # python 2.5 has cElementTree in the core
    import xml.etree.cElementTree as cElementTree
except:
    # try the old way
    try:
        import cElementTree
    except ImportError:
        useiter = False 
        try:
            from elementtree import ElementTree
        except ImportError:
            print """
ERROR:

Could not locate either the [elementtree] or the [cElementTree] package.
Please install one of them in order to work with the Scyther python interface.
The [cElementTree] packages can be found at http://effbot.org/zone/celementtree.htm

Note that you can still use the Scyther binaries in the 'Bin' directory.
        """
            sys.exit(1)

## Simply pick cElementTree
#import cElementTree
## Simply pick ElementTree
#useiter = False 
#from elementtree import ElementTree

import Term
import Attack
import Trace
import Claim
        
class XMLReader(object):
    
    def __init__ (self):
        self.varlist = []
        pass

    def readXML(self, input):
        # Use iter parse when possble so we can clear the attack after reading 
        # it in order to preserve memory (this requires cElementTree)

        attackbuffer = []
        claims = []
        
        if useiter:
            parser = cElementTree.iterparse(input)
        else:
            parser = ElementTree.parse(input).findall('*')

        for elem in parser:
            # The iter parser receives the input in tuples (event and element)
            # we only need the event
            if useiter:
                elem = elem[1]

            if elem.tag == 'state':
                attack = self.readAttack(elem)
                attackbuffer.append(attack)
                if useiter:
                    elem.clear()

            if elem.tag == 'claimstatus':
                claim = self.readClaim(elem)
                claim.attacks = attackbuffer
                claims.append(claim)

                # link to parent
                for attack in claim.attacks:
                    attack.claim = claim

                attackbuffer = []
                if useiter:
                    elem.clear()

        return claims

    # Read a term from XML
    def readTerm(self,xml):
        # If xml is None the term should also be none
        if xml == None:
            return None
        # If this is a term variable read it directly
        if (xml.tag in ('tuple','const','apply','encrypt','var')):
            return self.readSubTerm(xml)
        # Otherwise read from it's first child
        children = xml.getchildren()
        assert(len(children) == 1)
        return self.readSubTerm(children[0])

    def readSubTerm(self, tag):
        if tag.tag == 'tuple':
            return Term.TermTuple(self.readTerm(tag.find('op1')),self.readTerm(tag.find('op2')))
        elif tag.tag == 'const':
            return Term.TermConstant(tag.text)
        elif tag.tag == 'apply':
            return Term.TermApply(self.readTerm(tag.find('function')),self.readTerm(tag.find('arg')))
        elif tag.tag == 'encrypt':
            return Term.TermEncrypt(self.readTerm(tag.find('op')),self.readTerm(tag.find('key')))
        elif tag.tag == 'var':
            name = Term.TermConstant(tag.get('name'))
            # Instantiate this variable if possible (note this list is empty while reading
            # the variables section of the XML file)
            for inst in self.varlist:
                    if inst.name == name:
                        return inst
            # If it is not instantiated in varlist, just return a variable with this name and no
            # value
            return Term.TermVariable(name,None)
        else:
            raise Term.InvalidTerm, "Invalid term type in XML: %s" % tag.tag
    
    def readEvent(self,xml):
        label = self.readTerm(xml.find('label'))
        follows = xml.findall('follows')
        followlist = []
        for follow in follows: 
            follow = follow.find('after')
            if follow == None:
                # Ignore follow definitions that do not contain after
                continue
            follow = (int(follow.get('run')),int(follow.get('index')))
            followlist.append(follow)
            
        (etype,index) = (xml.get('type'),int(xml.get('index')))
        if etype in ('send','read','recv'):
            fr = self.readTerm(xml.find('from'))
            to = self.readTerm(xml.find('to'))
            message = self.readTerm(xml.find('message'))
            if (etype == 'send'):
                return Trace.EventSend(index,label,followlist,fr,to,message)
            else:
                return Trace.EventRead(index,label,followlist,fr,to,message)
        elif xml.get('type') == 'claim':
            role = self.readTerm(xml.find('role'))
            etype = self.readTerm(xml.find('type'))
            argument = self.readTerm(xml.find('argument'))
            # Freshness claims are implemented as Empty claims with
            # (Fresh,Value) as arguments
            try:
                if etype == 'Empty' and argument[0] == 'Fresh':
                    etype = Term.TermConstant('Fresh')
                    argument = argument[1]
                elif etype == 'Empty' and argument[0] == 'Compromised':
                    etype = Term.TermConstant('Compromised')
                    argument = argument[1]
            except:
                pass
            return Trace.EventClaim(index,label,followlist,role,etype,argument)
        else:
            raise Trace.InvalidAction, "Invalid action in XML: %s" % (xml.get('type'))

    def readRun(self,xml):
        assert(xml.tag == 'run')
        run = Trace.Run()
        run.id = int(xml.find('runid').text)
        # TODO why is protocol name a term??
        run.protocol = str(self.readTerm(xml.find('protocol')))
        run.intruder = xml.find('protocol').get('intruder') == 'true'
        run.role = xml.find('rolename').text
        for role in xml.find('roleagents'):
            name = role.find('rolename').text
            agent = self.readTerm(role.find('agent'))
            run.roleAgents[name] = agent
        for eventxml in xml.find('eventlist'):
            action = self.readEvent(eventxml)
            action.run = run
            run.eventList.append(action)
        for variable in xml.find('variables'):
            # Read the variables one by one
            assert(variable.tag == 'variable')
            var = self.readTerm(variable.find('name').find('term'))
            var.types = self.readTypeList(variable.find('name'))
            
            substxml = variable.find('substitution')
            # Read substitution if present
            if substxml != None:
                subst = self.readTerm(substxml.find('term'))
                subst.types = self.readTypeList(substxml)
                newvar = Term.TermVariable(var.name,subst)
                newvar.types = var.types
                var = newvar

            run.variables.append(var)
        return run
            
    # Read protocol description for a certain role
    def readRoleDescr(self,xml):
        assert(xml.tag == 'role')
        run = Trace.Run()
        # We will need the last label later on to see if a 
        # run is complete
        run.lastLabel = None
        run.role = xml.find('rolename').text
        for eventxml in xml.find('eventlist'):
            action = self.readEvent(eventxml)
            action.run = run
            run.eventList.append(action)
            run.lastLabel = action.label
        return run
    
    def readTypeList(self,xml):
        result = []
        vartypes = xml.find('type').find('termlist')
        for vartype in vartypes:
            # We will assume that types are simple strings
            result.append(str(self.readTerm(vartype)))
        return result
        
    def readClaim(self, xml):
        claim = Claim.Claim()
        for event in xml.getchildren():
            if event.tag == 'claimtype':
                claim.claimtype = self.readTerm(event)
            elif event.tag == 'label':
                # We store the full protocol,label construct for
                # consistency with the technical parts, so it is left to
                # the __str__ of claim to select the right element
                claim.label = self.readTerm(event)
            elif event.tag == 'protocol':
                claim.protocol = self.readTerm(event)
            elif event.tag == 'role':
                claim.role = self.readTerm(event)
            elif event.tag == 'parameter':
                claim.parameter = self.readTerm(event)

            elif event.tag == 'failed':
                claim.failed = int(event.text)
            elif event.tag == 'count':
                claim.count = int(event.text)
            elif event.tag == 'states':
                claim.states = int(event.text)

            elif event.tag == 'complete':
                claim.complete = True
            elif event.tag == 'timebound':
                claim.timebound = True
            else:
                print >>sys.stderr,"Warning unknown tag in claim: %s" % claim.tag

        claim.analyze()
        return claim

    def readAttack(self, xml):
        self.varlist = []
        attack = Attack.Attack()
        attack.id = int(xml.get('id'))
        # A state contains 4 direct child nodes:
        # broken, system, variables and semitrace
        # optionally a fifth: dot
        for event in xml.getchildren():
            if event.tag == 'broken':
                attack.broken.append((self.readTerm(event.find('claim')),
                    self.readTerm(event.find('label'))))
            elif event.tag == 'system':
                attack.match = int(event.find('match').text)
                for term in event.find('commandline'):
                    if attack.commandline != '':
                        attack.commandline += ' ' 
                    attack.commandline += term.text 
                for term in event.find('untrusted').find('termlist'):
                    attack.untrusted.append(str(self.readTerm(term)))
                for term in event.find('initialknowledge').find('termlist'):
                    attack.initialKnowledge.append(self.readTerm(term))
                for keypair in event.find('inversekeys'):
                    inverse = []
                    for term in keypair:
                        inverse.append(self.readTerm(term))
                    assert(len(inverse) == 0 or len(inverse) == 2)
                    attack.inverseKeys.append(inverse)
                # TODO why is protocol name a term??
                for protocolxml in event.findall('protocol'):
                    protocol = str(self.readTerm(protocolxml.find('name')))
                    descr = Trace.ProtocolDescription(protocol)
                    attack.protocoldescr[protocol] = descr
                    for rolexml in protocolxml.findall('role'):
                        roledescr = self.readRoleDescr(rolexml)
                        descr.roledescr[roledescr.role] = roledescr
                    
            elif event.tag == 'semitrace':
                for runxml in event:
                    run = self.readRun(runxml)
                    run.attack = attack
                    attack.semiTrace.runs.append(run)

            elif event.tag == 'dot':
                # Apparently Scyther already generated dot output,
                # store
                attack.scytherDot = event.text

            elif event.tag == 'variables':
                # Read the variables one by one
                for varxml in event:
                    if varxml.get('typeflaw') == 'true':
                        attack.typeflaws = True
                    var = self.readTerm(varxml.find('name').find('term'))
                    var.types = self.readTypeList(varxml.find('name'))
                    
                    substxml = varxml.find('substitution')
                    # Read substitution if present
                    if substxml != None:
                        subst = self.readTerm(substxml.find('term'))
                        subst.types = self.readTypeList(substxml)
                        newvar = Term.TermVariable(var.name,subst)
                        newvar.types = var.types
                        var = newvar
                        
                    attack.variables.append(var)
                    
                # When all have been read set self.varlist so that when
                # we read terms in the attacks they can be filled in using
                # this list
                self.varlist = attack.variables
            else:
                print >>sys.stderr,"Warning unknown tag in attack: %s" % event.tag
        return attack

