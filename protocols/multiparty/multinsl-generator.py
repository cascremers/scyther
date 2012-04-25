#!/usr/bin/python
#
# Generate Multi-party NSL protocol description for n parties
#
# Input: P variant
#
# variant uses some bits:
#    bit    mask    meaning if set to '1'
#            (message type 1)
#     0    1    nonces in reverse 
#     1    2    nonces after agents
#     2    4    agents in reverse 
#     3    8    interleaved variant
#             (message type 2)
#     4    16    nonces in reverse in message 2
#
# Convention similar to e.g. Prolog: capitals indicate open variables;
# in particular, they can be bound by _any_ value during the run,
# assuming full type flaws.
#
import sys
from optparse import OptionParser

def parseArgs():
    usage = "usage: %s [opts] Parties Variant" % sys.argv[0]
    parser = OptionParser(usage=usage)
    parser.add_option('-p','--protocol', dest='protocol',
        help='Generate another protocol [nsl,bke]', default="nsl",
        action='store')
    (opts, args) = parser.parse_args()
    if len(args) != 2:
        parser.print_help()
        sys.exit(0)
    if opts.protocol not in ["nsl","bke","nsl-priv-noprop","nsl-pub-nap","bke-nap"]:
        print "I don't know the %s protocol." % (opts.protocol)
        sys.exit(0)
    return (opts,args)


def variablerole (r, inrole):
    if r == inrole or inrole == 0:
        return False
    else:
        return True

def role (r,inrole):
    global P

    return "r%i" % (r % P)

def zeroconst ():
    
    """ This is 0 or some other stupid constant """

    return "zeroconst"

def nonce (r,inrole):
    global P

    if r == inrole:
        # nonce of our own
        return "n%i" % (r % P)
    else:
        # a variable: we want to see this in the notation
        return "N%i" % (r % P)

def extend (s1, s2):
    if s1 == "":
        return s2
    else:
        return s1 + "," + s2

def weavel (l1,l2,reverse1,swap,reverse2,interleave):
    """ l1 is typically a list of nonces, l2 might be empty (names) """
    global variant

    if reverse1:
        l1.reverse()
    if l2 == []:
        return l1
    else:
        if reverse2:
            l2.reverse()
        if swap:
            # swap
            l3 = l1
            l1 = l2
            l2 = l3
        if interleave:
            rl = []
            largest = max(len(l1),len(l2))
            for i in range (0,largest):
                if i < len(l1):
                    rl.append(l1[i])
                if i < len(l2):
                    rl.append(l2[i])
            return rl
        else:
            return l1 + l2

def message1 (label,inrole):
    global P,variant,opts

    if opts.protocol in ['bke','nsl']:
        noncelist = []
        for i in range(0,label+1):
            noncelist.append(nonce(i,inrole))
        rolelist = []
        for i in range(0,P):
            if i != (label+1) % P:
                rolelist.append(role(i,inrole))

        return ",".join(weavel(noncelist,rolelist,
            (variant & 1 != 0),
            (variant & 2 != 0),
            (variant & 4 != 0),
            (variant & 8 != 0)
            ))
    elif opts.protocol == 'nsl-priv-noprop':

        list = []
        for i in range(0,P):
            list.append(role(i,inrole))
        list.append(nonce(0,inrole))
        msg = ",".join(list)

        for i in range(1,label+1):
            msg = "{ %s,%s }sk(%s)" % (msg,nonce(i,inrole),role(i,inrole))

        return msg

    elif opts.protocol == 'nsl-pub-nap':

        list = []
        for i in range(0,P):
            list.append(role(i,inrole))
        list.append(nonce(0,inrole))
        msg = ",".join(list)

        for i in range(1,label+1):
            msg = "{ %s }sk(%s), %s" % (msg,role(i,inrole),nonce(i,inrole))

        msg = "{ %s }pk(%s)" % (msg,role(label+1,inrole))

        return msg
    elif opts.protocol == 'bke-nap':

        list = []
        for i in range(0,P):
            list.append(role(i,inrole))
        list.append(nonce(0,inrole))
        msg = ",".join(list)

        for i in range(1,label+1):
            msg = "{ %s }sk(%s), %s" % (msg,role(i,inrole),nonce(i,inrole))

        msg = "{ %s }pk(%s)" % (msg,role(label+1,inrole))

        return msg
    else:
        print "Hmm, I don't know how to create the first message for protocol %s" % (opts.protocol)

def message2 (label,inrole):
    global P,variant,opts

    if opts.protocol == "nsl":
        noncelist = []
        for i in range (((label + 1) % P),P):
            noncelist.append(nonce(i,inrole))

        return ",".join(weavel(noncelist,[],
            (variant & 16 != 0),
            False,
            False,
            False
            ))
    elif opts.protocol == "bke":
        noncelist = []
        for i in range (((label + 1) % P) + 1,P):
            noncelist.append(nonce(i,inrole))
        if len(noncelist) == 0:
            noncelist.append(zeroconst())

        return ",".join(weavel(noncelist,[],
            (variant & 16 != 0),
            False,
            False,
            False
            ))
    elif opts.protocol in ['nsl-priv-noprop','nsl-pub-nap']:
        msg = message1(P-1,inrole)
        for i in range(0,label-P+1):
            msg = "{ %s }sk(%s)" % (msg,role(i,inrole))

        if opts.protocol == 'nsl-pub-nap':
            msg = "{ %s }pk(%s)" % (msg,role(label+1,inrole))

        return msg
    elif opts.protocol == 'bke-nap':
        msg = message1(P-1,inrole)
        for i in range(0,label-P+1):
            msg = "{ %s }sk(%s)" % (msg,role(i,inrole))

        msg = "{ %s }%s" % (msg,nonce((label+1) % P,inrole))

        return msg
    else:
        print "Hmm, I don't know how to create the final message for protocol %s" % (opts.protocol)

def message (label,inrole):
    global P,opts

    if opts.protocol in ['bke','nsl']:
        s = "{ "
        if label < P:
            s = s + message1 (label,inrole)
        else:
            s = s + message2 (label,inrole)

        if opts.protocol == "bke" and not (label < P):
            s = s + " }" + nonce((label+1) % P, inrole)
        else:
            s = s + " }pk(%s)" % role(label+1,inrole)
        return s
    else:
        if label < P:
            return message1 (label,inrole)
        else:
            return message2 (label,inrole)


def action (event,label,inrole):
    s = "\t\t%s_%i(%s,%s, " % (event,label, role(label,inrole),
            role(label+1,inrole))
    s += message (label,inrole)
    s += " );\n"
    return s

def recv (label,inrole):
    return action ("recv", label,inrole)


def send (label,inrole):
    return action ("send", label,inrole)

def roledef (r):
    global P,opts

    s = ""
    s += "\trole " + role(r,r) + "\n\t{\n"

    # constants for this role
    
    s += "\t\tconst " + nonce (r,r) + ": Nonce;\n"

    # variables
    
    s += "\t\tvar "
    nr = 0
    for i in range (0,P):
        if r != i:
            if nr > 0:
                s += ","
            s += nonce(i,r)
            nr += 1

    s += ": Nonce;\n"

    # implicit role variables
    
    rolevars = []
    for i in range (0,P):
        if variablerole(i,r):
            rolevars.append(role(i,r))

    if rolevars != []:
        s += "\t\t// Implicit role variables: "
        s += ",".join(rolevars)
        s += ": Role;\n"
        
    # actions
    
    s += "\n"
    if r > 0:
        # Initial recv
        s += recv(r-1,r)
    s += send(r,r)
    s += recv(P+r-1,r)
    if r < (P-1):
        # Final send
        s += send(P+r,r)
    
    # claims
    
    if opts.protocol in ['bke','nsl','nsl-pub-nap','bke-nap']:
        s += "\t\tclaim_%sa( %s, Secret, %s );\n" % (role(r,r), role(r,r),
                nonce(r,r))
    s += "\t\tclaim_%sb( %s, Nisynch );\n" % (role(r,r), role(r,r))

    # close
    s += "\t}\n\n"
    return s


def protocol (args):
    global P,variant,opts

    P = int(args[0])
    variant = int(args[1])

    s = ""
    s += "// Generalized %s protocol for %i parties\n\n" % (opts.protocol,P)
    s += "// " + str(opts) + "\n\n"
    s += "// Variant %i\n" % variant
    
    if opts.protocol == "bke":
        s += "usertype Globalconstant;\n"
        s += "const %s: Globalconstant;\n" % (zeroconst())

    s += "\n"

    s += "protocol mnsl%iv%i(" % (P,variant)
    for i in range (0,P):
        if i > 0:
            s += ","
        s += role(i,i)
    s += ")\n{\n"

    for i in range (0,P):
        s += roledef(i)
    
    s += "}\n\n"

    s += "\n"
    return s

def main():
    global opts

    (opts,args) = parseArgs()
    print protocol(args)

# Only if main stuff
if __name__ == '__main__':
     main()
