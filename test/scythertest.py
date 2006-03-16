#!/usr/bin/python
#
#    Scyther wrapper
#
#    Standard tests
#
import os
import sys
from optparse import OptionParser
from scythercache import evaluate, scytheroverride, cacheoverride


#----------------------------------------------------------------------------
# Globals
#----------------------------------------------------------------------------
g_extra = ""

#----------------------------------------------------------------------------
# Parsing Output
#----------------------------------------------------------------------------

# status
def error_status(status):
    if status == 1 or status < 0:
        return True
    else:
        return False

# Parse output
def parse(scout):
    results = {}
    lines = scout.splitlines()
    for line in lines:
        data = line.split()
        if len(data) > 4 and data[0] == 'claim':
            claim = " ".join(data[1:2])
            tag = data[4]
            value = -1
            if tag == 'Fail':
                value = 0
            if tag == 'Ok':
                value = 1
            if value == -1:
                raise IOError, 'Scyther output for ' + commandline + ', line ' + line + ' cannot be parsed.'
            results[claim] = value
    return results

#----------------------------------------------------------------------------
# Default tests
#----------------------------------------------------------------------------

# Yield default protocol list (from any other one)
def default_protocols(plist):
    plist.sort()
    defaults = os.path.expanduser("~/svn/ecss/protocols/spdl/misc/spdl-defaults.inc")
    return [defaults] + plist

# Get the extra parameters
def get_extra_parameters():
    global g_extra

    return g_extra

# Set the extra parameters
def set_extra_parameters(args):
    global g_extra

    g_extra = args

# Add the extra parameters
def add_extra_parameters(args):
    global g_extra

    if args != "":
        if g_extra.find(args) == -1:
            if g_extra != "":
                g_extra = g_extra + " "
            g_extra = g_extra + args

# Yield arguments, given a bound type:
#     0: fast
#     1: thorough
#
def default_arguments(plist,match,bounds):
    n = 2 + bounds
    # These bounds assume at least two protocols, otherwise
    # stuff breaks.
    if n < 2:
        nmin = 2
    else:
        nmin = n
    timer = 1
    maxruns = 2
    maxlength = 10
    if bounds == 0:
        timer = 10 * (nmin**2)
        maxruns = 2*nmin
        maxlength = 2 + maxruns * 4
    elif bounds == 1:
        timer = 10 * (nmin**3)
        maxruns = 3*nmin
        maxlength = 4 + maxruns * 6
    elif bounds == 2:
        timer = 10 * 60    # 10 minutes
        maxruns = 3*nmin
        maxlength = 4 + maxruns * 6
    else:
        print "Don't know bounds method", bounds
        sys.exit()

    args = ""
    if timer > 0:
        args = args + " --timer=%i" % timer
    args = args + " --max-runs=%i --max-length=%i" % (maxruns, maxlength)

    if int(match) > 0:
        args += " --untyped"

    args += " --plain"

    args = get_extra_parameters() + " " + args
    return args

# Yield test results
def default_test(plist, match, bounds):
    pl = default_protocols(plist)
    args = default_arguments(plist,match,bounds)

    input = ""
    for fn in pl:
        if len(fn) > 0:
            f = open(fn, "r")
            input = input + f.read()
            f.close()
    
    # Use Scyther
    (status,scout) = evaluate(args,input)
    return (status,scout)

# Test, check for status, yield parsed results
def default_parsed(plist, match, bounds):
    (status,scout) = default_test(plist, match, bounds)
    if error_status(status):
        # Something went wrong
        print "*** Error when checking [", plist, match, bounds, "]"
        print
        sys.exit()
    return parse(scout)

# Some default options for the scyther wrapper
def default_options(parser):
    parser.add_option("-m","--match", dest="match",
            default = 0,
            help = "select matching method (0: no type flaws, 2: \
            full type flaws")
    parser.add_option("-b","--bounds", dest="bounds",
            default = 0,
            help = "bound type selection (0: quickscan, 1:thorough, 2: no time limit)")
    parser.add_option("-x","--extra", dest="extra",
            default = "",
            help = "add arguments to pass to Scyther")
    parser.add_option("-P","--program", dest="program",
            default = "",
            help = "define alternative scyther executable")
    parser.add_option("-N","--no-cache", dest="nocache",
            default = False,
            action = "store_true",
            help = "do not use cache mechanism")

# Process the default options
def process_default_options(options):
    if options.program != "":
        scytheroverride(options.program)
        print "Using", options.program, "as Scyther executable."
    if options.extra != "":
        add_extra_parameters(options.extra)
        print "Added extra options, now:", get_extra_parameters()
    if options.nocache:
        # Do not use cache
        print "Warning: Disabling cache"
        cacheoverride ()


#----------------------------------------------------------------------------
# Some default testing stuff
#----------------------------------------------------------------------------

def all_unless_given(plist):
    if plist == []:
        # Get the list
        import protocollist
        return protocollist.from_all()
    else:
        return plist

#    Scan for compilation errors or stuff like that

def scan_for_results(options,args):
    # Select specific list
    plist = all_unless_given(args)
    # Now check all things in the list
    for p in plist:
        # Test and gather output
        (status,scout) = default_test([p], 0, 0)
        print scout

    print
    print "Scan complete."

def scan_for_errors(options,args):
    # Select specific list
    plist = all_unless_given(args)
    # Now check all things in the list
    errorcount = 0
    for p in plist:
        # Test and gather output
        (status,scout) = default_test([p], 0, 0)
        error = False
        if error_status(status):
            error = True
        else:
            if scout.rfind("ERROR") != -1:
                error = True
            if scout.rfind("error") != -1:
                error = True
        if error:
            print "There is an error in the output for", p
            errorcount = errorcount + 1

    if errorcount > 0:
        print
    print "Scan complete. Found", errorcount, "error(s) in", len(plist), "files."

#    Scan for timeout protocols
#
#    The idea is that some things will generate a timeout, and we would like
#    to know which ones. However, this can just be a problem of the time
#    limit, and might not be caused by a loop at all. Therefore, some
#    scanning is needed.

def scan_for_timeouts(options,args):

    def parse_timeout(status,scout):
        if not error_status(status):
            if scout.rfind("time=") != -1:
                return True
        return False

    def check_for_timeout(p):
        # First a simple test
        (status,scout) = default_test([p], 0, 1)
        if not parse_timeout(status,scout):
            # Well if there is no timeout here...
            return False

        # More testing...
        
        return True

    # Select specific list
    plist = all_unless_given(args)
    # Now check all things in the list
    errorcount = 0
    for p in plist:
        # Test and gather output
        if check_for_timeout(p):
            print "There is a timeout for", p
            errorcount = errorcount + 1

    if errorcount > 0:
        print
    print "Scan complete. Found", errorcount, "timeout(s) in", len(plist), "files."

#----------------------------------------------------------------------------
# Standalone usage
#----------------------------------------------------------------------------

def main():
    parser = OptionParser()
    default_options(parser)
    parser.add_option("-e","--errors", dest="errors",
            default = False,
            action = "store_true",
            help = "detect compilation errors for all protocols [in list_all]")
    parser.add_option("-r","--results", dest="results",
            default = False,
            action = "store_true",
            help = "scan for results for all protocols [in list_all]")
    parser.add_option("-t","--timeouts", dest="timeouts",
            default = False,
            action = "store_true",
            help = "scan for timeout errors for all protocols [in list_all]")
    (options, args) = parser.parse_args()

    # Globals
    process_default_options(options)

    # Subcases
    if options.errors:
        scan_for_errors(options,args)
    elif options.results:
        scan_for_results(options,args)
    elif options.timeouts:
        scan_for_timeouts(options,args)
    else:
        # Not any other switch: just test the list then
        if args == []:
            print "Scyther default test needs at least one input file."
            sys.exit()
        (status,scout) = default_test(args, options.match, options.bounds)
        print "Status:", status
        print scout

# Only if main stuff
if __name__ == '__main__':
    main()
