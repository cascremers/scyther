#
# Misc.py
# Various helper functions

#---------------------------------------------------------------------------

""" Import externals """
import os.path

#---------------------------------------------------------------------------

def confirm(question):
    answer = ''
    while answer not in ('y','n'):
        print question,
        answer = raw_input().lower()
    return answer == 'y'

def exists(func,list):
    return len(filter(func,list)) > 0    

def forall(func,list):
    return len(filter(func,list)) == len(list)    

def uniq(li):
    result = []
    for elem in li:
        if (not elem in result):
            result.append(elem)
    return result

# Return a sorted copy of a list
def sorted(li):
    result = li[:]
    result.sort()
    return result


# path
def mypath(file):
    """ Construct a file path relative to the scyther-gui main directory
    """
    basedir = os.path.dirname(__file__)
    return os.path.join(basedir,file)

