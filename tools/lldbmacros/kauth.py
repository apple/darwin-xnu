""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""

from xnu import *
from utils import *

# Macro: walkkauthcache
@lldb_command('walkkauthcache')
def WalkKauthCache(cmd_args=None):
    """ Walks the bins of the kauth credential hash cache and prints out the
        number of bins and bin usage information.
    """
    PrintKauthCache()
# EndMacro: walkkauthcache

def PrintKauthCache(cmd_args=None):
    """ Routine to determine the size of the kauth cache, walk the bins
         and print out usage information.
    """
    anchor = unsigned(kern.globals.kauth_cred_table_anchor)
    alloc_info_struct = anchor - sizeof('struct _mhead')
    alloc_info = kern.GetValueFromAddress(alloc_info_struct, 'struct _mhead*')
    alloc_size = unsigned(alloc_info.mlen) - (sizeof('struct _mhead'))
    table_entries = alloc_size / sizeof('struct kauth_cred_entry_head')
    anchor = kern.globals.kauth_cred_table_anchor
    print "Cred cache has: " + str(table_entries) + " buckets\n"
    print "Number of items in each bucket ... \n"
    for i in range(0, table_entries):
        numinbucket = 0
        for kauth_cred in IterateTAILQ_HEAD(anchor[i], "cr_link"):
            numinbucket += 1
            #print str(kauth_cred.cr_posix)
            #print str(kauth_cred.cr_ref)
        print str(numinbucket) + "\n"
