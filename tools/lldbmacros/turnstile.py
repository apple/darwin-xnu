from xnu import *
import sys, shlex
from utils import *
from waitq import *
import xnudefines

@lldb_type_summary(['struct turnstile *'])
@header("{0: <20s} {1: <5s} {2: <20s} {3: <8s} {4: <8s} {5: <23s} {6: <20s} {7: <16s} {8: <20s} {9: <20s}".format("turnstile", "pri", "waitq", "type", "state", "inheritor", "proprietor", "gen count", "thread", "prev_thread"))
def GetTurnstileSummary(turnstile):
    """ Summarizes the turnstile
        params: turnstile = value of the object of type struct turnstile *
        returns: String with summary of the type.
    """

    type_and_gencount = Cast(addressof(turnstile.ts_type_gencount), 'union turnstile_type_gencount *')
    turnstile_type = ""

    if type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_NONE'):
      turnstile_type = "none   "
    elif type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_KERNEL_MUTEX'):
      turnstile_type = "knl_mtx"
    elif type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_ULOCK'):
      turnstile_type = "ulock  "
    elif type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_PTHREAD_MUTEX'):
      turnstile_type = "pth_mtx"
    elif type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_SYNC_IPC'):
      turnstile_type = "syn_ipc"
    elif type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_WORKLOOPS'):
      turnstile_type = "kqwl   "
    elif type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_WORKQS'):
      turnstile_type = "workq  "
    elif type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_KNOTE'):
      turnstile_type = "knote  "
    elif type_and_gencount.ts_type == GetEnumValue('turnstile_type_t::TURNSTILE_SLEEP_INHERITOR'):
      turnstile_type = "slp_inh"

    turnstile_state = ""
    if turnstile.ts_state & 0x1:
        turnstile_state += "T"
    elif turnstile.ts_state & 0x2:
        turnstile_state += "F"
    elif turnstile.ts_state & 0x4:
        turnstile_state += "H"
    elif turnstile.ts_state & 0x8:
        turnstile_state += "P"

    if turnstile.ts_inheritor_flags & 0x4:
        inheritor_type = "th"
    elif turnstile.ts_inheritor_flags & 0x8:
        inheritor_type = "ts"
    elif turnstile.ts_inheritor_flags & 0x40:
        inheritor_type = "wq"
    else:
        inheritor_type = "--"

    format_str = "{0: <#020x} {1: <5d} {2: <#020x} {3: <8s} {4: <8s} {6: <2s}:{5: <#020x} {7: <#020x} {8: <16d}"
    out_string = format_str.format(turnstile, turnstile.ts_priority, addressof(turnstile.ts_waitq),
            turnstile_type, turnstile_state, turnstile.ts_inheritor, inheritor_type,
            turnstile.ts_proprietor, type_and_gencount.ts_gencount)

    #if DEVELOPMENT
    format_str = " {0: <#020x} {1: <#020x}"
    if hasattr(turnstile, 'ts_thread'):
      out_string += format_str.format(turnstile.ts_thread, turnstile.ts_prev_thread)
    #endif
    return out_string

def PrintTurnstile(turnstile):
    """ print turnstile and it's free list.
        params:
            turnstile - turnstile to print
    """
    print GetTurnstileSummary(turnstile)

    """ print turnstile freelist if its not on a thread or freelist """
    if turnstile.ts_state & 0x3 == 0:
      needsHeader = True
      for free_turnstile in IterateListEntry(turnstile.ts_free_turnstiles, 'struct turnstile *', 'ts_free_elm', 's'):
        if needsHeader:
          print "    Turnstile free List"
          header_str = "    " + GetTurnstileSummary.header
          print header_str
          needsHeader = False
        print "    " + GetTurnstileSummary(free_turnstile)
        print ""
    return

# Macro: showturnstile
@lldb_command('showturnstile')
def ShowTurnstile(cmd_args=None, cmd_options={}):
    """ show the turnstile and all free turnstiles hanging off the turnstile.
        Usage: (lldb)showturnstile <struct turnstile *>
    """
    if not cmd_args:
      raise ArgumentError("Please provide arguments")

    turnstile = kern.GetValueFromAddress(cmd_args[0], 'struct turnstile *')
    print GetTurnstileSummary.header
    PrintTurnstile(turnstile)
    return
# EndMacro: showturnstile

@lldb_command('showturnstilehashtable')
def ShowTurnstileHashTable(cmd_args=None, cmd_options={}):
    """ show the global hash table for turnstiles.
        Usage: (lldb)showturnstilehashtable
    """
    print GetTurnstileSummary.header
    turnstile_htable_buckets = kern.globals.ts_htable_buckets
    for index in range(0, turnstile_htable_buckets):
        turnstile_bucket = GetObjectAtIndexFromArray(kern.globals.turnstile_htable, index)
        for turnstile in IterateQueue(turnstile_bucket.ts_ht_bucket_list, 'struct turnstile *', 'ts_htable_link'):
            PrintTurnstile(turnstile)
    return True

#if DEVELOPMENT
# Macro: showallturnstiles
@lldb_command('showallturnstiles')
def ShowAllTurnstiles(cmd_args=None, cmd_options={}):
    """ A DEVELOPMENT macro that walks the list of all allocated turnstile objects
        and prints them.
        usage: (lldb) showallturnstiles
    """
    if not hasattr(kern.globals, 'turnstiles_list'):
      print "It seems you are running a build of kernel that does not have the list of all turnstiles."
      return False
    print GetTurnstileSummary.header
    for turnstile in IterateQueue(kern.globals.turnstiles_list, 'struct turnstile *', 'ts_global_elm'):
        PrintTurnstile(turnstile)
    return True
# EndMacro showallturnstiles

# Macro: showallbusyturnstiles
@lldb_command('showallbusyturnstiles')
def ShowAllTurnstiles(cmd_args=None, cmd_options={}):
    """ A DEVELOPMENT macro that walks the list of all allocated turnstile objects
        and prints them.
        usage: (lldb) showallbusyturnstiles
    """
    if not hasattr(kern.globals, 'turnstiles_list'):
      print "It seems you are running a build of kernel that does not have the list of all turnstiles."
      return False
    print GetTurnstileSummary.header
    for turnstile in IterateQueue(kern.globals.turnstiles_list, 'struct turnstile *', 'ts_global_elm'):
      if turnstile.ts_state & 0x3 == 0:
        PrintTurnstile(turnstile)
    return True
# EndMacro showallbusyturnstiles

@lldb_command('showthreadbaseturnstiles', fancy=True)
def ShowThreadInheritorBase(cmd_args=None, cmd_options={}, O=None):
    """ A DEVELOPMENT macro that walks the list of userspace turnstiles pushing on a thread
        and prints them.
        usage: (lldb) showthreadbaseturnstiles thread_pointer
    """
    if not cmd_args:
        return O.error('invalid thread pointer')

    thread = kern.GetValueFromAddress(cmd_args[0], "thread_t")
    with O.table(GetTurnstileSummary.header):
        for turnstile in IteratePriorityQueue(thread.base_inheritor_queue, 'struct turnstile', 'ts_inheritor_links'):
            PrintTurnstile(turnstile)

@lldb_command('showthreadschedturnstiles', fancy=True)
def ShowThreadInheritorSched(cmd_args=None, cmd_options={}, O=None):
    """ A DEVELOPMENT macro that walks the list of kernelspace turnstiles pushing on a thread
        and prints them.
        usage: (lldb) showthreadschedturnstiles thread_pointer
    """
    if not cmd_args:
        return O.error('invalid thread pointer')

    thread = kern.GetValueFromAddress(cmd_args[0], "thread_t")
    with O.table(GetTurnstileSummary.header):
        for turnstile in IteratePriorityQueue(thread.sched_inheritor_queue, 'struct turnstile', 'ts_inheritor_links'):
            PrintTurnstile(turnstile)
#endif
