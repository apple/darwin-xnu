#!/usr/bin/env python

""" This file holds all static values that debugging macros need. These are typically object type strings, #defines in C etc.
    The objective is to provide a single place to be the bridge between C code in xnu and the python macros used by lldb.
    If you define a variable which has been copied/referred over from C code and has high chance of changing over time. It would
    be best to define a supporting function of format "populate_<variable_name>". This will help in running them to repopulate.
     
    Please take a look at example of kobject_types below before making changes to this file.
    Note: The Format of the function has to be populate_<variable_name> so that the automated updating will pick it up.
"""
import os, re

def GetStateString(strings_dict, state):
    """ Turn a dictionary from flag value to flag name and a state mask with
        those flags into a space-separated string of names.

        params:
            strings_dict: a dictionary of flag values to flag names
            state: the value to get the state string of
        return:
            a space separated list of flag names present in state
    """
    max_mask = max(strings_dict.keys())

    first = True
    output = ''
    mask = 0x1
    while mask <= max_mask:
        bit = int(state & mask)
        if bit:
            if bit in strings_dict:
                if not first:
                    output += ' '
                else:
                    first = False
                output += strings_dict[int(state & mask)]
            else:
                output += '{:#x}'.format(mask)
        mask = mask << 1

    return output

kdebug_flags_strings = { 0x00100000: 'RANGECHECK',
                         0x00200000: 'VALCHECK',
                         0x00400000: 'TYPEFILTER_CHECK',
                         0x80000000: 'BUFINIT' }
kdebug_typefilter_check = 0x00400000

kperf_samplers_strings = { 1 << 0: 'TH_INFO',
                           1 << 1: 'TH_SNAP',
                           1 << 2: 'KSTACK',
                           1 << 3: 'USTACK',
                           1 << 4: 'PMC_THREAD',
                           1 << 5: 'PMC_CPU',
                           1 << 6: 'PMC_CONFIG',
                           1 << 7: 'MEMINFO',
                           1 << 8: 'TH_SCHED',
                           1 << 9: 'TH_DISP',
                           1 << 10: 'TK_SNAP' }

lcpu_self = 0xFFFE
arm_level2_access_strings = [ " noaccess",
                              " supervisor(readwrite) user(noaccess)",
                              " supervisor(readwrite) user(readonly)",
                              " supervisor(readwrite) user(readwrite)",
                              " noaccess(reserved)",
                              " supervisor(readonly) user(noaccess)",
                              " supervisor(readonly) user(readonly)",
                              " supervisor(readonly) user(readonly)",
                              " "
                             ]

kq_state_strings = { 0x000: '',
                     0x001: 'SEL',
                     0x002: 'SLEEP',
                     0x004: 'PROCWAIT',
                     0x008: 'KEV32',
                     0x010: 'KEV64',
                     0x020: 'KEVQOS',
                     0x040: 'WORKQ',
                     0x080: 'WORKLOOP',
                     0x100: 'PROCESS',
                     0x200: 'DRAIN',
                     0x400: 'WAKEUP' }

kn_state_strings = { 0x0000: '',
                     0x0001: 'ACTIVE',
                     0x0002: 'QUEUED',
                     0x0004: 'DISABLED',
                     0x0008: 'DROPPING',
                     0x0010: 'LOCKED',
                     0x0020: 'ATTACHING',
                     0x0040: 'STAYACTIVE',
                     0x0080: 'DEFERDROP',
                     0x0100: 'ATTACHED',
                     0x0200: 'DISPATCH',
                     0x0400: 'UDATASPEC',
                     0x0800: 'SUPPRESS',
                     0x1000: 'MERGE_QOS',
                     0x2000: 'REQVANISH',
                     0x4000: 'VANISHED' }

kqrequest_state_strings = { 0x01: 'WORKLOOP',
                            0x02: 'THREQUESTED',
                            0x04: 'WAKEUP',
                            0x08: 'THOVERCOMMIT',
                            0x10: 'R2K_ARMED',
                            0x20: 'ALLOC_TURNSTILE' }
thread_qos_short_strings = { 0: '--',
                             1: 'MT',
                             2: 'BG',
                             3: 'UT',
                             4: 'DF',
                             5: 'IN',
                             6: 'UI',
                             7: 'MG' }

KQ_WORKQ = 0x40
KQ_WORKLOOP = 0x80
KQWQ_NBUCKETS = 8
KQWL_NBUCKETS = 8

DTYPE_VNODE = 1
DTYPE_SOCKET = 2
DTYPE_PSXSHM = 3
DTYPE_PSXSEM = 4
DTYPE_KQUEUE = 5
DTYPE_PIPE = 6
DTYPE_FSEVENTS = 7
DTYPE_ATALK = 8
DTYPE_NETPOLICY = 9
filetype_strings = { DTYPE_VNODE: 'VNODE',
                     DTYPE_SOCKET: 'SOCKET',
                     DTYPE_PSXSHM: 'PSXSHM',
                     DTYPE_PSXSEM: 'PSXSEM',
                     DTYPE_KQUEUE: 'KQUEUE',
                     DTYPE_PIPE: 'PIPE',
                     DTYPE_FSEVENTS: 'FSEVENTS',
                     DTYPE_ATALK: 'APLTALK',
                     DTYPE_NETPOLICY: 'NETPOLI'
                     }

mach_msg_type_descriptor_strings = {0: "PORT", 1: "OOLDESC", 2: "OOLPORTS", 3: "OOLVOLATILE"}

proc_state_strings = [ "", "Idle", "Run", "Sleep", "Stop", "Zombie", "Reaping" ]
proc_flag_explain_strings = ["!0x00000004 - process is 32 bit",  #only exception that does not follow bit settings
                             "0x00000001 - may hold advisory locks",
                             "0x00000002 - has a controlling tty",
                             "0x00000004 - process is 64 bit",
                             "0x00000008 - no SIGCHLD on child stop",
                             "0x00000010 - waiting for child exec/exit",
                             "0x00000020 - has started profiling",
                             "0x00000040 - in select; wakeup/waiting danger",
                             "0x00000080 - was stopped and continued",
                             "0x00000100 - has set privileges since exec",
                             "0x00000200 - system process: no signals, stats, or swap",
                             "0x00000400 - timing out during a sleep",
                             "0x00000800 - debugged process being traced",
                             "0x00001000 - debugging process has waited for child",
                             "0x00002000 - exit in progress",
                             "0x00004000 - process has called exec",
                             "0x00008000 - owe process an addupc() XXX",
                             "0x00010000 - affinity for Rosetta children",
                             "0x00020000 - wants to run Rosetta",
                             "0x00040000 - has wait() in progress",
                             "0x00080000 - kdebug tracing on for this process",
                             "0x00100000 - blocked due to SIGTTOU or SIGTTIN",
                             "0x00200000 - has called reboot()",
                             "0x00400000 - is TBE state",
                             "0x00800000 - signal exceptions",
                             "0x01000000 - has thread cwd",
                             "0x02000000 - has vfork() children",
                             "0x04000000 - not allowed to attach",
                             "0x08000000 - vfork() in progress",
                             "0x10000000 - no shared libraries",
                             "0x20000000 - force quota for root",
                             "0x40000000 - no zombies when children exit",
                             "0x80000000 - don't hang on remote FS ops"
                             ]
#File: xnu/osfmk/kern/ipc_kobject.h
# string representations for Kobject types
kobject_types = ['', 'THREAD', 'TASK', 'HOST', 'HOST_PRIV', 'PROCESSOR', 'PSET', 'PSET_NAME', 'TIMER', 'PAGER_REQ', 'DEVICE', 'XMM_OBJECT', 'XMM_PAGER', 'XMM_KERNEL', 'XMM_REPLY', 
                     'NOTDEF 15', 'NOTDEF 16', 'HOST_SEC', 'LEDGER', 'MASTER_DEV', 'TASK_NAME', 'SUBSYTEM', 'IO_DONE_QUE', 'SEMAPHORE', 'LOCK_SET', 'CLOCK', 'CLOCK_CTRL' , 'IOKIT_SPARE', 
                      'NAMED_MEM', 'IOKIT_CON', 'IOKIT_OBJ', 'UPL', 'MEM_OBJ_CONTROL', 'AU_SESSIONPORT', 'FILEPORT', 'LABELH', 'TASK_RESUME', 'VOUCHER', 'VOUCHER_ATTR_CONTROL', 'WORK_INTERVAL',
                      'UX_HANDLER']

def populate_kobject_types(xnu_dir_path):
    """ Function to read data from header file xnu/osfmk/kern/ipc_kobject.h
        and populate the known kobject types.
    """
    filename = os.path.join(xnu_dir_path, 'osfmk', 'kern', 'ipc_kobject.h')
    filedata = open(filename).read()
    object_regex = re.compile("^#define\s+(IKOT_[A-Z_]*)\s+(\d+)\s*",re.MULTILINE|re.DOTALL)
    kobject_found_types =[]
    for v in object_regex.findall(filedata):
        kobject_found_types.append(v[0])
    return kobject_found_types

FSHIFT = 11
FSCALE = 1 << FSHIFT

KDBG_BFINIT         = 0x80000000
KDBG_WRAPPED        = 0x008
KDCOPYBUF_COUNT     = 8192
KDS_PTR_NULL        = 0xffffffff

DBG_TRACE               = 1
DBG_TRACE_INFO          = 2
RAW_VERSION1            = 0x55aa0101
EVENTS_PER_STORAGE_UNIT = 2048

EMBEDDED_PANIC_MAGIC = 0x46554E4B
EMBEDDED_PANIC_STACKSHOT_SUCCEEDED_FLAG = 0x02

MACOS_PANIC_MAGIC = 0x44454544

if __name__ == "__main__":
    populate_kobject_types("../../")
    
