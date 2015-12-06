#!/usr/bin/env python

""" This file holds all static values that debugging macros need. These are typically object type strings, #defines in C etc.
    The objective is to provide a single place to be the bridge between C code in xnu and the python macros used by lldb.
    If you define a variable which has been copied/referred over from C code and has high chance of changing over time. It would
    be best to define a supporting function of format "populate_<variable_name>". This will help in running them to repopulate.
     
    Please take a look at example of kobject_types below before making changes to this file.
    Note: The Format of the function has to be populate_<variable_name> so that the automated updating will pick it up.
"""
import os, re

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
kq_state_strings = {0:"", 1:"SEL", 2:"SLEEP", 4:"PROCWAIT", 8:"KEV32", 16:"KEV64"}

kn_state_strings = {0:"", 1:"ACTIVE", 2:"QUEUED", 4:"DISABLED", 8:"DROPPING", 16:"USERWAIT", 32:"ATTACHING", 64:"STAYQUED"}

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
                      'NAMED_MEM', 'IOKIT_CON', 'IOKIT_OBJ', 'UPL', 'MEM_OBJ_CONTROL', 'AU_SESSIONPORT', 'FILEPORT', 'LABELH', 'TASK_RESUME', 'VOUCHER', 'VOUCHER_ATTR_CONTROL']

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

if __name__ == "__main__":
    populate_kobject_types("../../")
    
