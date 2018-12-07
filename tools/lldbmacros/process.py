
""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""

from xnu import *
import sys, shlex
from utils import *
from core.lazytarget import *
import time
import xnudefines
import memory

def GetProcNameForTask(task):
    """ returns a string name of the process. if proc is not valid "unknown" is returned
        params:
            task: value object represeting a task in the kernel.
        returns:
            str : A string name of the process linked to the task
    """
    if not task or not unsigned(task.bsd_info):
        return "unknown"
    p = Cast(task.bsd_info, 'proc *')
    return str(p.p_comm)

def GetProcPIDForTask(task):
    """ returns a int pid of the process. if the proc is not valid, val[5] from audit_token is returned.
        params:
            task: value object representing a task in the kernel
        returns:
            int : pid of the process or -1 if not found
    """
    if task and unsigned(task.bsd_info):
        p = Cast(task.bsd_info, 'proc *')
        return unsigned(p.p_pid)
    
    if task :
        return unsigned(task.audit_token.val[5])

    return -1

def GetProcInfo(proc):
    """ returns a string name, pid, parent and task for a proc_t. Decodes cred, flag and p_stat fields.
        params:
            proc : value object representing a proc in the kernel
        returns:
            str : A string describing various information for process.
    """
    out_string = ""
    out_string += ("Process {p: <#020x}\n\tname {p.p_comm: <20s}\n\tpid:{p.p_pid: <6d} " + 
                   "task:{p.task: <#020x} p_stat:{p.p_stat: <6d} parent pid: {p.p_ppid: <6d}\n"
                   ).format(p=proc)
    #print the Creds
    ucred = proc.p_ucred
    if ucred:
        out_string += "Cred: euid {:d} ruid {:d} svuid {:d}\n".format(ucred.cr_posix.cr_uid,
                                                                      ucred.cr_posix.cr_ruid,
                                                                      ucred.cr_posix.cr_svuid )
    #print the flags
    flags = int(proc.p_flag)
    out_string += "Flags: {0: <#020x}\n".format(flags)
    i = 1
    num = 1
    while num <= flags:
        if flags & num:
            out_string += "\t" + xnudefines.proc_flag_explain_strings[i] + "\n"
        elif num == 0x4: #special case for 32bit flag
            out_string += "\t" + xnudefines.proc_flag_explain_strings[0] + "\n"
        i += 1
        num = num << 1
    out_string += "State: "
    state_val = proc.p_stat
    if state_val < 1 or state_val > len(xnudefines.proc_state_strings) :
        out_string += "(Unknown)"
    else:
        out_string += xnudefines.proc_state_strings[int(state_val)]
    
    return out_string
    
def GetProcNameForPid(pid):
    """ Finds the name of the process corresponding to a given pid
        params:
            pid     : int, pid you want to find the procname for
        returns
            str     : Name of the process corresponding to the pid, "Unknown" if not found
    """
    for p in kern.procs:
        if int(p.p_pid) == int(pid):
            return str(p.p_comm)
    return "Unknown"

def GetProcForPid(search_pid):
    """ Finds the value object representing a proc in the kernel based on its pid
        params:
            search_pid  : int, pid whose proc structure you want to find
        returns:
            value       : The value object representing the proc, if a proc corresponding
                          to the given pid is found. Returns None otherwise
    """
    if search_pid == 0:
        return kern.globals.initproc
    else:
        headp = kern.globals.allproc
        for proc in IterateListEntry(headp, 'struct proc *', 'p_list'):
            if proc.p_pid == search_pid:
                return proc
        return None

@lldb_command('allproc')
def AllProc(cmd_args=None):
    """ Walk through the allproc structure and print procinfo for each process structure. 
        params: 
            cmd_args - [] : array of strings passed from lldb command prompt
    """
    for proc in kern.procs :
        print GetProcInfo(proc)
    

@lldb_command('zombproc')
def ZombProc(cmd_args=None):
    """ Routine to print out all procs in the zombie list
        params: 
            cmd_args - [] : array of strings passed from lldb command prompt
    """
    if len(kern.zombprocs) != 0:
        print "\nZombie Processes:"
        for proc in kern.zombprocs:
            print GetProcInfo(proc) + "\n\n"

@lldb_command('zombtasks')
def ZombTasks(cmd_args=None):
    """ Routine to print out all tasks in the zombie list
        params: None
    """
    out_str = ""
    if len(kern.zombprocs) != 0:
        header = "\nZombie Tasks:\n"
        header += GetTaskSummary.header + " " + GetProcSummary.header
        for proc in kern.zombprocs:
            if proc.p_stat != 5:
                t = Cast(proc.task, 'task *')
                out_str += GetTaskSummary(t) +" "+ GetProcSummary(proc) + "\n"
        if out_str != "":
            print header
            print out_str

@lldb_command('zombstacks')
def ZombStacks(cmd_args=None):
    """ Routine to print out all stacks of tasks that are exiting
    """
    header_flag = 0
    for proc in kern.zombprocs:
        if proc.p_stat != 5:
            if header_flag == 0:
                print "\nZombie Stacks:"
                header_flag = 1
            t = Cast(proc.task, 'task *')
            ShowTaskStacks(t)
#End of Zombstacks

def GetASTSummary(ast):
    """ Summarizes an AST field
        Flags:
        P - AST_PREEMPT
        Q - AST_QUANTUM
        U - AST_URGENT
        H - AST_HANDOFF
        Y - AST_YIELD
        A - AST_APC
        L - AST_LEDGER
        B - AST_BSD
        K - AST_KPERF
        M - AST_MACF
        G - AST_GUARD
        T - AST_TELEMETRY_USER
        T - AST_TELEMETRY_KERNEL
        T - AST_TELEMETRY_WINDOWED
        S - AST_SFI
        D - AST_DTRACE
        I - AST_TELEMETRY_IO
        E - AST_KEVENT
        R - AST_REBALANCE
        N - AST_UNQUIESCE
    """
    out_string = ""
    state = int(ast)
    thread_state_chars = {0x0:'', 0x1:'P', 0x2:'Q', 0x4:'U', 0x8:'H', 0x10:'Y', 0x20:'A',
                          0x40:'L', 0x80:'B', 0x100:'K', 0x200:'M',
                          0x1000:'G', 0x2000:'T', 0x4000:'T', 0x8000:'T', 0x10000:'S',
                          0x20000: 'D', 0x40000: 'I', 0x80000: 'E', 0x100000: 'R', 0x200000: 'N'}
    state_str = ''
    mask = 0x1
    while mask <= 0x80000:
        state_str += thread_state_chars[int(state & mask)]
        mask = mask << 1

    return state_str


@lldb_type_summary(['kcdata_descriptor *', 'kcdata_descriptor_t'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: <10s} {4: <5s}".format("kcdata_descriptor", "begin_addr", "cur_pos", "size", "flags"))
def GetKCDataSummary(kcdata):
    """ Summarizes kcdata_descriptor structure
        params: kcdata: value - value object representing kcdata_descriptor
        returns: str - summary of the kcdata object
    """
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x} {3: <10d} {4: <#05x}"
    return format_string.format(kcdata, kcdata.kcd_addr_begin, kcdata.kcd_addr_end, kcdata.kcd_length, kcdata.kcd_flags)


@lldb_type_summary(['task', 'task_t'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: >5s} {4: <5s}".format("task","vm_map", "ipc_space", "#acts", "flags"))
def GetTaskSummary(task, showcorpse=False):
    """ Summarizes the important fields in task structure.
        params: task: value - value object representing a task in kernel
        returns: str - summary of the task
    """
    out_string = ""
    format_string = '{0: <#020x} {1: <#020x} {2: <#020x} {3: >5d} {4: <5s}'
    thread_count = int(task.thread_count)
    task_flags = ''
    if hasattr(task, "suppression_generation") and (int(task.suppression_generation) & 0x1) == 0x1:
        task_flags += 'P'
    if hasattr(task, "effective_policy") and int(task.effective_policy.tep_sup_active) == 1:
        task_flags += 'N'
    if hasattr(task, "suspend_count") and int(task.suspend_count) > 0:
        task_flags += 'S'
    if hasattr(task, 'task_imp_base') and unsigned(task.task_imp_base):
        tib = task.task_imp_base
        if int(tib.iit_receiver) == 1:
            task_flags += 'R'
        if int(tib.iit_donor) == 1:
            task_flags += 'D'
        if int(tib.iit_assertcnt) > 0:
            task_flags += 'B'

    # check if corpse flag is set
    if unsigned(task.t_flags) & 0x20:
        task_flags += 'C'
    if unsigned(task.t_flags) & 0x40:
        task_flags += 'P'

    out_string += format_string.format(task, task.map, task.itk_space, thread_count, task_flags)
    if showcorpse is True and unsigned(task.corpse_info) != 0:
        out_string += " " + GetKCDataSummary(task.corpse_info)
    return out_string

def GetThreadName(thread):
    """ Get the name of a thread, if possible.  Returns the empty string
        otherwise.
    """
    if int(thread.uthread) != 0:
        uthread = Cast(thread.uthread, 'uthread *')
        if int(uthread.pth_name) != 0 :
            th_name_strval = Cast(uthread.pth_name, 'char *')
            if len(str(th_name_strval)) > 0 :
                return str(th_name_strval)

    return ''

@lldb_type_summary(['thread *', 'thread_t'])
@header("{0: <24s} {1: <10s} {2: <20s} {3: <6s} {4: <6s} {5: <15s} {6: <15s} {7: <8s} {8: <12s} {9: <32s} {10: <20s} {11: <20s} {12: <20s}".format('thread', 'thread_id', 'processor', 'base', 'pri', 'sched_mode', 'io_policy', 'state', 'ast', 'waitq', 'wait_event', 'wmesg', 'thread_name'))
def GetThreadSummary(thread):
    """ Summarize the thread structure. It decodes the wait state and waitevents from the data in the struct.
        params: thread: value - value objecte representing a thread in kernel
        returns: str - summary of a thread
        
        State flags:
        W - WAIT
        S - SUSP
        R - RUN
        U - Uninterruptible
        H - Terminated
        A - Terminated and on termination queue
        I - Idle thread
        C - Crashed thread

        policy flags:
        B - darwinbg
        T - IO throttle
        P - IO passive
        D - Terminated
    """
    out_string = ""
    format_string = "{0: <24s} {1: <10s} {2: <20s} {3: <6s} {4: <6s} {5: <15s} {6: <15s} {7: <8s} {8: <12s} {9: <32s} {10: <20s} {11: <20s} {12: <20s}"
    thread_ptr_str = str("{0: <#020x}".format(thread))
    if int(thread.static_param) : 
        thread_ptr_str+="[WQ]"
    thread_id = hex(thread.thread_id)
    processor = hex(thread.last_processor)
    base_priority = str(int(thread.base_pri))
    sched_priority = str(int(thread.sched_pri))
    sched_mode = ''
    mode = str(thread.sched_mode)
    if "TIMESHARE" in mode:
        sched_mode+="timeshare"
    elif "FIXED" in mode:
        sched_mode+="fixed"
    elif "REALTIME" in mode:
        sched_mode+="realtime"
        
    if (unsigned(thread.bound_processor) != 0):
        sched_mode+=" bound"
        
    # TH_SFLAG_THROTTLED
    if (unsigned(thread.sched_flags) & 0x0004):
        sched_mode+=" BG"
    
    io_policy_str = ""
    thread_name = GetThreadName(thread)
    if int(thread.uthread) != 0:
        uthread = Cast(thread.uthread, 'uthread *')

        #check for io_policy flags 
        if int(uthread.uu_flag) & 0x400:
            io_policy_str+='RAGE '
        
        #now flags for task_policy
        
        io_policy_str = ""
        
        if int(thread.effective_policy.thep_darwinbg) != 0:
            io_policy_str += "B"
        if int(thread.effective_policy.thep_io_tier) != 0:
            io_policy_str += "T"
        if int(thread.effective_policy.thep_io_passive) != 0:
            io_policy_str += "P"
        if int(thread.effective_policy.thep_terminated) != 0:
            io_policy_str += "D"
                
    state = int(thread.state)
    thread_state_chars = {0x0:'', 0x1:'W', 0x2:'S', 0x4:'R', 0x8:'U', 0x10:'H', 0x20:'A', 0x40:'P', 0x80:'I'}
    state_str = ''
    mask = 0x1
    while mask <= 0x80 :
        state_str += thread_state_chars[int(state & mask)]
        mask = mask << 1
    
    if int(thread.inspection):
        state_str += 'C'

    ast = int(thread.ast) | int(thread.reason)
    ast_str = GetASTSummary(ast)
    
    #wait queue information
    wait_queue_str = ''
    wait_event_str = ''
    wait_message = ''
    if ( state & 0x1 ) != 0:
        #we need to look at the waitqueue as well
        wait_queue_str = str("{0: <#020x}".format(int(hex(thread.waitq), 16)))
        wait_event_str = str("{0: <#020x}".format(int(hex(thread.wait_event), 16)))
        wait_event_str_sym = kern.Symbolicate(int(hex(thread.wait_event), 16))
        if len(wait_event_str_sym) > 0:
            wait_event_str = wait_event_str.strip() + " <" + wait_event_str_sym + ">"
        if int(thread.uthread) != 0 :
            uthread = Cast(thread.uthread, 'uthread *')
            if int(uthread.uu_wmesg) != 0:
                wait_message = str(Cast(uthread.uu_wmesg, 'char *'))
            
    out_string += format_string.format(thread_ptr_str, thread_id, processor, base_priority, sched_priority, sched_mode, io_policy_str, state_str, ast_str, wait_queue_str, wait_event_str, wait_message, thread_name)
    return out_string


def GetTaskRoleString(role):
    role_strs = {
                 0 : "TASK_UNSPECIFIED",
                 1 : "TASK_FOREGROUND_APPLICATION",
                 2 : "TASK_BACKGROUND_APPLICATION",
                 3 : "TASK_CONTROL_APPLICATION",
                 4 : "TASK_GRAPHICS_SERVER",
                 5 : "TASK_THROTTLE_APPLICATION",
                 6 : "TASK_NONUI_APPLICATION",
                 7 : "TASK_DEFAULT_APPLICATION",
                }
    return role_strs[int(role)]

def GetCoalitionFlagString(coal):
    flags = []
    if (coal.privileged):
        flags.append('privileged')
    if (coal.termrequested):
        flags.append('termrequested')
    if (coal.terminated):
        flags.append('terminated')
    if (coal.reaped):
        flags.append('reaped')
    if (coal.notified):
        flags.append('notified')
    if (coal.efficient):
        flags.append('efficient')
    return "|".join(flags)

def GetCoalitionTasks(queue, coal_type, thread_details=False):
    sfi_strs = {
                 0x0  : "SFI_CLASS_UNSPECIFIED",
                 0x1  : "SFI_CLASS_DARWIN_BG",
                 0x2  : "SFI_CLASS_APP_NAP",
                 0x3  : "SFI_CLASS_MANAGED_FOCAL",
                 0x4  : "SFI_CLASS_MANAGED_NONFOCAL",
                 0x5  : "SFI_CLASS_DEFAULT_FOCAL",
                 0x6  : "SFI_CLASS_DEFAULT_NONFOCAL",
                 0x7  : "SFI_CLASS_KERNEL",
                 0x8  : "SFI_CLASS_OPTED_OUT",
                 0x9  : "SFI_CLASS_UTILITY",
                 0xA  : "SFI_CLASS_LEGACY_FOCAL",
                 0xB  : "SFI_CLASS_LEGACY_NONFOCAL",
                 0xC  : "SFI_CLASS_USER_INITIATED_FOCAL",
                 0xD  : "SFI_CLASS_USER_INITIATED_NONFOCAL",
                 0xE  : "SFI_CLASS_USER_INTERACTIVE_FOCAL",
                 0xF  : "SFI_CLASS_USER_INTERACTIVE_NONFOCAL",
                 0x10 : "SFI_CLASS_MAINTENANCE",
                }
    tasks = []
    field_name = 'task_coalition'
    for task in IterateLinkageChain(queue, 'task *', field_name, coal_type * sizeof('queue_chain_t')):
        task_str = "({0: <d},{1: #x}, {2: <s}, {3: <s})".format(GetProcPIDForTask(task),task,GetProcNameForTask(task),GetTaskRoleString(task.effective_policy.tep_role))
        if thread_details:
            for thread in IterateQueue(task.threads, "thread_t", "task_threads"):
                task_str += "\n\t\t\t|-> thread:" + hex(thread) + ", " + sfi_strs[int(thread.sfi_class)]
        tasks.append(task_str)
    return tasks

def GetCoalitionTypeString(type):
    """ Convert a coalition type field into a string
    Currently supported types (from <mach/coalition.h>):
        COALITION_TYPE_RESOURCE
        COALITION_TYPE_JETSAM
    """
    if type == 0: # COALITION_TYPE_RESOURCE
        return 'RESOURCE'
    if type == 1:
        return 'JETSAM'
    return '<unknown>'

def GetResourceCoalitionSummary(coal, verbose=False):
    """ Summarize a resource coalition
    """
    out_string = "Resource Coalition:\n\t  Ledger:\n"
    thread_details = False
    if config['verbosity'] > vSCRIPT:
        thread_details = True
    ledgerp = coal.r.ledger
    if verbose and unsigned(ledgerp) != 0:
        i = 0
        while i != ledgerp.l_template.lt_cnt:
            out_string += "\t\t"
            out_string += GetLedgerEntrySummary(kern.globals.task_ledger_template, ledgerp.l_entries[i], i)
            i = i + 1
    out_string += "\t  bytesread {0: <d}\n\t  byteswritten {1: <d}\n\t  gpu_time {2: <d}".format(coal.r.bytesread, coal.r.byteswritten, coal.r.gpu_time)
    out_string += "\n\t  total_tasks {0: <d}\n\t  dead_tasks {1: <d}\n\t  active_tasks {2: <d}".format(coal.r.task_count, coal.r.dead_task_count, coal.r.task_count - coal.r.dead_task_count)
    out_string += "\n\t  last_became_nonempty_time {0: <d}\n\t  time_nonempty {1: <d}".format(coal.r.last_became_nonempty_time, coal.r.time_nonempty)
    out_string += "\n\t  cpu_ptime {0: <d}".format(coal.r.cpu_ptime)
    if verbose:
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_DEFAULT] {0: <d}".format(coal.r.cpu_time_eqos[0])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_MAINTENANCE] {0: <d}".format(coal.r.cpu_time_eqos[1])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_BACKGROUND] {0: <d}".format(coal.r.cpu_time_eqos[2])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_UTILITY] {0: <d}".format(coal.r.cpu_time_eqos[3])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_LEGACY] {0: <d}".format(coal.r.cpu_time_eqos[4])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_USER_INITIATED] {0: <d}".format(coal.r.cpu_time_eqos[5])
        out_string += "\n\t  cpu_time_effective[THREAD_QOS_USER_INTERACTIVE] {0: <d}".format(coal.r.cpu_time_eqos[6])
    out_string += "\n\t  Tasks:\n\t\t"
    tasks = GetCoalitionTasks(addressof(coal.r.tasks), 0, thread_details)
    out_string += "\n\t\t".join(tasks)
    return out_string

def GetJetsamCoalitionSummary(coal, verbose=False):
    out_string = "Jetsam Coalition:"
    thread_details = False
    if config['verbosity'] > vSCRIPT:
        thread_details = True
    if unsigned(coal.j.leader) == 0:
        out_string += "\n\t  NO Leader!"
    else:
        out_string += "\n\t  Leader:\n\t\t"
        out_string += "({0: <d},{1: #x}, {2: <s}, {3: <s})".format(GetProcPIDForTask(coal.j.leader),coal.j.leader,GetProcNameForTask(coal.j.leader),GetTaskRoleString(coal.j.leader.effective_policy.tep_role))
    out_string += "\n\t  Extensions:\n\t\t"
    tasks = GetCoalitionTasks(addressof(coal.j.extensions), 1, thread_details)
    out_string += "\n\t\t".join(tasks)
    out_string += "\n\t  XPC Services:\n\t\t"
    tasks = GetCoalitionTasks(addressof(coal.j.services), 1, thread_details)
    out_string += "\n\t\t".join(tasks)
    out_string += "\n\t  Other Tasks:\n\t\t"
    tasks = GetCoalitionTasks(addressof(coal.j.other), 1, thread_details)
    out_string += "\n\t\t".join(tasks)
    out_string += "\n\t  Thread Group: {0: <#020x}\n".format(coal.j.thread_group)
    return out_string

@lldb_type_summary(['coalition_t', 'coalition *'])
@header("{0: <20s} {1: <15s} {2: <10s} {3: <10s} {4: <10s} {5: <12s} {6: <12s} {7: <20s}".format("coalition", "type", "id", "ref count", "act count", "focal cnt", "nonfocal cnt","flags"))
def GetCoalitionSummary(coal):
    if unsigned(coal) == 0:
        return '{0: <#020x} {1: <15s} {2: <10d} {3: <10d} {4: <10d} {5: <12d} {6: <12d} {7: <s}'.format(0, "", -1, -1, -1, -1, -1, "")
    out_string = ""
    format_string = '{0: <#020x} {1: <15s} {2: <10d} {3: <10d} {4: <10d} {5: <12d} {6: <12d} {7: <s}'
    type_string = GetCoalitionTypeString(coal.type)
    flag_string = GetCoalitionFlagString(coal)
    out_string += format_string.format(coal, type_string, coal.id, coal.ref_count, coal.active_count, coal.focal_task_count, coal.nonfocal_task_count, flag_string)
    return out_string

def GetCoalitionInfo(coal, verbose=False):
    """ returns a string describing a coalition, including details about the particular coalition type.
        params:
            coal : value object representing a coalition in the kernel
        returns:
            str : A string describing the coalition.
    """
    if unsigned(coal) == 0:
        return "<null coalition>"
    typestr = GetCoalitionTypeString(coal.type)
    flagstr = GetCoalitionFlagString(coal)
    out_string = ""
    out_string += "Coalition {c: <#020x}\n\tID {c.id: <d}\n\tType {c.type: <d} ({t: <s})\n\tRefCount {c.ref_count: <d}\n\tActiveCount {c.active_count: <d}\n\tFocal Tasks: {c.focal_task_count: <d}\n\tNon-Focal Tasks: {c.nonfocal_task_count: <d}\n\tFlags {f: <s}\n\t".format(c=coal,t=typestr,f=flagstr)
    if coal.type == 0: # COALITION_TYPE_RESOURCE
        out_string += GetResourceCoalitionSummary(coal, verbose)
    elif coal.type == 1: # COALITION_TYPE_JETSAM
        out_string += GetJetsamCoalitionSummary(coal, verbose)
    else:
        out_string += "Unknown Type"

    return out_string

# Macro: showcoalitioninfo

@lldb_command('showcoalitioninfo')
def ShowCoalitionInfo(cmd_args=None, cmd_options={}):
    """  Display more detailed information about a coalition
         Usage: showcoalitioninfo <address of coalition>
    """
    verbose = False
    if config['verbosity'] > vHUMAN:
        verbose = True
    if not cmd_args:
        raise ArgumentError("No arguments passed")
    coal = kern.GetValueFromAddress(cmd_args[0], 'coalition *')
    if not coal:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetCoalitionInfo(coal, verbose)

# EndMacro: showcoalitioninfo

# Macro: showallcoalitions

@lldb_command('showallcoalitions')
def ShowAllCoalitions(cmd_args=None):
    """  Print a summary listing of all the coalitions
    """
    global kern
    print GetCoalitionSummary.header
    for c in kern.coalitions:
        print GetCoalitionSummary(c)

# EndMacro: showallcoalitions

# Macro: showallthreadgroups

@lldb_type_summary(['struct thread_group *', 'thread_group *'])
@header("{0: <20s} {1: <5s} {2: <16s} {3: <5s} {4: <8s} {5: <20s}".format("thread_group", "id", "name", "refc", "flags", "recommendation"))
def GetThreadGroupSummary(tg):
    if unsigned(tg) == 0:
        return '{0: <#020x} {1: <5d} {2: <16s} {3: <5d} {4: <8s} {5: <20d}'.format(0, -1, "", -1, "", -1)
    out_string = ""
    format_string = '{0: <#020x} {1: <5d} {2: <16s} {3: <5d} {4: <8s} {5: <20d}'
    tg_flags = ''
    if (tg.tg_flags & 0x1):
        tg_flags += 'E'
    if (tg.tg_flags & 0x2):
        tg_flags += 'U'
    out_string += format_string.format(tg, tg.tg_id, tg.tg_name, tg.tg_refcount, tg_flags, tg.tg_recommendation)
    return out_string

@lldb_command('showallthreadgroups')
def ShowAllThreadGroups(cmd_args=None):
    """  Print a summary listing of all thread groups
    """
    global kern
    print GetThreadGroupSummary.header
    for tg in kern.thread_groups:
        print GetThreadGroupSummary(tg)

# EndMacro: showallthreadgroups

# Macro: showtaskcoalitions

@lldb_command('showtaskcoalitions', 'F:')
def ShowTaskCoalitions(cmd_args=None, cmd_options={}):
    """
    """
    task_list = []
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options["-F"])
    elif cmd_args:
        t = kern.GetValueFromAddress(cmd_args[0], 'task *')
        task_list.append(t)
    else:
        raise ArgumentError("No arguments passed")

    if len(task_list) > 0:
        print GetCoalitionSummary.header
    for task in task_list:
        print GetCoalitionSummary(task.coalition[0])
        print GetCoalitionSummary(task.coalition[1])

# EndMacro: showtaskcoalitions

@lldb_type_summary(['proc', 'proc *'])
@header("{0: >6s} {1: ^20s} {2: >14s} {3: ^10s} {4: <20s}".format("pid", "process", "io_policy", "wq_state", "command"))
def GetProcSummary(proc):
    """ Summarize the process data. 
        params:
          proc : value - value representaitng a proc * in kernel
        returns:
          str - string summary of the process.
    """
    out_string = ""
    format_string= "{0: >6d} {1: >#020x} {2: >14s} {3: >2d} {4: >2d} {5: >2d}    {6: <20s}"
    pval = proc.GetSBValue()
    #code.interact(local=locals())
    if str(pval.GetType()) != str(gettype('proc *')) :
        return "Unknown type " + str(pval.GetType()) + " " + str(hex(proc))
    if not proc:
        out_string += "Process " + hex(proc) + " is not valid."
        return out_string 
    pid = int(proc.p_pid)
    proc_addr = int(hex(proc), 16)
    proc_rage_str = ""
    if int(proc.p_lflag) & 0x400000 :
        proc_rage_str = "RAGE"
    
    task = Cast(proc.task, 'task *')
    
    io_policy_str = ""
    
    if int(task.effective_policy.tep_darwinbg) != 0:
        io_policy_str += "B"
    if int(task.effective_policy.tep_lowpri_cpu) != 0:
        io_policy_str += "L"
    
    if int(task.effective_policy.tep_io_tier) != 0:
        io_policy_str += "T"
    if int(task.effective_policy.tep_io_passive) != 0:
        io_policy_str += "P"
    if int(task.effective_policy.tep_terminated) != 0:
        io_policy_str += "D"
    
    if int(task.effective_policy.tep_latency_qos) != 0:
        io_policy_str += "Q"
    if int(task.effective_policy.tep_sup_active) != 0:
        io_policy_str += "A"
    
    
    try:
        work_queue = Cast(proc.p_wqptr, 'workqueue *')
        if proc.p_wqptr != 0 :
            wq_num_threads = int(work_queue.wq_nthreads)
            wq_idle_threads = int(work_queue.wq_thidlecount)
            wq_req_threads = int(work_queue.wq_reqcount)
        else:
            wq_num_threads = 0
            wq_idle_threads = 0
            wq_req_threads = 0
    except:
        wq_num_threads = -1
        wq_idle_threads = -1
        wq_req_threads = -1
    process_name = str(proc.p_comm)
    if process_name == 'xpcproxy':
        for thread in IterateQueue(task.threads, 'thread *', 'task_threads'):
            thread_name = GetThreadName(thread)
            if thread_name:
                process_name += ' (' + thread_name + ')'
                break
    out_string += format_string.format(pid, proc_addr, " ".join([proc_rage_str, io_policy_str]), wq_num_threads, wq_idle_threads, wq_req_threads, process_name)
    return out_string

@lldb_type_summary(['tty_dev_t', 'tty_dev_t *'])
@header("{0: <20s} {1: <10s} {2: <10s} {3: <15s} {4: <15s} {5: <15s} {6: <15s}".format("tty_dev","master", "slave", "open", "free", "name", "revoke"))
def GetTTYDevSummary(tty_dev):
    """ Summarizes the important fields in tty_dev_t structure.
        params: tty_dev: value - value object representing a tty_dev_t in kernel
        returns: str - summary of the tty_dev
    """
    out_string = ""
    format_string = "{0: <#020x} {1: <#010x} {2: <#010x} {3: <15s} {4: <15s} {5: <15s} {6: <15s}" 
    open_fn = kern.Symbolicate(int(hex(tty_dev.open), 16))
    free_fn = kern.Symbolicate(int(hex(tty_dev.free), 16))
    name_fn = kern.Symbolicate(int(hex(tty_dev.name), 16))
    revoke_fn = kern.Symbolicate(int(hex(tty_dev.revoke), 16))
    out_string += format_string.format(tty_dev, tty_dev.master, tty_dev.slave, open_fn, free_fn, name_fn, revoke_fn)
    return out_string

# Macro: showtask

@lldb_command('showtask', 'F:') 
def ShowTask(cmd_args=None, cmd_options={}):
    """  Routine to print a summary listing of given task
         Usage: showtask <address of task>
         or   : showtask -F <name of task>  
    """
    task_list = []
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options['-F'])
    else:
        if not cmd_args:
            raise ArgumentError("Invalid arguments passed.")

        tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
        if not tval:
            raise ("Unknown arguments: %r" % cmd_args)
        task_list.append(tval)
    
    for tval in task_list:
        print GetTaskSummary.header + " " + GetProcSummary.header
        pval = Cast(tval.bsd_info, 'proc *')
        print GetTaskSummary(tval) +" "+ GetProcSummary(pval)

# EndMacro: showtask

# Macro: showpid

@lldb_command('showpid') 
def ShowPid(cmd_args=None):
    """  Routine to print a summary listing of task corresponding to given pid
         Usage: showpid <pid value>
    """
    if not cmd_args:
        raise ArgumentError("No arguments passed")
    pidval = ArgumentStringToInt(cmd_args[0])
    for t in kern.tasks:
        pval = Cast(t.bsd_info, 'proc *')
        if pval and pval.p_pid == pidval:
            print GetTaskSummary.header + " " + GetProcSummary.header
            print GetTaskSummary(t) + " " + GetProcSummary(pval)
            break

# EndMacro: showpid

# Macro: showproc

@lldb_command('showproc') 
def ShowProc(cmd_args=None):
    """  Routine to print a summary listing of task corresponding to given proc
         Usage: showproc <address of proc>
    """
    if not cmd_args:
        raise ArgumentError("No arguments passed")
    pval = kern.GetValueFromAddress(cmd_args[0], 'proc *')
    if not pval:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetTaskSummary.header + " " + GetProcSummary.header
    tval = Cast(pval.task, 'task *')
    print GetTaskSummary(tval) +" "+ GetProcSummary(pval)

# EndMacro: showproc

# Macro: showprocinfo

@lldb_command('showprocinfo') 
def ShowProcInfo(cmd_args=None):
    """  Routine to display name, pid, parent & task for the given proc address
         It also shows the Cred, Flags and state of the process
         Usage: showprocinfo <address of proc>
    """
    if not cmd_args:
        raise ArgumentError("No arguments passed")
    pval = kern.GetValueFromAddress(cmd_args[0], 'proc *')
    if not pval:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetProcInfo(pval)

# EndMacro: showprocinfo

#Macro: showprocfiles

@lldb_command('showprocfiles')
def ShowProcFiles(cmd_args=None):
    """ Given a proc_t pointer, display the list of open file descriptors for the referenced process.
        Usage: showprocfiles <proc_t>
    """
    if not cmd_args:
        print ShowProcFiles.__doc__
        return
    proc = kern.GetValueFromAddress(cmd_args[0], 'proc_t')
    proc_filedesc = proc.p_fd
    proc_lastfile = unsigned(proc_filedesc.fd_lastfile)
    proc_ofiles = proc_filedesc.fd_ofiles
    if unsigned(proc_ofiles) == 0:
        print 'No open files for proc {0: <s}'.format(cmd_args[0])
        return
    print "{0: <5s} {1: <18s} {2: <10s} {3: <8s} {4: <18s} {5: <64s}".format('FD', 'FILEGLOB', 'FG_FLAGS', 'FG_TYPE', 'FG_DATA','INFO')
    print "{0:-<5s} {0:-<18s} {0:-<10s} {0:-<8s} {0:-<18s} {0:-<64s}".format("")
    count = 0

    while count <= proc_lastfile:
        if unsigned(proc_ofiles[count]) != 0:
            out_str = ''
            proc_fd_flags = proc_ofiles[count].f_flags
            proc_fd_fglob = proc_ofiles[count].f_fglob
            out_str += "{0: <5d} ".format(count)
            out_str += "{0: <#18x} ".format(unsigned(proc_fd_fglob))
            out_str += "0x{0:0>8x} ".format(unsigned(proc_fd_flags))
            proc_fd_ftype = unsigned(proc_fd_fglob.fg_ops.fo_type)
            if proc_fd_ftype in xnudefines.filetype_strings:
                out_str += "{0: <8s} ".format(xnudefines.filetype_strings[proc_fd_ftype])
            else:
                out_str += "?: {0: <5d} ".format(proc_fd_ftype)
            out_str += "{0: <#18x} ".format(unsigned(proc_fd_fglob.fg_data))
            if proc_fd_ftype == 1:
                fd_name = Cast(proc_fd_fglob.fg_data, 'struct vnode *').v_name
                out_str += "{0: <64s}".format(fd_name)
            out_str += "\n"
            print out_str
        count += 1

#EndMacro: showprocfiles

#Macro: showtty

@lldb_command('showtty')
def ShowTTY(cmd_args=None):
    """ Display information about a struct tty
        Usage: showtty <tty struct>
    """
    if not cmd_args:
        print ShowTTY.__doc__
        return
    
    tty = kern.GetValueFromAddress(cmd_args[0], 'struct tty *')
    print "TTY structure at:              {0: <s}".format(cmd_args[0])
    print "Last input to raw queue:       {0: <#18x} \"{1: <s}\"".format(unsigned(tty.t_rawq.c_cs), tty.t_rawq.c_cs)
    print "Last input to canonical queue: {0: <#18x} \"{1: <s}\"".format(unsigned(tty.t_canq.c_cs), tty.t_canq.c_cs)
    print "Last output data:              {0: <#18x} \"{1: <s}\"".format(unsigned(tty.t_outq.c_cs), tty.t_outq.c_cs)
    tty_state_info = [
                  ['', 'TS_SO_OLOWAT (Wake up when output <= low water)'],
                  ['- (synchronous I/O mode)', 'TS_ASYNC (async I/O mode)'],
                  ['', 'TS_BUSY (Draining output)'],
                  ['- (Carrier is NOT present)', 'TS_CARR_ON (Carrier is present)'],
                  ['', 'TS_FLUSH (Outq has been flushed during DMA)'],
                  ['- (Open has NOT completed)', 'TS_ISOPEN (Open has completed)'],
                  ['', 'TS_TBLOCK (Further input blocked)'],
                  ['', 'TS_TIMEOUT (Wait for output char processing)'],
                  ['', 'TS_TTSTOP (Output paused)'],
                  ['', 'TS_WOPEN (Open in progress)'],
                  ['', 'TS_XCLUDE (Tty requires exclusivity)'],
                  ['', 'TS_BKSL (State for lowercase \\ work)'],
                  ['', 'TS_CNTTB (Counting tab width, ignore FLUSHO)'],
                  ['', 'TS_ERASE (Within a \\.../ for PRTRUB)'],
                  ['', 'TS_LNCH (Next character is literal)'],
                  ['', 'TS_TYPEN (Retyping suspended input (PENDIN))'],
                  ['', 'TS_CAN_BYPASS_L_RINT (Device in "raw" mode)'],
                  ['- (Connection NOT open)', 'TS_CONNECTED (Connection open)'],
                  ['', 'TS_SNOOP (Device is being snooped on)'],
                  ['', 'TS_SO_OCOMPLETE (Wake up when output completes)'],
                  ['', 'TS_ZOMBIE (Connection lost)'],
                  ['', 'TS_CAR_OFLOW (For MDMBUF - handle in driver)'],
                  ['', 'TS_CTS_OFLOW (For CCTS_OFLOW - handle in driver)'],
                  ['', 'TS_DSR_OFLOW (For CDSR_OFLOW - handle in driver)']
                ]
    index = 0
    mask = 0x1
    tty_state = unsigned(tty.t_state)
    print "State:"
    while index < 24:
        if tty_state & mask != 0:
            if len(tty_state_info[index][1]) > 0:
                print '\t' + tty_state_info[index][1]
        else:
            if len(tty_state_info[index][0]) > 0:
                print '\t' + tty_state_info[index][0]
        index += 1
        mask = mask << 1
    print "Flags:                    0x{0:0>8x}".format(unsigned(tty.t_flags))
    print "Foreground Process Group: 0x{0:0>16x}".format(unsigned(tty.t_pgrp))
    print "Enclosing session:        0x{0:0>16x}".format(unsigned(tty.t_session))
    print "Termios:"
    print "\tInput Flags:   0x{0:0>8x}".format(unsigned(tty.t_termios.c_iflag))
    print "\tOutput Flags:  0x{0:0>8x}".format(unsigned(tty.t_termios.c_oflag))
    print "\tControl Flags: 0x{0:0>8x}".format(unsigned(tty.t_termios.c_cflag))
    print "\tLocal Flags:   0x{0:0>8x}".format(unsigned(tty.t_termios.c_lflag))
    print "\tInput Speed:   {0: <8d}".format(tty.t_termios.c_ispeed)
    print "\tOutput Speed:  {0: <8d}".format(tty.t_termios.c_ospeed)
    print "High Watermark: {0: <d} bytes".format(tty.t_hiwat)
    print "Low Watermark : {0: <d} bytes".format(tty.t_lowat)

#EndMacro: showtty

#Macro showallttydevs

@lldb_command('showallttydevs')
def ShowAllTTYDevs(cmd_args=[], cmd_options={}):
    """ Show a list of ttydevs registered in the system.
        Usage:
        (lldb)showallttydevs
    """
    tty_dev_head = kern.globals.tty_dev_head
    tty_dev = tty_dev_head
    print GetTTYDevSummary.header
    while unsigned(tty_dev) != 0:
        print GetTTYDevSummary(tty_dev)
        tty_dev = tty_dev.next
    return ""

#EndMacro: showallttydevs

#Macro: dumpthread_terminate_queue

@lldb_command('dumpthread_terminate_queue')
def DumpThreadTerminateQueue(cmd_args=None):
    """ Displays the contents of the specified call_entry queue.
        Usage: dumpthread_terminate_queue 
    """
    
    count = 0
    print GetThreadSummary.header
    for th in IterateQueue(addressof(kern.globals.thread_terminate_queue), 'struct thread *',  'q_link'):
        print GetThreadSummary(th)
        count += 1
    print "{0: <d} entries!".format(count)

#EndMacro: dumpthread_terminate_queue

#Macro: dumpcrashed_thread_queue

@lldb_command('dumpcrashed_thread_queue')
def DumpCrashedThreadsQueue(cmd_args=None):
    """ Displays the contents of the specified call_entry queue.
        Usage: dumpcrashed_thread_queue 
    """
    
    count = 0
    print GetThreadSummary.header
    for th in IterateQueue(addressof(kern.globals.crashed_threads_queue), 'struct thread *',  'q_link'):
        print GetThreadSummary(th)
        count += 1
    print "{0: <d} entries!".format(count)

#EndMacro: dumpcrashed_thread_queue

#Macro: dumpcallqueue

@lldb_command('dumpcallqueue')
def DumpCallQueue(cmd_args=None):
    """ Displays the contents of the specified call_entry queue.
        Usage: dumpcallqueue <queue_head_t *>
    """
    if not cmd_args:
        raise ArgumentError("Invalid arguments")

    print "{0: <18s} {1: <18s} {2: <18s} {3: <64s} {4: <18s}".format('CALL_ENTRY', 'PARAM0', 'PARAM1', 'DEADLINE', 'FUNC')
    callhead = kern.GetValueFromAddress(cmd_args[0], 'queue_head_t *')
    count = 0
    for callentry in IterateQueue(callhead, 'struct call_entry *',  'q_link'):
        print "{0: <#18x} {1: <#18x} {2: <#18x} {3: <64d} {4: <#18x}".format(
              unsigned(callentry), unsigned(callentry.param0), unsigned(callentry.param1), 
              unsigned(callentry.deadline), unsigned(callentry.func))
        count += 1
    print "{0: <d} entries!".format(count)

#EndMacro: dumpcallqueue

@lldb_command('showalltasklogicalwrites')
def ShowAllTaskIOStats(cmd_args=None):
    """ Commad to print I/O stats for all tasks
    """
    print "{0: <20s} {1: <20s} {2: <20s} {3: <20s} {4: <20s} {5: <20s}".format("task", "Immediate Writes", "Deferred Writes", "Invalidated Writes", "Metadata Writes", "name")
    for t in kern.tasks:
        pval = Cast(t.bsd_info, 'proc *')
        print "{0: <#18x} {1: >20d} {2: >20d} {3: >20d} {4: >20d} {5: <20s}".format(t,
            t.task_immediate_writes, 
            t.task_deferred_writes,
            t.task_invalidated_writes,
            t.task_metadata_writes,
            str(pval.p_comm)) 


@lldb_command('showalltasks','C')
def ShowAllTasks(cmd_args=None, cmd_options={}):
    """  Routine to print a summary listing of all the tasks
         wq_state -> reports "number of workq threads", "number of scheduled workq threads", "number of pending work items"
         if "number of pending work items" seems stuck at non-zero, it may indicate that the workqueue mechanism is hung
         io_policy -> RAGE  - rapid aging of vnodes requested
                     NORM  - normal I/O explicitly requested (this is the default)
                     PASS  - passive I/O requested (i.e. I/Os do not affect throttling decisions)
                     THROT - throttled I/O requested (i.e. thread/task may be throttled after each I/O completes)
         Usage: (lldb) showalltasks -C  : describe the corpse structure
    """
    global kern
    extra_hdr = ''
    showcorpse = False
    if '-C' in cmd_options:
        showcorpse = True
        extra_hdr += " " + GetKCDataSummary.header

    print GetTaskSummary.header + extra_hdr + " " + GetProcSummary.header
    for t in kern.tasks:
        pval = Cast(t.bsd_info, 'proc *')
        out_str = GetTaskSummary(t, showcorpse) + " " + GetProcSummary(pval)
        print out_str
    ZombTasks()

@lldb_command('taskforpmap')
def TaskForPmap(cmd_args=None):
    """ Find the task whose pmap corresponds to <pmap>.
        Syntax: (lldb) taskforpmap <pmap>
            Multiple -v's can be specified for increased verbosity
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Too few arguments to taskforpmap.")
    pmap = kern.GetValueFromAddress(cmd_args[0], 'pmap_t')
    print GetTaskSummary.header + " " + GetProcSummary.header
    for tasklist in [kern.tasks, kern.terminated_tasks]:
        for t in tasklist:
            if t.map.pmap == pmap:
                pval = Cast(t.bsd_info, 'proc *')
                out_str = GetTaskSummary(t) + " " + GetProcSummary(pval)
                print out_str

@lldb_command('showterminatedtasks') 
def ShowTerminatedTasks(cmd_args=None):
    """  Routine to print a summary listing of all the terminated tasks
         wq_state -> reports "number of workq threads", "number of scheduled workq threads", "number of pending work items"
         if "number of pending work items" seems stuck at non-zero, it may indicate that the workqueue mechanism is hung
         io_policy -> RAGE  - rapid aging of vnodes requested
                     NORM  - normal I/O explicitly requested (this is the default)
                     PASS  - passive I/O requested (i.e. I/Os do not affect throttling decisions)
                     THROT - throttled I/O requested (i.e. thread/task may be throttled after each I/O completes)
        syntax: (lldb)showallterminatedtasks
    """
    global kern
    print GetTaskSummary.header + " " + GetProcSummary.header
    for t in kern.terminated_tasks:
        pval = Cast(t.bsd_info, 'proc *')
        print GetTaskSummary(t) +" "+ GetProcSummary(pval)
    return True

# Macro: showtaskstacks

def ShowTaskStacks(task):
    """ Print a task with summary and stack information for each of its threads 
    """
    global kern
    print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(task.bsd_info, 'proc *')
    print GetTaskSummary(task) + " " + GetProcSummary(pval)
    for th in IterateQueue(task.threads, 'thread *', 'task_threads'):
        print "  " + GetThreadSummary.header
        print "  " + GetThreadSummary(th)
        print GetThreadBackTrace(th, prefix="    ") + "\n"

def FindTasksByName(searchstr, ignore_case=True):
    """ Search the list of tasks by name. 
        params:
            searchstr: str - a regex like string to search for task
            ignore_case: bool - If False then exact matching will be enforced
        returns:
            [] - array of task object. Empty if not found any
    """
    re_options = 0   
    if ignore_case:
        re_options = re.IGNORECASE
    search_regex = re.compile(searchstr, re_options)
    retval = []
    for t in kern.tasks: 
        pval = Cast(t.bsd_info, "proc *")
        process_name = "{:s}".format(pval.p_comm)
        if search_regex.search(process_name):
            retval.append(t)
    return retval

@lldb_command('showtaskstacks', 'F:')
def ShowTaskStacksCmdHelper(cmd_args=None, cmd_options={}):
    """ Routine to print out the stack for each thread in a task
        Usage: showtaskstacks <0xaddress of task>
           or: showtaskstacks -F launchd   
    """

    if "-F" in cmd_options:
        find_task_str = cmd_options["-F"]
        task_list = FindTasksByName(find_task_str)
        for tval in task_list:
            ShowTaskStacks(tval)
        return
    
    if not cmd_args:
        raise ArgumentError("No arguments passed")

    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        raise ArgumentError("unknown arguments: {:s}".format(str(cmd_args)))
    else:
        ShowTaskStacks(tval)
        return

# EndMacro: showtaskstacks

def CheckTaskProcRefs(task, proc):
    for thread in IterateQueue(task.threads, 'thread *', 'task_threads'):
        if int(thread.uthread) == 0:
            continue
        uthread = Cast(thread.uthread, 'uthread *')
        refcount = int(uthread.uu_proc_refcount)
        uu_ref_index = int(uthread.uu_pindex)
        if refcount == 0:
            continue
        for ref in range(0, uu_ref_index):
            if unsigned(uthread.uu_proc_ps[ref]) == unsigned(proc):
                print GetTaskSummary.header + " " + GetProcSummary.header
                pval = Cast(task.bsd_info, 'proc *')
                print GetTaskSummary(task) + " " + GetProcSummary(pval)
                print "\t" + GetThreadSummary.header
                print "\t" + GetThreadSummary(thread) + "\n"

                for frame in range (0, 10):
                    trace_addr = unsigned(uthread.uu_proc_pcs[ref][frame])
                    symbol_arr = kern.SymbolicateFromAddress(unsigned(trace_addr))
                    if symbol_arr:
                        symbol_str = str(symbol_arr[0].addr)
                    else:
                        symbol_str = ''
                    print '{0: <#x} {1: <s}'.format(trace_addr, symbol_str)
    return

@lldb_command('showprocrefs')
def ShowProcRefs(cmd_args = None):
    """ Display information on threads/BTs that could be holding a reference on the specified proc
        NOTE: We can't say affirmatively if any of these references are still held since
              there's no way to pair references with drop-refs in the current infrastructure.
        Usage: showprocrefs <proc>
    """
    if cmd_args == None or len(cmd_args) < 1:
         raise ArgumentError("No arguments passed")

    proc = kern.GetValueFromAddress(cmd_args[0], 'proc *')

    for t in kern.tasks:
        CheckTaskProcRefs(t, proc)
    for t in kern.terminated_tasks:
        CheckTaskProcRefs(t, proc)

    return

@lldb_command('showallthreads')
def ShowAllThreads(cmd_args = None):
    """ Display info about all threads in the system
    """
    for t in kern.tasks:
        ShowTaskThreads([str(int(t))])
        print " \n"
        
    for t in kern.terminated_tasks:
        print "Terminated: \n"
        ShowTaskThreads([str(int(t))])
        print " \n"
        
    return

@lldb_command('showtaskthreads', "F:")
def ShowTaskThreads(cmd_args = None, cmd_options={}):
    """ Display thread information for a given task
        Usage: showtaskthreads <0xaddress of task>
           or: showtaskthreads -F <name>
    """
    task_list = []
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options["-F"])
    elif cmd_args:
        t = kern.GetValueFromAddress(cmd_args[0], 'task *')
        task_list.append(t)
    else:
        raise ArgumentError("No arguments passed")
    
    for task in task_list:
        print GetTaskSummary.header + " " + GetProcSummary.header
        pval = Cast(task.bsd_info, 'proc *')
        print GetTaskSummary(task) + " " + GetProcSummary(pval)
        print "\t" + GetThreadSummary.header
        for thval in IterateQueue(task.threads, 'thread *', 'task_threads'):
            print "\t" + GetThreadSummary(thval)
    return

@lldb_command('showact')
def ShowAct(cmd_args=None):
    """ Routine to print out the state of a specific thread.
        usage: showact <activation> 
    """
    if not cmd_args:
        raise ArgumentError("No arguments passed")
    threadval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    print GetThreadSummary.header
    print GetThreadSummary(threadval)

@lldb_command('showactstack')
def ShowActStack(cmd_args=None):
    """ Routine to print out the stack of a specific thread.
        usage:  showactstack <activation> 
    """
    if not cmd_args:
        raise ArgumentError("No arguments passed")
    threadval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    print GetThreadSummary.header
    print GetThreadSummary(threadval)
    print GetThreadBackTrace(threadval, prefix="\t")
    return

@lldb_command('switchtoact')
def SwitchToAct(cmd_args=None):
    """ Switch to different context specified by activation
    This command allows gdb to examine the execution context and call
    stack for the specified activation. For example, to view the backtrace
    for an activation issue "switchtoact <address>", followed by "bt".
    Before resuming execution, issue a "resetctx" command, to
    return to the original execution context.
    """
    if cmd_args is None or len(cmd_args) < 1:
        raise ArgumentError("No arguments passed")
    thval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    lldbthread = GetLLDBThreadForKernelThread(thval)
    print GetThreadSummary.header
    print GetThreadSummary(thval)
    LazyTarget.GetProcess().selected_thread = lldbthread
    if not LazyTarget.GetProcess().SetSelectedThread(lldbthread):
        print "Failed to switch thread."
    return

@lldb_command('switchtoregs')
def SwitchToRegs(cmd_args=None):
    """ Routine to switch to a register state.
        Usage: (lldb) switchtoregs <struct arm_saved_state[64] *>
        This command creates a fake thread in lldb with the saved register state.
        Note: This command ONLY works for ARM based kernel setup.
    """
    
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("No arguments passed")

    lldb_process = LazyTarget.GetProcess()
    
    saved_state = ArgumentStringToInt(cmd_args[0])
    # any change to this logic requires change in operating_system.py as well
    fake_thread_id = 0xdead0000 | (saved_state & ~0xffff0000)
    fake_thread_id = fake_thread_id & 0xdeadffff
    lldb_process.CreateOSPluginThread(0xdeadbeef, saved_state)
    lldbthread = lldb_process.GetThreadByID(int(fake_thread_id))
    
    if not lldbthread.IsValid():
        print "Failed to create thread"
        return

    lldb_process.selected_thread = lldbthread
    if not lldb_process.SetSelectedThread(lldbthread):
        print "Failed to switch thread"
    print "Switched to Fake thread created from register state at 0x%x" % saved_state
            


# Macro: showallstacks
@lldb_command('showallstacks')
def ShowAllStacks(cmd_args=None):
    """Routine to print out the stack for each thread in the system.
    """
    for t in kern.tasks:
        ShowTaskStacks(t)
        print " \n"    
    ZombStacks()
    return
        
# EndMacro: showallstacks

# Macro: showcurrentstacks
@lldb_command('showcurrentstacks')
def ShowCurrentStacks(cmd_args=None):
    """ Routine to print out the thread running on each cpu (incl. its stack)
    """
    processor_list = kern.GetGlobalVariable('processor_list')
    current_processor = processor_list
    while unsigned(current_processor) > 0:
        print "\n" + GetProcessorSummary(current_processor)
        active_thread = current_processor.active_thread
        if unsigned(active_thread) != 0 :
            task_val = active_thread.task
            proc_val = Cast(task_val.bsd_info, 'proc *')
            print GetTaskSummary.header + " " + GetProcSummary.header
            print GetTaskSummary(task_val) + " " + GetProcSummary(proc_val)
            print "\t" + GetThreadSummary.header
            print "\t" + GetThreadSummary(active_thread)
            print "\tBacktrace:"
            print GetThreadBackTrace(active_thread, prefix="\t")
        current_processor = current_processor.processor_list
    return
# EndMacro: showcurrentstacks

@lldb_command('showcurrentthreads')
def ShowCurrentThreads(cmd_args=None):
    """ Display info about threads running on each cpu """
    processor_list = kern.GetGlobalVariable('processor_list')
    current_processor = processor_list
    while unsigned(current_processor) > 0:
        print GetProcessorSummary(current_processor)
        active_thread = current_processor.active_thread
        if unsigned(active_thread) != 0 :
            task_val = active_thread.task
            proc_val = Cast(task_val.bsd_info, 'proc *')
            print GetTaskSummary.header + " " + GetProcSummary.header
            print GetTaskSummary(task_val) + " " + GetProcSummary(proc_val)
            print "\t" + GetThreadSummary.header
            print "\t" + GetThreadSummary(active_thread)
        current_processor = current_processor.processor_list
    return

def GetFullBackTrace(frame_addr, verbosity = vHUMAN, prefix = ""):
    """ Get backtrace across interrupt context. 
        params: frame_addr - int - address in memory which is a frame pointer (ie. rbp, r7)
                prefix - str - prefix for each line of output.
        
    """
    out_string = ""
    bt_count = 0
    frame_ptr = frame_addr
    previous_frame_ptr = 0
    # <rdar://problem/12677290> lldb unable to find symbol for _mh_execute_header
    mh_execute_addr = int(lldb_run_command('p/x (uintptr_t *)&_mh_execute_header').split('=')[-1].strip(), 16)
    while frame_ptr and frame_ptr != previous_frame_ptr and bt_count < 128:
        if (not kern.arch.startswith('arm') and frame_ptr < mh_execute_addr) or (kern.arch.startswith('arm') and frame_ptr > mh_execute_addr):
            break
        pc_val = kern.GetValueFromAddress(frame_ptr + kern.ptrsize,'uintptr_t *')
        pc_val = unsigned(dereference(pc_val))
        out_string += prefix + GetSourceInformationForAddress(pc_val) + "\n"
        bt_count +=1
        previous_frame_ptr = frame_ptr
        frame_val = kern.GetValueFromAddress((frame_ptr), 'uintptr_t *')
        if unsigned(frame_val) == 0:
            break
        frame_ptr = unsigned(dereference(frame_val))
        
    return out_string

@lldb_command('fullbt')
def FullBackTrace(cmd_args=[]):
    """ Show full backtrace across the interrupt boundary.
        Syntax: fullbt <frame ptr>
        Example: fullbt  `$rbp` 
    """
    if len(cmd_args) < 1:
        print FullBackTrace.__doc__
        return False
    print GetFullBackTrace(ArgumentStringToInt(cmd_args[0]), prefix="\t")

@lldb_command('fullbtall')
def FullBackTraceAll(cmd_args=[]):
    """ Show full backtrace across the interrupt boundary for threads running on all processors.
        Syntax: fullbtall
        Example: fullbtall
    """
    for processor in IterateLinkedList(kern.globals.processor_list, 'processor_list') :
        print "\n" + GetProcessorSummary(processor)
        active_thread = processor.active_thread
        if unsigned(active_thread) != 0 :
            task_val = active_thread.task
            proc_val = Cast(task_val.bsd_info, 'proc *')
            print GetTaskSummary.header + " " + GetProcSummary.header
            print GetTaskSummary(task_val) + " " + GetProcSummary(proc_val)
            print "\t" + GetThreadSummary.header
            print "\t" + GetThreadSummary(active_thread)
            print "\tBacktrace:"
                
            ThreadVal = GetLLDBThreadForKernelThread(active_thread)

            FramePtr = ThreadVal.frames[0].GetFP()
            
            print GetFullBackTrace(unsigned(FramePtr), prefix="\t")
            

@lldb_command('symbolicate')
def SymbolicateAddress(cmd_args=[]):
    """ Symbolicate an address for symbol information from loaded symbols
        Example: "symbolicate 0xaddr" is equivalent to "output/a 0xaddr"
    """
    if len(cmd_args) < 1:
        print "Invalid address.\nSyntax: symbolicate <address>"
        return False
    print GetSourceInformationForAddress(ArgumentStringToInt(cmd_args[0]))
    return True

@lldb_command('showinitchild')
def ShowInitChild(cmd_args=None):
    """ Routine to print out all processes in the system
        which are children of init process
    """
    headp = kern.globals.initproc.p_children
    for pp in IterateListEntry(headp, 'struct proc *', 'p_sibling'):
        print GetProcInfo(pp)
    return

@lldb_command('showproctree')
def ShowProcTree(cmd_args=None):
    """ Routine to print the processes in the system in a hierarchical tree form. This routine does not print zombie processes.
        If no argument is given, showproctree will print all the processes in the system.
        If pid is specified, showproctree prints all the descendants of the indicated process
    """
    search_pid = 0
    if cmd_args:
        search_pid = ArgumentStringToInt(cmd_args[0])
    
    if search_pid < 0:
        print "pid specified must be a positive number"
        print ShowProcTree.__doc__
        return
    
    hdr_format = "{0: <6s} {1: <14s} {2: <9s}\n"
    out_string = hdr_format.format("PID", "PROCESS", "POINTER")
    out_string += hdr_format.format('='*3, '='*7, '='*7)
    proc = GetProcForPid(search_pid)
    out_string += "{0: <6d} {1: <14s} [ {2: #019x} ]\n".format(proc.p_ppid, proc.p_pptr.p_comm, unsigned(proc.p_pptr))
    out_string += "|--{0: <6d} {1: <16s} [ {2: #019x} ]\n".format(proc.p_pid, proc.p_comm, unsigned(proc))
    print out_string
    ShowProcTreeRecurse(proc, "|  ")
    
    return

def ShowProcTreeRecurse(proc, prefix=""):
    """ Prints descendants of a given proc in hierarchial tree form
        params:
            proc  : core.value representing a struct proc * in the kernel
        returns:
            str   : String containing info about a given proc and its descendants in tree form
    """
    if proc.p_childrencnt > 0:
        head_ptr = proc.p_children.lh_first
        
        for p in IterateListEntry(proc.p_children, 'struct proc *', 'p_sibling'):
            print prefix + "|--{0: <6d} {1: <16s} [ {2: #019x} ]\n".format(p.p_pid, p.p_comm, unsigned(p))
            ShowProcTreeRecurse(p, prefix + "|  ")

@lldb_command('showthreadfortid')
def ShowThreadForTid(cmd_args=None):
    """ The thread structure contains a unique thread_id value for each thread.
        This command is used to retrieve the address of the thread structure(thread_t)
        corresponding to a given thread_id.
    """
    if not cmd_args:
        print "Please provide thread_t whose tid you'd like to look up"
        print ShowThreadForTid.__doc__
        return
    search_tid = ArgumentStringToInt(cmd_args[0])
    for taskp in kern.tasks:
        for actp in IterateQueue(taskp.threads, 'struct thread *', 'task_threads'):
            if search_tid == int(actp.thread_id):
                print "Found {0: #019x}".format(actp)
                print GetThreadSummary.header
                print GetThreadSummary(actp)
                return
    print "Not a valid thread_id"

def GetProcessorSummary(processor):
    """ Internal function to print summary of processor
        params: processor - value representing struct processor * 
        return: str - representing the details of given processor
    """
    
    processor_state_str = "INVALID" 
    processor_state = int(processor.state)
    
    processor_states = {
                0: 'OFF_LINE',
                1: 'SHUTDOWN',
                2: 'START',
                # 3 (formerly INACTIVE)
                4: 'IDLE',
                5: 'DISPATCHING',
                6: 'RUNNING'
                }
    
    if processor_state in processor_states:
        processor_state_str = "{0: <11s} ".format(processor_states[processor_state])

    processor_recommended_str = ""
    if int(processor.is_recommended) == 0:
        processor_recommended_str = " (not recommended)"

    ast = 0
    preemption_disable = 0
    preemption_disable_str = ""

    if kern.arch == 'x86_64':
        cpu_data = kern.globals.cpu_data_ptr[processor.cpu_id]
        if (cpu_data != 0) :
            ast = cpu_data.cpu_pending_ast
            preemption_disable = cpu_data.cpu_preemption_level
    # On arm64, it's kern.globals.CpuDataEntries[processor.cpu_id].cpu_data_vaddr
    # but LLDB can't find CpuDataEntries...

    ast_str = GetASTSummary(ast)

    if (preemption_disable != 0) :
        preemption_disable_str = "Preemption Disabled"

    out_str = "Processor {: <#018x} cpu_id {:>#4x} AST: {:<6s} State {:<s}{:<s} {:<s}\n".format(
            processor, int(processor.cpu_id), ast_str, processor_state_str, processor_recommended_str,
            preemption_disable_str)
    return out_str   

def GetLedgerEntrySummary(ledger_template, ledger, i, show_footprint_interval_max=False):
    """ Internal function to get internals of a ledger entry (*not* a ledger itself)
        params: ledger_template - value representing struct ledger_template_t for the task or thread
                ledger - value representing struct ledger_entry *
        return: str - formatted output information of ledger entries
    """
    ledger_limit_infinity = (uint64_t(0x1).value << 63) - 1
    lf_refill_scheduled = 0x0400
    lf_tracking_max = 0x4000

    out_str = ''
    now = unsigned(kern.globals.sched_tick) / 20
    lim_pct = 0

    out_str += "{: >32s} {:<2d}:".format(ledger_template.lt_entries[i].et_key, i)
    out_str += "{: >15d} ".format(unsigned(ledger.le_credit) - unsigned(ledger.le_debit))
    if (ledger.le_flags & lf_tracking_max):
        if (show_footprint_interval_max):
            out_str += "{:12d} ".format(ledger._le._le_max.le_interval_max)
        out_str += "{:14d} ".format(ledger._le._le_max.le_lifetime_max)
    else:
        if (show_footprint_interval_max):
            out_str += "           - "
        out_str += "             - "
    out_str += "{:12d} {:12d} ".format(unsigned(ledger.le_credit), unsigned(ledger.le_debit))
    if (unsigned(ledger.le_limit) != ledger_limit_infinity):
        out_str += "{:12d} ".format(unsigned(ledger.le_limit))
    else:
        out_str += "           - "

    if (ledger.le_flags & lf_refill_scheduled):
        out_str += "{:15d} ".format(ledger._le.le_refill.le_refill_period)
    else:
        out_str += "              - "

    if (ledger.le_flags & lf_refill_scheduled):
        out_str += "{:9d} ".format((unsigned(ledger.le_limit) * 100) / ledger._le.le_refill.le_refill_period)
    else:
        out_str += "        - "

    if (unsigned(ledger.le_warn_level) != ledger_limit_infinity):
        out_str += "{:9d} ".format((unsigned(ledger.le_warn_level) * 100) / unsigned(ledger.le_limit))
    else:
        out_str += "        - "

    if ((unsigned(ledger.le_credit) - unsigned(ledger.le_debit)) > unsigned(ledger.le_limit)):
        out_str += "    X "
    else:
        out_str += "      "

    out_str += "{:#8x}\n".format(ledger.le_flags)
    return out_str

def GetThreadLedgerSummary(thread_val):
    """ Internal function to get a summary of ledger entries for the given thread
        params: thread - value representing struct thread *
        return: str - formatted output information for ledger entries of the input thread
    """
    out_str = "   [{:#08x}]\n".format(thread_val)
    ledgerp = thread_val.t_threadledger
    if ledgerp:
        i = 0
        while i != ledgerp.l_template.lt_cnt:
            out_str += GetLedgerEntrySummary(kern.globals.thread_ledger_template,
                ledgerp.l_entries[i], i)
            i = i + 1
    return out_str

def GetTaskLedgers(task_val, show_footprint_interval_max=False):
    """ Internal function to get summary of ledger entries from the task and its threads
        params: task_val - value representing struct task *
        return: str - formatted output information for ledger entries of the input task
    """
    out_str = ''
    task_ledgerp = task_val.ledger
    i = 0
    out_str += "{: #08x} ".format(task_val)
    pval = Cast(task_val.bsd_info, 'proc *')
    if pval:
        out_str += "{: <5s}:\n".format(pval.p_comm)
    else:
        out_str += "Invalid process:\n"
    while i != task_ledgerp.l_template.lt_cnt:
        out_str += GetLedgerEntrySummary(kern.globals.task_ledger_template, task_ledgerp.l_entries[i], i, show_footprint_interval_max)
        i = i + 1

    # Now walk threads
    for thval in IterateQueue(task_val.threads, 'thread *', 'task_threads'):
        out_str += GetThreadLedgerSummary(thval)

    return out_str

# Macro: showtaskledgers

@lldb_command('showtaskledgers', 'F:I') 
def ShowTaskLedgers(cmd_args=None, cmd_options={}):
    """  Routine to print a summary  of ledger entries for the task and all of its threads
         or   : showtaskledgers [ -I ] [ -F ] <task>
         options:
            -I: show footprint interval max (DEV/DEBUG only)
            -F: specify task via name instead of address
        -
    """
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options["-F"])
        for tval in task_list:
            print GetTaskLedgers.header
            print GetTaskLedgers(tval)
        return
    
    if not cmd_args:
        raise ArgumentError("No arguments passed.")
    show_footprint_interval_max = False
    if "-I" in cmd_options:
        show_footprint_interval_max = True
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        raise ArgumentError("unknown arguments: %r" %cmd_args)
    if (show_footprint_interval_max):
        print "{0: <15s} {1: >16s} {2: <2s} {3: >15s} {4: >12s} {5: >14s} {6: >12s} {7: >12s} {8: >12s}   {9: <15s} {10: <8s} {11: <9s} {12: <6s} {13: >6s}".format(
        "task [thread]", "entry", "#", "balance", "intrvl_max", "lifetime_max", "credit",
        "debit", "limit", "refill period", "lim pct", "warn pct", "over?", "flags")
    else:
        print "{0: <15s} {1: >16s} {2: <2s} {3: >15s} {4: >14s} {5: >12s} {6: >12s} {7: >12s}   {8: <15s} {9: <8s} {10: <9s} {11: <6s} {12: >6s}".format(
        "task [thread]", "entry", "#", "balance", "lifetime_max", "credit",
        "debit", "limit", "refill period", "lim pct", "warn pct", "over?", "flags")
    print GetTaskLedgers(tval, show_footprint_interval_max)

# EndMacro: showtaskledgers

# Macro: showalltaskledgers

@lldb_command('showalltaskledgers') 
def ShowAllTaskLedgers(cmd_args=None, cmd_options={}):
    """  Routine to print a summary  of ledger entries for all tasks and respective threads
         Usage: showalltaskledgers
    """
    for t in kern.tasks:
        task_val = unsigned(t)
        ShowTaskLedgers([task_val], cmd_options=cmd_options)
    
# EndMacro: showalltaskledgers

# Macro: showprocuuidpolicytable

@lldb_type_summary(['proc_uuid_policy_entry'])
@header("{0: <36s} {1: <10s}".format("uuid", "flags"))
def GetProcUUIDPolicyEntrySummary(entry):
    """ Summarizes the important fields in proc_uuid_policy_entry structure.
        params: entry: value - value object representing an entry
        returns: str - summary of the entry
    """
    data = []
    for i in range(16):
        data.append(int(entry.uuid[i]))
    flags = unsigned(entry.flags)
    out_string = "{a[0]:02X}{a[1]:02X}{a[2]:02X}{a[3]:02X}-{a[4]:02X}{a[5]:02X}-{a[6]:02X}{a[7]:02X}-{a[8]:02X}{a[9]:02X}-{a[10]:02X}{a[11]:02X}{a[12]:02X}{a[13]:02X}{a[14]:02X}{a[15]:02X} 0x{b:0>8x}".format(a=data, b=flags)
    return out_string

@lldb_command('showprocuuidpolicytable')
def ShowProcUUIDPolicyTable(cmd_args=None):
    """ Routine to print the proc UUID policy table
        Usage: showprocuuidpolicytable
    """
    hashslots = unsigned(kern.globals.proc_uuid_policy_hash_mask)
    print "{0: <8s} ".format("slot") + GetProcUUIDPolicyEntrySummary.header
    for i in range(0, hashslots+1):
        headp = addressof(kern.globals.proc_uuid_policy_hashtbl[i])
        entrynum = 0
        for entry in IterateListEntry(headp, 'struct proc_uuid_policy_entry *', 'entries'):
            print "{0: >2d}.{1: <5d} ".format(i, entrynum) + GetProcUUIDPolicyEntrySummary(entry)
            entrynum += 1


# EndMacro: showprocuuidpolicytable

@lldb_command('showalltaskpolicy') 
def ShowAllTaskPolicy(cmd_args=None):
    """  
         Routine to print a summary listing of all the tasks
         wq_state -> reports "number of workq threads", "number of scheduled workq threads", "number of pending work items"
         if "number of pending work items" seems stuck at non-zero, it may indicate that the workqueue mechanism is hung
         io_policy -> RAGE  - rapid aging of vnodes requested
                     NORM  - normal I/O explicitly requested (this is the default)
                     PASS  - passive I/O requested (i.e. I/Os do not affect throttling decisions)
                     THROT - throttled I/O requested (i.e. thread/task may be throttled after each I/O completes)
    """
    global kern
    print GetTaskSummary.header + " " + GetProcSummary.header
    for t in kern.tasks:
        pval = Cast(t.bsd_info, 'proc *')
        print GetTaskSummary(t) +" "+ GetProcSummary(pval)
        requested_strings = [
                ["int_darwinbg",        "DBG-int"],
                ["ext_darwinbg",        "DBG-ext"],
                ["int_iotier",          "iotier-int"],
                ["ext_iotier",          "iotier-ext"],
                ["int_iopassive",       "passive-int"],
                ["ext_iopassive",       "passive-ext"],
                ["bg_iotier",           "bg-iotier"],
                ["terminated",          "terminated"],
                ["th_pidbind_bg",       "bg-pidbind"],
                ["t_apptype",           "apptype"],
                ["t_boosted",           "boosted"],
                ["t_role",              "role"],
                ["t_tal_enabled",       "tal-enabled"],
                ["t_base_latency_qos",  "latency-base"],
                ["t_over_latency_qos",  "latency-override"],
                ["t_base_through_qos",  "throughput-base"],
                ["t_over_through_qos",  "throughput-override"]
                ]
        
        requested=""
        for value in requested_strings:
            if t.requested_policy.__getattr__(value[0]) :
                requested+=value[1] + ": " + str(t.requested_policy.__getattr__(value[0])) + " "
            else:
                requested+=""
        
        suppression_strings = [
                ["t_sup_active",        "active"],
                ["t_sup_lowpri_cpu",    "lowpri-cpu"],
                ["t_sup_timer",         "timer-throttling"],
                ["t_sup_disk",          "disk-throttling"],
                ["t_sup_cpu_limit",     "cpu-limits"],
                ["t_sup_suspend",       "suspend"],
                ["t_sup_bg_sockets",    "bg-sockets"]
                ]
            
        suppression=""
        for value in suppression_strings:
            if t.requested_policy.__getattr__(value[0]) :
                suppression+=value[1] + ": " + str(t.requested_policy.__getattr__(value[0])) + " "
            else:
                suppression+=""

        effective_strings = [
                ["darwinbg",        "background"],
                ["lowpri_cpu",      "lowpri-cpu"],
                ["io_tier",         "iotier"],
                ["io_passive",      "passive"],
                ["all_sockets_bg",  "bg-allsockets"],
                ["new_sockets_bg",  "bg-newsockets"],
                ["bg_iotier",       "bg-iotier"],
                ["terminated",      "terminated"],
                ["t_gpu_deny",      "gpu-deny"],
                ["t_tal_engaged",   "tal-engaged"],
                ["t_suspended",     "suspended"],
                ["t_watchers_bg",   "bg-watchers"],
                ["t_latency_qos",   "latency-qos"],
                ["t_through_qos",   "throughput-qos"],
                ["t_sup_active",    "suppression-active"],
                ["t_role",          "role"]
                ]
            
        effective=""
        for value in effective_strings:
            if t.effective_policy.__getattr__(value[0]) :
                effective+=value[1] + ": " + str(t.effective_policy.__getattr__(value[0])) + " "
            else:
                effective+=""
                
        print "requested: " + requested
        print "suppression: " + suppression
        print "effective: " + effective


@lldb_type_summary(['wait_queue', 'wait_queue_t'])
@header("{: <20s} {: <20s} {: <15s} {:<5s} {:<5s} {: <20s}".format("waitq", "interlock", "policy", "members", "threads", "eventmask"))
def GetWaitQSummary(waitq):
    """ Summarizes the important fields in task structure.
        params: task: value - value object representing a task in kernel
        returns: str - summary of the task
    """
    out_string = ""
    format_string = '{: <#020x} {: <#020x} {: <15s} {: <5d} {: <5d} {: <#020x}'
    
    wqtype = ""

    if (waitq.wq_fifo == 1) :
        wqtype += "FIFO"
    else :
        wqtype += "PRIO"
        
    if (waitq.wq_prepost == 1) :
        wqtype += "Prepost"
        
    if (waitq.wq_type == 0x3) :
        wqtype += "Set"
    elif (waitq.wq_type == 0x2) :
        wqtype += "Queue"
    else :
        wqtype += "INVALID"
        
    out_string += format_string.format(waitq, unsigned(waitq.wq_interlock.lock_data), policy, 0, 0, unsigned(waitq.wq_eventmask))
    
    out_string += "\n" + GetThreadSummary.header

    for thread in IterateQueue(waitq.wq_queue, "thread_t", "links"):
        out_string += "\n" + GetThreadSummary(thread)

    return out_string


@lldb_command('showallsuspendedtasks', '')
def ShowSuspendedTasks(cmd_args=[], options={}):
    """ Show a list of suspended tasks with their process name summary.
    """
    print GetTaskSummary.header + ' ' + GetProcSummary.header
    for t in kern.tasks:
        if t.suspend_count > 0:
            print GetTaskSummary(t) + ' ' + GetProcSummary(Cast(t.bsd_info, 'proc *'))
    return True

# Macro: showallpte
@lldb_command('showallpte')
def ShowAllPte(cmd_args=None):
    """ Prints out the physical address of the pte for all tasks
    """
    head_taskp = addressof(kern.globals.tasks)
    taskp = Cast(head_taskp.next, 'task *')
    while taskp != head_taskp:
        procp = Cast(taskp.bsd_info, 'proc *')
        out_str = "task = {:#x} pte = {:#x}\t".format(taskp, taskp.map.pmap.ttep)
        if procp != 0:
            out_str += "{:s}\n".format(procp.p_comm)
        else:
            out_str += "\n"
        print out_str
        taskp = Cast(taskp.tasks.next, 'struct task *')

# EndMacro: showallpte

# Macro: showallrefcounts
@lldb_command('showallrefcounts')
@header("{0: <20s} {1: ^10s}".format("task", "ref_count"))
def ShowAllRefCounts(cmd_args=None):
    """ Prints the ref_count of all tasks
    """
    out_str = ''
    head_taskp = addressof(kern.globals.tasks)
    taskp = Cast(head_taskp.next, 'task *')
    print ShowAllRefCounts.header
    while taskp != head_taskp:
        out_str += "{: <#20x}".format(taskp)
        out_str += "{: ^10d}\n".format(taskp.ref_count)
        taskp = Cast(taskp.tasks.next, 'task *')
    print out_str
# EndMacro: showallrefcounts

# Macro: showallrunnablethreads
@lldb_command('showallrunnablethreads')
def ShowAllRunnableThreads(cmd_args=None):
    """ Prints the sched usage information for all threads of each task
    """
    out_str = ''
    for taskp in kern.tasks:
        for actp in IterateQueue(taskp.threads, 'thread *', 'task_threads'):
            if int(actp.state & 0x4):
                ShowActStack([unsigned(actp)])

# EndMacro: showallrunnablethreads

# Macro: showallschedusage
@lldb_command('showallschedusage')
@header("{0:<20s} {1:^10s} {2:^10s} {3:^15s}".format("Thread", "Priority", "State", "sched_usage"))
def ShowAllSchedUsage(cmd_args=None):
    """ Prints the sched usage information for all threads of each task
    """
    out_str = ''
    for taskp in kern.tasks:
        ShowTask([unsigned(taskp)])
        print ShowAllSchedUsage.header
        for actp in IterateQueue(taskp.threads, 'thread *', 'task_threads'):
            out_str = "{: <#20x}".format(actp)
            out_str += "{: ^10s}".format(str(int(actp.sched_pri)))
            state = int(actp.state)
            thread_state_chars = {0:'', 1:'W', 2:'S', 4:'R', 8:'U', 16:'H', 32:'A', 64:'P', 128:'I'}
            state_str = ''
            state_str += thread_state_chars[int(state & 0x1)]
            state_str += thread_state_chars[int(state & 0x2)]
            state_str += thread_state_chars[int(state & 0x4)]
            state_str += thread_state_chars[int(state & 0x8)]
            state_str += thread_state_chars[int(state & 0x10)]
            state_str += thread_state_chars[int(state & 0x20)]
            state_str += thread_state_chars[int(state & 0x40)]
            state_str += thread_state_chars[int(state & 0x80)]
            out_str += "{: ^10s}".format(state_str)
            out_str += "{: >15d}".format(actp.sched_usage)
            print out_str + "\n"
        print "\n\n"

# EndMacro: showallschedusage

#Macro: showprocfilessummary
@lldb_command('showprocfilessummary')
@header("{0: <20s} {1: <20s} {2: >10s}".format("Process", "Name", "Number of Open Files"))
def ShowProcFilesSummary(cmd_args=None):
    """ Display the summary of open file descriptors for all processes in task list
        Usage: showprocfilessummary
    """
    print ShowProcFilesSummary.header
    for proc in kern.procs:
        proc_filedesc = proc.p_fd
        proc_ofiles = proc_filedesc.fd_ofiles
        proc_lastfile = unsigned(proc_filedesc.fd_lastfile)
        count = 0
        proc_file_count = 0
        if proc_filedesc.fd_nfiles != 0:
            while count <= proc_lastfile:
                if unsigned(proc_ofiles[count]) != 0:
                    proc_file_count += 1
                count += 1
        print "{0: <#020x} {1: <20s} {2: >10d}".format(proc, proc.p_comm, proc_file_count)

#EndMacro: showprocfilessummary

@lldb_command('workinguserstacks')
def WorkingUserStacks(cmd_args=None):
    """ Print out the user stack for each thread in a task, followed by the user libraries.
        Syntax: (lldb) workinguserstacks <task_t>
    """
    if not cmd_args:
        print "Insufficient arguments" + ShowTaskUserStacks.__doc__
        return False
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(task.bsd_info, 'proc *')
    print GetTaskSummary(task) + " " + GetProcSummary(pval) + "\n \n"
    for thval in IterateQueue(task.threads, 'thread *', 'task_threads'):
        print "For thread 0x{0:x}".format(thval)
        try:
            ShowThreadUserStack([hex(thval)])
        except Exception as exc_err:
            print "Failed to show user stack for thread 0x{0:x}".format(thval)
            if config['debug']:
                raise exc_err
            else:
                print "Enable debugging ('(lldb) xnudebug debug') to see detailed trace."
    WorkingUserLibraries([hex(task)])
    return

@static_var("exec_load_path", 0)
@lldb_command("workingkuserlibraries")
def WorkingUserLibraries(cmd_args=None):
    """ Show binary images known by dyld in target task
        For a given user task, inspect the dyld shared library state and print information about all Mach-O images.
        Syntax: (lldb)workinguserlibraries <task_t>
    """
    if not cmd_args:
        print "Insufficient arguments"
        print ShowTaskUserLibraries.__doc__
        return False

    print "{0: <18s} {1: <12s} {2: <36s} {3: <50s}".format('address','type','uuid','path')
    out_format = "0x{0:0>16x} {1: <12s} {2: <36s} {3: <50s}"
    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')
    is_task_64 = int(task.t_flags) & 0x1
    dyld_all_image_infos_address = unsigned(task.all_image_info_addr)
    cur_data_offset = 0
    if dyld_all_image_infos_address == 0:
        print "No dyld shared library information available for task"
        return False
    vers_info_data = GetUserDataAsString(task, dyld_all_image_infos_address, 112)
    version = _ExtractDataFromString(vers_info_data, cur_data_offset, "uint32_t")
    cur_data_offset += 4
    if version > 12:
        print "Unknown dyld all_image_infos version number %d" % version
    image_info_count = _ExtractDataFromString(vers_info_data, cur_data_offset, "uint32_t")
    WorkingUserLibraries.exec_load_path = 0
    if is_task_64:
        image_info_size = 24
        image_info_array_address = _ExtractDataFromString(vers_info_data, 8, "uint64_t")
        dyld_load_address = _ExtractDataFromString(vers_info_data, 8*4, "uint64_t")
        dyld_all_image_infos_address_from_struct = _ExtractDataFromString(vers_info_data, 8*13, "uint64_t")
    else:
        image_info_size = 12
        image_info_array_address = _ExtractDataFromString(vers_info_data, 4*2, "uint32_t")
        dyld_load_address = _ExtractDataFromString(vers_info_data, 4*5, "uint32_t")
        dyld_all_image_infos_address_from_struct = _ExtractDataFromString(vers_info_data, 4*14, "uint32_t")
    # Account for ASLR slide before dyld can fix the structure
    dyld_load_address = dyld_load_address + (dyld_all_image_infos_address - dyld_all_image_infos_address_from_struct)

    i = 0
    while i < image_info_count:
        image_info_address = image_info_array_address + i * image_info_size
        img_data = GetUserDataAsString(task, image_info_address, image_info_size)
        if is_task_64:
            image_info_addr = _ExtractDataFromString(img_data, 0, "uint64_t")
            image_info_path = _ExtractDataFromString(img_data, 8, "uint64_t")
        else:
            image_info_addr = _ExtractDataFromString(img_data, 0, "uint32_t")
            image_info_path = _ExtractDataFromString(img_data, 4, "uint32_t")
        PrintImageInfo(task, image_info_addr, image_info_path)
        i += 1

    # load_path might get set when the main executable is processed.
    if WorkingUserLibraries.exec_load_path != 0:
        PrintImageInfo(task, dyld_load_address, WorkingUserLibraries.exec_load_path)
    return

# Macro: showstackaftertask
@lldb_command('showstackaftertask','F:')
def Showstackaftertask(cmd_args=None,cmd_options={}):
    """ Routine to print the thread stacks for all tasks succeeding a given task
        Usage: showstackaftertask <0xaddress of task>
           or: showstackaftertask  -F <taskname>
    """
    if "-F" in cmd_options:
        # Find the task pointer corresponding to its task name
        find_task_str = cmd_options["-F"]
        task_list = FindTasksByName(find_task_str)

        # Iterate through the list of tasks and print all task stacks thereafter
        for tval in task_list:
            ListTaskStacks(tval)
        return

    if not cmd_args:
        raise ArgumentError("Insufficient arguments")
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        raise ArgumentError("unknown arguments: {:s}".format(str(cmd_args)))
    else:
        ListTaskStacks(tval)

    ZombStacks()
    return
# EndMacro: showstackaftertask

def ListTaskStacks(task):
    """ Search for a given task and print the list of all task stacks thereafter.
    """
    # Initialize local variable task_flag to mark when a given task is found.
    task_flag=0

    for t in kern.tasks:
        if (task_flag == 1):
            ShowTaskStacks(t)
            print "\n"
        if (t == task):
            task_flag = 1

# Macro: showstackafterthread
@lldb_command('showstackafterthread')
def Showstackafterthread(cmd_args = None):
    """ Routine to print the stacks of all threads succeeding a given thread.
        Usage: Showstackafterthread <0xaddress of thread>
    """
    # local variable thread_flag is used to mark when a given thread is found.
    thread_flag=0
    if cmd_args:
       threadval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    else:
        raise ArgumentError("No arguments passed")
    # Iterate through list of all tasks to look up a given thread
    for t in kern.tasks:
        if(thread_flag==1):
            pval = Cast(t.bsd_info, 'proc *')
            print GetTaskSummary.header + " "+ GetProcSummary.header
            print GetTaskSummary(t) +     " "+ GetProcSummary(pval)
            print "\n"
         # Look up for a given thread from the the list of threads of a given task
        for thval in IterateQueue(t.threads, 'thread *', 'task_threads'):
            if (thread_flag==1):
               print "\n"
               print "  " + GetThreadSummary.header
               print "  " + GetThreadSummary(thval)
               print GetThreadBackTrace(thval, prefix="\t")+"\n"
               print "\n"

            if(thval==threadval):
               pval = Cast(t.bsd_info, 'proc *')
               process_name = "{:s}".format(pval.p_comm)
               print "\n\n"
               print " *** Continuing to dump the thread stacks from the process *** :" + " " + process_name
               print "\n\n"
               thread_flag = 1
        print '\n'
    return

