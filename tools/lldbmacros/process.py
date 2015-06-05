
""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""

from xnu import *
import sys, shlex
from utils import *
from core.lazytarget import *
import xnudefines

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
        C - AST_CHUD
        C - AST_CHUD_URGENT
        G - AST_GUARD
        T - AST_TELEMETRY_USER
        T - AST_TELEMETRY_KERNEL
        T - AST_TELEMETRY_WINDOWED
        S - AST_SFI
    """
    out_string = ""
    state = int(ast)
    thread_state_chars = {0x0:'', 0x1:'P', 0x2:'Q', 0x4:'U', 0x8:'H', 0x10:'Y', 0x20:'A',
                          0x40:'L', 0x80:'B', 0x100:'K', 0x200:'M', 0x400:'C', 0x800:'C',
                          0x1000:'G', 0x2000:'T', 0x4000:'T', 0x8000:'T', 0x10000:'S'}
    state_str = ''
    mask = 0x1
    while mask <= 0x10000 :
        state_str += thread_state_chars[int(state & mask)]
        mask = mask << 1
    
    return state_str


@lldb_type_summary(['task', 'task_t'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: >5s} {4: <5s}".format("task","vm_map", "ipc_space", "#acts", "flags"))
def GetTaskSummary(task):
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
    out_string += format_string.format(task, task.map, task.itk_space, thread_count, task_flags)
    return out_string

@lldb_type_summary(['thread *', 'thread_t'])
@header("{0: <24s} {1: <10s} {2: <20s} {3: <6s} {4: <6s} {5: <15s} {6: <15s} {7: <8s} {8: <12s} {9: <32s} {10: <20s} {11: <20s} {12: <20s}".format('thread', 'thread_id', 'processor', 'base', 'pri', 'sched_mode', 'io_policy', 'state', 'ast', 'wait_queue', 'wait_event', 'wmesg', 'thread_name'))
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

        policy flags:
        B - darwinbg
        L - lowpri cpu
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
    thread_name = ''
    processor = hex(thread.last_processor)
    base_priority = str(int(thread.priority))
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
    if int(thread.uthread) != 0:
        uthread = Cast(thread.uthread, 'uthread *')
        #check for thread name
        if int(uthread.pth_name) != 0 :
            th_name_strval = Cast(uthread.pth_name, 'char *')
            if len(str(th_name_strval)) > 0 :
                thread_name = str(th_name_strval)
        
        #check for io_policy flags 
        if int(uthread.uu_flag) & 0x400:
            io_policy_str+='RAGE '
        
        #now flags for task_policy
        
        io_policy_str = ""
        
        if int(thread.effective_policy.darwinbg) != 0:
            io_policy_str += "B"
        if int(thread.effective_policy.lowpri_cpu) != 0:
            io_policy_str += "L"
        
        if int(thread.effective_policy.io_tier) != 0:
            io_policy_str += "T"
        if int(thread.effective_policy.io_passive) != 0:
            io_policy_str += "P"
        if int(thread.effective_policy.terminated) != 0:
            io_policy_str += "D"
                
    state = int(thread.state)
    thread_state_chars = {0x0:'', 0x1:'W', 0x2:'S', 0x4:'R', 0x8:'U', 0x10:'H', 0x20:'A', 0x40:'P', 0x80:'I'}
    state_str = ''
    mask = 0x1
    while mask <= 0x80 :
        state_str += thread_state_chars[int(state & mask)]
        mask = mask << 1
        
    ast = int(thread.ast) | int(thread.reason)
    ast_str = GetASTSummary(ast)
    
    #wait queue information
    wait_queue_str = ''
    wait_event_str = ''
    wait_message = ''
    if ( state & 0x1 ) != 0:
        #we need to look at the waitqueue as well
        wait_queue_str = str("{0: <#020x}".format(int(hex(thread.wait_queue), 16)))
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
    

@lldb_type_summary(['coalition_t', 'coalition'])
@header("{:>18s} {:>10s} {:>8s} {:>8s} {:>8s} {:>8s}".format("coalition", "id", "refcount", "active", "focal", "nonfocal"))
def GetCoalitionSummary(coal):
    out_string = ""
    format_string = '{:>#018x} {:>10d} {:>8d} {:>8d} {:>8d} {:>8d}'

    flags_string = ''
    if (coal.terminated):
        flags_string += ' terminated'
    if (coal.reaped):
        flags_string += ' reaped'
    out_string += format_string.format(coal, coal.id, coal.ref_count, coal.active_count, coal.focal_tasks_count, coal.non_focal_tasks_count)

    return out_string

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
    
    if int(task.effective_policy.darwinbg) != 0:
        io_policy_str += "B"
    if int(task.effective_policy.lowpri_cpu) != 0:
        io_policy_str += "L"
    
    if int(task.effective_policy.io_tier) != 0:
        io_policy_str += "T"
    if int(task.effective_policy.io_passive) != 0:
        io_policy_str += "P"
    if int(task.effective_policy.terminated) != 0:
        io_policy_str += "D"
    
    if int(task.effective_policy.t_suspended) != 0:
        io_policy_str += "S"
    if int(task.effective_policy.t_latency_qos) != 0:
        io_policy_str += "Q"
    if int(task.effective_policy.t_sup_active) != 0:
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

@lldb_type_summary(['kqueue *'])
@header("{: <20s} {: <20s} {: <6s} {: <20s} {: <10s}".format('kqueue', 'process', '#events', 'wqs', 'state'))
def GetKQueueSummary(kq):
    """ summarizes kqueue information
        returns: str - summary of kqueue
    """
    out_string = ""
    format_string = "{o: <#020x} {o.kq_p: <#020x} {o.kq_count: <6d} {o.kq_wqs: <#020x} {st_str: <10s}"
    state = int(kq.kq_state)
    state_str = ''
    mask = 0x1
    while mask <= 0x80 :
        if int(state & mask):
            state_str += ' ' + xnudefines.kq_state_strings[int(state & mask)]
        mask = mask << 1
    out_string += format_string.format(o=kq, st_str=state_str)
    return out_string

@lldb_type_summary(['knote *'])
@header("{0: <20s}".format('knote'))
def GetKnoteSummary(kn):
    """ Summarizes a knote and related information
        returns: str - summary of knote
    """
    out_string = ""
    format_string = "{o: <#020x}"
    out_string += format_string.format(o=kn)
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
        print "No arguments passed"
        print ShowPid.__doc__
        return False
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
        print "No arguments passed"
        print ShowProc.__doc__
        return False
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
        print "No arguments passed"
        print ShowProcInfo.__doc__
        return False
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

    # Filetype map
    filetype_dict = {
                1: 'VNODE',
                2: 'SOCKET',
                3: 'PSXSHM',
                4: 'PSXSEM',
                5: 'KQUEUE',
                6: 'PIPE',
                7: 'FSEVENTS'
              }

    while count <= proc_lastfile:
        if unsigned(proc_ofiles[count]) != 0:
            out_str = ''
            proc_fd_flags = proc_ofiles[count].f_flags
            proc_fd_fglob = proc_ofiles[count].f_fglob
            out_str += "{0: <5d} ".format(count)
            out_str += "{0: <#18x} ".format(unsigned(proc_fd_fglob))
            out_str += "0x{0:0>8x} ".format(unsigned(proc_fd_flags))
            proc_fd_ftype = unsigned(proc_fd_fglob.fg_ops.fo_type)
            if proc_fd_ftype in filetype_dict:
                out_str += "{0: <8s} ".format(filetype_dict[proc_fd_ftype])
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

#Macro: showkqueue
@lldb_command('showkqueue' ,'')
def ShowKQueue(cmd_args=[], cmd_options={}):
    """ Given a struct kqueue pointer, display the summary of the kqueue
        Usage: (lldb) showkqueue <struct kqueue *>
    """
    if not cmd_args:
        raise ArgumentError('Invalid arguments')

    kq = kern.GetValueFromAddress(cmd_args[0], 'struct kqueue *')
    print GetKQueueSummary.header
    print GetKQueueSummary(kq)

#EndMacro: showkqueue

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

#Macro: dumpcallqueue

@lldb_command('dumpcallqueue')
def DumpCallQueue(cmd_args=None):
    """ Displays the contents of the specified call_entry queue.
        Usage: dumpcallqueue <queue_head_t *>
    """
    if not cmd_args:
        print DumpCallQueue.__doc__
        return
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

@lldb_command('showallcoalitions')
def ShowAllCoalitions(cmd_args=None):
    """  Routine to print a summary listing of all the coalitions
    """
    global kern
    
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
    

    print GetCoalitionSummary.header
    for c in kern.coalitions:
        print GetCoalitionSummary(c)
        for task in IterateQueue(c.tasks, "task_t", "coalition_tasks"):
            print "\t" + hex(task) + " " + GetProcNameForTask(task) + " " + role_strs[int(task.effective_policy.t_role)]
            for thread in IterateQueue(task.threads, "thread_t", "task_threads"):
                print "\t\t" + hex(thread) + " " + sfi_strs[int(thread.sfi_class)]


@lldb_command('showalltasks') 
def ShowAllTasks(cmd_args=None):
    """  Routine to print a summary listing of all the tasks
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
    ZombTasks()

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
    if cmd_args == None or len(cmd_args) < 1:
        print "No arguments passed"
        print ShowAct.__doc__
        return False
    threadval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    print GetThreadSummary.header
    print GetThreadSummary(threadval)

@lldb_command('showactstack')
def ShowActStack(cmd_args=None):
    """ Routine to print out the stack of a specific thread.
        usage:  showactstack <activation> 
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "No arguments passed"
        print ShowAct.__doc__.strip()
        return False
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
    if cmd_args == None or len(cmd_args) < 1:
        print "No arguments passed"
        print SwitchToAct.__doc__.strip()
        return False
    thval = kern.GetValueFromAddress(cmd_args[0], 'thread *')
    lldbthread = GetLLDBThreadForKernelThread(thval)
    print GetThreadSummary.header
    print GetThreadSummary(thval)
    LazyTarget.GetProcess().selected_thread = lldbthread
    if not LazyTarget.GetProcess().SetSelectedThread(lldbthread):
        print "Failed to switch thread."
    return
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
        if (kern.arch != 'arm' and frame_ptr < mh_execute_addr) or (kern.arch == 'arm' and frame_ptr > mh_execute_addr):
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

# Macro: showallprocessors

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

    out_str = "Processor {: <#018x} cpu_id {:>#4x} State {:<s}\n".format(processor, int(processor.cpu_id), processor_state_str)
    return out_str   

def GetGroupSetSummary(runq, task_map):
    """ Internal function to print summary of group run queue
        params: runq - value representing struct run_queue * 
        return: str - representing the details of given run_queue
    """
    out_str = "    runq: count {: <10d} highq: {: <10d} urgency {: <10d}\n".format(runq.count, runq.highq, runq.urgency)
    
    runq_queue_i = 0
    runq_queue_count = sizeof(runq.queues)/sizeof(runq.queues[0])
    
    for runq_queue_i in range(runq_queue_count) :
        runq_queue_head = addressof(runq.queues[runq_queue_i])
        runq_queue_p = runq_queue_head.next
        
        if unsigned(runq_queue_p) != unsigned(runq_queue_head):
            runq_queue_this_count = 0
            
            for entry in IterateQueue(runq_queue_head, "sched_entry_t", "links"):
                runq_queue_this_count += 1
            
            out_str += "      Queue [{: <#012x}] Priority {: <3d} count {:d}\n".format(runq_queue_head, runq_queue_i, runq_queue_this_count)
            for entry in IterateQueue(runq_queue_head, "sched_entry_t", "links"):
                group = entry.group
                task = task_map.get(unsigned(group), "Unknown task!")
                out_str += "\tEntry [{: <#012x}] Priority {: <3d} Group {: <#012x} Task {: <#012x}\n".format(unsigned(entry), entry.sched_pri, unsigned(entry.group), unsigned(task))
                
    return out_str

@lldb_command('showrunq')
def ShowRunq(cmd_args=None):
    """  Routine to print information of a runq
         Usage: showrunq <runq>
    """
    out_str = ''
    runq = kern.GetValueFromAddress(cmd_args[0], 'struct run_queue *')
    out_str += GetRunQSummary(runq)
    print out_str

def GetRunQSummary(runq):
    """ Internal function to print summary of run_queue
        params: runq - value representing struct run_queue * 
        return: str - representing the details of given run_queue
    """
    out_str = "    runq: count {: <10d} highq: {: <10d} urgency {: <10d}\n".format(runq.count, runq.highq, runq.urgency)
    
    runq_queue_i = 0
    runq_queue_count = sizeof(runq.queues)/sizeof(runq.queues[0])
    
    for runq_queue_i in range(runq_queue_count) :
        runq_queue_head = addressof(runq.queues[runq_queue_i])
        runq_queue_p = runq_queue_head.next
        
        if unsigned(runq_queue_p) != unsigned(runq_queue_head):
            runq_queue_this_count = 0
            
            for thread in IterateQueue(runq_queue_head, "thread_t", "links"):
                runq_queue_this_count += 1
            
            out_str += "      Queue [{: <#012x}] Priority {: <3d} count {:d}\n".format(runq_queue_head, runq_queue_i, runq_queue_this_count)
            out_str += "\t" + GetThreadSummary.header + "\n"
            for thread in IterateQueue(runq_queue_head, "thread_t", "links"):
                out_str += "\t" + GetThreadSummary(thread) + "\n"
                if config['verbosity'] > vHUMAN :
                    out_str += "\t" + GetThreadBackTrace(thread, prefix="\t\t") + "\n"
    return out_str


def GetGrrrSummary(grrr_runq):
    """ Internal function to print summary of grrr_run_queue
        params: grrr_runq - value representing struct grrr_run_queue * 
        return: str - representing the details of given grrr_run_queue
    """
    out_str = "    GRRR Info: Count {: <10d} Weight {: <10d} Current Group {: <#012x}\n".format(grrr_runq.count,
        grrr_runq.weight, grrr_runq.current_group)
    grrr_group_i = 0
    grrr_group_count = sizeof(grrr_runq.groups)/sizeof(grrr_runq.groups[0])
    for grrr_group_i in range(grrr_group_count) :
        grrr_group = addressof(grrr_runq.groups[grrr_group_i])
        if grrr_group.count > 0:
            out_str += "      Group {: <3d} [{: <#012x}] ".format(grrr_group.index, grrr_group)
            out_str += "Count {:d} Weight {:d}\n".format(grrr_group.count, grrr_group.weight)
            grrr_group_client_head = addressof(grrr_group.clients)
            out_str += GetThreadSummary.header
            for thread in IterateQueue(grrr_group_client_head, "thread_t", "links"):
                out_str += "\t" + GetThreadSummary(thread) + "\n"
                if config['verbosity'] > vHUMAN :
                    out_str += "\t" + GetThreadBackTrace(thread, prefix="\t\t") + "\n"
    return out_str

@lldb_command('showallprocessors') 
def ShowAllProcessors(cmd_args=None):
    """  Routine to print information of all psets and processors
         Usage: showallprocessors
    """
    pset = addressof(kern.globals.pset0)
    show_grrr = 0
    show_priority_runq = 0
    show_priority_pset_runq = 0
    show_group_pset_runq = 0
    show_fairshare_grrr = 0
    show_fairshare_list = 0
    sched_enum_val = kern.globals._sched_enum
    
    if sched_enum_val == 1:
        show_priority_runq = 1
        show_fairshare_list = 1
    elif sched_enum_val == 2:
        show_priority_pset_runq = 1
        show_fairshare_list = 1
    elif sched_enum_val == 4:
        show_grrr = 1
        show_fairshare_grrr = 1
    elif sched_enum_val == 5:
        show_priority_runq = 1
        show_group_pset_runq = 1
        show_fairshare_list = 1
    elif sched_enum_val == 6:
        show_priority_pset_runq = 1        
        show_priority_runq = 1
        show_fairshare_list = 1

    out_str = ''
    
    out_str += "Scheduler: {:s} ({:s}, {:d})\n".format(kern.globals.sched_string,
            kern.Symbolicate(unsigned(kern.globals.sched_current_dispatch)),
            sched_enum_val)
    
    out_str += "Runnable threads: {:d} Timeshare threads: {:d} Background threads {:d}\n".format(
            kern.globals.sched_run_count, kern.globals.sched_share_count, kern.globals.sched_background_count)    
    
    if show_group_pset_runq:
        # Create a group->task mapping
        task_map = {}
        for task in kern.tasks:
            task_map[unsigned(task.sched_group)] = task
        for task in kern.terminated_tasks:
            task_map[unsigned(task.sched_group)] = task
    
    while unsigned(pset) != 0:
        out_str += "Processor Set  {: <#012x} Count {:d} (cpu_id {:<#x}-{:<#x})\n".format(pset, 
            pset.cpu_set_count, pset.cpu_set_low, pset.cpu_set_hi)
        
        if show_priority_pset_runq:
            runq = pset.pset_runq
            out_str += GetRunQSummary(runq)
            
        if show_group_pset_runq:
            out_str += "Main Runq:\n"    
            runq = pset.pset_runq
            out_str += GetGroupSetSummary(runq, task_map)
            out_str += "All Groups:\n"    
            # TODO: Possibly output task header for each group
            for group in IterateQueue(kern.globals.sched_groups, "sched_group_t", "sched_groups"):
                if (group.runq.count != 0) :
                    task = task_map.get(unsigned(group), "Unknown task!")
                    out_str += "Group {: <#012x} Task {: <#012x}\n".format(unsigned(group), unsigned(task))
                    out_str += GetRunQSummary(group.runq)
        
        out_str += "  Active Processors:\n"
        for processor in IterateQueue(pset.active_queue, "processor_t", "processor_queue"):
            out_str += "    "
            out_str += GetProcessorSummary(processor)
            if show_priority_runq:
                runq = processor.runq
                out_str += GetRunQSummary(runq)
            if show_grrr:
                grrr_runq = processor.grrr_runq
                out_str += GetGrrrSummary(grrr_runq)

        out_str += "  Idle Processors:\n"
        for processor in IterateQueue(pset.idle_queue, "processor_t", "processor_queue"):
            out_str += "    " + GetProcessorSummary(processor)
            if show_priority_runq:            
                out_str += GetRunQSummary(processor.runq)

        out_str += "  Idle Secondary Processors:\n"
        for processor in IterateQueue(pset.idle_secondary_queue, "processor_t", "processor_queue"):
            out_str += "    " + GetProcessorSummary(processor)
            if show_priority_runq:            
                out_str += GetRunQSummary(processor.runq)
        
        pset = pset.pset_list

    out_str += "\nRealtime Queue Count {:d}\n".format(kern.globals.rt_runq.count)
    for rt_runq_thread in IterateQueue(kern.globals.rt_runq.queue, "thread_t", "links"):
        out_str += ShowTask([unsigned(rt_runq_thread.task)])
        out_str += ShowAct([unsigned(rt_runq_thread)])
    
    out_str += "\n"
    if show_fairshare_list:
        out_str += "Fair Share Queue Count {:d}\n".format(kern.globals.fs_runq.count)
        for fs_runq_thread in IterateQueue(kern.globals.fs_runq.queue, "thread_t", "links"):
            out_str += ShowTask([unsigned(fs_runq_thread.task)])
            out_str += ShowAct([unsigned(rt_runq_thread)])
    if show_fairshare_grrr:
        out_str += "Fair Share Queue Count {:d}\n".format(kern.globals.fs_grrr_runq.count)
        fs_grrr = addressof(kern.globals.fs_grrr_runq)
        out_str += GetGrrrSummary(fs_grrr)

    print out_str
# EndMacro: showallprocessors

def GetLedgerEntrySummary(ledger_template, ledger, i):
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
        out_str += "{:9d} {:5d} ".format(ledger._le.le_peaks[0].le_max, now - unsigned(ledger._le.le_peaks[0].le_time))
        out_str += "{:9d} {:4d} ".format(ledger._le.le_peaks[1].le_max, now - unsigned(ledger._le.le_peaks[1].le_time))
    else:
        out_str += "        -     -         -    - "
    
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

@header("{0: <15s} {1: >16s} {2: <2s} {3: >15s} {4: >9s} {5: >6s} {6: >8s} {7: <10s} {8: <9s} \
    {9: <12s} {10: <7s} {11: <15s} {12: <8s} {13: <9s} {14: <6s} {15: >6s}".format(
    "task [thread]", "entry", "#", "balance", "peakA", "(age)", "peakB", "(age)", "credit",
     "debit", "limit", "refill period", "lim pct", "warn pct", "over?", "flags"))
def GetTaskLedgers(task_val):
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
        out_str += GetLedgerEntrySummary(kern.globals.task_ledger_template, task_ledgerp.l_entries[i], i)
        i = i + 1

    # Now walk threads
    for thval in IterateQueue(task_val.threads, 'thread *', 'task_threads'):
        out_str += GetThreadLedgerSummary(thval)

    return out_str

# Macro: showtaskledgers

@lldb_command('showtaskledgers', 'F:') 
def ShowTaskLedgers(cmd_args=None, cmd_options={}):
    """  Routine to print a summary  of ledger entries for the task and all of its threads
         Usage: showtaskledgers <address of task>
         or   : showtaskledgers -F <name of task>
    """
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options["-F"])
        for tval in task_list:
            print GetTaskLedgers.header
            print GetTaskLedgers(tval)
        return
    
    if not cmd_args:
        raise ArgumentError("No arguments passed.")
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        raise ArgumentError("unknown arguments: %r" %cmd_args)
    print GetTaskLedgers.header
    print GetTaskLedgers(tval)

# EndMacro: showtaskledgers

# Macro: showalltaskledgers

@lldb_command('showalltaskledgers') 
def ShowAllTaskLedgers(cmd_args=None):
    """  Routine to print a summary  of ledger entries for all tasks and respective threads
         Usage: showalltaskledgers
    """
    for t in kern.tasks:
        task_val = unsigned(t)
        ShowTaskLedgers([task_val])
    
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
                ["th_workq_bg",         "bg-workq"],
                ["t_apptype",           "apptype"],
                ["t_boosted",           "boosted"],
                ["t_int_gpu_deny",      "gpudeny-int"],
                ["t_ext_gpu_deny",      "gpudeny-ext"],
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
                

        pended_strings = [
                ["t_updating_policy",     "updating"],
                ["update_sockets",        "update_sockets"],
                ["t_update_timers",       "update_timers"],
                ["t_update_watchers",     "update_watchers"]
                ]
            
        pended=""
        for value in pended_strings:
            if t.pended_policy.__getattr__(value[0]) :
                pended+=value[1] + ": " + str(t.pended_policy.__getattr__(value[0])) + " "
            else:
                pended+=""
                
        print "requested: " + requested
        print "suppression: " + suppression
        print "effective: " + effective
        print "pended: " + pended


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


