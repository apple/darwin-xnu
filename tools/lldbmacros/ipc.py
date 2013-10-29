""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""
from xnu import *
import sys, shlex
from utils import *
from process import *
import xnudefines

@header("{0: <20s} {1: <6s} {2: <6s} {3: <10s} {4: <15s}".format("task", "pid", '#acts', "tablesize", "command"))
def GetTaskIPCSummary(task):
    """ Display a task's ipc summary. 
        params:
            task : core.value represeting a Task in kernel
        returns
            str - string of ipc info for the task
    """
    out_string = ''
    format_string = "{0: <#020x} {1: <6d} {2: <6d} {3: <10d} {4: <15s}"
    pval = Cast(task.bsd_info, 'proc *')
    table_size = int(task.itk_space.is_table_size)
    proc_name = str(pval.p_comm)
    out_string += format_string.format(task, pval.p_pid, task.thread_count, table_size, proc_name)
    return out_string

@header("{0: <20s} {1: <28s} {2: <12s} {3: <6s} {4: <4s}  {5: <20s} {6: <4s}\n".format(
            "port", "mqueue", "recvname", "flags", "refs", "recvname", "dest"))
def GetPortSummary(port, show_kmsg_summary=True, prefix=""):
    """ Display a port's summary
        params:
            port : core.value representing a port in the kernel
        returns
            str  : string of ipc info for the given port
    """
    out_string = ""
    portp = Cast(port, 'struct ipc_port *')
    destspacep = kern.GetValueFromAddress(0, 'struct ipc_space *')
    spacep = portp.data.receiver
    format_string = "{0: #019x} {1: #019x} {2: <8s} {3: #011x}   {4: <5s} {5: #05x}  {6: #019x}  {7: <16s}\n"
    if portp.ip_object.io_bits & 0x80000000:
        out_string += prefix + format_string.format(
                                unsigned(portp), addressof(portp.ip_messages), ' '*8,
                                unsigned(portp.ip_messages.data.port.receiver_name),
                                "APort", portp.ip_object.io_references,
                                unsigned(portp.ip_messages.data.port.receiver_name),
                                GetPortDestProc(portp))
    else:
        out_string += prefix + format_string.format(
                                unsigned(portp), addressof(portp.ip_messages), ' '*8,
                                unsigned(portp.ip_messages.data.port.receiver_name),
                                "DPort", portp.ip_object.io_references, unsigned(portp),
                                "inactive-port")
    
    if show_kmsg_summary:
        kmsgp = Cast(portp.ip_messages.data.port.messages.ikmq_base, 'ipc_kmsg_t')
        out_string += prefix + GetKMsgSummary.header + prefix + GetKMsgSummary(kmsgp)
        
        kmsgheadp = kmsgp
        kmsgp = kmsgp.ikm_next
        while (kmsgp) != (kmsgheadp):
            out_string += prefix + GetKMsgSummary(kmsgp)
            kmsgp = kmsgp.ikm_next
    return out_string

def GetPortDestProc(portp):
    """ Display the name and pid of a given port's receiver
        params:
            portp : core.value representing a pointer to a port in the kernel
            destspacep : core.value representing a pointer to an ipc_space
        returns:
            str   : string containing receiver's name and pid
    """
    spacep = portp.data.receiver
    out_str = "Not found"
    for tsk in kern.tasks:
        if tsk.itk_space == spacep:
            if tsk.bsd_info:
                destprocp = Cast(tsk.bsd_info, 'struct proc *')
                out_str = "{0:s}({1: <d})".format(destprocp.p_comm, destprocp.p_pid)
            else:
                out_str = "task {0: #019x}".format(desttaskp)
            break
    
    return out_str

@header("{0: <20s} {1: <28s} {2: <12s} {3: <6s} {4: <6s} {5: <19s} {6: <6s}\n".format(
            "dest-port", "kmsg", "msgid", "disp", "size", "reply-port", "source"))
def GetKMsgSummary(kmsgp):
    """ Display a summary for type ipc_kmsg_t
        params:
            kmsgp : core.value representing the given ipc_kmsg_t struct
        returns:
            str   : string of summary info for the given ipc_kmsg_t instance
    """
    kmsghp = kmsgp.ikm_header
    kmsgh = dereference(kmsghp)
    out_string = ""
    out_string += "{0: <19s} {1: #019x} {2: <8s} {3: #011x}   ".format(
                    ' '*19, unsigned(kmsgp), ' '*8, kmsgh.msgh_id)
    
    if (kmsgh.msgh_bits & 0xff) == 19:
        out_string += "{0: <2s}".format("rC")
    else:
        out_string += "{0: <2s}".format("rM")
    
    if (kmsgh.msgh_bits & 0xff00) == (19 << 8):
        out_string += "{0: <2s}".format("lC")
    else:
        out_string += "{0: <2s}".format("lM")
    if kmsgh.msgh_bits & 0xf0000000:
        out_string += "{0: <2s}".format("c")
    else:
        out_string += "{0: <2s}".format("s")
    
    out_string += "{0: >5d}  {1: #019x}  {2: <16s}\n".format(
                    unsigned(kmsgh.msgh_size), kmsgh.msgh_local_port,
                    GetKMsgSrc(kmsgp))
    return out_string

def GetKMsgSrc(kmsgp):
    """ Routine that prints a kmsg's source process and pid details
        params:
            kmsgp : core.value representing the given ipc_kmsg_t struct
        returns:
            str  : string containing the name and pid of the kmsg's source proc
    """
    kmsgsrchp = Cast(kmsgp, 'ipc_kmsg_t').ikm_header
    kmsgpid = int(Cast(kern.GetValueFromAddress(unsigned(kmsgsrchp) + kmsgsrchp.msgh_size, 'uint *')[10], 'pid_t'))
    
    return "{0:s} ({1:d})".format(GetProcNameForPid(kmsgpid), kmsgpid)

@header("{0: <20s} {1: <28s} {2: <12s} {3: <6s} {4: <6s} {5: <20s} {6: <7s}\n".format(
            "portset", "waitqueue", "recvname", "flags", "refs", "recvname", "process"))
def GetPortSetSummary(pset):
    """ Display summary for a given struct ipc_pset *
        params:
            pset : core.value representing a pset in the kernel
        returns:
            str  : string of summary information for the given pset
    """
    out_str = ""
    if pset.ips_object.io_bits & 0x80000000:
        out_str += "{0: #019x}  {1: #019x} {2: <7s} {3: #011x}   {4: <4s} {5: >6d}  {6: #019x}   ".format(
                    unsigned(pset), addressof(pset.ips_messages), ' '*7,
                    pset.ips_messages.data.pset.local_name, "ASet",
                    pset.ips_object.io_references,
                    pset.ips_messages.data.pset.local_name)

    else:
        out_str += "{0: #019x}  {1: #019x} {2: <7s} {3: #011x}   {4: <4s} {5: >6d}  {6: #019x}   ".format(
                    unsigned(pset), addressof(pset.ips_messages), ' '*7,
                    pset.ips_messages.data.pset.local_name, "DSet",
                    pset.ips_object.io_references,
                    pset.ips_messages.data.pset.local_name)
    
    once = True
    setlinksp = addressof(pset.ips_messages.data.pset.set_queue.wqs_setlinks)
    wql = Cast(pset.ips_messages.data.pset.set_queue.wqs_setlinks.next, 'WaitQueueLink *')
    portoff = getfieldoffset('struct ipc_port', 'ip_messages')
    prefix_str = "{0:<21s}".format(' '*21)
    while unsigned(wql) != unsigned(Cast(setlinksp, 'void *')):
        portp = kern.GetValueFromAddress(unsigned(wql.wql_element.wqe_queue) - portoff, 'ipc_port *')
        if once:
            once = False
            out_str += "{0:s}\n{1:s}{2:s}".format(GetPortDestProc(portp), prefix_str, GetPortSummary.header)
        out_str += GetPortSummary(portp, False, prefix_str)
        wql = Cast(wql.wql_setlinks.next, 'WaitQueueLink *')
    return out_str

# Macro: showipc

@lldb_command('showipc') 
def ShowIPC(cmd_args=None):
    """  Routine to print data for the given IPC space 
         Usage: showipc <address of ipc space>
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowIPC.__doc__
        return False
    ipc = kern.GetValueFromAddress(cmd_args[0], 'ipc_space *')
    if not ipc:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetIPCInformation.header
    print GetIPCInformation(ipc, False, False)

# EndMacro: showipc

# Macro: showtaskipc

@lldb_command('showtaskipc') 
def ShowTaskIPC(cmd_args=None):
    """  Routine to print IPC summary of given task
         Usage: showtaskipc <address of task>
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowTaskIPC.__doc__
        return False
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(tval.bsd_info, 'proc *')
    print GetTaskSummary(tval) + " " + GetProcSummary(pval)
    print GetTaskIPCSummary.header
    print GetTaskIPCSummary(tval)

# EndMacro: showtaskipc

# Macro: showallipc

@lldb_command('showallipc') 
def ShowAllIPC(cmd_args=None):
    """  Routine to print IPC summary of all tasks
         Usage: showallipc
    """
    for t in kern.tasks:
        print GetTaskSummary.header + " " + GetProcSummary.header
        pval = Cast(t.bsd_info, 'proc *')
        print GetTaskSummary(t) + " " + GetProcSummary(pval)
        print GetIPCInformation.header
        print GetIPCInformation(t.itk_space, False, False) + "\n\n"

# EndMacro: showallipc

@lldb_command('showipcsummary')
def ShowIPCSummary(cmd_args=None):
    """ Summarizes the IPC state of all tasks. 
        This is a convenient way to dump some basic clues about IPC messaging. You can use the output to determine
        tasks that are candidates for further investigation.
    """
    print GetTaskIPCSummary.header
    for t in kern.tasks:
        print GetTaskIPCSummary(t)
    return

def GetKObjectFromPort(portval):
    """ Get Kobject description from the port.
        params: portval - core.value representation of 'ipc_port *' object
        returns: str - string of kobject information
    """
    kobject_str = "{0: <#020x}".format(portval.kdata.kobject)
    io_bits = unsigned(portval.ip_object.io_bits)
    objtype_index = io_bits & 0xfff
    if objtype_index < len(xnudefines.kobject_types) :
        desc_str = "kobject({0:s})".format(xnudefines.kobject_types[objtype_index])
    else:
        desc_str = "kobject(UNKNOWN) {:d}".format(objtype_index)
    return kobject_str + " " + desc_str

@static_var('destcache', {})    
def GetDestinationProcessFromPort(port):
    """
        params: port - core.value representation of 'ipc_port *' object
        returns: str - name of process 
    """
    out_str = ''
    dest_space = port.data.receiver
    found_dest = False
    #update destcache if data is not found
    if hex(dest_space) not in GetDestinationProcessFromPort.destcache:
        for t in kern.tasks:
            if hex(t.itk_space) == hex(dest_space):
                pval = Cast(t.bsd_info, 'proc *')
                GetDestinationProcessFromPort.destcache[hex(dest_space)] = (t, pval)
                found_dest = True
                break
        #end of for loop
    else: found_dest = True
    
    if found_dest:
        (ftask , fproc) = GetDestinationProcessFromPort.destcache[hex(dest_space)]
        if fproc:
            out_str = "{0:s}({1:d})".format(fproc.p_comm, fproc.p_pid )
        else:
            out_str = "task {0: <#020x}".format(ftask)
    return out_str
    
        
    
@header("{0: <20s} {1: <20s}".format("destname", "destination") )
def GetPortDestinationSummary(port):
    """ Get destination information for a port. 
        params: port - core.value representation of 'ipc_port *' object
        returns: str - string of info about ports destination
    """
    out_str = ''
    format_string = "{0: <20s} {1: <20s}"
    destname_str = ''
    destination_str = ''
    ipc_space_kernel = unsigned(kern.globals.ipc_space_kernel)
    target_spaceval = port.data.receiver
    if unsigned(target_spaceval) == ipc_space_kernel :
        destname_str = GetKObjectFromPort(port)
    else:
        if int(port.ip_object.io_bits) & 0x80000000 :
            destname_str = "{0: <#020x}".format(port.ip_messages.data.port.receiver_name)
            destination_str = GetDestinationProcessFromPort(port)
        else:
            destname_str = "{0: <#020x}".format(port)
            destination_str = "inactive-port"
    
    out_str += format_string.format(destname_str, destination_str)
    return out_str
    
@lldb_type_summary(['ipc_entry_t'])
@header("{0: <20s} {1: <20s} {2: <8s} {3: <8s} {4: <20s} {5: <20s}".format("object", "name","rite", "urefs", "destname", "destination"))
def GetIPCEntrySummary(entry, ipc_name=''):
    """ Get summary of a ipc entry.
        params:
            entry - core.value representing ipc_entry_t in the kernel
            ipc_name - str of format '0x0123' for display in summary.  
        returns:
            str - string of ipc entry related information
    """
    out_str = ''    
    entry_ptr = int(hex(entry), 16)
    format_string = "{0: <#020x} {1: <12s} {2: <8s} {3: <8d} {4: <20s} {5: <20s}"
    right_str = ''
    destname_str = ''
    destination_str = ''
    
    ie_object = entry.ie_object
    ie_bits = int(entry.ie_bits)
    urefs = int(ie_bits & 0xffff)
    if ie_bits & 0x00100000 :
        right_str = 'Dead'
    elif ie_bits & 0x00080000:
        right_str = 'Set'
    else:
        if ie_bits & 0x00010000 :
            if ie_bits & 0x00020000 :
                right_str = 'SR'
            else:
                right_str = 'S'
        elif ie_bits & 0x00020000:
            right_str = 'R'
        elif ie_bits & 0x00040000 :
            right_str = 'O'
        if int(entry.index.request) != 0:
            portval = Cast(ie_object, 'ipc_port_t')
            requestsval = portval.ip_requests
            sorightval = requestsval[int(entry.index.request)].notify.port
            soright_ptr = unsigned(sorightval)
            if soright_ptr != 0:
                 if soright_ptr & 0x1 : right_str +='s'
                 elif soright_ptr & 0x2 : right_str +='d'
                 else : right_str +='n'
        if ie_bits & 0x00800000 : right_str +='c'
        # now show the port destination part
        destname_str = GetPortDestinationSummary(Cast(ie_object, 'ipc_port_t'))
        
    out_str = format_string.format(ie_object, ipc_name, right_str, urefs, destname_str, destination_str)
    return out_str

@header("{0: >20s}".format("user bt") )
def GetPortUserStack(port, task):
    """ Get UserStack information for the given port & task. 
        params: port - core.value representation of 'ipc_port *' object
                task - value representing 'task *' object
        returns: str - string information on port's userstack
    """
    out_str = ''
    ie_port_callstack = port.ip_callstack
    ie_port_spares = port.ip_spares[0]
    proc_val = Cast(task.bsd_info, 'proc *')  
    if ie_port_callstack[0]:
        out_str += "{: <10x}".format(ie_port_callstack[0])
        count = 1
        while count < 16 and ie_port_callstack[count]:
            out_str += ": <10x".format(ie_port_callstack[count])
            count = count + 1
        if ie_port_spares != proc_val.p_pid:
            out_str += " ({:<10d})".format(ie_port_spares)
        out_str += '\n'
    return out_str

@lldb_type_summary(['ipc_space *'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: <8s} {4: <10s} {5: <16s} {6: <10s} {7: <7s}".format('ipc_space', 'is_task', 'is_table', 'flags', 'ports', 'table_next', 'low_mod', 'high_mod'))
def GetIPCInformation(space, show_entries=False, show_userstack=False):
    """ Provide a summary of the ipc space
    """
    out_str = ''
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x} {3: <8s} {4: <10d} {5: <#01x} {6: >10d} {7: >10d}"
    is_tableval = space.is_table
    ports = int(space.is_table_size)
    flags =''
    is_bits = int(space.is_bits)
    if (is_bits & 0x40000000) == 0: flags +='A'
    else: flags += ' '
    if (is_bits & 0x20000000) != 0: flags +='G'
    out_str += format_string.format(space, space.is_task, space.is_table, flags, space.is_table_size, space.is_table_next, space.is_low_mod, space.is_high_mod)
    
    #should show the each individual entries if asked.
    if show_entries == True:
        out_str += "\n\t" + GetIPCEntrySummary.header + "\n"
        num_entries = ports
        index = 0
        while index < num_entries:
            entryval = GetObjectAtIndexFromArray(is_tableval, index)
            entry_ie_bits = unsigned(entryval.ie_bits)
            if (int(entry_ie_bits) & 0x001f0000 ) != 0:
                entry_name = "{0: <#020x}".format( (index <<8 | entry_ie_bits >> 24) )
                out_str += "\t" + GetIPCEntrySummary(entryval, entry_name) + "\n"
                if show_userstack == True:
                    entryport = Cast(entryval.ie_object, 'ipc_port *')
                    if entryval.ie_object and (int(entry_ie_bits) & 0x00070000) and entryport.ip_callstack[0]:
                        out_str += GetPortUserStack.header
                        out_str += GetPortUserStack(entryport, space.is_task)
            index +=1    
    #done with showing entries
    return out_str

# Macro: showrights

@lldb_command('showrights') 
def ShowRights(cmd_args=None):
    """  Routine to print rights information for the given IPC space 
         Usage: showrights <address of ipc space>
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowRights.__doc__
        return False
    ipc = kern.GetValueFromAddress(cmd_args[0], 'ipc_space *')
    if not ipc:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetIPCInformation.header
    print GetIPCInformation(ipc, True, False)

# EndMacro: showrights

@lldb_command('showtaskrights')
def ShowTaskRights(cmd_args=None):
    """ Routine to ipc rights information for a task
        Usage: showtaskrights <task address>
    """
    if cmd_args == None:
        print "No arguments passed"
        print ShowTaskStacksCmdHelper.__doc__
        return False
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(tval.bsd_info, 'proc *')
    print GetTaskSummary(tval) + " " + GetProcSummary(pval)
    print GetIPCInformation.header
    print GetIPCInformation(tval.itk_space, True, False)

# Macro: showataskrightsbt

@lldb_command('showtaskrightsbt')
def ShowTaskRightsBt(cmd_args=None):
    """ Routine to ipc rights information with userstacks for a task
        Usage: showtaskrightsbt <task address>
    """
    if cmd_args == None:
        print "No arguments passed"
        print ShowTaskRightsBt.__doc__
        return False
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(tval.bsd_info, 'proc *')
    print GetTaskSummary(tval) + " " + GetProcSummary(pval)
    print GetIPCInformation.header
    print GetIPCInformation(tval.itk_space, True, True)

# EndMacro: showtaskrightsbt

# Macro: showallrights

@lldb_command('showallrights') 
def ShowAllRights(cmd_args=None):
    """  Routine to print rights information for IPC space of all tasks
         Usage: showallrights
    """
    for t in kern.tasks:
        print GetTaskSummary.header + " " + GetProcSummary.header
        pval = Cast(t.bsd_info, 'proc *')
        print GetTaskSummary(t) + " " + GetProcSummary(pval)
        print GetIPCInformation.header
        print GetIPCInformation(t.itk_space, True, False) + "\n\n"

# EndMacro: showallrights

# Macro: showpipestats
@lldb_command('showpipestats')
def ShowPipeStats(cmd_args=None):
    """ Display pipes usage information in the kernel
    """
    print "Number of pipes: {: d}".format(kern.globals.amountpipes)
    print "Memory used by pipes: {:s}".format(sizeof_fmt(int(kern.globals.amountpipekva)))
    print "Max memory allowed for pipes: {:s}".format(sizeof_fmt(int(kern.globals.maxpipekva)))
# EndMacro: showpipestats

# Macro: showtaskbusyports
@lldb_command('showtaskbusyports')
def ShowTaskBusyPorts(cmd_args=None):
    """ Routine to print information about receive rights belonging to this task that
        have enqueued messages. This is oten a sign of a blocked or hung process
        Usage: showtaskbusyports <task address>
    """
    if not cmd_args:
        print "No arguments passed. Please pass in the address of a task"
        print ShowTaskBusyPorts.__doc__
        return
    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')
    print GetTaskBusyPorts(task)
    return

def GetTaskBusyPorts(task):
    """ Prints all busy ports for a given task. ie. all receive rights belonging
        to this task that have enqueued messages.
        params:
            task : core.value representing a task in kernel
        returns:
            str  : String containing information about the given task's busy ports
    """
    isp = task.itk_space
    i = 0
    out_string = ""
    while i < isp.is_table_size:
        iep = addressof(isp.is_table[i])
        if iep.ie_bits & 0x00020000:
            port = Cast(iep.ie_object, 'ipc_port_t')
            if port.ip_messages.data.port.msgcount > 0:
                out_string += GetPortSummary.header + GetPortSummary(port)
        i = i + 1
    return out_string
# EndMacro: showtaskbusyports

# Macro: showallbusyports
@lldb_command('showallbusyports')
def ShowAllBusyPorts(cmd_args=None):
    """ Routine to print information about all receive rights on the system that
        have enqueued messages.
    """
    task_queue_head = kern.globals.tasks
    
    for tsk in kern.tasks:
        print GetTaskBusyPorts(tsk)
    return
# EndMacro: showallbusyports

# Macro: showmqueue:
@lldb_command('showmqueue')
def ShowMQueue(cmd_args=None):
    """ Routine that lists details about a given mqueue
        Syntax: (lldb) showmqueue 0xaddr
    """
    if not cmd_args:
        print "Please specify the address of the ipc_mqueue whose details you want to print"
        print ShowMQueue.__doc__
        return
    mqueue = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_mqueue *')
    wq_type = mqueue.data.pset.set_queue.wqs_wait_queue.wq_type
    if int(wq_type) == 3:
        psetoff = getfieldoffset('struct ipc_pset *', 'ips_messages')
        pset = unsigned(ArgumentStringToInt(cmd_args[0])) - unsigned(psetoff)
        print GetPortSetSummary.header + GetPortSetSummary(kern.GetValueFromAddress(pset, 'struct ipc_pset *'))
    if int(wq_type) == 2:
        portoff = getfieldoffset('struct ipc_port', 'ip_messages')
        port = unsigned(ArgumentStringToInt(cmd_args[0])) - unsigned(portoff)
        print GetPortSummary.header + GetPortSummary(kern.GetValueFromAddress(port, 'struct ipc_port *'))
# EndMacro: showmqueue

# Macro: showpset
@lldb_command('showpset')
def ShowPSet(cmd_args=None):
    """ Routine that prints details for a given ipc_pset *
        Syntax: (lldb) showpset 0xaddr
    """
    if not cmd_args:
        print "Please specify the address of the pset whose details you want to print"
        print ShowPSet.__doc__
        return
    
    print GetPortSetSummary.header + GetPortSetSummary(kern.GetValueFromAddress(cmd_args[0], 'ipc_pset *'))
# EndMacro: showpset

