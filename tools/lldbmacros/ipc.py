""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""
from xnu import *
import sys, shlex
from utils import *
from process import *
from atm import *
from bank import *
from waitq import *
from ioreg import *
import xnudefines

@header("{0: <20s} {1: <6s} {2: <6s} {3: <10s} {4: <20s}".format("task", "pid", '#acts', "tablesize", "command"))
def GetTaskIPCSummary(task, show_busy = False):
    """ Display a task's ipc summary. 
        params:
            task : core.value represeting a Task in kernel
        returns
            str - string of ipc info for the task
    """
    out_string = ''
    format_string = "{0: <#020x} {1: <6d} {2: <6d} {3: <10d} {4: <20s}"
    busy_format = " {0: <10d} {1: <6d}"
    proc_name = ''
    if not task.active:
        proc_name = 'terminated: '
    if task.halting:
        proc_name += 'halting: '
    pval = Cast(task.bsd_info, 'proc *')
    if int(pval) != 0:
        proc_name += str(pval.p_comm)
    elif int(task.task_imp_base) != 0 and hasattr(task.task_imp_base, 'iit_procname'):
        proc_name += str(task.task_imp_base.iit_procname)
    table_size = int(task.itk_space.is_table_size)
    out_string += format_string.format(task, pval.p_pid, task.thread_count, table_size, proc_name)
    if show_busy:
        nbusy, nmsgs = GetTaskBusyPortsSummary(task)
        out_string += busy_format.format(nbusy, nmsgs)
        return (out_string, table_size, nbusy, nmsgs)
    return (out_string, table_size)

@header("{0: <20s} {1: <6s} {2: <6s} {3: <10s} {4: <20s} {5: <10s} {6: <6s}".format("task", "pid", '#acts', "tablesize", "command", "#busyports", "#kmsgs"))
def GetTaskBusyIPCSummary(task):
    return GetTaskIPCSummary(task, True)

def GetTaskBusyPortsSummary(task):
    isp = task.itk_space
    i = 0
    nbusy = 0
    nmsgs = 0
    while i < isp.is_table_size:
        iep = addressof(isp.is_table[i])
        if iep.ie_bits & 0x00020000:
            port = Cast(iep.ie_object, 'ipc_port_t')
            if port.ip_messages.data.port.msgcount > 0:
                nbusy += 1
                nmsgs += port.ip_messages.data.port.msgcount
        i = i + 1
    return (nbusy, nmsgs)


@header("{0: <20s} {1: <28s} {2: <12s} {3: <6s} {4: <4s}  {5: <20s} {6: <4s}\n".format(
            "port", "mqueue", "recvname", "flags", "refs", "recvname", "dest"))
def PrintPortSummary(port, show_kmsg_summary=True, prefix=""):
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
    print out_string
    if show_kmsg_summary:
        kmsgp = Cast(portp.ip_messages.data.port.messages.ikmq_base, 'ipc_kmsg_t')
        if unsigned(kmsgp):
            print prefix + GetKMsgSummary.header + prefix + GetKMsgSummary(kmsgp, prefix)
            kmsgheadp = kmsgp
            kmsgp = kmsgp.ikm_next
            while (kmsgp) != (kmsgheadp):
                print prefix + GetKMsgSummary(kmsgp, prefix)
                kmsgp = kmsgp.ikm_next
    return

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
                out_str = "unknown"
            break
    
    return out_str


def GetPortDispositionString(disp):
    if (disp < 0): ## use negative numbers for request ports
        portname = 'notify'
        if disp == -1:
            disp_str = 'reqNS'
        elif disp == -2:
            disp_str = 'reqPD'
        elif disp == -3:
            disp_str = 'reqSPa'
        elif disp == -4:
            disp_str = 'reqSPr'
        elif disp == -5:
            disp_str = 'reqSPra'
        else:
            disp_str = '-X'
    ## These dispositions should match those found in osfmk/mach/message.h
    elif disp == 16:
        disp_str = 'R'  ## receive
    elif disp == 24:
        disp_str = 'dR' ## dispose receive
    elif disp == 17:
        disp_str = 'S'  ## (move) send
    elif disp == 19:
        disp_str = 'cS' ## copy send
    elif disp == 20:
        disp_str = 'mS' ## make send
    elif disp == 25:
        disp_str = 'dS' ## dispose send
    elif disp == 18:
        disp_str = 'O'  ## send-once
    elif disp == 21:
        disp_str = 'mO' ## make send-once
    elif disp == 26:
        disp_str = 'dO' ## dispose send-once
    ## faux dispositions used to string-ify IPC entry types
    elif disp == 100:
        disp_str = 'PS' ## port set
    elif disp == 101:
        disp_str = 'dead' ## dead name
    elif disp == 102:
        disp_str = 'L' ## LABELH
    elif disp == 103:
        disp_str = 'V' ## Thread voucher (thread->ith_voucher->iv_port)
    ## Catch-all
    else:
        disp_str = 'X'  ## invalid
    return disp_str


@header("{:<20s} {:<28s} {:<12s} {:<8s} {:<6s} {:<19s} {:<26s} {:<26s}\n".format(
            "", "kmsg", "msgid", "disp", "size", "reply-port", "source", "destination"))
def GetKMsgSummary(kmsgp, prefix_str=""):
    """ Display a summary for type ipc_kmsg_t
        params:
            kmsgp : core.value representing the given ipc_kmsg_t struct
        returns:
            str   : string of summary info for the given ipc_kmsg_t instance
    """
    kmsghp = kmsgp.ikm_header
    kmsgh = dereference(kmsghp)
    out_string = ""
    out_string += "{0: <20s} {1: <#019x} {2: <8s} {3: <#011x} ".format(
                    ' ', unsigned(kmsgp), ' '*8, kmsgh.msgh_id)
    prefix_str = "{0: <20s} ".format(' ') + prefix_str
    disposition = ""
    bits = kmsgh.msgh_bits & 0xff
    
    # remote port
    if bits == 17:
        disposition = "rS"
    elif bits == 18:
        disposition = "rO"
    else :
        disposition = "rX" # invalid
    
    out_string += "{0: <2s}".format(disposition)
    
    # local port
    disposition = ""
    bits = (kmsgh.msgh_bits & 0xff00) >> 8
    
    if bits == 17:
        disposition = "lS"
    elif bits == 18:
        disposition = "lO"
    elif bits == 0:
        disposition = "l-"
    else:
        disposition = "lX"  # invalid
        
    out_string += "{0: <2s}".format(disposition)
    
    # voucher
    disposition = ""
    bits = (kmsgh.msgh_bits & 0xff0000) >> 16
    
    if bits == 17:
        disposition = "vS"
    elif bits == 0:
        disposition = "v-"
    else:
        disposition = "vX"

    out_string += "{0: <2s}".format(disposition) 
        
    # complex message
    if kmsgh.msgh_bits & 0x80000000:
        out_string += "{0: <1s}".format("c")
    else:
        out_string += "{0: <1s}".format("s")
    
    # importance boost
    if kmsgh.msgh_bits & 0x20000000:
        out_string += "{0: <1s}".format("I")
    else:
        out_string += "{0: <1s}".format("-")
    
    dest_proc_name = ""
    if kmsgp.ikm_header.msgh_remote_port:
        dest_proc_name = GetDestinationProcessFromPort(kmsgp.ikm_header.msgh_remote_port)

    out_string += "{0: ^6d}   {1: <#019x} {2: <26s} {3: <26s}\n".format(
                    unsigned(kmsgh.msgh_size), unsigned(kmsgh.msgh_local_port),
                    GetKMsgSrc(kmsgp), dest_proc_name)
    
    if kmsgh.msgh_bits & 0x80000000:
        out_string += prefix_str + "\t" + GetKMsgComplexBodyDesc.header + "\n"
        out_string += prefix_str + "\t" + GetKMsgComplexBodyDesc(kmsgp, prefix_str + "\t") + "\n"
    
    return out_string

@header("{: <20s} {: <20s} {: <10s}".format("descriptor", "address", "size"))
def GetMachMsgOOLDescriptorSummary(desc):
    """ Returns description for mach_msg_ool_descriptor_t * object
    """
    format_string = "{: <#020x} {: <#020x} {: <#010x}"
    out_string = format_string.format(desc, desc.address, desc.size)
    return out_string


def GetKmsgDescriptors(kmsgp):
    """ Get a list of descriptors in a complex message
    """
    kmsghp = kmsgp.ikm_header
    kmsgh = dereference(kmsghp)
    if not (kmsgh.msgh_bits & 0x80000000):
        return []
    ## Something in the python/lldb types is not getting alignment correct here.
    ## I'm grabbing a pointer to the body manually, and using tribal knowledge
    ## of the location of the descriptor count to get this correct
    body = Cast(addressof(Cast(addressof(kmsgh), 'char *')[sizeof(kmsgh)]), 'mach_msg_body_t *')
    #dsc_count = body.msgh_descriptor_count
    dsc_count = dereference(Cast(body, 'uint32_t *'))
    #dschead = Cast(addressof(body[1]), 'mach_msg_descriptor_t *')
    dschead = Cast(addressof(Cast(addressof(body[0]), 'char *')[sizeof('uint32_t')]), 'mach_msg_descriptor_t *')
    dsc_list = []
    for i in range(dsc_count):
        dsc_list.append(dschead[i])
    return (body, dschead, dsc_list)


@header("{: <20s} {: <8s} {: <20s} {: <10s} {: <20s}".format("kmsgheader", "size", "body", "ds_count", "dsc_head"))
def GetKMsgComplexBodyDesc(kmsgp, prefix_str=""):
    """ Routine that prints a complex kmsg's body
    """
    kmsghp = kmsgp.ikm_header
    kmsgh = dereference(kmsghp)
    if not (kmsgh.msgh_bits & 0x80000000):
        return ""
    format_string = "{: <#020x} {: <#08x} {: <#020x} {: <#010x} {: <#020x}"
    out_string = ""

    (body, dschead, dsc_list) = GetKmsgDescriptors(kmsgp)
    out_string += format_string.format(kmsghp, sizeof(dereference(kmsghp)), body, len(dsc_list), dschead)
    for dsc in dsc_list:
        try:
            dsc_type = unsigned(dsc.type.type)
            out_string += "\n" + prefix_str + "Descriptor: " + xnudefines.mach_msg_type_descriptor_strings[dsc_type]
            if dsc_type == 0:
                # its a port.
                p = dsc.port.name
                dstr = GetPortDispositionString(dsc.port.disposition)
                out_string += " disp:{:s}, name:{: <#20x}".format(dstr, p)
            elif unsigned(dsc.type.type) in (1,3):
                # its OOL DESCRIPTOR or OOL VOLATILE DESCRIPTOR
                ool = dsc.out_of_line
                out_string += " " + GetMachMsgOOLDescriptorSummary(addressof(ool))
        except:
            out_string += "\n" + prefix_str + "Invalid Descriptor: {}".format(dsc)
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


def PrintPortSetMembers(space, setid, show_kmsg_summary):
    """ Print out the members of a given IPC PSet
    """
    num_entries = int(space.is_table_size)
    is_tableval = space.is_table
    setid_str = GetWaitqSetidString(setid)

    prefix_str = "{0:<21s}".format(' '*21)
    once = True
    verbose = False
    if config['verbosity'] > vHUMAN:
        verbose = True

    idx = 0
    while idx < num_entries:
        entryval = GetObjectAtIndexFromArray(is_tableval, idx)
        ie_bits = unsigned(entryval.ie_bits)
        if not (ie_bits & 0x00180000):
            # It's a port entry that's _not_ dead
            portval = Cast(entryval.ie_object, 'ipc_port_t')
            waitq = addressof(portval.ip_messages.data.port.waitq)
            psets = GetWaitqSets(addressof(portval.ip_messages.data.port.waitq))
            for ps in psets:
                if ps == setid_str:
                    if once:
                        once = False
                        print "{:s}\n{:s}{:s}".format(GetPortDestProc(portval), prefix_str, PrintPortSummary.header)
                    PrintPortSummary(portval, show_kmsg_summary, prefix_str)
            if verbose:
                sys.stderr.write('{:d}/{:d}...          \r'.format(idx, num_entries))
        idx += 1
    return

def FindEntryName(obj, space):
    """ Routine to locate a port/ipc_object in an ipc_space
        and return the name within that space.
    """
    if space == 0:
        return 0

    num_entries = int(space.is_table_size)
    is_tableval = space.is_table
    idx = 0
    while idx < num_entries:
        entry_val = GetObjectAtIndexFromArray(is_tableval, idx)
        entry_bits= unsigned(entry_val.ie_bits)
        entry_obj = 0
        if (int(entry_bits) & 0x001f0000) != 0: ## it's a valid entry
            entry_obj = unsigned(entry_val.ie_object)
        if entry_obj == unsigned(obj):
            nm = (idx << 8) | (entry_bits >> 24)
            return nm
        idx += 1
    return 0


@header("{0: <20s} {1: <28s} {2: <12s} {3: <6s} {4: <6s} {5: <20s} {6: <7s}\n".format(
            "portset", "waitqueue", "recvname", "flags", "refs", "recvname", "process"))
def PrintPortSetSummary(pset, space = 0):
    """ Display summary for a given struct ipc_pset *
        params:
            pset : core.value representing a pset in the kernel
        returns:
            str  : string of summary information for the given pset
    """
    out_str = ""
    show_kmsg_summary = False
    if config['verbosity'] > vHUMAN :
        show_kmsg_summary = True

    local_name = FindEntryName(pset, space)
    setid = 0
    if pset.ips_object.io_bits & 0x80000000:
        setid = pset.ips_messages.data.pset.setq.wqset_id
        out_str += "{0: #019x}  {1: #019x} {2: <7s} {3: #011x}   {4: <4s} {5: >6d}  {6: #019x}   ".format(
                    unsigned(pset), addressof(pset.ips_messages), ' '*7,
                    local_name, "ASet",
                    pset.ips_object.io_references,
                    local_name)

    else:
        out_str += "{0: #019x}  {1: #019x} {2: <7s} {3: #011x}   {4: <4s} {5: >6d}  {6: #019x}   ".format(
                    unsigned(pset), addressof(pset.ips_messages), ' '*7,
                    local_name, "DSet",
                    pset.ips_object.io_references,
                    local_name)
    print out_str

    if setid != 0 and space != 0:
        PrintPortSetMembers(space, setid, show_kmsg_summary)

    return

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
    print PrintIPCInformation.header
    PrintIPCInformation(ipc, False, False)

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
    print GetTaskBusyIPCSummary.header
    (summary, table_size, nbusy, nmsgs) = GetTaskBusyIPCSummary(tval)
    print summary

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
        print PrintIPCInformation.header
        PrintIPCInformation(t.itk_space, False, False) + "\n\n"

# EndMacro: showallipc

@lldb_command('showipcsummary')
def ShowIPCSummary(cmd_args=None):
    """ Summarizes the IPC state of all tasks. 
        This is a convenient way to dump some basic clues about IPC messaging. You can use the output to determine
        tasks that are candidates for further investigation.
    """
    print GetTaskIPCSummary.header
    ipc_table_size = 0
    for t in kern.tasks:
        (summary, table_size) = GetTaskIPCSummary(t)
        ipc_table_size += table_size
        print summary
    for t in kern.terminated_tasks:
        (summary, table_size) = GetTaskIPCSummary(t)
        ipc_table_size += table_size
    print "Total Table size: {:d}".format(ipc_table_size)
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
        objtype_str = xnudefines.kobject_types[objtype_index]
        if objtype_str == 'IOKIT_OBJ':
            iokit_classnm = GetObjectTypeStr(portval.kdata.kobject)
            if not iokit_classnm:
                iokit_classnm = "<unknown class>"
            else:
                iokit_classnm = re.sub(r'vtable for ', r'', iokit_classnm)
            desc_str = "kobject({:s}:{:s})".format(objtype_str, iokit_classnm)
        else:
            desc_str = "kobject({0:s})".format(objtype_str)
            if xnudefines.kobject_types[objtype_index] in ('TASK_RESUME', 'TASK'):
                desc_str += " " + GetProcNameForTask(Cast(portval.kdata.kobject, 'task *'))
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
@header("{: <20s} {: <12s} {: <8s} {: <8s} {: <8s} {: <8s} {: <20s} {: <20s}".format("object", "name", "rite", "urefs", "nsets", "nmsgs", "destname", "destination"))
def GetIPCEntrySummary(entry, ipc_name='', rights_filter=0):
    """ Get summary of a ipc entry.
        params:
            entry - core.value representing ipc_entry_t in the kernel
            ipc_name - str of format '0x0123' for display in summary.  
        returns:
            str - string of ipc entry related information

        types of rights:
            'Dead'  : Dead name
            'Set'   : Port set
            'S'     : Send right
            'R'     : Receive right
            'O'     : Send-once right
        types of notifications:
            'd'     : Dead-Name notification requested
            's'     : Send-Possible notification armed
            'r'     : Send-Possible notification requested
            'n'     : No-Senders notification requested
            'x'     : Port-destroy notification requested
    """
    out_str = ''
    entry_ptr = int(hex(entry), 16)
    format_string = "{: <#020x} {: <12s} {: <8s} {: <8d} {: <8d} {: <8d} {: <20s} {: <20s}"
    right_str = ''
    destname_str = ''
    destination_str = ''

    ie_object = entry.ie_object
    ie_bits = int(entry.ie_bits)
    urefs = int(ie_bits & 0xffff)
    nsets = 0
    nmsgs = 0
    if ie_bits & 0x00100000 :
        right_str = 'Dead'
    elif ie_bits & 0x00080000:
        right_str = 'Set'
        psetval = Cast(ie_object, 'ipc_pset *')
        set_str = GetWaitqSets(addressof(psetval.ips_messages.data.pset.setq.wqset_q))
        nsets = len(set_str)
        nmsgs = 0
    else:
        if ie_bits & 0x00010000 :
            if ie_bits & 0x00020000 :
                # SEND + RECV
                right_str = 'SR'
            else:
                # SEND only
                right_str = 'S'
        elif ie_bits & 0x00020000:
            # RECV only
            right_str = 'R'
        elif ie_bits & 0x00040000 :
            # SEND_ONCE
            right_str = 'O'
        portval = Cast(ie_object, 'ipc_port_t')
        if int(entry.index.request) != 0:
            requestsval = portval.ip_requests
            sorightval = requestsval[int(entry.index.request)].notify.port
            soright_ptr = unsigned(sorightval)
            if soright_ptr != 0:
                # dead-name notification requested
                right_str += 'd'
                # send-possible armed
                if soright_ptr & 0x1 : right_str +='s'
                # send-possible requested
                if soright_ptr & 0x2 : right_str +='r'
        # No-senders notification requested
        if portval.ip_nsrequest != 0: right_str += 'n'
        # port-destroy notification requested
        if portval.ip_pdrequest != 0: right_str += 'x'

        # early-out if the rights-filter doesn't match
        if rights_filter != 0 and rights_filter != right_str:
            return ''

        # append the generation to the name value
        # (from osfmk/ipc/ipc_entry.h)
        # bits    rollover period
        # 0 0     64
        # 0 1     48
        # 1 0     32
        # 1 1     16
        ie_gen_roll = { 0:'.64', 1:'.48', 2:'.32', 3:'.16' }
        ipc_name = '{:s}{:s}'.format(strip(ipc_name), ie_gen_roll[(ie_bits & 0x00c00000) >> 22])

        # now show the port destination part
        destname_str = GetPortDestinationSummary(Cast(ie_object, 'ipc_port_t'))
        # Get the number of sets to which this port belongs
        set_str = GetWaitqSets(addressof(portval.ip_messages.data.port.waitq))
        nsets = len(set_str)
        nmsgs = portval.ip_messages.data.port.msgcount
    if rights_filter == 0 or rights_filter == right_str:
        out_str = format_string.format(ie_object, ipc_name, right_str, urefs, nsets, nmsgs, destname_str, destination_str)
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
@header("{0: <20s} {1: <20s} {2: <20s} {3: <8s} {4: <10s} {5: <18s} {6: >8s} {7: <8s}".format('ipc_space', 'is_task', 'is_table', 'flags', 'ports', 'table_next', 'low_mod', 'high_mod'))
def PrintIPCInformation(space, show_entries=False, show_userstack=False, rights_filter=0):
    """ Provide a summary of the ipc space
    """
    out_str = ''
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x} {3: <8s} {4: <10d} {5: <#18x} {6: >8d} {7: <8d}"
    is_tableval = space.is_table
    ports = int(space.is_table_size)
    flags =''
    is_bits = int(space.is_bits)
    if (is_bits & 0x40000000) == 0: flags +='A'
    else: flags += ' '
    if (is_bits & 0x20000000) != 0: flags +='G'
    print format_string.format(space, space.is_task, space.is_table, flags, space.is_table_size, space.is_table_next, space.is_low_mod, space.is_high_mod)
    
    #should show the each individual entries if asked.
    if show_entries == True:
        print "\t" + GetIPCEntrySummary.header
        num_entries = ports
        index = 0
        while index < num_entries:
            entryval = GetObjectAtIndexFromArray(is_tableval, index)
            entry_ie_bits = unsigned(entryval.ie_bits)
            if (int(entry_ie_bits) & 0x001f0000 ) != 0:
                entry_name = "{0: <#020x}".format( (index <<8 | entry_ie_bits >> 24) )
                entry_str = GetIPCEntrySummary(entryval, entry_name, rights_filter)
                if len(entry_str) > 0:
                    print "                  \r\t" + entry_str
                    if show_userstack == True:
                        entryport = Cast(entryval.ie_object, 'ipc_port *')
                        if entryval.ie_object and (int(entry_ie_bits) & 0x00070000) and entryport.ip_callstack[0]:
                            print GetPortUserStack.header + GetPortUserStack(entryport, space.is_task)
                else:
                    # give some progress indication (this is especially
                    # helpful for tasks with large sets of rights)
                    sys.stderr.write(' {:d}/{:d}...\r'.format(index, num_entries))
            index += 1
    #done with showing entries
    return out_str

# Macro: showrights

@lldb_command('showrights', 'R:')
def ShowRights(cmd_args=None, cmd_options={}):
    """  Routine to print rights information for the given IPC space 
         Usage: showrights [-R rights_type] <address of ipc space>
                -R rights_type  : only display rights matching the string 'rights_type'

                types of rights:
                    'Dead'  : Dead name
                    'Set'   : Port set
                    'S'     : Send right
                    'R'     : Receive right
                    'O'     : Send-once right
                types of notifications:
                    'd'     : Dead-Name notification requested
                    's'     : Send-Possible notification armed
                    'r'     : Send-Possible notification requested
                    'n'     : No-Senders notification requested
                    'x'     : Port-destroy notification requested
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowRights.__doc__
        return False
    ipc = kern.GetValueFromAddress(cmd_args[0], 'ipc_space *')
    if not ipc:
        print "unknown arguments:", str(cmd_args)
        return False
    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]
    print PrintIPCInformation.header
    PrintIPCInformation(ipc, True, False, rights_type)

# EndMacro: showrights

@lldb_command('showtaskrights','R:')
def ShowTaskRights(cmd_args=None, cmd_options={}):
    """ Routine to ipc rights information for a task
        Usage: showtaskrights [-R rights_type] <task address>
               -R rights_type  : only display rights matching the string 'rights_type'

               types of rights:
                   'Dead'  : Dead name
                   'Set'   : Port set
                   'S'     : Send right
                   'R'     : Receive right
                   'O'     : Send-once right
               types of notifications:
                   'd'     : Dead-Name notification requested
                   's'     : Send-Possible notification armed
                   'r'     : Send-Possible notification requested
                   'n'     : No-Senders notification requested
                   'x'     : Port-destroy notification requested
    """
    if cmd_args == None:
        print "No arguments passed"
        print ShowTaskStacksCmdHelper.__doc__
        return False
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        print "unknown arguments:", str(cmd_args)
        return False
    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]
    print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(tval.bsd_info, 'proc *')
    print GetTaskSummary(tval) + " " + GetProcSummary(pval)
    print PrintIPCInformation.header
    PrintIPCInformation(tval.itk_space, True, False, rights_type)

# Macro: showataskrightsbt

@lldb_command('showtaskrightsbt', 'R:')
def ShowTaskRightsBt(cmd_args=None, cmd_options={}):
    """ Routine to ipc rights information with userstacks for a task
        Usage: showtaskrightsbt [-R rights_type] <task address>
               -R rights_type  : only display rights matching the string 'rights_type'

               types of rights:
                   'Dead'  : Dead name
                   'Set'   : Port set
                   'S'     : Send right
                   'R'     : Receive right
                   'O'     : Send-once right
               types of notifications:
                   'd'     : Dead-Name notification requested
                   's'     : Send-Possible notification armed
                   'r'     : Send-Possible notification requested
                   'n'     : No-Senders notification requested
                   'x'     : Port-destroy notification requested
    """
    if cmd_args == None:
        print "No arguments passed"
        print ShowTaskRightsBt.__doc__
        return False
    tval = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not tval:
        print "unknown arguments:", str(cmd_args)
        return False
    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]
    print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(tval.bsd_info, 'proc *')
    print GetTaskSummary(tval) + " " + GetProcSummary(pval)
    print PrintIPCInformation.header
    PrintIPCInformation(tval.itk_space, True, True, rights_type)

# EndMacro: showtaskrightsbt

# Macro: showallrights

@lldb_command('showallrights', 'R:')
def ShowAllRights(cmd_args=None, cmd_options={}):
    """  Routine to print rights information for IPC space of all tasks
         Usage: showallrights [-R rights_type]
                -R rights_type  : only display rights matching the string 'rights_type'

                types of rights:
                    'Dead'  : Dead name
                    'Set'   : Port set
                    'S'     : Send right
                    'R'     : Receive right
                    'O'     : Send-once right
                types of notifications:
                    'd'     : Dead-Name notification requested
                    's'     : Send-Possible notification armed
                    'r'     : Send-Possible notification requested
                    'n'     : No-Senders notification requested
                    'x'     : Port-destroy notification requested
    """
    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]
    for t in kern.tasks:
        print GetTaskSummary.header + " " + GetProcSummary.header
        pval = Cast(t.bsd_info, 'proc *')
        print GetTaskSummary(t) + " " + GetProcSummary(pval)
        try:
            print PrintIPCInformation.header
            PrintIPCInformation(t.itk_space, True, False, rights_type) + "\n\n"
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            print "Failed to get IPC information. Do individual showtaskrights <task> to find the error. \n\n"

# EndMacro: showallrights


def GetInTransitPortSummary(port, disp, holding_port, holding_kmsg):
    """ String-ify the in-transit dispostion of a port.
    """
    ## This should match the summary generated by GetIPCEntrySummary
    ##              "object"   "name"   "rite"  "urefs" "nsets" "nmsgs" "destname" "destination"
    format_str = "\t{: <#20x} {: <12} {: <8s} {: <8d} {: <8d} {: <8d} p:{: <#19x} k:{: <#19x}"
    portname = 'intransit'

    disp_str = GetPortDispositionString(disp)

    out_str = format_str.format(unsigned(port), 'in-transit', disp_str, 0, 0, port.ip_messages.data.port.msgcount, unsigned(holding_port), unsigned(holding_kmsg))
    return out_str


def GetDispositionFromEntryType(entry_bits):
    """ Translate an IPC entry type into an in-transit disposition. This allows
        the GetInTransitPortSummary function to be re-used to string-ify IPC
        entry types.
    """
    ebits = int(entry_bits)
    if (ebits & 0x003f0000) == 0:
        return 0

    if (ebits & 0x00010000) != 0:
        return 17 ## MACH_PORT_RIGHT_SEND
    elif (ebits & 0x00020000) != 0:
        return 16 ## MACH_PORT_RIGHT_RECEIVE
    elif (ebits & 0x00040000) != 0:
        return 18 ## MACH_PORT_RIGHT_SEND_ONCE
    elif (ebits & 0x00080000) != 0:
        return 100 ## MACH_PORT_RIGHT_PORT_SET
    elif (ebits & 0x00100000) != 0:
        return 101 ## MACH_PORT_RIGHT_DEAD_NAME
    elif (ebits & 0x00200000) != 0:
        return 102 ## MACH_PORT_RIGHT_LABELH
    else:
        return 0

def GetDispositionFromVoucherPort(th_vport):
    """ Translate a thread's voucher port into a 'disposition'
    """
    if unsigned(th_vport) > 0:
        return 103  ## Voucher type
    return 0


g_kmsg_prog = 0
g_progmeter = {
    0 : '*',
    1 : '-',
    2 : '\\',
    3 : '|',
    4 : '/',
    5 : '-',
    6 : '\\',
    7 : '|',
    8 : '/',
}

def PrintProgressForKmsg():
    global g_kmsg_prog
    global g_progmeter
    sys.stderr.write(" {:<1s}\r".format(g_progmeter[g_kmsg_prog % 9]))
    g_kmsg_prog += 1


def CollectPortsForAnalysis(port, disposition):
    """
    """
    p = Cast(port, 'struct ipc_port *')
    yield (p, disposition)

    # no-senders notification port
    if unsigned(p.ip_nsrequest) != 0:
        PrintProgressForKmsg()
        yield (Cast(p.ip_nsrequest, 'struct ipc_port *'), -1)

    # port-death notification port
    if unsigned(p.ip_pdrequest) != 0:
        PrintProgressForKmsg()
        yield (Cast(p.ip_pdrequest, 'struct ipc_port *'), -2)

    ## ports can have many send-possible notifications armed: go through the table!
    if unsigned(p.ip_requests) != 0:
        table = Cast(p.ip_requests, 'struct ipc_port_request *')
        table_sz = int(table.name.size.its_size)
        for i in range(table_sz):
            if i == 0:
                continue
            ipr = table[i]
            if unsigned(ipr.name.name) != 0:
                ipr_bits = unsigned(ipr.notify.port) & 3
                ipr_port = kern.GetValueFromAddress(int(ipr.notify.port) & ~3, 'struct ipc_port *')
                ipr_disp = 0
                if ipr_bits & 3: ## send-possible armed and requested
                    ipr_disp = -5
                elif ipr_bits & 2: ## send-possible requested
                    ipr_disp = -4
                elif ipr_bits & 1: ## send-possible armed
                    ipr_disp = -3
                PrintProgressForKmsg()
                yield (ipr_port, ipr_disp)
    return

def CollectKmsgPorts(task, task_port, kmsgp):
    """ Look through a message, 'kmsgp' destined for 'task'
        (enqueued on task_port). Collect any port descriptors,
        remote, local, voucher, or other port references
        into a (ipc_port_t, disposition) list.
    """
    kmsgh = dereference(kmsgp.ikm_header)

    p_list = []

    PrintProgressForKmsg()
    if kmsgh.msgh_remote_port and unsigned(kmsgh.msgh_remote_port) != unsigned(task_port):
        disp = kmsgh.msgh_bits & 0x1f
        p_list += list(CollectPortsForAnalysis(kmsgh.msgh_remote_port, disp))

    if kmsgh.msgh_local_port and unsigned(kmsgh.msgh_local_port) != unsigned(task_port) \
       and unsigned(kmsgh.msgh_local_port) != unsigned(kmsgh.msgh_remote_port):
        disp = (kmsgh.msgh_bits & 0x1f00) >> 8
        p_list += list(CollectPortsForAnalysis(kmsgh.msgh_local_port, disp))

    if kmsgp.ikm_voucher:
        p_list += list(CollectPortsForAnalysis(kmsgp.ikm_voucher, 0))

    if kmsgh.msgh_bits & 0x80000000:
        ## Complex message - look for descriptors
        PrintProgressForKmsg()
        (body, dschead, dsc_list) = GetKmsgDescriptors(kmsgp)
        for dsc in dsc_list:
            PrintProgressForKmsg()
            dsc_type = unsigned(dsc.type.type)
            if dsc_type == 0 or dsc_type == 2: ## 0 == port, 2 == ool port
                if dsc_type == 0:
                    ## its a port descriptor
                    dsc_disp = dsc.port.disposition
                    p_list += list(CollectPortsForAnalysis(dsc.port.name, dsc_disp))
                else:
                    ## it's an ool_ports descriptor which is an array of ports
                    dsc_disp = dsc.ool_ports.disposition
                    dispdata = Cast(dsc.ool_ports.address, 'struct ipc_port *')
                    for pidx in range(dsc.ool_ports.count):
                        PrintProgressForKmsg()
                        p_list += list(CollectPortsForAnalysis(dispdata[pidx], dsc_disp))
    return p_list

def CollectKmsgPortRefs(task, task_port, kmsgp, p_refs):
    """ Recursively collect all references to ports inside the kmsg 'kmsgp'
        into the set 'p_refs'
    """
    p_list = CollectKmsgPorts(task, task_port, kmsgp)

    ## Iterate over each ports we've collected, to see if they
    ## have messages on them, and then recurse!
    for p, pdisp in p_list:
        ptype = (p.ip_object.io_bits & 0x7fff0000) >> 16
        p_refs.add((p, pdisp, ptype))
        if ptype != 0: ## don't bother with port sets
            continue
        ## If the port that's in-transit has messages already enqueued,
        ## go through each of those messages and look for more ports!
        if p.ip_messages.data.port.msgcount > 0:
            p_kmsgp = Cast(p.ip_messages.data.port.messages.ikmq_base, 'ipc_kmsg_t')
            kmsgheadp = p_kmsgp
            while unsigned(p_kmsgp) > 0:
                CollectKmsgPortRefs(task, p, p_kmsgp, p_refs)
                p_kmsgp = p_kmsgp.ikm_next
                if p_kmsgp == kmsgheadp:
                    break;


def FindKmsgPortRefs(instr, task, task_port, kmsgp, qport):
    """ Look through a message, 'kmsgp' destined for 'task'. If we find
        any port descriptors, remote, local, voucher, or other port that
        matches 'qport', return a short description
        which should match the format of GetIPCEntrySummary.
    """

    out_str = instr
    p_list = CollectKmsgPorts(task, task_port, kmsgp)

    ## Run through all ports we've collected looking for 'qport'
    for p, pdisp in p_list:
        PrintProgressForKmsg()
        if unsigned(p) == unsigned(qport):
            ## the port we're looking for was found in this message!
            if len(out_str) > 0:
                out_str += '\n'
            out_str += GetInTransitPortSummary(p, pdisp, task_port, kmsgp)

        ptype = (p.ip_object.io_bits & 0x7fff0000) >> 16
        if ptype != 0: ## don't bother with port sets
            continue

        ## If the port that's in-transit has messages already enqueued,
        ## go through each of those messages and look for more ports!
        if p.ip_messages.data.port.msgcount > 0:
            p_kmsgp = Cast(p.ip_messages.data.port.messages.ikmq_base, 'ipc_kmsg_t')
            kmsgheadp = p_kmsgp
            while unsigned(p_kmsgp) > 0:
                out_str = FindKmsgPortRefs(out_str, task, p, p_kmsgp, qport)
                p_kmsgp = p_kmsgp.ikm_next
                if p_kmsgp == kmsgheadp:
                    break
    return out_str


port_iteration_do_print_taskname = False
registeredport_idx = -10
excports_idx = -20
intransit_idx = -1000
taskports_idx = -2000
thports_idx = -3000

def IterateAllPorts(tasklist, func, ctx, include_psets, follow_busyports, should_log):
    """ Iterate over all ports in the system, calling 'func'
        for each entry in 
    """
    global port_iteration_do_print_taskname
    global intransit_idx, taskports_idx, thports_idx, registeredport_idx, excports_idx

    ## XXX: also host special ports

    entry_port_type_mask = 0x00070000
    if include_psets:
        entry_port_type_mask = 0x000f0000

    if tasklist is None:
        tasklist = kern.tasks
        tasklist += kern.terminated_tasks

    tidx = 1

    for t in tasklist:
        # Write a progress line.  Using stderr avoids automatic newline when
        # writing to stdout from lldb.  Blank spaces at the end clear out long
        # lines.
        if should_log:
            procname = ""
            if not t.active:
                procname = 'terminated: '
            if t.halting:
                procname += 'halting: '
            t_p = Cast(t.bsd_info, 'proc *')
            if unsigned(t_p) != 0:
                procname += str(t_p.p_name)
            elif unsigned(t.task_imp_base) != 0 and hasattr(t.task_imp_base, 'iit_procname'):
                procname += str(t.task_imp_base.iit_procname)
            sys.stderr.write("  checking {:s} ({}/{})...{:50s}\r".format(procname, tidx, len(tasklist), ''))
        tidx += 1

        port_iteration_do_print_taskname = True
        space = t.itk_space
        num_entries = int(space.is_table_size)
        is_tableval = space.is_table
        idx = 0
        while idx < num_entries:
            entry_val = GetObjectAtIndexFromArray(is_tableval, idx)
            entry_bits= unsigned(entry_val.ie_bits)
            entry_obj = 0
            entry_str = ''
            entry_name = "{:x}".format( (idx << 8 | entry_bits >> 24) )

            entry_disp = GetDispositionFromEntryType(entry_bits)

            ## If the entry in the table represents a port of some sort,
            ## then make the callback provided
            if int(entry_bits) & entry_port_type_mask:
                eport = Cast(entry_val.ie_object, 'ipc_port_t')
                ## Make the callback
                func(t, space, ctx, idx, entry_val, eport, entry_disp)

                ## if the port has pending messages, look through
                ## each message for ports (and recurse)
                if follow_busyports and unsigned(eport) > 0 and eport.ip_messages.data.port.msgcount > 0:
                    ## collect all port references from all messages
                    kmsgp = Cast(eport.ip_messages.data.port.messages.ikmq_base, 'ipc_kmsg_t')
                    kmsgheadp = kmsgp
                    while unsigned(kmsgp) > 0:
                        p_refs = set()
                        CollectKmsgPortRefs(t, eport, kmsgp, p_refs)
                        for (port, pdisp, ptype) in p_refs:
                            func(t, space, ctx, intransit_idx, None, port, pdisp)
                        kmsgp = kmsgp.ikm_next
                        if kmsgp == kmsgheadp:
                            break

            idx = idx + 1
        ## while (idx < num_entries)

        ## Task ports (send rights)
        if unsigned(t.itk_sself) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_sself, 17)
        if unsigned(t.itk_host) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_host, 17)
        if unsigned(t.itk_bootstrap) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_bootstrap, 17)
        if unsigned(t.itk_seatbelt) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_seatbelt, 17)
        if unsigned(t.itk_gssd) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_gssd, 17)
        if unsigned(t.itk_debug_control) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_debug_control, 17)
        if unsigned(t.itk_task_access) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_task_access, 17)

        ## Task name port (not a send right, just a naked ref)
        if unsigned(t.itk_nself) > 0:
            func(t, space, ctx, taskports_idx, 0,t.itk_nself, 0)

        ## task resume port is a receive right to resume the task
        if unsigned(t.itk_resume) > 0:
            func(t, space, ctx, taskports_idx, 0, t.itk_resume, 16)

        ## registered task ports (all send rights)
        tr_idx = 0
        tr_max = sizeof(t.itk_registered) / sizeof(t.itk_registered[0])
        while tr_idx < tr_max:
            tport = t.itk_registered[tr_idx]
            if unsigned(tport) > 0:
                try:
                    func(t, space, ctx, registeredport_idx, 0, tport, 17)
                except Exception, e:
                    print("\texception looking through registered port {:d}/{:d} in {:s}".format(tr_idx,tr_max,t))
                    pass
            tr_idx += 1

        ## Task exception ports
        exidx = 0
        exmax = sizeof(t.exc_actions) / sizeof(t.exc_actions[0])
        while exidx < exmax: ## see: osfmk/mach/[arm|i386]/exception.h
            export = t.exc_actions[exidx].port ## send right
            if unsigned(export) > 0:
                try:
                    func(t, space, ctx, excports_idx, 0, export, 17)
                except Exception, e:
                    print("\texception looking through exception port {:d}/{:d} in {:s}".format(exidx,exmax,t))
                    pass
            exidx += 1

        ## XXX: any  ports still valid after clearing IPC space?!

        for thval in IterateQueue(t.threads, 'thread *', 'task_threads'):
            ## XXX: look at block reason to see if it's in mach_msg_receive - then look at saved state / message

            ## Thread port (send right)
            if unsigned(thval.ith_sself) > 0:
                thport = thval.ith_sself
                func(t, space, ctx, thports_idx, 0, thport, 17) ## see: osfmk/mach/message.h
            ## Thread special reply port (send-once right)
            if unsigned(thval.ith_special_reply_port) > 0:
                thport = thval.ith_special_reply_port
                func(t, space, ctx, thports_idx, 0, thport, 18) ## see: osfmk/mach/message.h
            ## Thread voucher port
            if unsigned(thval.ith_voucher) > 0:
                vport = thval.ith_voucher.iv_port
                if unsigned(vport) > 0:
                    vdisp = GetDispositionFromVoucherPort(vport)
                    func(t, space, ctx, thports_idx, 0, vport, vdisp)
            ## Thread exception ports
            if unsigned(thval.exc_actions) > 0:
                exidx = 0
                while exidx < exmax: ## see: osfmk/mach/[arm|i386]/exception.h
                    export = thval.exc_actions[exidx].port ## send right
                    if unsigned(export) > 0:
                        try:
                            func(t, space, ctx, excports_idx, 0, export, 17)
                        except Exception, e:
                            print("\texception looking through exception port {:d}/{:d} in {:s}".format(exidx,exmax,t))
                            pass
                    exidx += 1
            ## XXX: the message on a thread (that's currently being received)
        ## for (thval in t.threads)
    ## for (t in tasklist)


# Macro: findportrights
def FindPortRightsCallback(task, space, ctx, entry_idx, ipc_entry, ipc_port, port_disp):
    """ Callback which uses 'ctx' as the (port,rights_types) tuple for which
        a caller is seeking references. This should *not* be used from a
        recursive call to IterateAllPorts.
    """
    global port_iteration_do_print_taskname

    (qport, rights_type) = ctx
    entry_name = ''
    entry_str = ''
    if unsigned(ipc_entry) != 0:
        entry_bits = unsigned(ipc_entry.ie_bits)
        entry_name = "{:x}".format( (entry_idx << 8 | entry_bits >> 24) )
        if (int(entry_bits) & 0x001f0000) != 0 and unsigned(ipc_entry.ie_object) == unsigned(qport):
            ## it's a valid entry, and it points to the port
            entry_str = '\t' + GetIPCEntrySummary(ipc_entry, entry_name, rights_type)

    procname = GetProcNameForTask(task)
    if unsigned(ipc_port) != 0 and ipc_port.ip_messages.data.port.msgcount > 0:
        sys.stderr.write("  checking {:s} busy-port {}:{:#x}...{:30s}\r".format(procname, entry_name, unsigned(ipc_port), ''))
        ## Search through busy ports to find descriptors which could
        ## contain the only reference to this port!
        kmsgp = Cast(ipc_port.ip_messages.data.port.messages.ikmq_base, 'ipc_kmsg_t')
        kmsgheadp = kmsgp
        while unsigned(kmsgp):
            entry_str = FindKmsgPortRefs(entry_str, task, ipc_port, kmsgp, qport)
            kmsgp = kmsgp.ikm_next
            if kmsgp == kmsgheadp:
                break;
    if len(entry_str) > 0:
        sys.stderr.write("{:80s}\r".format(''))
        if port_iteration_do_print_taskname:
            print "Task: {0: <#x} {1: <s}".format(task, procname)
            print '\t' + GetIPCEntrySummary.header
            port_iteration_do_print_taskname = False
        print entry_str

@lldb_command('findportrights', 'R:S:')
def FindPortRights(cmd_args=None, cmd_options={}):
    """  Routine to locate and print all extant rights to a given port
         Usage: findportrights [-R rights_type] [-S <ipc_space_t>] <ipc_port_t>
                -S ipc_space    : only search the specified ipc space
                -R rights_type  : only display rights matching the string 'rights_type'

                types of rights:
                    'Dead'  : Dead name
                    'Set'   : Port set
                    'S'     : Send right
                    'R'     : Receive right
                    'O'     : Send-once right
                types of notifications:
                    'd'     : Dead-Name notification requested
                    's'     : Send-Possible notification armed
                    'r'     : Send-Possible notification requested
                    'n'     : No-Senders notification requested
                    'x'     : Port-destroy notification requested
    """
    if not cmd_args:
        raise ArgumentError("no port address provided")
    port = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_port *')

    rights_type = 0
    if "-R" in cmd_options:
        rights_type = cmd_options["-R"]

    tasklist = None
    if "-S" in cmd_options:
        space = kern.GetValueFromAddress(cmd_options["-S"], 'struct ipc_space *')
        tasklist = [ space.is_task ]

    ## Don't include port sets
    ## Don't recurse on busy ports (we do that manually)
    ## DO log progress
    IterateAllPorts(tasklist, FindPortRightsCallback, (port, rights_type), False, False, True)
    sys.stderr.write("{:120s}\r".format(' '))

    print "Done."
    return
# EndMacro: findportrights

# Macro: countallports

def CountPortsCallback(task, space, ctx, entry_idx, ipc_entry, ipc_port, port_disp):
    """ Callback which uses 'ctx' as the set of all ports found in the
        iteration. This should *not* be used from a recursive
        call to IterateAllPorts.
    """
    global intransit_idx

    (p_set, p_intransit, p_bytask) = ctx

    ## Add the port address to the set of all port addresses
    p_set.add(unsigned(ipc_port))

    if entry_idx == intransit_idx:
        p_intransit.add(unsigned(ipc_port))

    if task.active or (task.halting and not task.active):
        pname = str(Cast(task.bsd_info, 'proc *').p_name)
        if not pname in p_bytask.keys():
            p_bytask[pname] = { 'transit':0, 'table':0, 'other':0 }
        if entry_idx == intransit_idx:
            p_bytask[pname]['transit'] += 1
        elif entry_idx >= 0:
            p_bytask[pname]['table'] += 1
        else:
            p_bytask[pname]['other'] += 1


@lldb_command('countallports', 'P')
def CountAllPorts(cmd_args=None, cmd_options={}):
    """ Routine to search for all as many references to ipc_port structures in the kernel
        that we can find.
        Usage: countallports [-P]
                -P : include port sets in the count (default: NO)
    """
    p_set = set()
    p_intransit = set()
    p_bytask = {}

    find_psets = False
    if "-P" in cmd_options:
        find_psets = True

    ## optionally include port sets
    ## DO recurse on busy ports
    ## DO log progress
    IterateAllPorts(None, CountPortsCallback, (p_set, p_intransit, p_bytask), find_psets, True, True)
    sys.stderr.write("{:120s}\r".format(' '))

    print "Total ports found: {:d}".format(len(p_set))
    print "In Transit: {:d}".format(len(p_intransit))
    print "By Task:"
    for pname in sorted(p_bytask.keys()):
        count = p_bytask[pname]
        print "\t{: <20s}: table={: <5d}, transit={: <5d}, other={: <5d}".format(pname, count['table'], count['transit'], count['other'])
    return
# EndMacro: countallports

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
    PrintTaskBusyPorts(task)
    return

def PrintTaskBusyPorts(task):
    """ Prints all busy ports for a given task. ie. all receive rights belonging
        to this task that have enqueued messages.
        params:
            task : core.value representing a task in kernel
        returns:
            str  : String containing information about the given task's busy ports
    """
    isp = task.itk_space
    i = 0
    while i < isp.is_table_size:
        iep = addressof(isp.is_table[i])
        if iep.ie_bits & 0x00020000:
            port = Cast(iep.ie_object, 'ipc_port_t')
            if port.ip_messages.data.port.msgcount > 0:
                print PrintPortSummary.header
                PrintPortSummary(port)
        i = i + 1
    return
# EndMacro: showtaskbusyports

# Macro: showallbusyports
@lldb_command('showallbusyports')
def ShowAllBusyPorts(cmd_args=None):
    """ Routine to print information about all receive rights on the system that
        have enqueued messages.
    """
    task_queue_head = kern.globals.tasks

    for tsk in kern.tasks:
        PrintTaskBusyPorts(tsk)
    return
# EndMacro: showallbusyports

# Macro: showbusyportsummary
@lldb_command('showbusyportsummary')
def ShowBusyPortSummary(cmd_args=None):
    """ Routine to print a summary of information about all receive rights
        on the system that have enqueued messages.
    """
    task_queue_head = kern.globals.tasks

    ipc_table_size = 0
    ipc_busy_ports = 0
    ipc_msgs = 0

    print GetTaskBusyIPCSummary.header
    for tsk in kern.tasks:
        (summary, table_size, nbusy, nmsgs) = GetTaskBusyIPCSummary(tsk)
        ipc_table_size += table_size
        ipc_busy_ports += nbusy
        ipc_msgs += nmsgs
        print summary
    for t in kern.terminated_tasks:
        (summary, table_size, nbusy, nmsgs) = GetTaskBusyIPCSummary(tsk)
        ipc_table_size += table_size
        ipc_busy_ports += nbusy
        ipc_msgs += nmsgs
        print summary
    print "Total Table Size: {:d}, Busy Ports: {:d}, Messages in-flight: {:d}".format(ipc_table_size, ipc_busy_ports, ipc_msgs)
    return
# EndMacro: showbusyportsummary

# Macro: showport:
@lldb_command('showport','K')
def ShowPort(cmd_args=None, cmd_options={}):
    """ Routine that lists details about a given IPC port 
        Syntax: (lldb) showport 0xaddr
    """
    show_kmsgs = True
    if "-K" in cmd_options:
        show_kmsgs = False
    if not cmd_args:
        print "Please specify the address of the port whose details you want to print"
        print ShowPort.__doc__
        return
    port = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_port *')
    print PrintPortSummary.header
    PrintPortSummary(port, show_kmsgs)
# EndMacro: showport

# Macro: showmqueue:
@lldb_command('showmqueue', "S:")
def ShowMQueue(cmd_args=None, cmd_options={}):
    """ Routine that lists details about a given mqueue
        Syntax: (lldb) showmqueue 0xaddr [-S ipc_space]
    """
    if not cmd_args:
        print "Please specify the address of the ipc_mqueue whose details you want to print"
        print ShowMQueue.__doc__
        return
    space = 0
    if "-S" in cmd_options:
        space = kern.GetValueFromAddress(cmd_options["-S"], 'struct ipc_space *')
    mqueue = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_mqueue *')
    wq_type = mqueue.data.pset.setq.wqset_q.waitq_type
    if int(wq_type) == 3:
        psetoff = getfieldoffset('struct ipc_pset', 'ips_messages')
        pset = unsigned(ArgumentStringToInt(cmd_args[0])) - unsigned(psetoff)
        print PrintPortSetSummary.header
        PrintPortSetSummary(kern.GetValueFromAddress(pset, 'struct ipc_pset *'), space)
    elif int(wq_type) == 2:
        portoff = getfieldoffset('struct ipc_port', 'ip_messages')
        port = unsigned(ArgumentStringToInt(cmd_args[0])) - unsigned(portoff)
        print PrintPortSummary.header
        PrintPortSummary(kern.GetValueFromAddress(port, 'struct ipc_port *'))
    else:
        print "Invalid mqueue? (waitq type {:d} is invalid)".format(int(wq_type))
# EndMacro: showmqueue

# Macro: showkmsg:
@lldb_command('showkmsg')
def ShowKMSG(cmd_args=[]):
    """ Show detail information about a <ipc_kmsg_t> structure
        Usage: (lldb) showkmsg <ipc_kmsg_t>
    """
    if not cmd_args:
        raise ArgumentError('Invalid arguments')
    kmsg = kern.GetValueFromAddress(cmd_args[0], 'ipc_kmsg_t')
    print GetKMsgSummary.header
    print GetKMsgSummary(kmsg)

# EndMacro: showkmsg

# Macro: showpset
@lldb_command('showpset', "S:")
def ShowPSet(cmd_args=None, cmd_options={}):
    """ Routine that prints details for a given ipc_pset *
        Syntax: (lldb) showpset 0xaddr [-S ipc_space]
    """
    if not cmd_args:
        print "Please specify the address of the pset whose details you want to print"
        print ShowPSet.__doc__
        return
    space = 0
    if "-S" in cmd_options:
        space = kern.GetValueFromAddress(cmd_options["-S"], 'struct ipc_space *')

    print PrintPortSetSummary.header
    PrintPortSetSummary(kern.GetValueFromAddress(cmd_args[0], 'ipc_pset *'), space)
# EndMacro: showpset

# IPC importance inheritance related macros.

@lldb_command('showalliits')
def ShowAllIITs(cmd_args=[], cmd_options={}):
    """ Development only macro. Show list of all iits allocated in the system. """
    try:
        iit_queue = kern.globals.global_iit_alloc_queue 
    except ValueError:
        print "This debug macro is only available in development or debug kernels"
        return
    
    print GetIPCImportantTaskSummary.header
    for iit in IterateQueue(iit_queue, 'struct ipc_importance_task *', 'iit_allocation'):
        print GetIPCImportantTaskSummary(iit)
    return

@header("{: <18s} {: <3s} {: <18s} {: <20s} {: <18s} {: <8s}".format("ipc_imp_inherit", "don", "to_task", "proc_name", "from_elem", "depth"))
@lldb_type_summary(['ipc_importance_inherit *', 'ipc_importance_inherit_t'])
def GetIPCImportanceInheritSummary(iii):
    """ describes iii object of type ipc_importance_inherit_t * """
    out_str = ""
    fmt = "{o: <#018x} {don: <3s} {o.iii_to_task.iit_task: <#018x} {task_name: <20s} {o.iii_from_elem: <#018x} {o.iii_depth: <#08x}"
    donating_str = ""
    if unsigned(iii.iii_donating):
        donating_str = "DON"
    taskname = GetProcNameForTask(iii.iii_to_task.iit_task)
    if hasattr(iii.iii_to_task, 'iit_bsd_pid'):
        taskname =  "({:d}) {:s}".format(iii.iii_to_task.iit_bsd_pid, iii.iii_to_task.iit_procname)
    out_str += fmt.format(o=iii, task_name = taskname, don=donating_str)
    return out_str

@static_var('recursion_count', 0)
@header("{: <18s} {: <4s} {: <8s} {: <8s} {: <18s} {: <18s}".format("iie", "type", "refs", "made", "#kmsgs", "#inherits"))
@lldb_type_summary(['ipc_importance_elem *'])
def GetIPCImportanceElemSummary(iie):
    """ describes an ipc_importance_elem * object """

    if GetIPCImportanceElemSummary.recursion_count > 500:
        GetIPCImportanceElemSummary.recursion_count = 0
        return "Recursion of 500 reached"

    out_str = ''
    fmt = "{: <#018x} {: <4s} {: <8d} {: <8d} {: <#018x} {: <#018x}"
    if unsigned(iie.iie_bits) & 0x80000000:
        type_str = "INH"
        inherit_count = 0
    else:
        type_str = 'TASK'
        iit = Cast(iie, 'struct ipc_importance_task *')
        inherit_count = sum(1 for i in IterateQueue(iit.iit_inherits, 'struct ipc_importance_inherit *',  'iii_inheritance'))

    refs = unsigned(iie.iie_bits) & 0x7fffffff
    made_refs = unsigned(iie.iie_made)
    kmsg_count = sum(1 for i in IterateQueue(iie.iie_kmsgs, 'struct ipc_kmsg *',  'ikm_inheritance'))
    out_str += fmt.format(iie, type_str, refs, made_refs, kmsg_count, inherit_count)
    if config['verbosity'] > vHUMAN:
        if kmsg_count > 0:
            out_str += "\n\t"+ GetKMsgSummary.header 
            for k in IterateQueue(iie.iie_kmsgs, 'struct ipc_kmsg *',  'ikm_inheritance'):
                out_str += "\t" + "{: <#018x}".format(k.ikm_header.msgh_remote_port) + '   ' + GetKMsgSummary(k, "\t").lstrip() 
            out_str += "\n"
        if inherit_count > 0:
            out_str += "\n\t" + GetIPCImportanceInheritSummary.header + "\n"
            for i in IterateQueue(iit.iit_inherits, 'struct ipc_importance_inherit *',  'iii_inheritance'):
                out_str += "\t" + GetIPCImportanceInheritSummary(i) + "\n"
            out_str += "\n"
        if type_str == "INH":
            iii = Cast(iie, 'struct ipc_importance_inherit *')
            out_str += "Inherit from: " + GetIPCImportanceElemSummary(iii.iii_from_elem)

    return out_str

@header("{: <18s} {: <18s} {: <20s}".format("iit", "task", "name"))
@lldb_type_summary(['ipc_importance_task *'])
def GetIPCImportantTaskSummary(iit):
    """ iit is a ipc_importance_task value object.
    """
    fmt = "{: <#018x} {: <#018x} {: <20s}"
    out_str=''
    pname = GetProcNameForTask(iit.iit_task)
    if hasattr(iit, 'iit_bsd_pid'):
        pname = "({:d}) {:s}".format(iit.iit_bsd_pid, iit.iit_procname)
    out_str += fmt.format(iit, iit.iit_task, pname)
    return out_str

@lldb_command('showallimportancetasks')
def ShowIPCImportanceTasks(cmd_args=[], cmd_options={}):
    """ display a list of all tasks with ipc importance information. 
        Usage: (lldb) showallimportancetasks
        Tip: add "-v" to see detailed information on each kmsg or inherit elems 
    """
    print ' ' + GetIPCImportantTaskSummary.header + ' ' + GetIPCImportanceElemSummary.header
    for t in kern.tasks:
        s = ""
        if unsigned(t.task_imp_base):
            s += ' ' + GetIPCImportantTaskSummary(t.task_imp_base)
            s += ' ' + GetIPCImportanceElemSummary(addressof(t.task_imp_base.iit_elem))
            print s

@lldb_command('showipcimportance', '')
def ShowIPCImportance(cmd_args=[], cmd_options={}):
    """ Describe an importance from <ipc_importance_elem_t> argument.
        Usage: (lldb) showimportance <ipc_importance_elem_t>
    """
    if not cmd_args:
        raise ArgumentError("Please provide valid argument")

    elem = kern.GetValueFromAddress(cmd_args[0], 'ipc_importance_elem_t')
    print GetIPCImportanceElemSummary.header
    print GetIPCImportanceElemSummary(elem)

@header("{: <18s} {: <10s} {: <18s} {: <18s} {: <8s} {: <5s} {: <5s} {: <5s}".format("ivac", "refs", "port", "tbl", "tblsize", "index", "Grow", "freelist"))
@lldb_type_summary(['ipc_voucher_attr_control *', 'ipc_voucher_attr_control_t'])
def GetIPCVoucherAttrControlSummary(ivac):
    """ describes a voucher attribute control settings """
    out_str = ""
    fmt = "{c: <#018x} {c.ivac_refs: <10d} {c.ivac_port: <#018x} {c.ivac_table: <#018x} {c.ivac_table_size: <8d} {c.ivac_key_index: <5d} {growing: <5s} {c.ivac_freelist: <5d}"
    growing_str = ""
    
    if unsigned(ivac) == 0:
        return "{: <#018x}".format(ivac)

    if unsigned(ivac.ivac_is_growing):
        growing_str = "Y"
    out_str += fmt.format(c=ivac, growing = growing_str)
    return out_str

@lldb_command('showivac','')
def ShowIPCVoucherAttributeControl(cmd_args=[], cmd_options={}):
    """ Show summary of voucher attribute contols.
        Usage: (lldb) showivac <ipc_voucher_attr_control_t>
    """
    if not cmd_args:
        raise ArgumentError("Please provide correct arguments.")
    ivac = kern.GetValueFromAddress(cmd_args[0], 'ipc_voucher_attr_control_t')
    print GetIPCVoucherAttrControlSummary.header
    print GetIPCVoucherAttrControlSummary(ivac)
    if config['verbosity'] > vHUMAN:
        cur_entry_index = 0
        last_entry_index = unsigned(ivac.ivac_table_size)
        print "index " + GetIPCVoucherAttributeEntrySummary.header
        while cur_entry_index < last_entry_index:
            print "{: <5d} ".format(cur_entry_index) + GetIPCVoucherAttributeEntrySummary(addressof(ivac.ivac_table[cur_entry_index]))
            cur_entry_index += 1

    


@header("{: <18s} {: <30s} {: <30s} {: <30s} {: <30s} {: <30s}".format("ivam", "get_value_fn", "extract_fn", "release_value_fn", "command_fn", "release_fn"))
@lldb_type_summary(['ipc_voucher_attr_manager *', 'ipc_voucher_attr_manager_t'])
def GetIPCVoucherAttrManagerSummary(ivam):
    """ describes a voucher attribute manager settings """
    out_str = ""
    fmt = "{: <#018x} {: <30s} {: <30s} {: <30s} {: <30s} {: <30s}"
    
    if unsigned(ivam) == 0 :
        return "{: <#018x}".format(ivam)

    get_value_fn = kern.Symbolicate(unsigned(ivam.ivam_get_value))
    extract_fn = kern.Symbolicate(unsigned(ivam.ivam_extract_content))
    release_value_fn = kern.Symbolicate(unsigned(ivam.ivam_release_value))
    command_fn = kern.Symbolicate(unsigned(ivam.ivam_command))
    release_fn = kern.Symbolicate(unsigned(ivam.ivam_release))
    out_str += fmt.format(ivam, get_value_fn, extract_fn, release_value_fn, command_fn, release_fn)
    return out_str



@header("{: <18s} {: <10s} {:s} {:s}".format("ivgte", "key", GetIPCVoucherAttrControlSummary.header.strip(), GetIPCVoucherAttrManagerSummary.header.strip()))
@lldb_type_summary(['ipc_voucher_global_table_element *', 'ipc_voucher_global_table_element_t'])
def GetIPCVoucherGlobalTableElementSummary(ivgte):
    """ describes a ipc_voucher_global_table_element object """
    out_str = ""
    fmt = "{g: <#018x} {g.ivgte_key: <10d} {ctrl_s:s} {mgr_s:s}"
    out_str += fmt.format(g=ivgte, ctrl_s=GetIPCVoucherAttrControlSummary(ivgte.ivgte_control), mgr_s=GetIPCVoucherAttrManagerSummary(ivgte.ivgte_manager))
    return out_str

@lldb_command('showglobalvouchertable', '')
def ShowGlobalVoucherTable(cmd_args=[], cmd_options={}):
    """ show detailed information of all voucher attribute managers registered with vouchers system
        Usage: (lldb) showglobalvouchertable
    """
    entry_size = sizeof(kern.globals.iv_global_table[0])
    elems = sizeof(kern.globals.iv_global_table) / entry_size
    print GetIPCVoucherGlobalTableElementSummary.header
    for i in range(elems):
        elt = addressof(kern.globals.iv_global_table[i])
        print GetIPCVoucherGlobalTableElementSummary(elt)

# Type summaries for Bag of Bits.

@lldb_type_summary(['user_data_value_element', 'user_data_element_t'])
@header("{0: <20s} {1: <16s} {2: <20s} {3: <20s} {4: <16s} {5: <20s}".format("user_data_ve", "maderefs", "checksum", "hash value", "size", "data"))
def GetBagofBitsElementSummary(data_element):
    """ Summarizes the Bag of Bits element
        params: data_element = value of the object of type user_data_value_element_t
        returns: String with summary of the type.
    """
    format_str = "{0: <#020x} {1: <16d} {2: <#020x} {3: <#020x} {4: <16d}"
    out_string = format_str.format(data_element, unsigned(data_element.e_made), data_element.e_sum, data_element.e_hash, unsigned(data_element.e_size))
    out_string += " 0x"

    for i in range(0, (unsigned(data_element.e_size) - 1)):
      out_string += "{:02x}".format(int(data_element.e_data[i]))
    return out_string

def GetIPCHandleSummary(handle_ptr):
    """ converts a handle value inside a voucher attribute table to ipc element and returns appropriate summary.
        params: handle_ptr - uint64 number stored in handle of voucher.
        returns: str - string summary of the element held in internal structure
    """
    elem = kern.GetValueFromAddress(handle_ptr, 'ipc_importance_elem_t')
    if elem.iie_bits & 0x80000000 :
        iie = Cast(elem, 'struct ipc_importance_inherit *')
        return GetIPCImportanceInheritSummary(iie)
    else:
        iit = Cast(elem, 'struct ipc_importance_task *')
        return GetIPCImportantTaskSummary(iit)

def GetATMHandleSummary(handle_ptr):
    """ Convert a handle value to atm value and returns corresponding summary of its fields.
        params: handle_ptr - uint64 number stored in handle of voucher
        returns: str - summary of atm value
    """
    elem = kern.GetValueFromAddress(handle_ptr, 'atm_value *')
    return GetATMValueSummary(elem)

def GetBankHandleSummary(handle_ptr):
    """ converts a handle value inside a voucher attribute table to bank element and returns appropriate summary.
        params: handle_ptr - uint64 number stored in handle of voucher.
        returns: str - summary of bank element
    """
    if handle_ptr == 1 :
        return "Bank task of Current task"
    elem = kern.GetValueFromAddress(handle_ptr, 'bank_element_t')
    if elem.be_type & 1 :
        ba = Cast(elem, 'struct bank_account *')
        return GetBankAccountSummary(ba)
    else:
        bt = Cast(elem, 'struct bank_task *')
        return GetBankTaskSummary(bt)

def GetBagofBitsHandleSummary(handle_ptr):
    """ Convert a handle value to bag of bits value and returns corresponding summary of its fields.
        params: handle_ptr - uint64 number stored in handle of voucher
        returns: str - summary of bag of bits element
    """
    elem = kern.GetValueFromAddress(handle_ptr, 'user_data_element_t')
    return GetBagofBitsElementSummary(elem)

@static_var('attr_managers',{1: GetATMHandleSummary, 2: GetIPCHandleSummary, 3: GetBankHandleSummary, 7: GetBagofBitsHandleSummary})
def GetHandleSummaryForKey(handle_ptr, key_num):
    """ Get a summary of handle pointer from the voucher attribute manager. 
        For example key 1 -> ATM and it puts atm_value_t in the handle. So summary of it would be atm value and refs etc.
                    key 2 -> ipc and it puts either ipc_importance_inherit_t or ipc_important_task_t.
                    key 3 -> Bank and it puts either bank_task_t or bank_account_t.
                    key 7 -> Bag of Bits and it puts user_data_element_t in handle. So summary of it would be Bag of Bits content and refs etc.
    """
    key_num = int(key_num)
    if key_num not in GetHandleSummaryForKey.attr_managers:
        return "Unknown key %d" % key_num
    return GetHandleSummaryForKey.attr_managers[key_num](handle_ptr)


@header("{: <18s} {: <18s} {: <10s} {: <4s} {: <18s} {: <18s}".format("ivace", "value_handle", "#refs", "rel?", "maderefs", "next_layer"))
@lldb_type_summary(['ivac_entry *', 'ivac_entry_t'])
def GetIPCVoucherAttributeEntrySummary(ivace, manager_key_num = 0):
    """ Get summary for voucher attribute entry.
    """
    out_str = ""
    fmt = "{e: <#018x} {e.ivace_value: <#018x} {e.ivace_refs: <10d} {release: <4s} {made_refs: <18s} {next_layer: <18s}"
    release_str = ""
    free_str = ""
    made_refs = ""
    next_layer = ""

    if unsigned(ivace.ivace_releasing):
        release_str = "Y"
    if unsigned(ivace.ivace_free):
        free_str = 'F'
    if unsigned(ivace.ivace_layered):
        next_layer = "{: <#018x}".format(ivace.ivace_u.ivaceu_layer)
    else:
        made_refs = "{: <18d}".format(ivace.ivace_u.ivaceu_made)

    out_str += fmt.format(e=ivace, release=release_str, made_refs=made_refs, next_layer=next_layer)
    if config['verbosity'] > vHUMAN and manager_key_num > 0:
        out_str += " " + GetHandleSummaryForKey(unsigned(ivace.ivace_value), manager_key_num)
    if config['verbosity'] > vHUMAN :
        out_str += ' {: <2s} {: <4d} {: <4d}'.format(free_str, ivace.ivace_next, ivace.ivace_index)
    return out_str

@lldb_command('showivacfreelist','')
def ShowIVACFreeList(cmd_args=[], cmd_options={}):
    """ Walk the free list and print every entry in the list.
        usage: (lldb) showivacfreelist <ipc_voucher_attr_control_t>
    """
    if not cmd_args:
        raise ArgumentError('Please provide <ipc_voucher_attr_control_t>')
    ivac = kern.GetValueFromAddress(cmd_args[0], 'ipc_voucher_attr_control_t')
    print GetIPCVoucherAttrControlSummary.header
    print GetIPCVoucherAttrControlSummary(ivac)
    if unsigned(ivac.ivac_freelist) == 0:
        print "ivac table is full"
        return
    print "index " + GetIPCVoucherAttributeEntrySummary.header
    next_free = unsigned(ivac.ivac_freelist)
    while next_free != 0:
        print "{: <5d} ".format(next_free) + GetIPCVoucherAttributeEntrySummary(addressof(ivac.ivac_table[next_free]))
        next_free = unsigned(ivac.ivac_table[next_free].ivace_next)



@header('{: <18s} {: <8s} {: <18s} {: <18s} {: <18s} {: <18s} {: <18s}'.format("ipc_voucher", "refs", "checksum", "hash", "tbl_size", "table", "voucher_port"))
@lldb_type_summary(['ipc_voucher *', 'ipc_voucher_t'])
def GetIPCVoucherSummary(voucher, show_entries=False):
    """ describe a voucher from its ipc_voucher * object """
    out_str = ""
    fmt = "{v: <#018x} {v.iv_refs: <8d} {v.iv_sum: <#018x} {v.iv_hash: <#018x} {v.iv_table_size: <#018x} {v.iv_table: <#018x} {v.iv_port: <#018x}"
    out_str += fmt.format(v = voucher)
    entries_str = ''
    if show_entries or config['verbosity'] > vHUMAN:
        elems = unsigned(voucher.iv_table_size)
        entries_header_str = "\n\t" + "{: <5s} {: <3s} {: <16s} {: <30s}".format("index", "key", "value_index", "manager") + " " + GetIPCVoucherAttributeEntrySummary.header
        fmt =  "{: <5d} {: <3d} {: <16d} {: <30s}"
        for i in range(elems):
            voucher_entry_index = unsigned(voucher.iv_inline_table[i])
            if voucher_entry_index:
                s = fmt.format(i, GetVoucherManagerKeyForIndex(i), voucher_entry_index, GetVoucherAttributeManagerNameForIndex(i))
                e = GetVoucherValueHandleFromVoucherForIndex(voucher, i)
                if e is not None:
                    s += " " + GetIPCVoucherAttributeEntrySummary(addressof(e), GetVoucherManagerKeyForIndex(i) )
                if entries_header_str :
                    entries_str = entries_header_str
                    entries_header_str = ''
                entries_str += "\n\t" + s 
        if not entries_header_str:
            entries_str += "\n\t"
    out_str += entries_str
    return out_str

def GetVoucherManagerKeyForIndex(idx):
    """ Returns key number for index based on global table. Will raise index error if value is incorrect
    """
    return unsigned(kern.globals.iv_global_table[idx].ivgte_key)

def GetVoucherAttributeManagerForKey(k):
    """ Walks through the iv_global_table and finds the attribute manager name
        params: k - int key number of the manager
        return: cvalue - the attribute manager object. 
                None - if not found
    """
    retval = None
    entry_size = sizeof(kern.globals.iv_global_table[0])
    elems = sizeof(kern.globals.iv_global_table) / entry_size
    for i in range(elems):
        elt = addressof(kern.globals.iv_global_table[i])
        if k == unsigned(elt.ivgte_key):
            retval = elt.ivgte_manager
            break
    return retval

def GetVoucherAttributeControllerForKey(k):
    """ Walks through the iv_global_table and finds the attribute controller
        params: k - int key number of the manager
        return: cvalue - the attribute controller object. 
                None - if not found
    """
    retval = None
    entry_size = sizeof(kern.globals.iv_global_table[0])
    elems = sizeof(kern.globals.iv_global_table) / entry_size
    for i in range(elems):
        elt = addressof(kern.globals.iv_global_table[i])
        if k == unsigned(elt.ivgte_key):
            retval = elt.ivgte_control
            break
    return retval


def GetVoucherAttributeManagerName(ivam):
    """ find the name of the ivam object
        param: ivam - cvalue object of type ipc_voucher_attr_manager_t
        returns: str - name of the manager
    """
    return kern.Symbolicate(unsigned(ivam))

def GetVoucherAttributeManagerNameForIndex(idx):
    """ get voucher attribute manager name for index 
        return: str - name of the attribute manager object
    """
    return GetVoucherAttributeManagerName(GetVoucherAttributeManagerForKey(GetVoucherManagerKeyForIndex(idx)))

def GetVoucherValueHandleFromVoucherForIndex(voucher, idx):
    """ traverse the voucher attrs and get value_handle in the voucher attr controls table
        params:
            voucher - cvalue object of type ipc_voucher_t
            idx - int index in the entries for which you wish to get actual handle for
        returns: cvalue object of type ivac_entry_t
                 None if no handle found.
    """
    manager_key = GetVoucherManagerKeyForIndex(idx)
    voucher_num_elems = unsigned(voucher.iv_table_size)
    if idx >= voucher_num_elems:
        debuglog("idx %d is out of range max: %d" % (idx, voucher_num_elems))
        return None
    voucher_entry_value = unsigned(voucher.iv_inline_table[idx])
    debuglog("manager_key %d" % manager_key)
    ivac = GetVoucherAttributeControllerForKey(manager_key)
    if ivac is None or unsigned(ivac) == 0:
        debuglog("No voucher attribute controller for idx %d" % idx)
        return None

    ivac = kern.GetValueFromAddress(unsigned(ivac), 'ipc_voucher_attr_control_t')  # ??? No idea why lldb does not addressof directly
    ivace_table = ivac.ivac_table
    if voucher_entry_value >= unsigned(ivac.ivac_table_size):
        print "Failed to get ivace for value %d in table of size %d" % (voucher_entry_value, unsigned(ivac.ivac_table_size))
        return None
    return ivace_table[voucher_entry_value]



@lldb_command('showallvouchers')
def ShowAllVouchers(cmd_args=[], cmd_options={}):
    """ Display a list of all vouchers in the global voucher hash table
        Usage: (lldb) showallvouchers 
    """
    iv_hash_table = kern.globals.ivht_bucket
    num_buckets =  sizeof(kern.globals.ivht_bucket) / sizeof(kern.globals.ivht_bucket[0])
    print GetIPCVoucherSummary.header
    for i in range(num_buckets):
        for v in IterateQueue(iv_hash_table[i], 'ipc_voucher_t', 'iv_hash_link'):
            print GetIPCVoucherSummary(v)

@lldb_command('showvoucher', '')
def ShowVoucher(cmd_args=[], cmd_options={}):
    """ Describe a voucher from <ipc_voucher_t> argument.
        Usage: (lldb) showvoucher <ipc_voucher_t>
    """
    if not cmd_args:
        raise ArgumentError("Please provide valid argument")

    voucher = kern.GetValueFromAddress(cmd_args[0], 'ipc_voucher_t')
    print GetIPCVoucherSummary.header
    print GetIPCVoucherSummary(voucher, show_entries=True)

def GetSpaceSendRightEntries(space, port):
    """ Get entry summaries for all send rights to port address in an IPC space.
        params:
            space - the IPC space to search for send rights
            port_addr - the port address to match, or 0 to get all send rights
        returns: an array of IPC entries
    """
    entry_table = space.is_table
    ports = int(space.is_table_size)
    i = 0
    entries = []

    while i < ports:
        entry = GetObjectAtIndexFromArray(entry_table, i)

        entry_ie_bits = unsigned(entry.ie_bits)
        if (entry_ie_bits & 0x00010000) != 0 and (not port or entry.ie_object == port):
            entries.append(entry)
        i += 1

    return entries

@lldb_command('showportsendrights')
def ShowPortSendRights(cmd_args=[], cmd_options={}):
    """ Display a list of send rights across all tasks for a given port.
        Usage: (lldb) showportsendrights <ipc_port_t>
    """
    if not cmd_args:
        raise ArgumentError("no port address provided")
    port = kern.GetValueFromAddress(cmd_args[0], 'struct ipc_port *')
    i = 1

    return FindPortRights(cmd_args=[unsigned(port)], cmd_options={'-R':'S'})


@lldb_command('showtasksuspenders')
def ShowTaskSuspenders(cmd_args=[], cmd_options={}):
    """ Display the tasks and send rights that are holding a target task suspended.
        Usage: (lldb) showtasksuspenders <task_t>
    """
    if not cmd_args:
        raise ArgumentError("no task address provided")
    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')

    if task.suspend_count == 0:
        print "task {:#x} ({:s}) is not suspended".format(unsigned(task), Cast(task.bsd_info, 'proc_t').p_name)
        return

    # If the task has been suspended by the kernel (potentially by
    # kperf, using task_suspend_internal) or a client of task_suspend2
    # that does not convert its task suspension token to a port using
    # convert_task_suspension_token_to_port, then it's impossible to determine
    # which task did the suspension.
    port = task.itk_resume
    if not port:
        print "task {:#x} ({:s}) is suspended but no resume port exists".format(unsigned(task), Cast(task.bsd_info, 'proc_t').p_name)
        return

    return FindPortRights(cmd_args=[unsigned(port)], cmd_options={'-R':'S'})
