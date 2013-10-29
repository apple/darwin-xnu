from xnu import *
from utils import *
import sys

def GetKDPPacketHeaderInt(request=0, is_reply=False, seq=0, length=0, key=0):
    """ create a 64 bit number that could be saved as pkt_hdr_t
        params:
            request:int   - 7 bit kdp_req_t request type
            is_reply:bool - False => request, True => reply 
            seq: int      - 8  sequence number within session 
            length: int   - 16 bit length of entire pkt including hdr 
            key: int      - session key 
        returns:
            int - 64 bit number to be saved in memory
    """
    retval = request 
    if is_reply:
        retval = 1<<7 |retval
    retval = (seq << 8) | retval
    retval = (length << 16) | retval
    #retval = (retval << 32) | key
    retval = (key << 32) | retval
    return retval


def KDPDumpInfo(subcmd, file_name="", dest_ip="", router_ip="", port=0):
    """ Setup the state for DUMP INFO commands for sending coredump etc
    """
    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Nothing to do here."
        return False
    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        return False

    kdp_pkt_size = GetType('kdp_dumpinfo_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        return False

    data_addr = int(addressof(kern.globals.manual_pkt))
    pkt = kern.GetValueFromAddress(data_addr, 'kdp_dumpinfo_req_t *')
    if len(file_name) > 49:
        file_name = file_name[:49]
    if len(dest_ip) > 15:
        dest_ip = dest_ip[:15]
    if len(router_ip) > 15:
        router_ip = router_ip[:15]

    header_value =GetKDPPacketHeaderInt(request=GetEnumValue('kdp_req_t::KDP_DUMPINFO'), length=kdp_pkt_size)
    # 0x1f is same as KDP_DUMPINFO
    if ( WriteInt64ToMemoryAddress((header_value), int(addressof(pkt.hdr))) and
         WriteInt32ToMemoryAddress(subcmd, int(addressof(pkt.type))) and
         WriteStringToMemoryAddress(file_name, int(addressof(pkt.name))) and
         WriteStringToMemoryAddress(dest_ip, int(addressof(pkt.destip))) and
         WriteStringToMemoryAddress(router_ip, int(addressof(pkt.routerip)))
         ):
         #We have saved important data successfully
        if port > 0:
            if not WriteInt32ToMemoryAddress(port, int(addressof(pkt.port))):
                return False
        if WriteInt32ToMemoryAddress(1, input_address):
            return True
    return False

@lldb_command('sendcore')
def KDPSendCore(cmd_args=None):
    """  Configure kernel to send a coredump to the specified IP
    Syntax: sendcore <IP address> [filename]
    Configure the kernel to transmit a kernel coredump to a server (kdumpd) 
    at the specified IP address. This is useful when the remote target has
    not been previously configured to transmit coredumps, and you wish to
    preserve kernel state for later examination. NOTE: You must issue a "continue"
    command after using this macro to trigger the kernel coredump. The kernel
    will resume waiting in the debugger after completion of the coredump. You
    may disable coredumps by executing the "disablecore" macro. You can 
    optionally specify the filename to be used for the generated core file.

    """
    if cmd_args == None or len(cmd_args) < 1:
        print KDPSendCore.__doc__
        return False
    ip_address = cmd_args[0]
    filename=""
    if len(cmd_args) >=2:
        filename = cmd_args[1].strip()
    retval = KDPDumpInfo(GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_CORE'), file_name=filename, dest_ip=ip_address)
    if retval:
        print "Remote system has been setup for coredump. Please detach/continue the system. "
        return True
    else:
        print "Something went wrong. Failed to setup the coredump on the target."
        return False

    
@lldb_command('sendsyslog')
def KDPSendSyslog(cmd_args=None):
    """ Configure kernel to send a system log to the specified IP
        Syntax: sendsyslog <IP address> [filename]
        Configure the kernel to transmit a kernel system log to a server (kdumpd) 
        at the specified IP address. NOTE: You must issue a "continue"
        command after using this macro to trigger the kernel system log. The kernel
        will resume waiting in the debugger after completion. You can optionally
        specify the name to be used for the generated system log.
    """
    if cmd_args == None or len(cmd_args) < 1:
        print KDPSendSyslog.__doc__
        return False
    ip_address = cmd_args[0]
    filename =""
    if len(cmd_args) >=2:
        filename = cmd_args[1].strip()
    retval = KDPDumpInfo(GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_SYSTEMLOG'), file_name = filename, dest_ip = ip_address)
    if retval:
        print "Remote system has been setup to send system log. please detach/continue the system."
        return True
    else:
        print "Something went wrong. Failed to setup the systemlog on the target."
        return False

@lldb_command('sendpaniclog')
def KDPSendPaniclog(cmd_args=None):
    """ Configure kernel to send a panic log to the specified IP
        Syntax: sendpaniclog <IP address> [filename]
        Configure the kernel to transmit a kernel paniclog to a server (kdumpd) 
        at the specified IP address. NOTE: You must issue a "continue"
        command after using this macro to trigger the kernel panic log. The kernel
        will resume waiting in the debugger after completion. You can optionally
        specify the name to be used for the generated panic log.
    """
    if cmd_args == None or len(cmd_args) < 1:
        print KDPSendPaniclog.__doc__
        return False
    ip_address = cmd_args[0]
    filename =""
    if len(cmd_args) >=2:
        filename = cmd_args[1].strip()
    retval = KDPDumpInfo(GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_PANICLOG'), file_name = filename, dest_ip = ip_address)
    if retval:
        print "Remote system has been setup to send panic log. please detach/continue the system."
        return True
    else:
        print "Something went wrong. Failed to setup the paniclog on the target."
        return False


@lldb_command('disablecore')
def KDPDisableCore(cmd_args=None):
    """ Configure the kernel to disable coredump transmission
        Reconfigures the kernel so that it no longer transmits kernel coredumps. This
        complements the "sendcore" macro, but it may be used if the kernel has been
        configured to transmit coredumps through boot-args as well.

    """
    retval = KDPDumpInfo(GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_DISABLE'))
    if retval :
        print "Disabled coredump functionality on remote system."
    else:
        print "Failed to disable coredump functionality."
    return retval

@lldb_command('resume_on')
def KDPResumeON(cmd_args=None):
    """ The target system will resume when detaching  or exiting from lldb. 
        This is the default behavior.
    """
    subcmd = GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_SETINFO') | GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_RESUME') 
    retval = KDPDumpInfo(subcmd)
    if retval :
        print "Target system will resume on detaching from lldb."
    else:
        print "Failed to enable resume functionality."
    return retval

@lldb_command('resume_off')
def KDPResumeON(cmd_args=None):
    """ The target system will not resume when detaching  or exiting from lldb. 
    """
    subcmd = GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_SETINFO') | GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_NORESUME') 
    retval = KDPDumpInfo(subcmd)
    if retval :
        print "Target system will not resume on detaching from lldb."
    else:
        print "Failed to disable resume functionality."
    return retval



@lldb_command('getdumpinfo')
def KDPGetDumpInfo(cmd_args=None):
    """ Retrieve the current remote dump settings.
    """
    if not KDPDumpInfo(GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_GETINFO')):
        print "Failed to get dump settings."
        return False
    dumpinfo = Cast(addressof(kern.globals.manual_pkt.data), 'kdp_dumpinfo_reply_t *')
    target_dump_type = int(dumpinfo.type)
    if target_dump_type & GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_REBOOT'):
        print "System will reboot after kernel info gets dumped."
    else:
        print "System will not reboot after kernel info gets dumped."
    if target_dump_type & GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_RESUME'):
        print "System will allow a re-attach after KDP disconnect."
    else:
        print "System will not allow a re-attach after KDP disconnect."
    target_dump_type = target_dump_type & GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_MASK')
    if target_dump_type == GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_DISABLE'):
        print "Kernel not setup for remote dumps."
    else:
        kern_dump_type = ''
        if target_dump_type == GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_CORE'):
            kern_dump_type = "Core File"
        elif target_dump_type == GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_PANICLOG'):
            kern_dump_type = "Panic Log"
        elif target_dump_type == GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_SYSTEMLOG'):
            kern_dump_type = "System Log"
        print "Kernel dump type:" + kern_dump_type
        fname = "(autogenerated)"
        if int(dumpinfo.name[0]) != 0:
            fname = str(dumpinfo.name)
        print "Filename: " + fname
        print "Network Info: {:s} [{:d}] , Router: {:s}".format(dumpinfo.destip, dumpinfo.port, dumpinfo.routerip)
    # end of get dump info


@lldb_command('kdp-reenter')
def KDPReenter(cmd_args=None):
    """ Schedules reentry into the debugger 
        after <seconds> seconds, and resumes the target.
        usage: kdp-reenter <seconds>
    """
    if len(cmd_args) < 1:
        print "Please provide valid time in seconds"
        print KDPReenter.__doc__
        return False

    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Nothing to do here."
        return False

    num_seconds = ArgumentStringToInt(cmd_args[0])
    milliseconds_to_sleep = num_seconds * 1000
    if WriteInt32ToMemoryAddress(milliseconds_to_sleep, addressof(kern.globals.kdp_reentry_deadline)):
        lldb.debugger.HandleCommand('process continue')
        return True
    print "Failed to setup kdp-reentry."
    return False

@lldb_command('kdp-reboot')
def KDPReboot(cmd_args=None):
    """ Restart the remote target
    """
    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Nothing to do here."
        return False

    print "Rebooting the remote machine."
    lldb.debugger.HandleCommand('process plugin packet send --command 0x13')
    lldb.debugger.HandleCommand('detach')
    return True

@lldb_command('setdumpinfo')
def KDPSetDumpInfo(cmd_args=None):
    """ Configure the current remote dump settings. 
        Specify "" if you want to use the defaults (filename) or previously configured
        settings (ip/router). Specify 0 for the port if you wish to 
        use the previously configured/default setting for that.
        Syntax: setdumpinfo <filename> <ip> <router> <port>
    """
    if not cmd_args:
        print KDPSetDumpInfo.__doc__
        return False
    if len(cmd_args) < 4:
        print "Not enough arguments."
        print KDPSetDumpInfo.__doc__
        return False
    portnum = ArgumentStringToInt(cmd_args[3])
    retval = KDPDumpInfo(GetEnumValue('kdp_dumpinfo_t::KDP_DUMPINFO_SETINFO'), cmd_args[0], cmd_args[1], cmd_args[2], portnum)
    if retval:
        print "Successfully saved the dumpinfo."
    else:
        print "Failed to save the dumpinfo."
    return retval

