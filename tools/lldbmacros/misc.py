"""
Miscellaneous (Intel) platform-specific commands.
"""

from xnu import *
import xnudefines

@lldb_command('showmcastate')
def showMCAstate(cmd_args=None):
    """
    Print machine-check register state after MC exception.
    """
    if kern.arch != 'x86_64':
        print "Not available for current architecture."
        return

    present = ["not present", "present"]
    print 'MCA {:s}, control MSR {:s}, threshold status {:s}'.format(
    present[int(kern.globals.mca_MCA_present)],
    present[int(kern.globals.mca_control_MSR_present)],
    present[int(kern.globals.mca_threshold_status_present)])
    print '{:d} error banks, family code {:#0x}, machine-check dump state: {:d}'.format(
        kern.globals.mca_error_bank_count,
        kern.globals.mca_dump_state,
        kern.globals.mca_family)
    cpu = 0
    while kern.globals.cpu_data_ptr[cpu]:
        cd = kern.globals.cpu_data_ptr[cpu]
        mc = cd.cpu_mca_state
        if mc:
            print 'CPU {:d}: mca_mcg_ctl: {:#018x} mca_mcg_status {:#018x}'.format(cpu, mc.mca_mcg_ctl, mc.mca_mcg_status.u64)
            hdr = '{:<4s} {:<18s} {:<18s} {:<18s} {:<18s}'
            val = '{:>3d}: {:#018x} {:#018x} {:#018x} {:#018x}'
            print hdr.format('bank',
                    'mca_mci_ctl',
                    'mca_mci_status',
                    'mca_mci_addr',
                    'mca_mci_misc')
            for i in range(int(kern.globals.mca_error_bank_count)):
                bank = mc.mca_error_bank[i]
                print val.format(i,
                    bank.mca_mci_ctl,
                    bank.mca_mci_status.u64,
                    bank.mca_mci_addr,     
                    bank.mca_mci_misc)     
        print 'register state:'
        reg = cd.cpu_desc_index.cdi_ktss.ist1 - sizeof('x86_saved_state_t')
        print lldb_run_command('p/x *(x86_saved_state_t *) ' + hex(reg))
        cpu = cpu + 1

def dumpTimerList(anchor):
    """
    Utility function to dump the timer entries in list (anchor).
    """
    entry = Cast(anchor.head, 'queue_t')
    if entry == addressof(anchor):
        print '(empty)'
        return

    thdr = ' {:<22s}{:<17s}{:<16s} {:<14s} {:<18s}'
    print thdr.format('entry:','deadline','soft_deadline','to go','(*func)(param0,param1')
    while entry != addressof(anchor):
        timer_call = Cast(entry, 'timer_call_t')
        call_entry = Cast(entry, 'struct call_entry *')
        debugger_entry = kern.globals.debugger_entry_time
        if (debugger_entry < call_entry.deadline):
            delta_sign = ' '
            timer_fire = call_entry.deadline - debugger_entry
        else:
            delta_sign = '-'
            timer_fire = debugger_entry - call_entry.deadline
        tval = ' {:#018x}: {:16d} {:16d} {:s}{:3d}.{:09d}  ({:#018x})({:#018x},{:#018x})'
        print tval.format(entry,
            call_entry.deadline,
            timer_call.soft_deadline,
            delta_sign,
            timer_fire/1000000000,
            timer_fire%1000000000,
            call_entry.func,
            call_entry.param0,
            call_entry.param1)
        entry = entry.next

@lldb_command('longtermtimers')
def longtermTimers(cmd_args=None):
    """
    Print details of long-term timers and stats.
    """
    if kern.arch != 'x86_64':
        print "Not available for current architecture."
        return

    lt = kern.globals.timer_longterm
    ltt = lt.threshold
    EndofAllTime = -1
    if ltt.interval == EndofAllTime:
        print "Longterm timers disabled"
        return

    if lt.escalates > 0:
        ratio = lt.enqueues / lt.escalates
    else:
        ratio = lt.enqueues
    print     'Longterm timer object: {:#018x}'.format(addressof(lt))
    print     ' queue count         : {:d}'    .format(lt.queue.count)
    print     ' number of enqueues  : {:d}'    .format(lt.enqueues)
    print     ' number of dequeues  : {:d}'    .format(lt.dequeues)
    print     ' number of escalates : {:d}'    .format(lt.escalates)
    print     ' enqueues/escalates  : {:d}'    .format(ratio)
    print     ' threshold.interval  : {:d}'    .format(ltt.interval)
    print     ' threshold.margin    : {:d}'    .format(ltt.margin)
    print     ' scan_time           : {:d}'    .format(lt.scan_time)
    if ltt.preempted == EndofAllTime:
        print ' threshold.preempted : None'
    else:
        print ' threshold.preempted : {:d}'    .format(ltt.preempted)
    if ltt.deadline == EndofAllTime:
        print ' threshold.deadline  : None'
    else:
        print ' threshold.deadline  : {:d}'    .format(ltt.deadline)
        print ' threshold.call      : {:#018x}'.format(ltt.call)
        print ' actual deadline set : {:d}'    .format(ltt.deadline_set)
    print     ' threshold.scans     : {:d}'    .format(ltt.scans)
    print     ' threshold.preempts  : {:d}'    .format(ltt.preempts)
    print     ' threshold.latency   : {:d}'    .format(ltt.latency)
    print     '               - min : {:d}'    .format(ltt.latency_min)
    print     '               - max : {:d}'    .format(ltt.latency_max)
    dumpTimerList(lt.queue)


@lldb_command('processortimers')
def processorTimers(cmd_args=None):
    """
    Print details of processor timers, noting anything suspicious
    Also include long-term timer details
    """
    hdr = '{:<32s}{:<18s} {:<18s} {:<18s}'
    print hdr.format('Processor','Last dispatch','Next deadline','difference')
    p = kern.globals.processor_list
    while p:
        cpu = p.cpu_id
        rt_timer = kern.globals.cpu_data_ptr[cpu].rtclock_timer
        diff = p.last_dispatch - rt_timer.deadline
        tmr = 'Processor {:d}: {:#018x} {:#018x} {:#018x} {:#018x} {:s}'
        print tmr.format(cpu,
            p,
            p.last_dispatch,
            rt_timer.deadline,
            diff,
            ['probably BAD', '(ok)'][int(diff < 0)])
        if kern.arch == 'x86_64':
            print 'Next deadline set at: {:#018x}. Timer call list:'.format(rt_timer.when_set)
            dumpTimerList(rt_timer.queue)
        p = p.processor_list
    longtermTimers()


@lldb_command('showtimerwakeupstats')
def showTimerWakeupStats(cmd_args=None):
    """
    Displays interrupt and platform idle wakeup frequencies
    associated with each thread, timer time-to-deadline frequencies, and
    CPU time with user/system break down where applicable, with thread tags.
    """
    for task in kern.tasks:
        proc = Cast(task.bsd_info, 'proc_t')
        print dereference(task)
        print '{:d}({:s}), terminated thread timer wakeups: {:d} {:d} 2ms: {:d} 5ms: {:d} UT: {:d} ST: {:d}'.format(
            proc.p_pid,
            proc.p_comm,
# Commented-out references below to be addressed by rdar://13009660.
            0, #task.task_interrupt_wakeups,
            0, #task.task_platform_idle_wakeups,
            task.task_timer_wakeups_bin_1,
            task.task_timer_wakeups_bin_2,
            task.total_user_time,
            task.total_system_time)
        tot_wakes = 0 #task.task_interrupt_wakeups
        tot_platform_wakes = 0 #task.task_platform_idle_wakeups
        for thread in IterateQueue(task.threads, 'thread_t', 'task_threads'):
#           if thread.thread_interrupt_wakeups == 0:
#               continue
            print '\tThread ID 0x{:x}, Tag 0x{:x}, timer wakeups: {:d} {:d} {:d} {:d} <2ms: {:d}, <5ms: {:d} UT: {:d} ST: {:d}'.format(
                thread.thread_id,
                thread.thread_tag,
                0, #thread.thread_interrupt_wakeups,
                0, #thread.thread_platform_idle_wakeups,
                0, #thread.thread_callout_interrupt_wakeups,
                0, #thread.thread_callout_platform_idle_wakeups,
                0,0,0,0,
                thread.thread_timer_wakeups_bin_1,
                thread.thread_timer_wakeups_bin_2,
                thread.user_timer.all_bits,
                thread.system_timer.all_bits)
            tot_wakes += 0 #thread.thread_interrupt_wakeups
            tot_platform_wakes += 0 #thread.thread_platform_idle_wakeups
        print 'Task total wakeups: {:d} {:d}'.format(
            tot_wakes, tot_platform_wakes)

def DoReadMsr64(msr_address, lcpu):
    """ Read a 64-bit MSR from the specified CPU
        Params:
            msr_address: int - MSR index to read from
            lcpu: int - CPU identifier
        Returns:
            64-bit value read from the MSR
    """
    result = 0xbad10ad

    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Cannot read MSR."
        return result

    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        print "DoReadMsr64() failed to write 0 to input_address"
        return result
    
    kdp_pkt_size = GetType('kdp_readmsr64_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        print "DoReadMsr64() failed to write kdp_pkt_size"
        return result
    
    kgm_pkt = kern.GetValueFromAddress(data_address, 'kdp_readmsr64_req_t *')
    header_value = GetKDPPacketHeaderInt(
        request=GetEnumValue('kdp_req_t::KDP_READMSR64'),
        length=kdp_pkt_size)

    if not WriteInt64ToMemoryAddress(header_value, int(addressof(kgm_pkt.hdr))):
        print "DoReadMsr64() failed to write header_value"
        return result
    if not WriteInt32ToMemoryAddress(msr_address, int(addressof(kgm_pkt.address))):
        print "DoReadMsr64() failed to write msr_address"
        return result
    if not WriteInt16ToMemoryAddress(lcpu, int(addressof(kgm_pkt.lcpu))):
        print "DoReadMsr64() failed to write lcpu"
        return result
    if not WriteInt32ToMemoryAddress(1, input_address):
        print "DoReadMsr64() failed to write to input_address"
        return result

    result_pkt = Cast(addressof(kern.globals.manual_pkt.data),
        'kdp_readmsr64_reply_t *')
    if (result_pkt.error == 0):
        result = dereference(Cast(addressof(result_pkt.data), 'uint64_t *'))
    else:
        print "DoReadMsr64() result_pkt.error != 0"
    return result

def DoWriteMsr64(msr_address, lcpu, data):
    """ Write a 64-bit MSR
        Params: 
            msr_address: int - MSR index to write to
            lcpu: int - CPU identifier
            data: int - value to write
        Returns:
            True upon success, False if error
    """
    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Cannot write MSR."
        return False

    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        print "DoWriteMsr64() failed to write 0 to input_address"
        return False
    
    kdp_pkt_size = GetType('kdp_writemsr64_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        print "DoWriteMsr64() failed to kdp_pkt_size"
        return False
    
    kgm_pkt = kern.GetValueFromAddress(data_address, 'kdp_writemsr64_req_t *')
    header_value = GetKDPPacketHeaderInt(
        request=GetEnumValue('kdp_req_t::KDP_WRITEMSR64'),
        length=kdp_pkt_size)
    
    if not WriteInt64ToMemoryAddress(header_value, int(addressof(kgm_pkt.hdr))):
        print "DoWriteMsr64() failed to write header_value"
        return False
    if not WriteInt32ToMemoryAddress(msr_address, int(addressof(kgm_pkt.address))):
        print "DoWriteMsr64() failed to write msr_address"
        return False
    if not WriteInt16ToMemoryAddress(lcpu, int(addressof(kgm_pkt.lcpu))):
        print "DoWriteMsr64() failed to write lcpu"
        return False
    if not WriteInt64ToMemoryAddress(data, int(addressof(kgm_pkt.data))):
        print "DoWriteMsr64() failed to write data"
        return False
    if not WriteInt32ToMemoryAddress(1, input_address):
        print "DoWriteMsr64() failed to write to input_address"
        return False

    result_pkt = Cast(addressof(kern.globals.manual_pkt.data),
        'kdp_writemsr64_reply_t *')
    if not result_pkt.error == 0:
        print "DoWriteMsr64() error received in reply packet"
        return False
    
    return True

@lldb_command('readmsr64')
def ReadMsr64(cmd_args=None):
    """ Read the specified MSR. The CPU can be optionally specified
        Syntax: readmsr64 <msr> [lcpu]
    """
    if cmd_args == None or len(cmd_args) < 1:
        print ReadMsr64.__doc__
        return
    
    msr_address = ArgumentStringToInt(cmd_args[0])
    if len(cmd_args) > 1:
        lcpu = ArgumentStringToInt(cmd_args[1])
    else:
        lcpu = int(xnudefines.lcpu_self)

    msr_value = DoReadMsr64(msr_address, lcpu)
    print "MSR[{:x}]: {:#016x}".format(msr_address, msr_value)

@lldb_command('writemsr64')
def WriteMsr64(cmd_args=None):
    """ Write the specified MSR. The CPU can be optionally specified
        Syntax: writemsr64 <msr> <value> [lcpu]
    """
    if cmd_args == None or len(cmd_args) < 2:
        print WriteMsr64.__doc__
        return
    msr_address = ArgumentStringToInt(cmd_args[0])
    write_val = ArgumentStringToInt(cmd_args[1])
    if len(cmd_args) > 2:
        lcpu = ArgumentStringToInt(cmd_args[2])
    else:
        lcpu = xnudefines.lcpu_self

    if not DoWriteMsr64(msr_address, lcpu, write_val):
        print "writemsr64 FAILED"

def GetEVFlags(debug_arg):
    """ Return the EV Flags for the given kernel debug arg value
        params:
            debug_arg - value from arg member of kernel debug buffer entry
        returns: 
            str - string representing the EV Flag for given input arg value
    """
    out_str = ""
    if debug_arg & 1:
        out_str += "EV_RE "
    if debug_arg & 2:
        out_str += "EV_WR "
    if debug_arg & 4:
        out_str += "EV_EX "
    if debug_arg & 8:
        out_str += "EV_RM "
    if debug_arg & 0x00100:
        out_str += "EV_RBYTES "
    if debug_arg & 0x00200:
        out_str += "EV_WBYTES "
    if debug_arg & 0x00400:
        out_str += "EV_RCLOSED "
    if debug_arg & 0x00800:
        out_str += "EV_RCONN "
    if debug_arg & 0x01000:
        out_str += "EV_WCLOSED "
    if debug_arg & 0x02000:
        out_str += "EV_WCONN "
    if debug_arg & 0x04000:
        out_str += "EV_OOB "
    if debug_arg & 0x08000:
        out_str += "EV_FIN "
    if debug_arg & 0x10000:
        out_str += "EV_RESET "
    if debug_arg & 0x20000:
        out_str += "EV_TIMEOUT "
    
    return out_str

def GetKernelDebugBufferEntry(kdbg_entry):
    """ Extract the information from given kernel debug buffer entry and return the summary
        params:
            kdebug_entry - kd_buf - address of kernel debug buffer entry
        returns: 
            str - formatted output information of kd_buf entry
    """
    out_str = ""
    code_info_str = ""
    kdebug_entry = kern.GetValueFromAddress(kdbg_entry, 'kd_buf *')
    debugid     = kdebug_entry.debugid
    kdebug_arg1 = kdebug_entry.arg1
    kdebug_arg2 = kdebug_entry.arg2
    kdebug_arg3 = kdebug_entry.arg3
    kdebug_arg4 = kdebug_entry.arg4
    
    if kern.arch in ('x86_64', 'arm64'):
        kdebug_cpu   = kdebug_entry.cpuid
        ts_hi        = (kdebug_entry.timestamp >> 32) & 0xFFFFFFFF
        ts_lo        = kdebug_entry.timestamp & 0xFFFFFFFF
    else:
        kdebug_cpu   = (kdebug_entry.timestamp >> 56)
        ts_hi        = (kdebug_entry.timestamp >> 32) & 0x00FFFFFF
        ts_lo        = kdebug_entry.timestamp & 0xFFFFFFFF
    
    kdebug_class    = (debugid >> 24) & 0x000FF
    kdebug_subclass = (debugid >> 16) & 0x000FF
    kdebug_code     = (debugid >>  2) & 0x03FFF
    kdebug_qual     = (debugid) & 0x00003
    
    if kdebug_qual == 0:
        kdebug_qual = '-'
    elif kdebug_qual == 1:
        kdebug_qual = 'S'
    elif kdebug_qual == 2:
        kdebug_qual = 'E'
    elif kdebug_qual == 3:
        kdebug_qual = '?'

    # preamble and qual
    out_str += "{:<#20x} {:>6d} {:>#12x} ".format(kdebug_entry, kdebug_cpu, kdebug_entry.arg5)
    out_str += " {:#010x}{:08x} {:>6s} ".format(ts_hi, ts_lo, kdebug_qual)
    
    # class
    kdbg_class = ""
    if kdebug_class == 1:
        kdbg_class = "MACH"
    elif kdebug_class == 2:
        kdbg_class = "NET "
    elif kdebug_class == 3:
        kdbg_class = "FS  "
    elif kdebug_class == 4:
        kdbg_class = "BSD "
    elif kdebug_class == 5:
        kdbg_class = "IOK "
    elif kdebug_class == 6:
        kdbg_class = "DRVR"
    elif kdebug_class == 7:
        kdbg_class = "TRAC"
    elif kdebug_class == 8:
        kdbg_class = "DLIL"
    elif kdebug_class == 9:
        kdbg_class = "WQ  "
    elif kdebug_class == 10:
        kdbg_class = "CS  "
    elif kdebug_class == 11:
        kdbg_class = "CG  "
    elif kdebug_class == 20:
        kdbg_class = "MISC"
    elif kdebug_class == 30:
        kdbg_class = "SEC "
    elif kdebug_class == 31:
        kdbg_class = "DYLD"
    elif kdebug_class == 32:
        kdbg_class = "QT  "
    elif kdebug_class == 33:
        kdbg_class = "APPS"
    elif kdebug_class == 34:
        kdbg_class = "LAUN"
    elif kdebug_class == 36:
        kdbg_class = "PPT "
    elif kdebug_class == 37:
        kdbg_class = "PERF"
    elif kdebug_class == 38:
        kdbg_class = "IMP "
    elif kdebug_class == 39:
        kdbg_class = "PCTL"
    elif kdebug_class == 40:
        kdbg_class = "BANK"
    elif kdebug_class == 41:
        kdbg_class = "XPC "
    elif kdebug_class == 42:
        kdbg_class = "ATM "
    elif kdebug_class == 128:
        kdbg_class = "ANS "
    elif kdebug_class == 129:
        kdbg_class = "SIO "
    elif kdebug_class == 130:
        kdbg_class = "SEP "
    elif kdebug_class == 131:
        kdbg_class = "ISP "
    elif kdebug_class == 132:
        kdbg_class = "OSCA"
    elif kdebug_class == 133:
        kdbg_class = "EGFX"
    elif kdebug_class == 255:
        kdbg_class = "MIG "
    else:
        out_str += "{:^#10x} ".format(kdebug_class)
    
    if kdbg_class:
        out_str += "{:^10s} ".format(kdbg_class)

    # subclass and code
    out_str += " {:>#5x} {:>8d}   ".format(kdebug_subclass, kdebug_code)

    # space for debugid-specific processing
    # EVPROC from bsd/kern/sys_generic.c
    # MISCDBG_CODE(DBG_EVENT,DBG_WAIT)
    if debugid == 0x14100048:
        code_info_str += "waitevent "
        if kdebug_arg1 == 1:
            code_info_str += "before sleep"
        elif kdebug_arg1 == 2:
            code_info_str += "after  sleep"
        else:
            code_info_str += "????????????"
        code_info_str += " chan={:#08x} ".format(kdebug_arg2)
    elif debugid == 0x14100049:
        # MISCDBG_CODE(DBG_EVENT,DBG_WAIT|DBG_FUNC_START)
        code_info_str += "waitevent "
    elif debugid == 0x1410004a:
        # MISCDBG_CODE(DBG_EVENT,DBG_WAIT|DBG_FUNC_END)
        code_info_str += "waitevent error={:d} ".format(kdebug_arg1)
        code_info_str += "eqp={:#08x} ".format(kdebug_arg4)
        code_info_str += GetEVFlags(kdebug_arg3)
        code_info_str += "er_handle={:d} ".format(kdebug_arg2)
    elif debugid == 0x14100059:
        # MISCDBG_CODE(DBG_EVENT,DBG_DEQUEUE|DBG_FUNC_START)
        code_info_str += "evprocdeque proc={:#08x} ".format(kdebug_arg1)
        if kdebug_arg2 == 0:
            code_info_str += "remove first "
        else:
            code_info_str += "remove {:#08x} ".format(kdebug_arg2)
    elif debugid == 0x1410005a:
        # MISCDBG_CODE(DBG_EVENT,DBG_DEQUEUE|DBG_FUNC_END)
        code_info_str += "evprocdeque "
        if kdebug_arg1 == 0:
            code_info_str += "result=NULL "
        else:
            code_info_str += "result={:#08x} ".format(kdebug_arg1)
    elif debugid == 0x14100041:
        # MISCDBG_CODE(DBG_EVENT,DBG_POST|DBG_FUNC_START)
        code_info_str += "postevent "
        code_info_str += GetEVFlags(kdebug_arg1)
    elif debugid == 0x14100040:
        # MISCDBG_CODE(DBG_EVENT,DBG_POST)
        code_info_str += "postevent "
        code_info_str += "evq={:#08x} ".format(kdebug_arg1)
        code_info_str += "er_eventbits="
        code_info_str += GetEVFlags(kdebug_arg2)
        code_info_str +="mask="
        code_info_str += GetEVFlags(kdebug_arg3)
    elif debugid == 0x14100042:
        # MISCDBG_CODE(DBG_EVENT,DBG_POST|DBG_FUNC_END)
        code_info_str += "postevent "
    elif debugid == 0x14100055:
        # MISCDBG_CODE(DBG_EVENT,DBG_ENQUEUE|DBG_FUNC_START)
        code_info_str += "evprocenque eqp={:#08x} ".format(kdebug_arg1)
        if kdebug_arg2 & 1:
            code_info_str += "EV_QUEUED "
        code_info_str += GetEVFlags(kdebug_arg3)
    elif debugid == 0x14100050:
        # MISCDBG_CODE(DBG_EVENT,DBG_EWAKEUP)
        code_info_str += "evprocenque before wakeup eqp={:#08x} ".format(kdebug_arg4)
    elif debugid == 0x14100056:
        # MISCDBG_CODE(DBG_EVENT,DBG_ENQUEUE|DBG_FUNC_END)
        code_info_str += "evprocenque "
    elif debugid == 0x1410004d:
        # MISCDBG_CODE(DBG_EVENT,DBG_MOD|DBG_FUNC_START)
        code_info_str += "modwatch "
    elif debugid == 0x1410004c:
        # MISCDBG_CODE(DBG_EVENT,DBG_MOD)
        code_info_str += "modwatch er_handle={:d} ".format(kdebug_arg1)
        code_info_str += GetEVFlags(kdebug_arg2)
        code_info_str += "evq={:#08x} ", kdebug_arg3
    elif debugid == 0x1410004e:
    # MISCDBG_CODE(DBG_EVENT,DBG_MOD|DBG_FUNC_END)
        code_info_str += "modwatch er_handle={:d} ".format(kdebug_arg1)
        code_info_str += "ee_eventmask="
        code_info_str += GetEVFlags(kdebug_arg2)
        code_info_str += "sp={:#08x} ".format(kdebug_arg3)
        code_info_str += "flag="
        code_info_str += GetEVFlags(kdebug_arg4)
    else:
        code_info_str += "arg1={:#010x} ".format(kdebug_arg1)
        code_info_str += "arg2={:#010x} ".format(kdebug_arg2)
        code_info_str += "arg3={:#010x} ".format(kdebug_arg3)
        code_info_str += "arg4={:#010x} ".format(kdebug_arg4)
    
    # finish up
    out_str += "{:<25s}\n".format(code_info_str)
    return out_str

@lldb_command('showkerneldebugbuffercpu')
@header("{0: ^20s} {1: >6s} {2: >12s} {3: ^20s} {4: >6s} {5: ^10s} {6: >5s} {7: >8s} {8: ^25s}".
    format('kd_buf', 'CPU', 'Thread', 'Timestamp', 'S/E', 'Class', 'Sub', 'Code', 'Code Specific Info'))
def ShowKernelDebugBufferCPU(cmd_args=None):
    """ Prints the last N entries in the kernel debug buffer for specified cpu
        Syntax: showkerneldebugbuffercpu <cpu_num> <count>
    """
    if cmd_args == None or len(cmd_args) < 2:
        raise ArgumentError("Invalid arguments passed.")
    
    out_str = ""
    kdbg_str = ""
    cpu_number = ArgumentStringToInt(cmd_args[0])
    entry_count = ArgumentStringToInt(cmd_args[1])
    debugentriesfound = 0
    #  Check if KDBG_BFINIT (0x80000000) is set in kdebug_flags
    if (kern.globals.kd_ctrl_page.kdebug_flags & 0x80000000):   
        out_str += ShowKernelDebugBufferCPU.header + "\n"
        if entry_count == 0:
            out_str += "<count> is 0, dumping 50 entries\n"
            entry_count = 50

        if cpu_number >= kern.globals.kd_ctrl_page.kdebug_cpus:
            kdbg_str += "cpu number too big\n"
        else:
            kdbp = addressof(kern.globals.kdbip[cpu_number])
            kdsp = kdbp.kd_list_head
            while ((kdsp.raw != 0 and kdsp.raw != 0x00000000ffffffff) and (entry_count > 0)):
                kd_buffer = kern.globals.kd_bufs[kdsp.buffer_index]
                kdsp_actual = addressof(kd_buffer.kdsb_addr[kdsp.offset])
                if kdsp_actual.kds_readlast != kdsp_actual.kds_bufindx:
                    kds_buf = kdsp_actual.kds_records[kdsp_actual.kds_bufindx]
                    kds_bufptr = addressof(kds_buf)
                    while (entry_count > 0) and \
                        (unsigned(kds_bufptr) > unsigned(addressof(kdsp_actual.kds_records[kdsp_actual.kds_readlast]))):
                        kds_bufptr = kds_bufptr - sizeof(kds_buf)
                        entry_count = entry_count - 1
                        kdbg_str += GetKernelDebugBufferEntry(kds_bufptr)
                kdsp = kdsp_actual.kds_next
    else:
        kdbg_str += "Trace buffer not enabled for CPU {:d}\n".format(cpu_number)
    
    if kdbg_str:
        out_str += kdbg_str
        print out_str

@lldb_command('showkerneldebugbuffer')
def ShowKernelDebugBuffer(cmd_args=None):
    """ Prints the last N entries in the kernel debug buffer per cpu
        Syntax: showkerneldebugbuffer <count>
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Invalid arguments passed.")
    
    #  Check if KDBG_BFINIT (0x80000000) is set in kdebug_flags
    if (kern.globals.kd_ctrl_page.kdebug_flags & 0x80000000):
        entrycount = ArgumentStringToInt(cmd_args[0])
        if entrycount == 0:
            print "<count> is 0, dumping 50 entries per cpu\n"
            entrycount = 50
        cpu_num = 0
        while cpu_num < kern.globals.kd_ctrl_page.kdebug_cpus:
            ShowKernelDebugBufferCPU([str(cpu_num), str(entrycount)])
            cpu_num += 1
    else:
        print "Trace buffer not enabled\n"
