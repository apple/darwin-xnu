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

