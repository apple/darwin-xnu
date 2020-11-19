from xnu import *
from utils import *
from process import *
from misc import *
from memory import *
from ipc import *

# TODO: write scheduler related macros here

# Macro: showallprocrunqcount

@lldb_command('showallprocrunqcount')
def ShowAllProcRunQCount(cmd_args=None):
    """ Prints out the runq count for all processors
    """
    out_str = "Processor\t# Runnable\n"
    processor_itr = kern.globals.processor_list
    while processor_itr:
        out_str += "{:d}\t\t{:d}\n".format(processor_itr.cpu_id, processor_itr.runq.count)
        processor_itr = processor_itr.processor_list
    # out_str += "RT:\t\t{:d}\n".format(kern.globals.rt_runq.count)
    print out_str

# EndMacro: showallprocrunqcount

# Macro: showinterrupts

@lldb_command('showinterrupts')
def ShowInterrupts(cmd_args=None):
    """ Prints IRQ, IPI and TMR counts for each CPU
    """

    if not kern.arch.startswith('arm'):
        print "showinterrupts is only supported on arm/arm64"
        return

    base_address = kern.GetLoadAddressForSymbol('CpuDataEntries')
    struct_size = 16
    x = 0
    y = 0
    while x < unsigned(kern.globals.machine_info.physical_cpu):
        element = kern.GetValueFromAddress(base_address + (y * struct_size), 'uintptr_t *')[1]
        if element:
            cpu_data_entry = Cast(element, 'cpu_data_t *')
            print "CPU {} IRQ: {:d}\n".format(y, cpu_data_entry.cpu_stat.irq_ex_cnt)
            print "CPU {} IPI: {:d}\n".format(y, cpu_data_entry.cpu_stat.ipi_cnt)
            print "CPU {} PMI: {:d}\n".format(y, cpu_data_entry.cpu_monotonic.mtc_npmis)
            print "CPU {} TMR: {:d}\n".format(y, cpu_data_entry.cpu_stat.timer_cnt)
            x = x + 1
        y = y + 1

# EndMacro: showinterrupts

# Macro: showactiveinterrupts

@lldb_command('showactiveinterrupts')
def ShowActiveInterrupts(cmd_args=None):
    """  Prints the interrupts that are unmasked & active with the Interrupt Controller
         Usage: showactiveinterrupts <address of Interrupt Controller object>
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowActiveInterrupts.__doc__
        return False
    aic = kern.GetValueFromAddress(cmd_args[0], 'AppleInterruptController *')
    if not aic:
        print "unknown arguments:", str(cmd_args)
        return False

    aic_base = unsigned(aic._aicBaseAddress)
    current_interrupt = 0
    aic_imc_base = aic_base + 0x4180
    aic_him_offset = 0x80
    current_pointer = aic_imc_base
    unmasked = dereference(kern.GetValueFromAddress(current_pointer, 'uintptr_t *'))
    active = dereference(kern.GetValueFromAddress(current_pointer + aic_him_offset, 'uintptr_t *'))
    group_count = 0
    mask = 1
    while current_interrupt < 192:
        if (((unmasked & mask) == 0) and (active & mask)):
            print "Interrupt {:d} unmasked and active\n".format(current_interrupt)
        current_interrupt = current_interrupt + 1
        if (current_interrupt % 32 == 0):
            mask = 1
            group_count = group_count + 1
            unmasked = dereference(kern.GetValueFromAddress(current_pointer + (4 * group_count), 'uintptr_t *'))
            active = dereference(kern.GetValueFromAddress((current_pointer + aic_him_offset) + (4 * group_count), 'uintptr_t *'))
        else:
            mask = mask << 1
# EndMacro: showactiveinterrupts

# Macro: showirqbyipitimerratio
@lldb_command('showirqbyipitimerratio')
def ShowIrqByIpiTimerRatio(cmd_args=None):
    """ Prints the ratio of IRQ by sum of IPI & TMR counts for each CPU
    """
    if kern.arch == "x86_64":
        print "This macro is not supported on x86_64 architecture"
        return

    out_str = "IRQ-IT Ratio: "
    base_address = kern.GetLoadAddressForSymbol('CpuDataEntries')
    struct_size = 16
    x = 0
    y = 0
    while x < unsigned(kern.globals.machine_info.physical_cpu):
        element  = kern.GetValueFromAddress(base_address + (y * struct_size), 'uintptr_t *')[1]
        if element:
            cpu_data_entry = Cast(element, 'cpu_data_t *')
            out_str += "   CPU {} [{:.2f}]".format(y, float(cpu_data_entry.cpu_stat.irq_ex_cnt)/(cpu_data_entry.cpu_stat.ipi_cnt + cpu_data_entry.cpu_stat.timer_cnt))
            x = x + 1
        y = y + 1
    print out_str

# EndMacro: showirqbyipitimerratio

#Macro: showinterruptsourceinfo
@lldb_command('showinterruptsourceinfo')
def showinterruptsourceinfo(cmd_args = None):
    """  Extract information of interrupt source causing interrupt storms.
    """
    if not cmd_args:
        print "No arguments passed"
        return False
    #Dump IOInterruptVector object
    print "--- Dumping IOInterruptVector object ---\n"
    object_info = lldb_run_command("dumpobject {:s} IOInterruptVector".format(cmd_args[0]))
    print object_info
    print "--- Dumping IOFilterInterruptEventSource object ---\n"
    #Dump the IOFilterInterruptEventSource object.
    target_info=re.search('target =\s+(.*)',object_info)
    target= target_info.group()
    target= target.split()
    #Dump the Object pointer of the source who is triggering the Interrupts.
    vector_info=lldb_run_command("dumpobject {:s} ".format(target[2]))
    print vector_info
    owner_info= re.search('owner =\s+(.*)',vector_info)
    owner= owner_info.group()
    owner= owner.split()
    print "\n\n"
    out=lldb_run_command(" dumpobject {:s}".format(owner[2]))
    print out

# EndMacro: showinterruptsourceinfo

@lldb_command('showcurrentabstime')
def ShowCurremtAbsTime(cmd_args=None):
    """  Routine to print latest absolute time known to system before being stopped.
         Usage: showcurrentabstime
    """
    pset = addressof(kern.globals.pset0)
    processor_array = kern.globals.processor_array
    cur_abstime = 0

    while unsigned(pset) != 0:
        cpu_bitmap = int(pset.cpu_bitmask)
        for cpuid in IterateBitmap(cpu_bitmap):
            processor = processor_array[cpuid]
            if unsigned(processor.last_dispatch) > cur_abstime:
                cur_abstime = unsigned(processor.last_dispatch)

        pset = pset.pset_list

    print "Last dispatch time known: %d MATUs" % cur_abstime

bucketStr = ["FIXPRI (>UI)", "TIMESHARE_FG", "TIMESHARE_IN", "TIMESHARE_DF", "TIMESHARE_UT", "TIMESHARE_BG"]

@header("{:<18s} | {:>20s} | {:>20s} | {:>10s} | {:>10s}".format('Thread Group', 'Pending (us)', 'Interactivity Score', 'TG Boost', 'Highest Thread Pri'))
def GetSchedClutchBucketSummary(clutch_bucket):
    tg_boost = kern.globals.sched_clutch_bucket_group_pri_boost[clutch_bucket.scb_group.scbg_clutch.sc_tg_priority]
    pending_delta = kern.GetNanotimeFromAbstime(GetRecentTimestamp() - clutch_bucket.scb_group.scbg_pending_data.scct_timestamp) / 1000
    if (int)(clutch_bucket.scb_group.scbg_pending_data.scct_timestamp) == 18446744073709551615:
        pending_delta = 0
    return "0x{:<16x} | {:>20d} | {:>20d} | {:>10d} | {:>10d}".format(clutch_bucket.scb_group.scbg_clutch.sc_tg, pending_delta, clutch_bucket.scb_group.scbg_interactivity_data.scct_count, tg_boost, SchedPriorityStableQueueRootPri(clutch_bucket.scb_thread_runq, 'struct thread', 'th_clutch_runq_link')) 

def ShowSchedClutchForPset(pset):
    root_clutch = pset.pset_clutch_root
    print "\n{:s} : {:d}\n\n".format("Current Timestamp", GetRecentTimestamp())
    print "{:>10s} | {:>20s} | {:>30s} | {:>25s} | {:<18s} | {:>10s} | {:>10s} | {:>15s} | ".format("Root", "Root Buckets", "Clutch Buckets", "Threads", "Address", "Pri (Base)", "Count", "Deadline (us)") + GetSchedClutchBucketSummary.header
    print "=" * 300
    print "{:>10s} | {:>20s} | {:>30s} | {:>25s} | 0x{:<16x} | {:>10d} | {:>10d} | {:>15s} | ".format("Root", "*", "*", "*", addressof(root_clutch), (root_clutch.scr_priority if root_clutch.scr_thr_count > 0 else -1), root_clutch.scr_thr_count, "*")
    print "-" * 300

    for i in range(0, 6):
        root_bucket = root_clutch.scr_unbound_buckets[i]
        root_bucket_deadline = 0
        if root_bucket.scrb_clutch_buckets.scbrq_count != 0 and i != 0:
            root_bucket_deadline = kern.GetNanotimeFromAbstime(root_bucket.scrb_pqlink.deadline - GetRecentTimestamp()) / 1000
        print "{:>10s} | {:>20s} | {:>30s} | {:>25s} | 0x{:<16x} | {:>10s} | {:>10s} | {:>15d} | ".format("*", bucketStr[int(root_bucket.scrb_bucket)], "*", "*", addressof(root_bucket), "*", "*", root_bucket_deadline)
        clutch_bucket_runq = root_bucket.scrb_clutch_buckets
        clutch_bucket_list = []
        for pri in range(0,128):
            clutch_bucket_circleq = clutch_bucket_runq.scbrq_queues[pri]
            for clutch_bucket in IterateCircleQueue(clutch_bucket_circleq, 'struct sched_clutch_bucket', 'scb_runqlink'):
                clutch_bucket_list.append(clutch_bucket)
        if len(clutch_bucket_list) > 0:
            clutch_bucket_list.sort(key=lambda x: x.scb_priority, reverse=True)
            for clutch_bucket in clutch_bucket_list:
                print "{:>10s} | {:>20s} | {:>30s} | {:>25s} | {:<18s} | {:>10s} | {:>10s} | {:>15s} | ".format("", "", "", "", "", "", "", "")
                print "{:>10s} | {:>20s} | {:>30s} | {:>25s} | 0x{:<16x} | {:>10d} | {:>10d} | {:>15s} | ".format("*", "*", clutch_bucket.scb_group.scbg_clutch.sc_tg.tg_name, "*", clutch_bucket, clutch_bucket.scb_priority, clutch_bucket.scb_thr_count, "*") + GetSchedClutchBucketSummary(clutch_bucket)
                runq = clutch_bucket.scb_clutchpri_prioq
                for thread in IterateSchedPriorityQueue(runq, 'struct thread', 'th_clutch_pri_link'):
                    thread_name = GetThreadName(thread)[-24:]
                    if len(thread_name) == 0:
                        thread_name = "<unnamed thread>"
                    print "{:>10s} | {:>20s} | {:>30s} | {:<25s} | 0x{:<16x} | {:>10d} | {:>10s} | {:>15s} | ".format("*", "*", "*", thread_name, thread, thread.base_pri, "*", "*") 
        print "-" * 300
        root_bucket = root_clutch.scr_bound_buckets[i]
        root_bucket_deadline = 0
        if root_bucket.scrb_bound_thread_runq.count != 0:
            root_bucket_deadline = kern.GetNanotimeFromAbstime(root_bucket.scrb_pqlink.deadline - GetRecentTimestamp()) / 1000
        print "{:>10s} | {:>20s} | {:>30s} | {:>25s} | 0x{:<16x} | {:>10s} | {:>10d} | {:>15d} | ".format("*", bucketStr[int(root_bucket.scrb_bucket)] + " [Bound]", "*", "*", addressof(root_bucket), "*", root_bucket.scrb_bound_thread_runq.count, root_bucket_deadline)
        if root_bucket.scrb_bound_thread_runq.count == 0:
            print "-" * 300
            continue
        thread_runq = root_bucket.scrb_bound_thread_runq
        for pri in range(0, 128):
            thread_circleq = thread_runq.queues[pri]
            for thread in IterateCircleQueue(thread_circleq, 'struct thread', 'runq_links'):
                thread_name = GetThreadName(thread)[-24:]
                if len(thread_name) == 0:
                    thread_name = "<unnamed thread>"
                print "{:>10s} | {:>20s} | {:>30s} | {:<25s} | 0x{:<16x} | {:>10d} | {:>10s} | {:>15s} | ".format("*", "*", "*", thread_name, thread, thread.base_pri, "*", "*")
        print "-" * 300

@lldb_command('showschedclutch')
def ShowSchedClutch(cmd_args=[]):
    """ Routine to print the clutch scheduler hierarchy.
        Usage: showschedclutch <pset>
    """
    if not cmd_args:
        raise ArgumentError("Invalid argument")
    pset = kern.GetValueFromAddress(cmd_args[0], "processor_set_t")
    ShowSchedClutchForPset(pset)

@lldb_command('showschedclutchroot')
def ShowSchedClutchRoot(cmd_args=[]):
    """ show information about the root of the sched clutch hierarchy
        Usage: showschedclutchroot <root>
    """
    if not cmd_args:
        raise ArgumentError("Invalid argument")
    root = kern.GetValueFromAddress(cmd_args[0], "struct sched_clutch_root *")
    if not root:
        print "unknown arguments:", str(cmd_args)
        return False
    print "{:>30s} : 0x{:<16x}".format("Root", root)
    print "{:>30s} : 0x{:<16x}".format("Pset", root.scr_pset)
    print "{:>30s} : {:d}".format("Priority", (root.scr_priority if root.scr_thr_count > 0 else -1))
    print "{:>30s} : {:d}".format("Urgency", root.scr_urgency)
    print "{:>30s} : {:d}".format("Threads", root.scr_thr_count)
    print "{:>30s} : {:d}".format("Current Timestamp", GetRecentTimestamp())
    print "{:>30s} : {:b} (BG/UT/DF/IN/FG/FIX/NULL)".format("Runnable Root Buckets Bitmap", int(root.scr_runnable_bitmap[0]))

@lldb_command('showschedclutchrootbucket')
def ShowSchedClutchRootBucket(cmd_args=[]):
    """ show information about a root bucket in the sched clutch hierarchy
        Usage: showschedclutchrootbucket <root_bucket>
    """
    if not cmd_args:
        raise ArgumentError("Invalid argument")
    root_bucket = kern.GetValueFromAddress(cmd_args[0], "struct sched_clutch_root_bucket *")
    if not root_bucket:
        print "unknown arguments:", str(cmd_args)
        return False
    print "{:<30s} : 0x{:<16x}".format("Root Bucket", root_bucket)
    print "{:<30s} : {:s}".format("Bucket Name", bucketStr[int(root_bucket.scrb_bucket)])
    print "{:<30s} : {:d}".format("Deadline", (root_bucket.scrb_pqlink.deadline if root_bucket.scrb_clutch_buckets.scbrq_count != 0 else 0))
    print "{:<30s} : {:d}".format("Current Timestamp", GetRecentTimestamp())
    print "\n"
    clutch_bucket_runq = root_bucket.scrb_clutch_buckets
    clutch_bucket_list = []
    for pri in range(0,128):
        clutch_bucket_circleq = clutch_bucket_runq.scbrq_queues[pri]
        for clutch_bucket in IterateCircleQueue(clutch_bucket_circleq, 'struct sched_clutch_bucket', 'scb_runqlink'):
            clutch_bucket_list.append(clutch_bucket)
    if len(clutch_bucket_list) > 0:
        print "=" * 240
        print "{:>30s} | {:>18s} | {:>20s} | {:>20s} | ".format("Name", "Clutch Bucket", "Priority", "Count") + GetSchedClutchBucketSummary.header
        print "=" * 240
        clutch_bucket_list.sort(key=lambda x: x.scb_priority, reverse=True)
        for clutch_bucket in clutch_bucket_list:
            print "{:>30s} | 0x{:<16x} | {:>20d} | {:>20d} | ".format(clutch_bucket.scb_group.scbg_clutch.sc_tg.tg_name, clutch_bucket, clutch_bucket.scb_priority, clutch_bucket.scb_thr_count) + GetSchedClutchBucketSummary(clutch_bucket)

def SchedClutchBucketDetails(clutch_bucket):
    print "{:<30s} : 0x{:<16x}".format("Clutch Bucket", clutch_bucket)
    print "{:<30s} : {:s}".format("Scheduling Bucket", bucketStr[(int)(clutch_bucket.scb_bucket)])
    print "{:<30s} : 0x{:<16x}".format("Clutch Bucket Group", clutch_bucket.scb_group)
    print "{:<30s} : {:s}".format("TG Name", clutch_bucket.scb_group.scbg_clutch.sc_tg.tg_name)
    print "{:<30s} : {:d}".format("Priority", clutch_bucket.scb_priority)
    print "{:<30s} : {:d}".format("Thread Count", clutch_bucket.scb_thr_count)
    print "{:<30s} : 0x{:<16x}".format("Thread Group", clutch_bucket.scb_group.scbg_clutch.sc_tg)
    print "{:<30s} : {:6d} (inherited from clutch bucket group)".format("Interactivity Score", clutch_bucket.scb_group.scbg_interactivity_data.scct_count)
    print "{:<30s} : {:6d} (inherited from clutch bucket group)".format("Last Timeshare Update Tick", clutch_bucket.scb_group.scbg_timeshare_tick)
    print "{:<30s} : {:6d} (inherited from clutch bucket group)".format("Priority Shift", clutch_bucket.scb_group.scbg_pri_shift) 
    print "\n"
    runq = clutch_bucket.scb_clutchpri_prioq
    thread_list = []
    for thread in IterateSchedPriorityQueue(runq, 'struct thread', 'th_clutch_pri_link'):
        thread_list.append(thread)
    if len(thread_list) > 0:
        print "=" * 240
        print GetThreadSummary.header + "{:s}".format("Process Name")
        print "=" * 240
        for thread in thread_list:
            proc = Cast(thread.task.bsd_info, 'proc *')
            print GetThreadSummary(thread) + "{:s}".format(GetProcName(proc))

@lldb_command('showschedclutchbucket')
def ShowSchedClutchBucket(cmd_args=[]):
    """ show information about a clutch bucket in the sched clutch hierarchy
        Usage: showschedclutchbucket <clutch_bucket>
    """
    if not cmd_args:
        raise ArgumentError("Invalid argument")
    clutch_bucket = kern.GetValueFromAddress(cmd_args[0], "struct sched_clutch_bucket *")
    if not clutch_bucket:
        print "unknown arguments:", str(cmd_args)
        return False
    SchedClutchBucketDetails(clutch_bucket)

@lldb_command('abs2nano')
def ShowAbstimeToNanoTime(cmd_args=[]):
    """ convert mach_absolute_time units to nano seconds
        Usage: (lldb) abs2nano <timestamp in MATUs>
    """
    if not cmd_args:
        raise ArgumentError("Invalid argument")
    timedata = ArgumentStringToInt(cmd_args[0])
    ns = kern.GetNanotimeFromAbstime(timedata)
    us = float(ns) / 1000 
    ms = us / 1000 
    s = ms / 1000 
    
    if s > 60 :
        m = s / 60
        h = m / 60
        d = h / 24
        
        print "{:d} ns, {:f} us, {:f} ms, {:f} s, {:f} m, {:f} h, {:f} d".format(ns, us, ms, s, m, h, d)
    else:
        print "{:d} ns, {:f} us, {:f} ms, {:f} s".format(ns, us, ms, s)

 # Macro: showschedhistory

def GetRecentTimestamp():
    """
    Return a recent timestamp.
    TODO: on x86, if not in the debugger, then look at the scheduler
    """
    if kern.arch == 'x86_64':
        most_recent_dispatch = GetSchedMostRecentDispatch(False)
        if most_recent_dispatch > kern.globals.debugger_entry_time :
            return most_recent_dispatch
        else :
            return kern.globals.debugger_entry_time
    else :
        return GetSchedMostRecentDispatch(False)

def GetSchedMostRecentDispatch(show_processor_details=False):
    """ Return the most recent dispatch on the system, printing processor
        details if argument is true.
    """
    processor_list = kern.globals.processor_list

    most_recent_dispatch = 0
    current_processor = processor_list

    while unsigned(current_processor) > 0:
        active_thread = current_processor.active_thread
        if unsigned(active_thread) != 0 :
            task_val = active_thread.task
            proc_val = Cast(task_val.bsd_info, 'proc *')
            proc_name = "<unknown>" if unsigned(proc_val) == 0 else GetProcName(proc_val)

        last_dispatch = unsigned(current_processor.last_dispatch)

        if kern.arch == 'x86_64':
            cpu_data = kern.globals.cpu_data_ptr[current_processor.cpu_id]
            if (cpu_data != 0) :
                cpu_debugger_time = max(cpu_data.debugger_entry_time, cpu_data.debugger_ipi_time)
            time_since_dispatch = unsigned(cpu_debugger_time - last_dispatch)
            time_since_dispatch_us = kern.GetNanotimeFromAbstime(time_since_dispatch) / 1000.0
            time_since_debugger = unsigned(cpu_debugger_time - kern.globals.debugger_entry_time)
            time_since_debugger_us = kern.GetNanotimeFromAbstime(time_since_debugger) / 1000.0

            if show_processor_details:
                print "Processor last dispatch: {:16d} Entered debugger: {:16d} ({:8.3f} us after dispatch, {:8.3f} us after debugger) Active thread: 0x{t:<16x} 0x{t.thread_id:<8x} {proc_name:s}".format(last_dispatch, cpu_debugger_time,
                        time_since_dispatch_us, time_since_debugger_us, t=active_thread, proc_name=proc_name)
        else:
            if show_processor_details:
                print "Processor last dispatch: {:16d} Active thread: 0x{t:<16x} 0x{t.thread_id:<8x} {proc_name:s}".format(last_dispatch, t=active_thread, proc_name=proc_name)

        if last_dispatch > most_recent_dispatch:
            most_recent_dispatch = last_dispatch

        current_processor = current_processor.processor_list

    return most_recent_dispatch

@header("{:<18s} {:<10s} {:>16s} {:>16s} {:>16s} {:>16s} {:>18s} {:>16s} {:>16s} {:>16s} {:>16s} {:2s} {:2s} {:2s} {:>2s} {:<19s} {:<9s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>11s} {:>8s}".format("thread", "id", "on-core", "off-core", "runnable", "prichange", "last-duration (us)", "since-off (us)", "since-on (us)", "pending (us)", "pri-change (us)", "BP", "SP", "TP", "MP", "sched-mode", "state", "cpu-usage", "delta", "sch-usage", "stamp", "shift", "task", "thread-name"))
def ShowThreadSchedHistory(thread, most_recent_dispatch):
    """ Given a thread and the most recent dispatch time of a thread on the
        system, print out details about scheduler history for the thread.
    """

    thread_name = ""

    if unsigned(thread.uthread) != 0:
        uthread = Cast(thread.uthread, 'uthread *')
        # Doing the straightforward thing blows up weirdly, so use some indirections to get back on track
        if unsigned(uthread.pth_name) != 0 :
            thread_name = str(kern.GetValueFromAddress(unsigned(uthread.pth_name), 'char*'))

    task = thread.task
    task_name = "unknown"
    if task and unsigned(task.bsd_info):
        p = Cast(task.bsd_info, 'proc *')
        task_name = GetProcName(p)

    sched_mode = ""

    mode = str(thread.sched_mode)
    if "TIMESHARE" in mode:
        sched_mode+="timeshare"
    elif "FIXED" in mode:
        sched_mode+="fixed"
    elif "REALTIME" in mode:
        sched_mode+="realtime"

    if (unsigned(thread.bound_processor) != 0):
        sched_mode+="-bound"

    # TH_SFLAG_THROTTLED
    if (unsigned(thread.sched_flags) & 0x0004):
        sched_mode+="-BG"

    state = thread.state

    thread_state_chars = {0x0:'', 0x1:'W', 0x2:'S', 0x4:'R', 0x8:'U', 0x10:'H', 0x20:'A', 0x40:'P', 0x80:'I'}
    state_str = ''
    mask = 0x1
    while mask <= 0x80 :
        state_str += thread_state_chars[int(state & mask)]
        mask = mask << 1

    last_on = thread.computation_epoch
    last_off = thread.last_run_time
    last_runnable = thread.last_made_runnable_time
    last_prichange = thread.last_basepri_change_time

    if int(last_runnable) == 18446744073709551615 :
        last_runnable = 0

    if int(last_prichange) == 18446744073709551615 :
        last_prichange = 0

    time_on_abs = unsigned(last_off - last_on)
    time_on_us = kern.GetNanotimeFromAbstime(time_on_abs) / 1000.0

    time_pending_abs = unsigned(most_recent_dispatch - last_runnable)
    time_pending_us = kern.GetNanotimeFromAbstime(time_pending_abs) / 1000.0

    if int(last_runnable) == 0 :
        time_pending_us = 0

    last_prichange_abs = unsigned(most_recent_dispatch - last_prichange)
    last_prichange_us = kern.GetNanotimeFromAbstime(last_prichange_abs) / 1000.0

    if int(last_prichange) == 0 :
        last_prichange_us = 0

    time_since_off_abs = unsigned(most_recent_dispatch - last_off)
    time_since_off_us = kern.GetNanotimeFromAbstime(time_since_off_abs) / 1000.0
    time_since_on_abs = unsigned(most_recent_dispatch - last_on)
    time_since_on_us = kern.GetNanotimeFromAbstime(time_since_on_abs) / 1000.0

    fmt  = "0x{t:<16x} 0x{t.thread_id:<8x} {t.computation_epoch:16d} {t.last_run_time:16d} {last_runnable:16d} {last_prichange:16d} {time_on_us:18.3f} {time_since_off_us:16.3f} {time_since_on_us:16.3f} {time_pending_us:16.3f} {last_prichange_us:16.3f}"
    fmt2 = " {t.base_pri:2d} {t.sched_pri:2d} {t.task_priority:2d} {t.max_priority:2d} {sched_mode:19s}"
    fmt3 = " {state:9s} {t.cpu_usage:10d} {t.cpu_delta:10d} {t.sched_usage:10d} {t.sched_stamp:10d} {t.pri_shift:10d} {name:s} {thread_name:s}"

    out_str = fmt.format(t=thread, time_on_us=time_on_us, time_since_off_us=time_since_off_us, time_since_on_us=time_since_on_us, last_runnable=last_runnable, time_pending_us=time_pending_us, last_prichange=last_prichange, last_prichange_us=last_prichange_us)
    out_str += fmt2.format(t=thread, sched_mode=sched_mode)
    out_str += fmt3.format(t=thread, state=state_str, name=task_name, thread_name=thread_name)

    print out_str

def SortThreads(threads, column):
        if column != 'on-core' and column != 'off-core' and column != 'last-duration':
            raise ArgumentError("unsupported sort column")
        if column == 'on-core':
            threads.sort(key=lambda t: t.computation_epoch)
        elif column == 'off-core':
            threads.sort(key=lambda t: t.last_run_time)
        else:
            threads.sort(key=lambda t: t.last_run_time - t.computation_epoch)

@lldb_command('showschedhistory', 'S:')
def ShowSchedHistory(cmd_args=None, cmd_options=None):
    """ Routine to print out thread scheduling history, optionally sorted by a
        column.

        Usage: showschedhistory [-S on-core|off-core|last-duration] [<thread-ptr> ...]
    """

    sort_column = None
    if '-S' in cmd_options:
        sort_column = cmd_options['-S']

    if cmd_args:
        most_recent_dispatch = GetSchedMostRecentDispatch(False)

        print ShowThreadSchedHistory.header

        if sort_column:
            threads = []
            for thread_ptr in cmd_args:
                threads.append(kern.GetValueFromAddress(ArgumentStringToInt(thread_ptr), 'thread *'))

            SortThreads(threads, sort_column)

            for thread in threads:
                ShowThreadSchedHistory(thread, most_recent_dispatch)
        else:
            for thread_ptr in cmd_args:
                thread = kern.GetValueFromAddress(ArgumentStringToInt(thread_ptr), 'thread *')
                ShowThreadSchedHistory(thread, most_recent_dispatch)

        return

    run_buckets = kern.globals.sched_run_buckets

    run_count      = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_RUN')]
    fixpri_count   = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_FIXPRI')]
    share_fg_count = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_FG')]
    share_df_count = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_DF')]
    share_ut_count = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_UT')]
    share_bg_count = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_BG')]

    sched_pri_shifts = kern.globals.sched_run_buckets

    share_fg_shift = sched_pri_shifts[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_FG')]
    share_df_shift = sched_pri_shifts[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_DF')]
    share_ut_shift = sched_pri_shifts[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_UT')]
    share_bg_shift = sched_pri_shifts[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_BG')]


    print "Processors: {g.processor_avail_count:d} Runnable threads: {:d} Fixpri threads: {:d}\n".format(run_count, fixpri_count, g=kern.globals)
    print "FG Timeshare threads: {:d} DF Timeshare threads: {:d} UT Timeshare threads: {:d} BG Timeshare threads: {:d}\n".format(share_fg_count, share_df_count, share_ut_count, share_bg_count)
    print "Mach factor: {g.sched_mach_factor:d} Load factor: {g.sched_load_average:d} Sched tick: {g.sched_tick:d} timestamp: {g.sched_tick_last_abstime:d} interval:{g.sched_tick_interval:d}\n".format(g=kern.globals)
    print "Fixed shift: {g.sched_fixed_shift:d} FG shift: {:d} DF shift: {:d} UT shift: {:d} BG shift: {:d}\n".format(share_fg_shift, share_df_shift, share_ut_shift, share_bg_shift, g=kern.globals)
    print "sched_pri_decay_band_limit: {g.sched_pri_decay_band_limit:d} sched_decay_usage_age_factor: {g.sched_decay_usage_age_factor:d}\n".format(g=kern.globals)

    if kern.arch == 'x86_64':
        print "debugger_entry_time: {g.debugger_entry_time:d}\n".format(g=kern.globals)

    most_recent_dispatch = GetSchedMostRecentDispatch(True)
    print "Most recent dispatch: " + str(most_recent_dispatch)

    print ShowThreadSchedHistory.header

    if sort_column:
        threads = [t for t in IterateQueue(kern.globals.threads, 'thread *', 'threads')]

        SortThreads(threads, sort_column)

        for thread in threads:
            ShowThreadSchedHistory(thread, most_recent_dispatch)
    else:
        for thread in IterateQueue(kern.globals.threads, 'thread *', 'threads'):
            ShowThreadSchedHistory(thread, most_recent_dispatch)


# EndMacro: showschedhistory

def int32(n):
    n = n & 0xffffffff
    return (n ^ 0x80000000) - 0x80000000

# Macro: showallprocessors

def ShowGroupSetSummary(runq, task_map):
    """ Internal function to print summary of group run queue
        params: runq - value representing struct run_queue *
    """

    print "    runq: count {: <10d} highq: {: <10d} urgency {: <10d}\n".format(runq.count, int32(runq.highq), runq.urgency)

    runq_queue_i = 0
    runq_queue_count = sizeof(runq.queues)/sizeof(runq.queues[0])

    for runq_queue_i in xrange(runq_queue_count) :
        runq_queue_head = addressof(runq.queues[runq_queue_i])
        runq_queue_p = runq_queue_head.next

        if unsigned(runq_queue_p) != unsigned(runq_queue_head):
            runq_queue_this_count = 0

            for entry in ParanoidIterateLinkageChain(runq_queue_head, "sched_entry_t", "entry_links", circleQueue=True):
                runq_queue_this_count += 1

            print "      Queue [{: <#012x}] Priority {: <3d} count {:d}\n".format(runq_queue_head, runq_queue_i, runq_queue_this_count)
            for entry in ParanoidIterateLinkageChain(runq_queue_head, "sched_entry_t", "entry_links", circleQueue=True):
                group_addr = unsigned(entry) - (sizeof(dereference(entry)) * unsigned(entry.sched_pri))
                group = kern.GetValueFromAddress(unsigned(group_addr), 'sched_group_t')
                task = task_map.get(unsigned(group), 0x0)
                if task == 0x0 :
                    print "Cannot find task for group: {: <#012x}".format(group)
                print "\tEntry [{: <#012x}] Priority {: <3d} Group {: <#012x} Task {: <#012x}\n".format(unsigned(entry), entry.sched_pri, unsigned(group), unsigned(task))

@lldb_command('showrunq')
def ShowRunq(cmd_args=None):
    """  Routine to print information of a runq
         Usage: showrunq <runq>
    """

    if not cmd_args:
        print "No arguments passed"
        print ShowRunq.__doc__
        return False

    runq = kern.GetValueFromAddress(cmd_args[0], 'struct run_queue *')
    ShowRunQSummary(runq)

def ShowRunQSummary(runq):
    """ Internal function to print summary of run_queue
        params: runq - value representing struct run_queue *
    """

    print "    runq: count {: <10d} highq: {: <10d} urgency {: <10d}\n".format(runq.count, int32(runq.highq), runq.urgency)

    runq_queue_i = 0
    runq_queue_count = sizeof(runq.queues)/sizeof(runq.queues[0])

    for runq_queue_i in xrange(runq_queue_count) :
        runq_queue_head = addressof(runq.queues[runq_queue_i])
        runq_queue_p = runq_queue_head.head

        if unsigned(runq_queue_p):
            runq_queue_this_count = 0

            for thread in ParanoidIterateLinkageChain(runq_queue_head, "thread_t", "runq_links", circleQueue=True):
                runq_queue_this_count += 1

            print "      Queue [{: <#012x}] Priority {: <3d} count {:d}\n".format(runq_queue_head, runq_queue_i, runq_queue_this_count)
            print "\t" + GetThreadSummary.header + "\n"
            for thread in ParanoidIterateLinkageChain(runq_queue_head, "thread_t", "runq_links", circleQueue=True):
                print "\t" + GetThreadSummary(thread) + "\n"
                if config['verbosity'] > vHUMAN :
                    print "\t" + GetThreadBackTrace(thread, prefix="\t\t") + "\n"

def ShowRTRunQSummary(rt_runq):
    if (hex(rt_runq.count) == hex(0xfdfdfdfd)) :
        print "    Realtime Queue ({:<#012x}) uninitialized\n".format(addressof(rt_runq.queue))
        return
    print "    Realtime Queue ({:<#012x}) Count {:d}\n".format(addressof(rt_runq.queue), rt_runq.count)
    if rt_runq.count != 0:
        print "\t" + GetThreadSummary.header + "\n"
        for rt_runq_thread in ParanoidIterateLinkageChain(rt_runq.queue, "thread_t", "runq_links", circleQueue=True):
            print "\t" + GetThreadSummary(rt_runq_thread) + "\n"

def ShowGrrrSummary(grrr_runq):
    """ Internal function to print summary of grrr_run_queue
        params: grrr_runq - value representing struct grrr_run_queue *
    """
    print "    GRRR Info: Count {: <10d} Weight {: <10d} Current Group {: <#012x}\n".format(grrr_runq.count,
        grrr_runq.weight, grrr_runq.current_group)
    grrr_group_i = 0
    grrr_group_count = sizeof(grrr_runq.groups)/sizeof(grrr_runq.groups[0])
    for grrr_group_i in xrange(grrr_group_count) :
        grrr_group = addressof(grrr_runq.groups[grrr_group_i])
        if grrr_group.count > 0:
            print "      Group {: <3d} [{: <#012x}] ".format(grrr_group.index, grrr_group)
            print "Count {:d} Weight {:d}\n".format(grrr_group.count, grrr_group.weight)
            grrr_group_client_head = addressof(grrr_group.clients)
            print GetThreadSummary.header
            for thread in ParanoidIterateLinkageChain(grrr_group_client_head, "thread_t", "runq_links", circleQueue=True):
                print "\t" + GetThreadSummary(thread) + "\n"
                if config['verbosity'] > vHUMAN :
                    print "\t" + GetThreadBackTrace(thread, prefix="\t\t") + "\n"

def ShowActiveThread(processor):
    if (processor.active_thread != 0) :
        print "\t" + GetThreadSummary.header + "\n"
        print "\t" + GetThreadSummary(processor.active_thread) + "\n"

@lldb_command('showallprocessors')
@lldb_command('showscheduler')
def ShowScheduler(cmd_args=None):
    """  Routine to print information of all psets and processors
         Usage: showscheduler
    """
    node = addressof(kern.globals.pset_node0)
    show_grrr = 0
    show_priority_runq = 0
    show_priority_pset_runq = 0
    show_group_pset_runq = 0
    show_clutch = 0
    show_edge = 0
    sched_string = str(kern.globals.sched_string)

    if sched_string == "traditional":
        show_priority_runq = 1
    elif sched_string == "traditional_with_pset_runqueue":
        show_priority_pset_runq = 1
    elif sched_string == "grrr":
        show_grrr = 1
    elif sched_string == "multiq":
        show_priority_runq = 1
        show_group_pset_runq = 1
    elif sched_string == "dualq":
        show_priority_pset_runq = 1
        show_priority_runq = 1
    elif sched_string == "amp":
        show_priority_pset_runq = 1
        show_priority_runq = 1
    elif sched_string == "clutch":
        show_clutch = 1
    elif sched_string == "edge":
        show_edge = 1
    else :
        print "Unknown sched_string {:s}".format(sched_string)

    print "Scheduler: {:s}\n".format(sched_string)

    if show_clutch == 0 and show_edge == 0:
        run_buckets = kern.globals.sched_run_buckets
        run_count      = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_RUN')]
        fixpri_count   = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_FIXPRI')]
        share_fg_count = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_FG')]
        share_df_count = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_DF')]
        share_ut_count = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_UT')]
        share_bg_count = run_buckets[GetEnumValue('sched_bucket_t::TH_BUCKET_SHARE_BG')]
        print "Processors: {g.processor_avail_count:d} Runnable threads: {:d} Fixpri threads: {:d}\n".format(run_count, fixpri_count, g=kern.globals)
        print "FG Timeshare threads: {:d} DF Timeshare threads: {:d} UT Timeshare threads: {:d} BG Timeshare threads: {:d}\n".format(share_fg_count, share_df_count, share_ut_count, share_bg_count)
    
    processor_offline     = GetEnumValue('processor_state_t::PROCESSOR_OFF_LINE')
    processor_idle        = GetEnumValue('processor_state_t::PROCESSOR_IDLE')
    processor_dispatching = GetEnumValue('processor_state_t::PROCESSOR_DISPATCHING')
    processor_running     = GetEnumValue('processor_state_t::PROCESSOR_RUNNING')

    if show_group_pset_runq:
        if hasattr(kern.globals, "multiq_sanity_check"):
            print "multiq scheduler config: deep-drain {g.deep_drain:d}, ceiling {g.drain_ceiling:d}, depth limit {g.drain_depth_limit:d}, band limit {g.drain_band_limit:d}, sanity check {g.multiq_sanity_check:d}\n".format(g=kern.globals)
        else:
            print "multiq scheduler config: deep-drain {g.deep_drain:d}, ceiling {g.drain_ceiling:d}, depth limit {g.drain_depth_limit:d}, band limit {g.drain_band_limit:d}\n".format(g=kern.globals)

        # Create a group->task mapping
        task_map = {}
        for task in kern.tasks:
            task_map[unsigned(task.sched_group)] = task
        for task in kern.terminated_tasks:
            task_map[unsigned(task.sched_group)] = task

    print " \n"

    while node != 0:
        pset = node.psets
        pset = kern.GetValueFromAddress(unsigned(pset), 'struct processor_set *')

        while pset != 0:
            print "Processor Set  {: <#012x} Count {:d} (cpu_id {:<#x}-{:<#x})\n".format(pset,
                unsigned(pset.cpu_set_count), pset.cpu_set_low, pset.cpu_set_hi)

            rt_runq = kern.GetValueFromAddress(unsigned(addressof(pset.rt_runq)), 'struct rt_queue *')
            ShowRTRunQSummary(rt_runq)

            if show_priority_pset_runq:
                runq = kern.GetValueFromAddress(unsigned(addressof(pset.pset_runq)), 'struct run_queue *')
                ShowRunQSummary(runq)

            if show_group_pset_runq:
                print "Main Runq:\n"
                runq = kern.GetValueFromAddress(unsigned(addressof(pset.pset_runq)), 'struct run_queue *')
                ShowGroupSetSummary(runq, task_map)
                print "All Groups:\n"
                # TODO: Possibly output task header for each group
                for group in IterateQueue(kern.globals.sched_groups, "sched_group_t", "sched_groups"):
                    if (group.runq.count != 0) :
                        task = task_map.get(unsigned(group), "Unknown task!")
                        print "Group {: <#012x} Task {: <#012x}\n".format(unsigned(group), unsigned(task))
                        ShowRunQSummary(group.runq)
            print " \n"
            
            processor_array = kern.globals.processor_array

            print "Active Processors:\n"
            active_bitmap = int(pset.cpu_state_map[processor_dispatching]) | int(pset.cpu_state_map[processor_running])
            for cpuid in IterateBitmap(active_bitmap):
                processor = processor_array[cpuid]
                if processor != 0:
                    print "    " + GetProcessorSummary(processor)
                    ShowActiveThread(processor)

                    if show_priority_runq:
                        runq = processor.runq
                        ShowRunQSummary(runq)
                    if show_grrr:
                        grrr_runq = processor.grrr_runq
                        ShowGrrrSummary(grrr_runq)
            print " \n"


            print "Idle Processors:\n"
            idle_bitmap = int(pset.cpu_state_map[processor_idle]) & int(pset.primary_map)
            for cpuid in IterateBitmap(idle_bitmap):
                processor = processor_array[cpuid]
                if processor != 0:
                    print "    " + GetProcessorSummary(processor)
                    ShowActiveThread(processor)

                    if show_priority_runq:
                        ShowRunQSummary(processor.runq)
            print " \n"


            print "Idle Secondary Processors:\n"
            idle_bitmap = int(pset.cpu_state_map[processor_idle]) & ~(int(pset.primary_map))
            for cpuid in IterateBitmap(idle_bitmap):
                processor = processor_array[cpuid]
                if processor != 0:
                    print "    " + GetProcessorSummary(processor)
                    ShowActiveThread(processor)

                    if show_priority_runq:
                        print ShowRunQSummary(processor.runq)
            print " \n"


            print "Other Processors:\n"
            other_bitmap = 0
            for i in range(processor_offline, processor_idle):
                other_bitmap |= int(pset.cpu_state_map[i])
            other_bitmap &= int(pset.cpu_bitmask)
            for cpuid in IterateBitmap(other_bitmap):
                processor = processor_array[cpuid]
                if processor != 0:
                    print "    " + GetProcessorSummary(processor)
                    ShowActiveThread(processor)

                    if show_priority_runq:
                        ShowRunQSummary(processor.runq)
            print " \n"

            if show_clutch or show_edge:
                cluster_type = "SMP"
                if pset.pset_type == 1:
                    cluster_type = "E"
                elif pset.pset_type == 2:
                    cluster_type = "P"
                print "=== Clutch Scheduler Hierarchy Pset{:d} (Type: {:s}) ] ===\n\n".format(pset.pset_cluster_id, cluster_type)
                ShowSchedClutchForPset(pset)

            pset = pset.pset_list

        node = node.node_list

    print "\nCrashed Threads Queue: ({:<#012x})\n".format(addressof(kern.globals.crashed_threads_queue))
    first = True
    for thread in ParanoidIterateLinkageChain(kern.globals.crashed_threads_queue, "thread_t", "runq_links"):
        if first:
            print "\t" + GetThreadSummary.header
            first = False
        print "\t" + GetThreadSummary(thread)

    def dump_mpsc_thread_queue(name, head):
        head = addressof(head)
        print "\n{:s}: ({:<#012x})\n".format(name, head)
        first = True
        for thread in IterateMPSCQueue(head.mpd_queue, 'struct thread', 'mpsc_links'):
            if first:
                print "\t" + GetThreadSummary.header
                first = False
            print "\t" + GetThreadSummary(thread)

    dump_mpsc_thread_queue("Terminate Queue", kern.globals.thread_terminate_queue)
    dump_mpsc_thread_queue("Waiting For Kernel Stacks Queue", kern.globals.thread_stack_queue)
    dump_mpsc_thread_queue("Thread Exception Queue", kern.globals.thread_exception_queue)
    dump_mpsc_thread_queue("Thread Deallocate Queue", kern.globals.thread_deallocate_queue)

    print "\n"

    print "\n"

# EndMacro: showallprocessors


def ParanoidIterateLinkageChain(queue_head, element_type, field_name, field_ofst=0, circleQueue=False):
    """ Iterate over a Linkage Chain queue in kernel of type queue_head_t or circle_queue_head_t. (osfmk/kern/queue.h method 1 or circle_queue.h)
        This is equivalent to the qe_foreach_element() macro
        Blows up aggressively and descriptively when something goes wrong iterating a queue.
        Prints correctness errors, and throws exceptions on 'cannot proceed' errors
        If this is annoying, set the global 'enable_paranoia' to false.

        params:
            queue_head   - value       : Value object for queue_head.
            element_type - lldb.SBType : pointer type of the element which contains the queue_chain_t. Typically its structs like thread, task etc..
                         - str         : OR a string describing the type. ex. 'task *'
            field_name   - str         : Name of the field (in element) which holds a queue_chain_t
            field_ofst   - int         : offset from the 'field_name' (in element) which holds a queue_chain_t
                                         This is mostly useful if a particular element contains an array of queue_chain_t
        returns:
            A generator does not return. It is used for iterating.
            value  : An object thats of type (element_type). Always a pointer object
        example usage:
            for thread in IterateQueue(kern.globals.threads, 'thread *', 'threads'):
                print thread.thread_id
    """

    if type(element_type) is str:
        element_type = gettype(element_type)

    # Some ways of constructing a queue head seem to end up with the
    # struct object as the value and not a pointer to the struct head
    # In that case, addressof will give us a pointer to the struct, which is what we need
    if not queue_head.GetSBValue().GetType().IsPointerType() :
        queue_head = addressof(queue_head)

    if circleQueue:
        # Mosh the value into a brand new value, to really get rid of its old cvalue history
        queue_head = kern.GetValueFromAddress(unsigned(queue_head), 'struct circle_queue_head *').head
    else:
        # Mosh the value into a brand new value, to really get rid of its old cvalue history
        queue_head = kern.GetValueFromAddress(unsigned(queue_head), 'struct queue_entry *')

    if unsigned(queue_head) == 0:
        if not circleQueue and ParanoidIterateLinkageChain.enable_paranoia:
            print "bad queue_head_t: {:s}".format(queue_head)
        return

    if element_type.IsPointerType():
        struct_type = element_type.GetPointeeType()
    else:
        struct_type = element_type

    elem_ofst = getfieldoffset(struct_type, field_name) + field_ofst

    try:
        link = queue_head.next
        last_link = queue_head
        try_read_next = unsigned(queue_head.next)
    except:
        print "Exception while looking at queue_head: {:>#18x}".format(unsigned(queue_head))
        raise

    if ParanoidIterateLinkageChain.enable_paranoia:
        if unsigned(queue_head.next) == 0:
            raise ValueError("NULL next pointer on head: queue_head {:>#18x} next: {:>#18x} prev: {:>#18x}".format(queue_head, queue_head.next, queue_head.prev))
        if unsigned(queue_head.prev) == 0:
            print "NULL prev pointer on head: queue_head {:>#18x} next: {:>#18x} prev: {:>#18x}".format(queue_head, queue_head.next, queue_head.prev)
        if unsigned(queue_head.next) == unsigned(queue_head) and unsigned(queue_head.prev) != unsigned(queue_head):
            print "corrupt queue_head {:>#18x} next: {:>#18x} prev: {:>#18x}".format(queue_head, queue_head.next, queue_head.prev)

    if ParanoidIterateLinkageChain.enable_debug :
        print "starting at queue_head {:>#18x} next: {:>#18x} prev: {:>#18x}".format(queue_head, queue_head.next, queue_head.prev)

    addr = 0
    obj = 0

    try:
        while True:
            if not circleQueue and unsigned(queue_head) == unsigned(link):
                break;
            if ParanoidIterateLinkageChain.enable_paranoia:
                if unsigned(link.next) == 0:
                    raise ValueError("NULL next pointer: queue_head {:>#18x} link: {:>#18x} next: {:>#18x} prev: {:>#18x}".format(queue_head, link, link.next, link.prev))
                if unsigned(link.prev) == 0:
                    print "NULL prev pointer: queue_head {:>#18x} link: {:>#18x} next: {:>#18x} prev: {:>#18x}".format(queue_head, link, link.next, link.prev)
                if unsigned(last_link) != unsigned(link.prev):
                    print "Corrupt prev pointer: queue_head {:>#18x} link: {:>#18x} next: {:>#18x} prev: {:>#18x} prev link: {:>#18x} ".format(
                            queue_head, link, link.next, link.prev, last_link)

            addr = unsigned(link) - unsigned(elem_ofst);
            obj = kern.GetValueFromAddress(addr, element_type)
            if ParanoidIterateLinkageChain.enable_debug :
                print "yielding link: {:>#18x} next: {:>#18x} prev: {:>#18x} addr: {:>#18x} obj: {:>#18x}".format(link, link.next, link.prev, addr, obj)
            yield obj
            last_link = link
            link = link.next
            if circleQueue and unsigned(queue_head) == unsigned(link):
                break;
    except:
        exc_info = sys.exc_info()
        try:
            print "Exception while iterating queue: {:>#18x} link: {:>#18x} addr: {:>#18x} obj: {:>#18x} last link: {:>#18x}".format(queue_head, link, addr, obj, last_link)
        except:
            import traceback
            traceback.print_exc()
        raise exc_info[0], exc_info[1], exc_info[2]

ParanoidIterateLinkageChain.enable_paranoia = True
ParanoidIterateLinkageChain.enable_debug = False

def LinkageChainEmpty(queue_head):
    if not queue_head.GetSBValue().GetType().IsPointerType() :
        queue_head = addressof(queue_head)

    # Mosh the value into a brand new value, to really get rid of its old cvalue history
    # avoid using GetValueFromAddress
    queue_head = value(queue_head.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(unsigned(queue_head))))
    queue_head = cast(queue_head, 'struct queue_entry *')

    link = queue_head.next

    return unsigned(queue_head) == unsigned(link)

def bit_first(bitmap):
    return bitmap.bit_length() - 1

def lsb_first(bitmap):
    bitmap = bitmap & -bitmap
    return bit_first(bitmap)

def IterateBitmap(bitmap):
    """ Iterate over a bitmap, returning the index of set bits starting from 0

        params:
            bitmap       - value       : bitmap
        returns:
            A generator does not return. It is used for iterating.
            value  : index of a set bit
        example usage:
            for cpuid in IterateBitmap(running_bitmap):
                print processor_array[cpuid]
    """
    i = lsb_first(bitmap)
    while (i >= 0):
        yield i
        bitmap = bitmap & ~((1 << (i + 1)) - 1)
        i = lsb_first(bitmap)


# Macro: showallcallouts

from kevent import GetKnoteKqueue

def ShowThreadCall(prefix, call, recent_timestamp, is_pending=False):
    """
    Print a description of a thread_call_t and its relationship to its expected fire time
    """
    func = call.tc_func
    param0 = call.tc_param0
    param1 = call.tc_param1

    is_iotes = False

    func_name = kern.Symbolicate(func)

    extra_string = ""

    strip_func = kern.StripKernelPAC(unsigned(func))

    func_syms = kern.SymbolicateFromAddress(strip_func)
    # returns an array of SBSymbol

    if func_syms and func_syms[0] :
        func_name = func_syms[0].GetName()

        try :
            if ("IOTimerEventSource::timeoutAndRelease" in func_name or
                "IOTimerEventSource::timeoutSignaled" in func_name) :
                iotes = Cast(call.tc_param0, 'IOTimerEventSource*')
                try:
                    func = iotes.action
                    param0 = iotes.owner
                    param1 = unsigned(iotes)
                except AttributeError:
                    # This is horrible, horrible, horrible.  But it works.  Needed because IOEventSource hides the action member in an
                    # anonymous union when XNU_PRIVATE_SOURCE is set.  To grab it, we work backwards from the enabled member.
                    func = dereference(kern.GetValueFromAddress(addressof(iotes.enabled) - sizeof('IOEventSource::Action'), 'uint64_t *'))
                    param0 = iotes.owner
                    param1 = unsigned(iotes)

                workloop = iotes.workLoop
                thread = workloop.workThread

                is_iotes = True

                # re-symbolicate the func we found inside the IOTES
                strip_func = kern.StripKernelPAC(unsigned(func))
                func_syms = kern.SymbolicateFromAddress(strip_func)
                if func_syms and func_syms[0] :
                    func_name = func_syms[0].GetName()
                else :
                    func_name = str(FindKmodNameForAddr(func))

                # cast from IOThread to thread_t, because IOThread is sometimes opaque
                thread = Cast(thread, 'thread_t')
                thread_id = thread.thread_id
                thread_name = GetThreadName(thread)

                extra_string += "workloop thread: {:#x} ({:#x}) {:s}".format(thread, thread_id, thread_name)

            if "filt_timerexpire" in func_name :
                knote = Cast(call.tc_param0, 'struct knote *')
                kqueue = GetKnoteKqueue(knote)
                proc = kqueue.kq_p
                proc_name = GetProcName(proc)
                proc_pid = proc.p_pid

                extra_string += "kq: {:#018x} {:s}[{:d}]".format(kqueue, proc_name, proc_pid)

            if "mk_timer_expire" in func_name :
                timer = Cast(call.tc_param0, 'struct mk_timer *')
                port = timer.port

                extra_string += "port: {:#018x} {:s}".format(port, GetPortDestinationSummary(port))

            if "workq_kill_old_threads_call" in func_name :
                workq = Cast(call.tc_param0, 'struct workqueue *')
                proc = workq.wq_proc
                proc_name = GetProcName(proc)
                proc_pid = proc.p_pid

                extra_string += "{:s}[{:d}]".format(proc_name, proc_pid)

            if ("workq_add_new_threads_call" in func_name or
                "realitexpire" in func_name):
                proc = Cast(call.tc_param0, 'struct proc *')
                proc_name = GetProcName(proc)
                proc_pid = proc.p_pid

                extra_string += "{:s}[{:d}]".format(proc_name, proc_pid)

        except:
            print "exception generating extra_string for call: {:#018x}".format(call)
            if ShowThreadCall.enable_debug :
                raise

    if (func_name == "") :
        func_name = FindKmodNameForAddr(func)

    if (call.tc_flags & GetEnumValue('thread_call_flags_t::THREAD_CALL_FLAG_CONTINUOUS')) :
        timer_fire = call.tc_pqlink.deadline - (recent_timestamp + kern.globals.mach_absolutetime_asleep)
    else :
        timer_fire = call.tc_pqlink.deadline - recent_timestamp

    timer_fire_s = kern.GetNanotimeFromAbstime(timer_fire) / 1000000000.0

    ttd_s = kern.GetNanotimeFromAbstime(call.tc_ttd) / 1000000000.0

    if (is_pending) :
        pending_time = call.tc_pending_timestamp - recent_timestamp
        pending_time = kern.GetNanotimeFromAbstime(pending_time) / 1000000000.0

    flags = int(call.tc_flags)
    # TODO: extract this out of the thread_call_flags_t enum
    thread_call_flags = {0x0:'', 0x1:'A', 0x2:'W', 0x4:'D', 0x8:'R', 0x10:'S', 0x20:'O',
            0x40:'P', 0x80:'L', 0x100:'C'}

    flags_str = ''
    mask = 0x1
    while mask <= 0x100 :
        flags_str += thread_call_flags[int(flags & mask)]
        mask = mask << 1

    if is_iotes :
        flags_str += 'I'

    if (is_pending) :
        print ("{:s}{:#018x}: {:18d} {:18d} {:16.06f} {:16.06f} {:16.06f} {:9s} " +
                "{:#018x} ({:#018x}, {:#018x}) ({:s}) {:s}").format(prefix,
                unsigned(call), call.tc_pqlink.deadline, call.tc_soft_deadline, ttd_s,
                timer_fire_s, pending_time, flags_str,
                func, param0, param1, func_name, extra_string)
    else :
        print ("{:s}{:#018x}: {:18d} {:18d} {:16.06f} {:16.06f} {:9s} " +
                "{:#018x} ({:#018x}, {:#018x}) ({:s}) {:s}").format(prefix,
                unsigned(call), call.tc_pqlink.deadline, call.tc_soft_deadline, ttd_s,
                timer_fire_s, flags_str,
                func, param0, param1, func_name, extra_string)

ShowThreadCall.enable_debug = False

@header("{:>18s}  {:>18s} {:>18s} {:>16s} {:>16s} {:9s} {:>18s}".format(
            "entry", "deadline", "soft_deadline",
            "duration (s)", "to go (s)", "flags", "(*func) (param0, param1)"))
def PrintThreadGroup(group):
    header = PrintThreadGroup.header
    pending_header = "{:>18s}  {:>18s} {:>18s} {:>16s} {:>16s} {:>16s} {:9s} {:>18s}".format(
            "entry", "deadline", "soft_deadline",
            "duration (s)", "to go (s)", "pending", "flags", "(*func) (param0, param1)")

    recent_timestamp = GetRecentTimestamp()

    idle_timestamp_distance = group.idle_timestamp - recent_timestamp
    idle_timestamp_distance_s = kern.GetNanotimeFromAbstime(idle_timestamp_distance) / 1000000000.0

    is_parallel = ""

    if (group.tcg_flags & GetEnumValue('thread_call_group_flags_t::TCG_PARALLEL')) :
        is_parallel = " (parallel)"

    print "Group: {g.tcg_name:s} ({:#18x}){:s}".format(unsigned(group), is_parallel, g=group)
    print "\t" +"Thread Priority: {g.tcg_thread_pri:d}\n".format(g=group)
    print ("\t" +"Active: {g.active_count:<3d} Idle: {g.idle_count:<3d}" +
        "Blocked: {g.blocked_count:<3d} Pending: {g.pending_count:<3d}" +
        "Target: {g.target_thread_count:<3d}\n").format(g=group)

    if unsigned(group.idle_timestamp) is not 0 :
        print "\t" +"Idle Timestamp: {g.idle_timestamp:d} ({:03.06f})\n".format(idle_timestamp_distance_s,
            g=group)

    print "\t" +"Pending Queue: ({:>#18x})\n".format(addressof(group.pending_queue))
    if not LinkageChainEmpty(group.pending_queue) :
        print "\t\t" + pending_header
    for call in ParanoidIterateLinkageChain(group.pending_queue, "thread_call_t", "tc_qlink"):
        ShowThreadCall("\t\t", call, recent_timestamp, is_pending=True)

    print "\t" +"Delayed Queue (Absolute Time): ({:>#18x}) timer: ({:>#18x})\n".format(
            addressof(group.delayed_queues[0]), addressof(group.delayed_timers[0]))
    if not LinkageChainEmpty(group.delayed_queues[0]) :
        print "\t\t" + header
    for call in ParanoidIterateLinkageChain(group.delayed_queues[0], "thread_call_t", "tc_qlink"):
        ShowThreadCall("\t\t", call, recent_timestamp)

    print "\t" +"Delayed Queue (Continuous Time): ({:>#18x}) timer: ({:>#18x})\n".format(
            addressof(group.delayed_queues[1]), addressof(group.delayed_timers[1]))
    if not LinkageChainEmpty(group.delayed_queues[1]) :
        print "\t\t" + header
    for call in ParanoidIterateLinkageChain(group.delayed_queues[1], "thread_call_t", "tc_qlink"):
        ShowThreadCall("\t\t", call, recent_timestamp)

def PrintThreadCallThreads() :
    callout_flag = GetEnumValue('thread_tag_t::THREAD_TAG_CALLOUT')
    recent_timestamp = GetRecentTimestamp()

    for thread in IterateQueue(kern.globals.kernel_task.threads, 'thread *', 'task_threads'):
        if (thread.thread_tag & callout_flag) :
            print " {:#20x} {:#12x} {:s}".format(thread, thread.thread_id, GetThreadName(thread))
            state = thread.thc_state
            if state and state.thc_call :
                print "\t" + PrintThreadGroup.header
                ShowThreadCall("\t", state.thc_call, recent_timestamp)
                soft_deadline = state.thc_call_soft_deadline
                slop_time = state.thc_call_hard_deadline - soft_deadline
                slop_time = kern.GetNanotimeFromAbstime(slop_time) / 1000000000.0
                print "\t original soft deadline {:d}, hard deadline {:d} (leeway {:.06f}s)".format(
                        soft_deadline, state.thc_call_hard_deadline, slop_time)
                enqueue_time = state.thc_call_pending_timestamp - soft_deadline
                enqueue_time = kern.GetNanotimeFromAbstime(enqueue_time) / 1000000000.0
                print "\t time to enqueue after deadline: {:.06f}s (enqueued at: {:d})".format(
                        enqueue_time, state.thc_call_pending_timestamp)
                wait_time = state.thc_call_start - state.thc_call_pending_timestamp
                wait_time = kern.GetNanotimeFromAbstime(wait_time) / 1000000000.0
                print "\t time to start executing after enqueue: {:.06f}s (executing at: {:d})".format(
                        wait_time, state.thc_call_start)

                if (state.thc_IOTES_invocation_timestamp) :
                    iotes_acquire_time = state.thc_IOTES_invocation_timestamp - state.thc_call_start
                    iotes_acquire_time = kern.GetNanotimeFromAbstime(iotes_acquire_time) / 1000000000.0
                    print "\t IOTES acquire time: {:.06f}s (acquired at: {:d})".format(
                            iotes_acquire_time, state.thc_IOTES_invocation_timestamp)


@lldb_command('showcalloutgroup')
def ShowCalloutGroup(cmd_args=None):
    """ Prints out the pending and delayed thread calls for a specific group

        Pass 'threads' to show the thread call threads themselves.

        Callout flags:

        A - Allocated memory owned by thread_call.c
        W - Wait - thread waiting for call to finish running
        D - Delayed - deadline based
        R - Running - currently executing on a thread
        S - Signal - call from timer interrupt instead of thread
        O - Once - pend the enqueue if re-armed while running
        P - Reschedule pending - enqueue is pending due to re-arm while running
        L - Rate-limited - (App Nap)
        C - Continuous time - Timeout is in mach_continuous_time
        I - Callout is an IOTimerEventSource
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowCalloutGroup.__doc__
        return False

    if "threads" in cmd_args[0] :
        PrintThreadCallThreads()
        return

    group = kern.GetValueFromAddress(cmd_args[0], 'struct thread_call_group *')
    if not group:
        print "unknown arguments:", str(cmd_args)
        return False

    PrintThreadGroup(group)

@lldb_command('showallcallouts')
def ShowAllCallouts(cmd_args=None):
    """ Prints out the pending and delayed thread calls for the thread call groups

        Callout flags:

        A - Allocated memory owned by thread_call.c
        W - Wait - thread waiting for call to finish running
        D - Delayed - deadline based
        R - Running - currently executing on a thread
        S - Signal - call from timer interrupt instead of thread
        O - Once - pend the enqueue if re-armed while running
        P - Reschedule pending - enqueue is pending due to re-arm while running
        L - Rate-limited - (App Nap)
        C - Continuous time - Timeout is in mach_continuous_time
        I - Callout is an IOTimerEventSource
    """
    index_max = GetEnumValue('thread_call_index_t::THREAD_CALL_INDEX_MAX')

    for i in range (0, index_max) :
        group = addressof(kern.globals.thread_call_groups[i])
        PrintThreadGroup(group)

    print "Thread Call Threads:"
    PrintThreadCallThreads()

# EndMacro: showallcallouts

