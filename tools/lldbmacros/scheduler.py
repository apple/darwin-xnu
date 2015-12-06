from xnu import *
from utils import *
from process import *

# TODO: write scheduler related macros here

# Macro: showinterrupts

@lldb_command('showinterrupts')
def ShowInterrupts(cmd_args=None):
    """ Prints IRQ, IPI and TMR counts for each CPU
    """ 
    base_address = kern.GetLoadAddressForSymbol('CpuDataEntries')
    struct_size = 16  
    for x in range (0, unsigned(kern.globals.machine_info.physical_cpu)):
        element  = kern.GetValueFromAddress(base_address + (x * struct_size), 'uintptr_t *')[1]
        cpu_data_entry = Cast(element, 'cpu_data_t *')
        print "CPU {} IRQ: {:d}\n".format(x, cpu_data_entry.cpu_stat.irq_ex_cnt)
        print "CPU {} IPI: {:d}\n".format(x, cpu_data_entry.cpu_stat.ipi_cnt)
        print "CPU {} TMR: {:d}\n".format(x, cpu_data_entry.cpu_stat.timer_cnt)        
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


@lldb_command('showcurrentabstime')
def ShowCurremtAbsTime(cmd_args=None):
    """  Routine to print latest absolute time known to system before being stopped.
         Usage: showcurrentabstime
    """
    pset = addressof(kern.globals.pset0)
    cur_abstime = 0

    while unsigned(pset) != 0:
        for processor in IterateQueue(pset.active_queue, "processor_t", "processor_queue"):
            if unsigned(processor.last_dispatch) > cur_abstime:
                cur_abstime = unsigned(processor.last_dispatch)

        for processor in IterateQueue(pset.idle_queue, "processor_t", "processor_queue"):
            if unsigned(processor.last_dispatch) > cur_abstime:
                cur_abstime = unsigned(processor.last_dispatch)

        for processor in IterateQueue(pset.idle_secondary_queue, "processor_t", "processor_queue"):
            if unsigned(processor.last_dispatch) > cur_abstime:
                cur_abstime = unsigned(processor.last_dispatch)

        pset = pset.pset_list

    print "Last dispatch time known: %d MATUs" % cur_abstime


@lldb_command('abs2nano')
def ShowAbstimeToNanoTime(cmd_args=[]):
    """ convert mach_absolute_time units to nano seconds
        Usage: (lldb) abs2nano <timestamp in MATUs>
    """
    if not cmd_args:
        raise ArgumentError("Invalid argument")
    timedata = ArgumentStringToInt(cmd_args[0])
    print "%d ns" % kern.GetNanotimeFromAbstime(timedata)

 # Macro: showschedhistory

def ShowThreadSchedHistory(thread, most_recent_dispatch):
    out_str = ""
    thread_name = ""

    if int(thread.uthread) != 0:
        uthread = Cast(thread.uthread, 'uthread *')
        #check for thread name
        if int(uthread.pth_name) != 0 :
            th_name_strval = Cast(uthread.pth_name, 'char *')
            if len(str(th_name_strval)) > 0 :
                thread_name = str(th_name_strval)

    task = thread.task
    task_name = "unknown"
    if task and unsigned(task.bsd_info):
        p = Cast(task.bsd_info, 'proc *')
        task_name = str(p.p_name)

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

    time_on_abs = unsigned(last_off - last_on)
    time_on_us = kern.GetNanotimeFromAbstime(time_on_abs) / 1000.0

    time_since_off_abs = unsigned(most_recent_dispatch - last_off)
    time_since_off_us = kern.GetNanotimeFromAbstime(time_since_off_abs) / 1000.0
    time_since_on_abs = unsigned(most_recent_dispatch - last_on)
    time_since_on_us = kern.GetNanotimeFromAbstime(time_since_on_abs) / 1000.0

    fmt  = "0x{t:<16x} 0x{t.thread_id:<8x} {t.computation_epoch:16d} {t.last_run_time:16d} {time_on_us:16.3f} {time_since_off_us:16.3f} {time_since_on_us:16.3f}"
    fmt2 = " {t.base_pri:2d} {t.sched_pri:2d} {t.task_priority:2d} {t.max_priority:2d} {sched_mode:19s}"
    fmt3 = " {state:9s} {t.cpu_usage:10d} {t.cpu_delta:10d} {t.sched_usage:10d} {t.sched_stamp:10d} {t.pri_shift:10d} {name:s} {thread_name:s}"

    out_str = fmt.format(t=thread, sched_mode=sched_mode, time_on_us=time_on_us, time_since_off_us=time_since_off_us, time_since_on_us=time_since_on_us)
    out_str += fmt2.format(t=thread, sched_mode=sched_mode)
    out_str += fmt3.format(t=thread, state=state_str, name=task_name, thread_name=thread_name)

    return out_str

@lldb_command('showschedhistory')
def ShowSchedHistory(cmd_args=None):
    """ Routine to print out thread scheduling history
    """

    print "Processors: {:d} Runnable threads: {:d} Timeshare threads: {:d} Background threads {:d}\n".format(
            kern.globals.processor_avail_count, kern.globals.sched_run_count, kern.globals.sched_share_count, kern.globals.sched_background_count)

    print "Mach factor: {:d} Load factor: {:d} Last sched tick {:d}\n".format(
            kern.globals.sched_mach_factor, kern.globals.sched_load_average, kern.globals.sched_tick_last_abstime)

    print "Sched tick: {:d} Fixed shift: {:d} Pri shift: {:d} Background pri shift {:d}\n".format(
            kern.globals.sched_tick, kern.globals.sched_fixed_shift, kern.globals.sched_pri_shift, kern.globals.sched_background_pri_shift)

    processor_list = kern.GetGlobalVariable('processor_list')

    most_recent_dispatch = 0
    current_processor = processor_list
    while unsigned(current_processor) > 0:
        active_thread = current_processor.active_thread
        if unsigned(active_thread) != 0 :
            task_val = active_thread.task
            proc_val = Cast(task_val.bsd_info, 'proc *')
            proc_name = str(proc_val.p_name)

        last_dispatch = unsigned(current_processor.last_dispatch)

        print "Processor last dispatch: {last_dispatch:16d} Active thread: 0x{t:<16x} 0x{t.thread_id:<8x} {proc_name:s}".format(t=active_thread, last_dispatch=last_dispatch, proc_name=proc_name)

        if last_dispatch > most_recent_dispatch :
            most_recent_dispatch = last_dispatch

        current_processor = current_processor.processor_list

    print "Most recent dispatch: " + str(most_recent_dispatch)

    print "{:<18s} {:<10s} {:>16s} {:>16s} {:>16s} {:>16s} {:>16s} {:2s} {:2s} {:2s} {:>2s} {:<19s} {:<9s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>16s} {:>16s}".format(
            "thread", "id", "on-core", "off-core", "last-duration", "since-off", "since-on", "BP", "SP", "TP", "MP", "sched-mode", "state", "cpu-usage", "delta", "sch-usage", "stamp", "shift", "task", "thread-name")

    for thread in IterateQueue(kern.globals.threads, 'thread *', 'threads'):
        print ShowThreadSchedHistory(thread, most_recent_dispatch)

    return

# EndMacro: showschedhistory

