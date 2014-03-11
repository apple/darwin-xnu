
""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""
from xnu import *
import sys, shlex
from utils import *
import xnudefines
from process import *

# Macro: memstats
@lldb_command('memstats')
def Memstats(cmd_args=None):
    """ Prints out a summary of various memory statistics. In particular vm_page_wire_count should be greater than 2K or you are under memory pressure.
    """
    try:
        print "memorystatus_level: {: >10d}".format(kern.globals.memorystatus_level)
    except ValueError:
        pass
    try:
        print "memorystatus_available_pages: {: >10d}".format(kern.globals.memorystatus_available_pages)
    except ValueError:
        pass
    print "vm_page_throttled_count: {: >10d}".format(kern.globals.vm_page_throttled_count)
    print "vm_page_active_count:    {: >10d}".format(kern.globals.vm_page_active_count)
    print "vm_page_inactive_count:  {: >10d}".format(kern.globals.vm_page_inactive_count)
    print "vm_page_wire_count:      {: >10d}".format(kern.globals.vm_page_wire_count)
    print "vm_page_free_count:      {: >10d}".format(kern.globals.vm_page_free_count)
    print "vm_page_purgeable_count: {: >10d}".format(kern.globals.vm_page_purgeable_count)
    print "vm_page_inactive_target: {: >10d}".format(kern.globals.vm_page_inactive_target)
    print "vm_page_free_target:     {: >10d}".format(kern.globals.vm_page_free_target)
    print "inuse_ptepages_count:    {: >10d}".format(kern.globals.inuse_ptepages_count)
    print "vm_page_free_reserved:   {: >10d}".format(kern.globals.vm_page_free_reserved)

@xnudebug_test('test_memstats')
def TestMemstats(kernel_target, config, lldb_obj, isConnected ):
    """ Test the functionality of memstats command
        returns 
         - False on failure
         - True on success 
    """
    if not isConnected:
        print "Target is not connected. Cannot test memstats"
        return False
    res = lldb.SBCommandReturnObject()
    lldb_obj.debugger.GetCommandInterpreter().HandleCommand("memstats", res)
    result = res.GetOutput()
    if result.split(":")[1].strip().find('None') == -1 : 
        return True
    else: 
        return False

# EndMacro: memstats

# Macro: showmemorystatus
def CalculateLedgerPeak(phys_footprint_entry):
    """ Internal function to calculate ledger peak value for the given phys footprint entry
        params: phys_footprint_entry - value representing struct ledger_entry * 
        return: value - representing the ledger peak for the given phys footprint entry
    """
    now = kern.globals.sched_tick / 20
    ledger_peak = phys_footprint_entry.le_credit - phys_footprint_entry.le_debit
    if (now - phys_footprint_entry._le.le_peaks[0].le_time <= 1) and (phys_footprint_entry._le.le_peaks[0].le_max > ledger_peak):
        ledger_peak = phys_footprint_entry._le.le_peaks[0].le_max
    if (now - phys_footprint_entry._le.le_peaks[1].le_time <= 1) and (phys_footprint_entry._le.le_peaks[1].le_max > ledger_peak):
        ledger_peak = phys_footprint_entry._le.le_peaks[1].le_max
    return ledger_peak

@header("{: >8s} {: >22s} {: >22s} {: >11s} {: >11s} {: >12s} {: >10s} {: >13s} {: ^10s} {: >8s}  {: <20s}\n".format(
'pid', 'effective priority', 'requested priority', 'state', 'user_data', 'physical', 'iokit', 'footprint',
'spike', 'limit', 'command'))
def GetMemoryStatusNode(proc_val):
    """ Internal function to get memorystatus information from the given proc
        params: proc - value representing struct proc *
        return: str - formatted output information for proc object
    """
    out_str = ''
    task_val = Cast(proc_val.task, 'task *')
    task_ledgerp = task_val.ledger

    task_physmem_footprint_ledger_entry = task_ledgerp.l_entries[kern.globals.task_ledgers.phys_mem]
    task_iokit_footprint_ledger_entry = task_ledgerp.l_entries[kern.globals.task_ledgers.iokit_mem]
    task_phys_footprint_ledger_entry = task_ledgerp.l_entries[kern.globals.task_ledgers.phys_footprint]
    page_size = kern.globals.page_size
    
    phys_mem_footprint = (task_physmem_footprint_ledger_entry.le_credit - task_physmem_footprint_ledger_entry.le_debit) / page_size
    iokit_footprint = (task_iokit_footprint_ledger_entry.le_credit - task_iokit_footprint_ledger_entry.le_debit) / page_size
    phys_footprint = (task_phys_footprint_ledger_entry.le_credit - task_phys_footprint_ledger_entry.le_debit) / page_size
    phys_footprint_limit = task_phys_footprint_ledger_entry.le_limit / page_size
    ledger_peak = CalculateLedgerPeak(task_phys_footprint_ledger_entry)
    phys_footprint_spike = ledger_peak / page_size

    format_string = '{0: >8d} {1: >22d} {2: >22d} {3: #011x} {4: #011x} {5: >12d} {6: >10d} {7: >13d}'
    out_str += format_string.format(proc_val.p_pid, proc_val.p_memstat_effectivepriority,
        proc_val.p_memstat_requestedpriority, proc_val.p_memstat_state, proc_val.p_memstat_userdata,
        phys_mem_footprint, iokit_footprint, phys_footprint)
    if phys_footprint != phys_footprint_spike:
        out_str += "{: ^12d}".format(phys_footprint_spike)
    else:
        out_str += "{: ^12s}".format('-')
    out_str += "{: 8d}  {: <20s}\n".format(phys_footprint_limit, proc_val.p_comm)
    return out_str        

@lldb_command('showmemorystatus')
def ShowMemoryStatus(cmd_args=None):
    """  Routine to display each entry in jetsam list with a summary of pressure statistics
         Usage: showmemorystatus
    """
    bucket_index = 0
    bucket_count = 20
    print GetMemoryStatusNode.header
    print "{: >91s} {: >10s} {: >13s} {: ^10s} {: >8s}\n".format("(pages)", "(pages)", "(pages)",
        "(pages)", "(pages)")
    while bucket_index < bucket_count:
        current_bucket = kern.globals.memstat_bucket[bucket_index]
        current_list = current_bucket.list
        current_proc = Cast(current_list.tqh_first, 'proc *')
        while unsigned(current_proc) != 0:
            print GetMemoryStatusNode(current_proc)
            current_proc = current_proc.p_memstat_list.tqe_next
        bucket_index += 1
    print "\n\n"
    Memstats()
    
# EndMacro: showmemorystatus

# Macro: zprint

@lldb_type_summary(['zone','zone_t'])
@header("{:^18s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s}({:>6s} {:>6s} {:>6s}) {:^14s} {:<20s}".format(
'ZONE', 'TOT_SZ', 'PAGE_COUNT', 'ALLOC_ELTS', 'FREE_ELTS', 'FREE_SZ', 'ELT_SZ', 'ALLOC', 'ELTS', 'PGS', 'SLK', 'FLAGS', 'NAME'))
def GetZoneSummary(zone):
    """ Summarize a zone with important information. See help zprint for description of each field
        params: 
          zone: value - obj representing a zone in kernel
        returns: 
          str - summary of the zone
    """
    out_string = ""
    format_string = '{:#018x} {:10d} {:10d} {:10d} {:10d} {:10d} {:10d} {:10d} {:6d} {:6d} {:6d}  {markings} {name:s} ' 
    pagesize = 4096
    
    free_elements = (zone.cur_size / zone.elem_size) - zone.count
    free_size = free_elements * zone.elem_size
    
    alloc_count = zone.alloc_size / zone.elem_size
    alloc_pages = zone.alloc_size / pagesize
    alloc_slack = zone.alloc_size % zone.elem_size
    marks = [
            ["collectable",        "C"],
            ["expandable",         "X"],
            ["noencrypt",          "$"],
            ["caller_acct",        "@"],
            ["exhaustible",        "H"],
            ["allows_foreign",     "F"],
            ["async_prio_refill",  "R"],
            ["no_callout",         "O"],
            ["zleak_on",           "L"],
            ["doing_alloc",        "A"],
            ["waiting",            "W"],
            ["doing_gc",           "G"]
            ]
    if kern.arch == 'x86_64':
        marks.append(["gzalloc_exempt",     "M"])
        marks.append(["alignment_required", "N"])
        
    markings=""
    for mark in marks:
        if zone.__getattr__(mark[0]) :
            markings+=mark[1]
        else:
            markings+=" "
    out_string += format_string.format(zone, zone.cur_size, zone.page_count,
                    zone.count, free_elements, free_size,
                    zone.elem_size, zone.alloc_size, alloc_count,
                    alloc_pages, alloc_slack, name = zone.zone_name, markings=markings)
    
    if zone.exhaustible :
            out_string += "(max: {:d})".format(zone.max_size)
            
    return out_string

@lldb_command('zprint')
def Zprint(cmd_args=None):
    """ Routine to print a summary listing of all the kernel zones
    All columns are printed in decimal
    Legend:
        C - collectable
        X - expandable
        $ - not encrypted during hibernation
        @ - allocs and frees are accounted to caller process for KPRVT
        H - exhaustible
        F - allows foreign memory (memory not allocated from zone_map)
        M - gzalloc will avoid monitoring this zone
        R - will be refilled when below low water mark
        O - does not allow refill callout to fill zone on noblock allocation
        N - zone requires alignment (avoids padding this zone for debugging)
        A - currently trying to allocate more backing memory from kernel_memory_allocate
        W - another thread is waiting for more memory
        L - zone is being monitored by zleaks
        G - currently running GC
    """
    global kern
    print GetZoneSummary.header
    for zval in kern.zones:
        print GetZoneSummary(zval)

@xnudebug_test('test_zprint')
def TestZprint(kernel_target, config, lldb_obj, isConnected ):
    """ Test the functionality of zprint command
        returns 
         - False on failure
         - True on success 
    """
    if not isConnected:
        print "Target is not connected. Cannot test memstats"
        return False
    res = lldb.SBCommandReturnObject()
    lldb_obj.debugger.GetCommandInterpreter().HandleCommand("zprint", res)
    result = res.GetOutput()
    if len(result.split("\n")) > 2:
        return True
    else: 
        return False


# EndMacro: zprint

# Macro: showzfreelist

def ShowZfreeListHeader(zone):
    """ Helper routine to print a header for zone freelist.
        (Since the freelist does not have a custom type, this is not defined as a Type Summary).
        params:
            zone:zone_t - Zone object to print header info
        returns:
            None
    """
    out_str = ""
    out_str += "{0: <9s} {1: <12s} {2: <18s} {3: <18s} {4: <6s}\n".format('ELEM_SIZE', 'COUNT', 'NCOOKIE', 'PCOOKIE', 'FACTOR')
    out_str += "{0: <9d} {1: <12d} 0x{2:0>16x} 0x{3:0>16x} {4: <2d}/{5: <2d}\n\n".format(
                zone.elem_size, zone.count, kern.globals.zp_nopoison_cookie, kern.globals.zp_poisoned_cookie, zone.zp_count, kern.globals.zp_factor)
    out_str += "{0: <7s} {1: <18s} {2: <18s} {3: <18s} {4: <18s} {5: <18s} {6: <14s}\n".format(
                'NUM', 'ELEM', 'NEXT', 'BACKUP', '^ NCOOKIE', '^ PCOOKIE', 'POISON (PREV)')
    print out_str

def ShowZfreeListChain(zone, zfirst, zlimit):
    """ Helper routine to print a zone free list chain
        params:
            zone: zone_t - Zone object
            zfirst: void * - A pointer to the first element of the free list chain
            zlimit: int - Limit for the number of elements to be printed by showzfreelist
        returns:
            None
    """
    current = Cast(zfirst, 'void *')
    while ShowZfreeList.elts_found < zlimit:
        ShowZfreeList.elts_found += 1
        znext = dereference(Cast(current, 'vm_offset_t *'))
        backup_ptr = kern.GetValueFromAddress((unsigned(Cast(current, 'vm_offset_t')) + unsigned(zone.elem_size) - sizeof('vm_offset_t')), 'vm_offset_t *')
        backup_val = dereference(backup_ptr)
        n_unobfuscated = (unsigned(backup_val) ^ unsigned(kern.globals.zp_nopoison_cookie))
        p_unobfuscated = (unsigned(backup_val) ^ unsigned(kern.globals.zp_poisoned_cookie))
        poison_str = ''
        if p_unobfuscated == unsigned(znext):
            poison_str = "P ({0: <d})".format(ShowZfreeList.elts_found - ShowZfreeList.last_poisoned)
            ShowZfreeList.last_poisoned = ShowZfreeList.elts_found
        else:
            if n_unobfuscated != unsigned(znext):
                poison_str = "INVALID"
        print "{0: <7d} 0x{1:0>16x} 0x{2:0>16x} 0x{3:0>16x} 0x{4:0>16x} 0x{5:0>16x} {6: <14s}\n".format(
              ShowZfreeList.elts_found, unsigned(current), unsigned(znext), unsigned(backup_val), n_unobfuscated, p_unobfuscated, poison_str)
        if unsigned(znext) == 0:
            break
        current = Cast(znext, 'void *')

@static_var('elts_found',0)
@static_var('last_poisoned',0)
@lldb_command('showzfreelist')
def ShowZfreeList(cmd_args=None):
    """ Walk the freelist for a zone, printing out the primary and backup next pointers, the poisoning cookies, and the poisoning status of each element.
    Usage: showzfreelist <zone> [iterations]

        Will walk up to 50 elements by default, pass a limit in 'iterations' to override.
    """
    if not cmd_args:
        print ShowZfreeList.__doc__
        return
    ShowZfreeList.elts_found = 0
    ShowZfreeList.last_poisoned = 0

    zone = kern.GetValueFromAddress(cmd_args[0], 'struct zone *')
    zlimit = 50
    if len(cmd_args) >= 2:
        zlimit = ArgumentStringToInt(cmd_args[1])
    ShowZfreeListHeader(zone)

    if unsigned(zone.use_page_list) == 1:
        if unsigned(zone.allows_foreign) == 1:
            for free_page_meta in IterateQueue(zone.pages.any_free_foreign, 'struct zone_page_metadata *', 'pages'):
                if ShowZfreeList.elts_found == zlimit:
                    break
                zfirst = Cast(free_page_meta.elements, 'void *')
                if unsigned(zfirst) != 0:
                    ShowZfreeListChain(zone, zfirst, zlimit)
        for free_page_meta in IterateQueue(zone.pages.intermediate, 'struct zone_page_metadata *', 'pages'):
            if ShowZfreeList.elts_found == zlimit:
                break
            zfirst = Cast(free_page_meta.elements, 'void *')
            if unsigned(zfirst) != 0:
                ShowZfreeListChain(zone, zfirst, zlimit)
        for free_page_meta in IterateQueue(zone.pages.all_free, 'struct zone_page_metadata *', 'pages'):
            if ShowZfreeList.elts_found == zlimit:
                break
            zfirst = Cast(free_page_meta.elements, 'void *')
            if unsigned(zfirst) != 0:
                ShowZfreeListChain(zone, zfirst, zlimit)
    else:
        zfirst = Cast(zone.free_elements, 'void *')
        if unsigned(zfirst) != 0:
            ShowZfreeListChain(zone, zfirst, zlimit)
    
    if ShowZfreeList.elts_found == zlimit:
        print "Stopped at {0: <d} elements!".format(zlimit)
    else:
        print "Found {0: <d} elements!".format(ShowZfreeList.elts_found)

# EndMacro: showzfreelist

# Macro: zstack

@lldb_command('zstack')
def Zstack(cmd_args=None):
    """ Zone leak debugging: Print the stack trace of log element at <index>. If a <count> is supplied, it prints <count> log elements starting at <index>.
        Usage: zstack <index> [<count>]

        The suggested usage is to look at indexes below zcurrent and look for common stack traces.
        The stack trace that occurs the most is probably the cause of the leak.  Find the pc of the
        function calling into zalloc and use the countpcs command to find out how often that pc occurs in the log.
        The pc occuring in a high percentage of records is most likely the source of the leak.
        
        The findoldest command is also useful for leak debugging since it identifies the oldest record
        in the log, which may indicate the leaker.
    """
    if not cmd_args:
        print Zstack.__doc__
        return
    if int(kern.globals.log_records) == 0:
        print "Zone logging not enabled. Add 'zlog=<zone name>' to boot-args."
        return
    if int(kern.globals.zlog_btlog) == 0:
        print "Zone logging enabled, but zone has not been initialized yet."
        return

    count = 1
    if len(cmd_args) >= 2:
        count = ArgumentStringToInt(cmd_args[1])
    zstack_index = unsigned(cmd_args[0])
    while count and (zstack_index != 0xffffff):
        zstack_record_offset = zstack_index * unsigned(kern.globals.zlog_btlog.btrecord_size)
        zstack_record = kern.GetValueFromAddress(unsigned(kern.globals.zlog_btlog.btrecords) + zstack_record_offset, 'btlog_record_t *')
        ShowZStackRecord(zstack_record, zstack_index)
        zstack_index = zstack_record.next
        count -= 1

# EndMacro : zstack

# Macro: findoldest

@lldb_command('findoldest')
def FindOldest(cmd_args=None):
    """ Zone leak debugging: find and print the oldest record in the log.
        
        Once it prints a stack trace, find the pc of the caller above all the zalloc, kalloc and
        IOKit layers.  Then use the countpcs command to see how often this caller has allocated
        memory.  A caller with a high percentage of records in the log is probably the leaker.
    """
    if int(kern.globals.log_records) == 0:
        print FindOldest.__doc__
        return
    if int(kern.globals.zlog_btlog) == 0:
        print "Zone logging enabled, but zone has not been initialized yet."
        return
    index = kern.globals.zlog_btlog.head
    if unsigned(index) != 0xffffff:
        print "Oldest record is at log index: {0: <d}".format(index)
        Zstack([index])
    else:
        print "No Records Present"

# EndMacro : findoldest

# Macro: countpcs

@lldb_command('countpcs')
def Countpcs(cmd_args=None):
    """ Zone leak debugging: search the log and print a count of all log entries that contain the given <pc>
        in the stack trace.
        Usage: countpcs <pc>

        This is useful for verifying a suspected <pc> as being the source of
        the leak.  If a high percentage of the log entries contain the given <pc>, then it's most
        likely the source of the leak.  Note that this command can take several minutes to run.
    """
    if not cmd_args:
        print Countpcs.__doc__
        return
    if int(kern.globals.log_records) == 0:
        print "Zone logging not enabled. Add 'zlog=<zone name>' to boot-args."
        return
    if int(kern.globals.zlog_btlog) == 0:
        print "Zone logging enabled, but zone has not been initialized yet."
        return
    
    cpcs_index = unsigned(kern.globals.zlog_btlog.head)
    target_pc = unsigned(kern.GetValueFromAddress(cmd_args[0], 'void *'))
    found = 0
    depth = unsigned(kern.globals.zlog_btlog.btrecord_btdepth)

    while cpcs_index != 0xffffff:
        cpcs_record_offset = cpcs_index * unsigned(kern.globals.zlog_btlog.btrecord_size)
        cpcs_record = kern.GetValueFromAddress(unsigned(kern.globals.zlog_btlog.btrecords) + cpcs_record_offset, 'btlog_record_t *')
        frame = 0
        while frame < depth:
            frame_pc = unsigned(cpcs_record.bt[frame])
            if frame_pc == target_pc:
                found += 1
                break
            frame += 1
        cpcs_index = cpcs_record.next
    print "Occured {0: <d} times in log ({1: <d}{2: <s} of records)".format(found, (found * 100)/unsigned(kern.globals.zlog_btlog.activecount), '%')

# EndMacro: countpcs

# Macro: findelem

@lldb_command('findelem')
def FindElem(cmd_args=None):
    """ Zone corruption debugging: search the log and print out the stack traces for all log entries that
        refer to the given zone element.  
        Usage: findelem <elem addr>

        When the kernel panics due to a corrupted zone element, get the
        element address and use this command.  This will show you the stack traces of all logged zalloc and
        zfree operations which tells you who touched the element in the recent past.  This also makes
        double-frees readily apparent.
    """
    if not cmd_args:
        print FindElem.__doc__
        return
    if int(kern.globals.log_records) == 0:
        print "Zone logging not enabled. Add 'zlog=<zone name>' to boot-args."
        return
    if int(kern.globals.zlog_btlog) == 0:
        print "Zone logging enabled, but zone has not been initialized yet."
        return
  
    target_element = unsigned(kern.GetValueFromAddress(cmd_args[0], 'void *'))
    index = unsigned(kern.globals.zlog_btlog.head)
    prev_op = -1

    while index != 0xffffff:
        findelem_record_offset = index * unsigned(kern.globals.zlog_btlog.btrecord_size)
        findelem_record = kern.GetValueFromAddress(unsigned(kern.globals.zlog_btlog.btrecords) + findelem_record_offset, 'btlog_record_t *')
        if unsigned(findelem_record.element) == target_element:
            Zstack([index])
            if int(findelem_record.operation) == prev_op:
                print "{0: <s} DOUBLE OP! {1: <s}".format(('*' * 8), ('*' * 8))
                prev_op = int(findelem_record.operation)
        index = findelem_record.next

# EndMacro: findelem

# Macro: btlog_find

@lldb_command('btlog_find', "A")
def BtlogFind(cmd_args=None, cmd_options={}):
    """ Search the btlog_t for entries corresponding to the given element.
        Use -A flag to print all entries.
        Usage: btlog_find <btlog_t> <element>
        Usage: btlog_find <btlog_t> -A 
        Note: Backtraces will be in chronological order, with oldest entries aged out in FIFO order as needed.
    """
    if not cmd_args:
        raise ArgumentError("Need a btlog_t parameter")
    btlog = kern.GetValueFromAddress(cmd_args[0], 'btlog_t *')
    printall = False
    target_elem = 0xffffff

    if "-A" in cmd_options:
        printall = True
    else:
        if not printall and len(cmd_args) < 2:
            raise ArgumentError("<element> is missing in args. Need a search pointer.")
        target_elem = unsigned(kern.GetValueFromAddress(cmd_args[1], 'void *'))
    
    index = unsigned(btlog.head)
    progress = 0
    record_size = unsigned(btlog.btrecord_size)
    while index != 0xffffff:
        record_offset = index * record_size
        record = kern.GetValueFromAddress(unsigned(btlog.btrecords) + record_offset, 'btlog_record_t *')
        if unsigned(record.element) == target_elem or printall:
            print '{0: <s} OP {1: <d} {2: <#0x} {3: <s}\n'.format(('-' * 8), record.operation, target_elem, ('-' * 8))
            ShowBtlogBacktrace(btlog.btrecord_btdepth, record)
        index = record.next
        progress += 1
        if (progress % 1000) == 0: print '{0: <d} entries searched!\n'.format(progress)

#EndMacro: btlog_find

#Macro: showzalloc

@lldb_command('showzalloc')
def ShowZalloc(cmd_args=None):
    """ Prints a zallocation from the zallocations array based off its index and prints the associated symbolicated backtrace.
        Usage: showzalloc <index>
    """
    if not cmd_args:
        print ShowZalloc.__doc__
        return
    if unsigned(kern.globals.zallocations) == 0:
        print "zallocations array not initialized!"
        return
    zallocation = kern.globals.zallocations[ArgumentStringToInt(cmd_args[0])]
    print zallocation
    ShowZTrace([str(int(zallocation.za_trace_index))])

#EndMacro: showzalloc

#Macro: showztrace

@lldb_command('showztrace')
def ShowZTrace(cmd_args=None):
    """ Prints the backtrace from the ztraces array at index
        Usage: showztrace <trace index>
    """
    if not cmd_args:
        print ShowZTrace.__doc__
        return
    if unsigned(kern.globals.ztraces) == 0:
        print "ztraces array not initialized!"
        return
    ztrace_addr = kern.globals.ztraces[ArgumentStringToInt(cmd_args[0])]
    print ztrace_addr
    ShowZstackTraceHelper(ztrace_addr.zt_stack, ztrace_addr.zt_depth)

#EndMacro: showztrace

#Macro: showztraceaddr

@lldb_command('showztraceaddr')
def ShowZTraceAddr(cmd_args=None):
    """ Prints the struct ztrace passed in.
        Usage: showztraceaddr <trace address>
    """
    if not cmd_args:
        print ShowZTraceAddr.__doc__
        return
    ztrace_ptr = kern.GetValueFromAddress(cmd_args[0], 'struct ztrace *')
    print dereference(ztrace_ptr)
    ShowZstackTraceHelper(ztrace_ptr.zt_stack, ztrace_ptr.zt_depth)

#EndMacro: showztraceaddr

#Macro: showzstacktrace

@lldb_command('showzstacktrace')
def ShowZstackTrace(cmd_args=None):
    """ Routine to print a stacktrace stored by OSBacktrace.
        Usage: showzstacktrace <saved stacktrace> [size]

        size is optional, defaults to 15.
    """
    if not cmd_args:
        print ShowZstackTrace.__doc__
        return
    void_ptr_type = gettype('void *')
    void_double_ptr_type = void_ptr_type.GetPointerType()
    trace = kern.GetValueFromAddress(cmd_args[0], void_double_ptr_type)
    trace_size = 15
    if len(cmd_args) >= 2:
        trace_size = ArgumentStringToInt(cmd_args[1])
    ShowZstackTraceHelper(trace, trace_size)
    
#EndMacro: showzstacktrace

def ShowZstackTraceHelper(stack, depth):
    """ Helper routine for printing a zstack.
        params:
            stack: void *[] - An array of pointers representing the Zstack
            depth: int - The depth of the ztrace stack 
        returns:
            None
    """
    trace_current = 0
    while trace_current < depth:
        trace_addr = stack[trace_current]
        symbol_arr = kern.SymbolicateFromAddress(unsigned(trace_addr))
        if symbol_arr:
            symbol_str = str(symbol_arr[0].addr)
        else:
            symbol_str = ''
        print '{0: <#x} {1: <s}'.format(trace_addr, symbol_str)
        trace_current += 1

#Macro: showtopztrace

@lldb_command('showtopztrace')
def ShowTopZtrace(cmd_args=None):
    """ Shows the ztrace with the biggest size. 
        (According to top_ztrace, not by iterating through the hash table)
    """
    top_trace = kern.globals.top_ztrace
    print 'Index: {0: <d}'.format((unsigned(top_trace) - unsigned(kern.globals.ztraces)) / sizeof('struct ztrace'))
    print dereference(top_trace)
    ShowZstackTraceHelper(top_trace.zt_stack, top_trace.zt_depth)

#EndMacro: showtopztrace

#Macro: showzallocs

@lldb_command('showzallocs')
def ShowZallocs(cmd_args=None):
    """ Prints all allocations in the zallocations table
    """
    if unsigned(kern.globals.zallocations) == 0:
        print "zallocations array not initialized!"
        return
    print '{0: <5s} {1: <18s} {2: <5s} {3: <15s}'.format('INDEX','ADDRESS','TRACE','SIZE') 
    current_index = 0
    max_zallocation = unsigned(kern.globals.zleak_alloc_buckets)
    allocation_count = 0
    while current_index < max_zallocation:
        current_zalloc = kern.globals.zallocations[current_index]
        if int(current_zalloc.za_element) != 0:
            print '{0: <5d} {1: <#018x} {2: <5d} {3: <15d}'.format(current_index, current_zalloc.za_element, current_zalloc.za_trace_index, unsigned(current_zalloc.za_size))
            allocation_count += 1
        current_index += 1
    print 'Total Allocations: {0: <d}'.format(allocation_count)

#EndMacro: showzallocs

#Macro: showzallocsfortrace

@lldb_command('showzallocsfortrace')
def ShowZallocsForTrace(cmd_args=None):
    """ Prints all allocations pointing to the passed in trace's index into ztraces by looking through zallocations table
        Usage:  showzallocsfortrace <trace index>
    """
    if not cmd_args:
        print ShowZallocsForTrace.__doc__
        return
    print '{0: <5s} {1: <18s} {2: <15s}'.format('INDEX','ADDRESS','SIZE') 
    target_index = ArgumentStringToInt(cmd_args[0])
    current_index = 0
    max_zallocation = unsigned(kern.globals.zleak_alloc_buckets)
    allocation_count = 0
    while current_index < max_zallocation:
        current_zalloc = kern.globals.zallocations[current_index]
        if unsigned(current_zalloc.za_element) != 0 and (unsigned(current_zalloc.za_trace_index) == unsigned(target_index)):
            print '{0: <5d} {1: <#018x} {2: <6d}'.format(current_index, current_zalloc.za_element, current_zalloc.za_size)
            allocation_count += 1
        current_index += 1
    print 'Total Allocations: {0: <d}'.format(allocation_count)

#EndMacro: showzallocsfortrace

#Macro: showztraces

@lldb_command('showztraces')
def ShowZTraces(cmd_args=None):
    """ Prints all traces with size > 0
    """
    ShowZTracesAbove([0])

#EndMacro: showztraces

#Macro: showztracesabove

@lldb_command('showztracesabove')
def ShowZTracesAbove(cmd_args=None):
    """ Prints all traces with size greater than X
        Usage: showztracesabove <size>
    """
    if not cmd_args:
        print ShowZTracesAbove.__doc__
        return
    print '{0: <5s} {1: <6s}'.format('INDEX','SIZE')
    current_index = 0
    ztrace_count = 0
    max_ztrace = unsigned(kern.globals.zleak_trace_buckets)
    while current_index < max_ztrace:
        ztrace_current = kern.globals.ztraces[current_index]
        if ztrace_current.zt_size > unsigned(cmd_args[0]):
            print '{0: <5d} {1: <6d}'.format(current_index, int(ztrace_current.zt_size))
            ztrace_count += 1
        current_index += 1
    print 'Total traces: {0: <d}'.format(ztrace_count)

#EndMacro: showztracesabove

#Macro: showztracehistogram

@lldb_command('showztracehistogram')
def ShowZtraceHistogram(cmd_args=None):
    """ Prints the histogram of the ztrace table
    """
    print '{0: <5s} {1: <9s} {2: <10s}'.format('INDEX','HIT_COUNT','COLLISIONS')
    current_index = 0
    ztrace_count = 0
    max_ztrace = unsigned(kern.globals.zleak_trace_buckets)
    while current_index < max_ztrace:
        ztrace_current = kern.globals.ztraces[current_index]
        if ztrace_current.zt_hit_count != 0:
            print '{0: <5d} {1: <9d} {2: <10d}'.format(current_index, ztrace_current.zt_hit_count, ztrace_current.zt_collisions)
            ztrace_count += 1
        current_index += 1
    print 'Total traces: {0: <d}'.format(ztrace_count)
    
#EndMacro: showztracehistogram

#Macro: showzallochistogram

@lldb_command('showzallochistogram')
def ShowZallocHistogram(cmd_args=None):
    """ Prints the histogram for the zalloc table
    """
    print '{0: <5s} {1: <9s}'.format('INDEX','HIT_COUNT')
    current_index = 0
    zallocation_count = 0
    max_ztrace = unsigned(kern.globals.zleak_alloc_buckets)
    while current_index < max_ztrace:
        zallocation_current = kern.globals.zallocations[current_index]
        if zallocation_current.za_hit_count != 0:
            print '{0: <5d} {1: <9d}'.format(current_index, zallocation_current.za_hit_count)
            zallocation_count += 1
        current_index += 1
    print 'Total Allocations: {0: <d}'.format(zallocation_count)

#EndMacro: showzallochistogram

#Macro: showzstats

@lldb_command('showzstats')
def ShowZstats(cmd_args=None):
    """ Prints the zone leak detection stats
    """
    print 'z_alloc_collisions: {0: <d}, z_trace_collisions: {1: <d}'.format(unsigned(kern.globals.z_alloc_collisions), unsigned(kern.globals.z_trace_collisions))
    print 'z_alloc_overwrites: {0: <d}, z_trace_overwrites: {1: <d}'.format(unsigned(kern.globals.z_alloc_overwrites), unsigned(kern.globals.z_trace_overwrites))
    print 'z_alloc_recorded: {0: <d}, z_trace_recorded: {1: <d}'.format(unsigned(kern.globals.z_alloc_recorded), unsigned(kern.globals.z_trace_recorded))

#EndMacro: showzstats

def ShowBtlogBacktrace(depth, zstack_record):
    """ Helper routine for printing a BT Log record backtrace stack.
        params:
            depth:int - The depth of the zstack record
            zstack_record:btlog_record_t * - A BTLog record
        returns:
            None
    """
    out_str = ''
    frame = 0
    if not zstack_record:
        print "Zstack record none!"
        return
    depth_val = unsigned(depth)
    while frame < depth_val:
        frame_pc = zstack_record.bt[frame]
        if not frame_pc or int(frame_pc) == 0:
            break
        symbol_arr = kern.SymbolicateFromAddress(frame_pc)
        if symbol_arr:
            symbol_str = str(symbol_arr[0].addr)
        else:
            symbol_str = ''
        out_str += "{0: <#0x} <{1: <s}>\n".format(frame_pc, symbol_str)
        frame += 1
    print out_str

def ShowZStackRecord(zstack_record, zstack_index):
    """ Helper routine for printing a single zstack record
        params:
            zstack_record:btlog_record_t * -  A BTLog record
            zstack_index:int - Index for the record in the BTLog table
        returns:
            None
    """
    out_str = ('-' * 8)
    if zstack_record.operation == 1:
        out_str += "ALLOC  "
    else:
        out_str += "FREE   "
    out_str += "{0: <#0x} : Index {1: <d} {2: <s}\n".format(zstack_record.element, zstack_index, ('-' * 8))
    print out_str
    ShowBtlogBacktrace(kern.globals.zlog_btlog.btrecord_btdepth, zstack_record)

# Macro: showioalloc

@lldb_command('showioalloc')
def ShowIOAllocations(cmd_args=None):
    """ Show some accounting of memory allocated by IOKit allocators. See ioalloccount man page for details.
        Routine to display a summary of memory accounting allocated by IOKit allocators.
    """
    print "Instance allocation  = {0: <#0x} = {1: d}K".format(kern.globals.debug_ivars_size, (kern.globals.debug_ivars_size / 1024))
    print "Container allocation = {0: <#0x} = {1: d}K".format(kern.globals.debug_container_malloc_size, (kern.globals.debug_container_malloc_size / 1024))
    print "IOMalloc allocation  = {0: <#0x} = {1: d}K".format(kern.globals.debug_iomalloc_size, (kern.globals.debug_iomalloc_size / 1024))
    print "Container allocation = {0: <#0x} = {1: d}K".format(kern.globals.debug_iomallocpageable_size, (kern.globals.debug_iomallocpageable_size / 1024))
    
    
# EndMacro: showioalloc    


 
 
# Macro: showtaskvme
@lldb_command('showtaskvme')
def ShowTaskVmeHelper(cmd_args=None):
    """ Display a summary list of the specified vm_map's entries
        Usage: showtaskvme <task address>  (ex. showtaskvme 0x00ataskptr00 )
    """
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    ShowTaskVMEntries(task)

@lldb_command('showallvme')
def ShowAllVME(cmd_args=None):
    """ Routine to print a summary listing of all the vm map entries
        Go Through each task in system and show the vm info
    """
    for task in kern.tasks:
        ShowTaskVMEntries(task)

@lldb_command('showallvm')
def ShowAllVM(cmd_args=None):
    """ Routine to print a summary listing of all the vm maps
    """
    for task in kern.tasks:
        print GetTaskSummary.header + ' ' + GetProcSummary.header
        print GetTaskSummary(task) + ' ' + GetProcSummary(Cast(task.bsd_info, 'proc *'))
        print GetVMMapSummary.header
        print GetVMMapSummary(task.map)

@lldb_command("showtaskvm")
def ShowTaskVM(cmd_args=None):
    """ Display info about the specified task's vm_map
        syntax: (lldb) showtaskvm <task_ptr>
    """
    if not cmd_args:
        print ShowTaskVM.__doc__
        return False
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    if not task:
        print "Unknown arguments."
        return False
    print GetTaskSummary.header + ' ' + GetProcSummary.header
    print GetTaskSummary(task) + ' ' + GetProcSummary(Cast(task.bsd_info, 'proc *'))
    print GetVMMapSummary.header
    print GetVMMapSummary(task.map)
    return True

@lldb_command('showallvmstats')
def ShowAllVMStats(cmd_args=None):
    """ Print a summary of vm statistics in a table format
    """
    vmstats = lambda:None
    vmstats.wired_count = 0
    vmstats.resident_count = 0
    vmstats.resident_max = 0
    vmstats.internal = 0
    vmstats.external = 0
    vmstats.reusable = 0
    vmstats.compressed = 0
    vmstats.compressed_peak = 0
    vmstats.compressed_lifetime = 0
    vmstats.error = ''

    hdr_format = "{0: >10s} {1: <20s} {2: >6s} {3: >10s} {4: >10s} {5: >10s} {6: >10s} {7: >10s} {8: >10s} {9: >10s} {10: >10s} {11: >10s} {12: >10s} {13: >10s} {14:}"
    print hdr_format.format('pid', 'command', '#ents', 'wired', 'vsize', 'rsize', 'NEW RSIZE', 'max rsize', 'internal', 'external', 'reusable', 'compressed', 'compressed', 'compressed', '')
    print hdr_format.format('', '', '', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(current)', '(peak)', '(lifetime)', '')
    entry_format = "{p.p_pid: >10d} {p.p_comm: <20s} {m.hdr.nentries: >6d} {s.wired_count: >10d} {vsize: >10d} {s.resident_count: >10d} {s.new_resident_count: >10d} {s.resident_max: >10d} {s.internal: >10d} {s.external: >10d} {s.reusable: >10d} {s.compressed: >10d} {s.compressed_peak: >10d} {s.compressed_lifetime: >10d} {s.error}"

    for task in kern.tasks:
        proc = Cast(task.bsd_info, 'proc *')
        vmmap = Cast(task.map, '_vm_map *')
        vmstats.error = ''
        vmstats.wired_count = vmmap.pmap.stats.wired_count;
        vmstats.resident_count = unsigned(vmmap.pmap.stats.resident_count);
        vmstats.resident_max = vmmap.pmap.stats.resident_max;
        vmstats.internal = unsigned(vmmap.pmap.stats.internal);
        vmstats.external = unsigned(vmmap.pmap.stats.external);
        vmstats.reusable = unsigned(vmmap.pmap.stats.reusable);
        vmstats.compressed = unsigned(vmmap.pmap.stats.compressed);
        vmstats.compressed_peak = unsigned(vmmap.pmap.stats.compressed_peak);
        vmstats.compressed_lifetime = unsigned(vmmap.pmap.stats.compressed_lifetime);
        vmstats.new_resident_count = vmstats.internal + vmstats.external

        if vmstats.internal < 0:
            vmstats.error += '*'
        if vmstats.external < 0:
            vmstats.error += '*'
        if vmstats.reusable < 0:
            vmstats.error += '*'
        if vmstats.compressed < 0:
            vmstats.error += '*'
        if vmstats.compressed_peak < 0:
            vmstats.error += '*'
        if vmstats.compressed_lifetime < 0:
            vmstats.error += '*'
        if vmstats.new_resident_count +vmstats.reusable != vmstats.resident_count:
            vmstats.error += '*'

        print entry_format.format(p=proc, m=vmmap, vsize=(unsigned(vmmap.size) >> 12), t=task, s=vmstats)
        

def ShowTaskVMEntries(task):
    """  Routine to print out a summary listing of all the entries in a vm_map
        params: 
            task - core.value : a object of type 'task *'
        returns:
            None
    """
    print "vm_map entries for task " + hex(task)
    print GetTaskSummary.header
    print GetTaskSummary(task)
    if not task.map:
        print "Task {0: <#020x} has map = 0x0"
        return None
    print GetVMMapSummary.header
    print GetVMMapSummary(task.map)
    vme_list_head = task.map.hdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    print GetVMEntrySummary.header
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links"):
        print GetVMEntrySummary(vme)
    return None

@lldb_command("showmap")
def ShowMap(cmd_args=None):
    """ Routine to print out info about the specified vm_map
        usage: showmap <vm_map>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument.", ShowMap.__doc__
        return
    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    print GetVMMapSummary.header
    print GetVMMapSummary(map_val)

@lldb_command("showmapvme")
def ShowMapVME(cmd_args=None):
    """Routine to print out info about the specified vm_map and its vm entries
        usage: showmapvme <vm_map>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument.", ShowMap.__doc__
        return
    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    print GetVMMapSummary.header
    print GetVMMapSummary(map_val)
    vme_list_head = map_val.hdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    print GetVMEntrySummary.header
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links"):
        print GetVMEntrySummary(vme)
    return None

@lldb_type_summary(['_vm_map *', 'vm_map_t'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: >5s} {4: >5s} {5: <20s} {6: <20s}".format("vm_map", "pmap", "vm_size", "#ents", "rpage", "hint", "first_free"))
def GetVMMapSummary(vmmap):
    """ Display interesting bits from vm_map struct """
    out_string = ""
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x} {3: >5d} {4: >5d} {5: <#020x} {6: <#020x}"
    vm_size = uint64_t(vmmap.size).value
    resident_pages = 0
    if vmmap.pmap != 0: resident_pages = int(vmmap.pmap.stats.resident_count)
    out_string += format_string.format(vmmap, vmmap.pmap, vm_size, vmmap.hdr.nentries, resident_pages, vmmap.hint, vmmap.first_free)
    return out_string

@lldb_type_summary(['vm_map_entry'])
@header("{0: <20s} {1: <20s} {2: <5s} {3: >7s} {4: <20s} {5: <20s}".format("entry", "start", "prot", "#page", "object", "offset"))
def GetVMEntrySummary(vme):
    """ Display vm entry specific information. """
    out_string = ""
    format_string = "{0: <#020x} {1: <#20x} {2: <1x}{3: <1x}{4: <3s} {5: >7d} {6: <#020x} {7: <#020x}"
    vme_protection = int(vme.protection)
    vme_max_protection = int(vme.max_protection)
    vme_extra_info_str ="SC-Ds"[int(vme.inheritance)]
    if int(vme.is_sub_map) != 0 : 
        vme_extra_info_str +="s"
    elif int(vme.needs_copy) != 0 :
        vme_extra_info_str +="n"
    num_pages = (unsigned(vme.links.end) - unsigned(vme.links.start)) >> 12
    out_string += format_string.format(vme, vme.links.start, vme_protection, vme_max_protection, vme_extra_info_str, num_pages, vme.object.vm_object, vme.offset)
    return out_string

# EndMacro: showtaskvme
@lldb_command('showmapwired')
def ShowMapWired(cmd_args=None):
    """ Routine to print out a summary listing of all the entries with wired pages in a vm_map
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument", ShowMapWired.__doc__
        return
    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    

@lldb_type_summary(['kmod_info_t *'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: >3s} {4: >5s} {5: >20s} {6: <30s}".format('kmod_info', 'address', 'size', 'id', 'refs', 'version', 'name'))
def GetKextSummary(kmod):
    """ returns a string representation of kext information 
    """
    out_string = ""
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x} {3: >3d} {4: >5d} {5: >20s} {6: <30s}"
    out_string += format_string.format(kmod, kmod.address, kmod.size, kmod.id, kmod.reference_count, kmod.version, kmod.name)
    return out_string

@lldb_type_summary(['uuid_t'])
@header("")    
def GetUUIDSummary(uuid):
    """ returns a string representation like CA50DA4C-CA10-3246-B8DC-93542489AA26
    """
    arr = Cast(addressof(uuid), 'uint8_t *')
    data = []
    for i in range(16):
        data.append(int(arr[i]))
    return "{a[0]:02X}{a[1]:02X}{a[2]:02X}{a[3]:02X}-{a[4]:02X}{a[5]:02X}-{a[6]:02X}{a[7]:02X}-{a[8]:02X}{a[9]:02X}-{a[10]:02X}{a[11]:02X}{a[12]:02X}{a[13]:02X}{a[14]:02X}{a[15]:02X}".format(a=data)

@lldb_command('showallkmods')
def ShowAllKexts(cmd_args=None):
    """Display a summary listing of all loaded kexts (alias: showallkmods)
    """
    kmod_val = kern.globals.kmod
    print "{: <36s} ".format("UUID") + GetKextSummary.header
    kextuuidinfo = GetKextLoadInformation()
    for kval in IterateLinkedList(kmod_val, 'next'):
        uuid = "........-....-....-....-............"
        kaddr = unsigned(kval.address)
        for l in kextuuidinfo :
            if kaddr == int(l[1],16):
                uuid = l[0]
                break
        print uuid + " " + GetKextSummary(kval) 

def GetKextLoadInformation(addr=0):
    """ Extract the kext uuid and load address information from the kernel data structure.
        params:
            addr - int - optional integer that is the address to search for.
        returns: 
            [] - array with each entry of format ( 'UUID', 'Hex Load Address')
    """
    # because of <rdar://problem/12683084>, we can't find summaries directly 
    #addr = hex(addressof(kern.globals.gLoadedKextSummaries.summaries))
    baseaddr = unsigned(kern.globals.gLoadedKextSummaries) + 0x10
    summaries_begin = kern.GetValueFromAddress(baseaddr, 'OSKextLoadedKextSummary *')
    total_summaries = int(kern.globals.gLoadedKextSummaries.numSummaries)
    kext_version = int(kern.globals.gLoadedKextSummaries.version)
    entry_size = 64 + 16 + 8 + 8 + 8 + 4 + 4
    if kext_version >= 2 :
        entry_size = int(kern.globals.gLoadedKextSummaries.entry_size)
    retval = []
    for i in range(total_summaries):
        tmpaddress = unsigned(summaries_begin) + (i * entry_size)
        current_kext = kern.GetValueFromAddress(tmpaddress, 'OSKextLoadedKextSummary *')
        if addr != 0 :
            if addr == unsigned(current_kext.address):
                retval.append((GetUUIDSummary(current_kext.uuid) , hex(current_kext.address), str(current_kext.name) ))
        else:
            retval.append((GetUUIDSummary(current_kext.uuid) , hex(current_kext.address), str(current_kext.name) )) 
        
    return retval

lldb_alias('showallkexts', 'showallkmods')

def GetOSKextVersion(version_num):
    """ returns a string of format 1.2.3x from the version_num
        params: version_num - int
        return: str 
    """
    if version_num == -1 :
        return "invalid"
    (MAJ_MULT, MIN_MULT, REV_MULT,STAGE_MULT) = (100000000, 1000000, 10000, 1000)
    version = version_num
    
    vers_major = version / MAJ_MULT
    version = version - (vers_major * MAJ_MULT)
    
    vers_minor = version / MIN_MULT
    version = version - (vers_minor * MIN_MULT)
    
    vers_revision = version / REV_MULT
    version = version - (vers_revision * REV_MULT)
    
    vers_stage = version / STAGE_MULT
    version = version - (vers_stage * STAGE_MULT)
    
    vers_stage_level = version 
    
    out_str = "%d.%d" % (vers_major, vers_minor)
    if vers_revision > 0: out_str += ".%d" % vers_revision
    if vers_stage == 1 : out_str += "d%d" % vers_stage_level
    if vers_stage == 3 : out_str += "a%d" % vers_stage_level
    if vers_stage == 5 : out_str += "b%d" % vers_stage_level
    if vers_stage == 6 : out_str += "fc%d" % vers_stage_level
    
    return out_str

@lldb_command('showallknownkmods')
def ShowAllKnownKexts(cmd_args=None):
    """ Display a summary listing of all kexts known in the system.
        This is particularly useful to find if some kext was unloaded before this crash'ed state.
    """
    kext_count = int(kern.globals.sKextsByID.count)
    index = 0
    kext_dictionary = kern.globals.sKextsByID.dictionary
    print "%d kexts in sKextsByID:" % kext_count
    print "{0: <20s} {1: <20s} {2: >5s} {3: >20s} {4: <30s}".format('OSKEXT *', 'load_addr', 'id', 'version', 'name')
    format_string = "{0: <#020x} {1: <20s} {2: >5s} {3: >20s} {4: <30s}"
    
    while index < kext_count:
        kext_dict = GetObjectAtIndexFromArray(kext_dictionary, index)
        kext_name = str(kext_dict.key.string)
        osk = Cast(kext_dict.value, 'OSKext *')
        if int(osk.flags.loaded) :
            load_addr = "{0: <#020x}".format(osk.kmod_info)
            id = "{0: >5d}".format(osk.loadTag)
        else:
            load_addr = "------"
            id = "--"
        version_num = unsigned(osk.version)
        version = GetOSKextVersion(version_num)
        print format_string.format(osk, load_addr, id, version, kext_name)
        index += 1
    
    return

@lldb_command('showkmodaddr')
def ShowKmodAddr(cmd_args=[]):
    """ Given an address, print the offset and name for the kmod containing it 
        Syntax: (lldb) showkmodaddr <addr>
    """
    if len(cmd_args) < 1:
        raise ArgumentError("Insufficient arguments")

    addr = ArgumentStringToInt(cmd_args[0])
    kmod_val = kern.globals.kmod
    for kval in IterateLinkedList(kmod_val, 'next'):
        if addr >= unsigned(kval.address) and addr <= (unsigned(kval.address) + unsigned(kval.size)):
            print GetKextSummary.header
            print GetKextSummary(kval) + " offset = {0: #0x}".format((addr - unsigned(kval.address)))
            return True
    return False

@lldb_command('addkext','F:N:')
def AddKextSyms(cmd_args=[], cmd_options={}):
    """ Add kext symbols into lldb.
        This command finds symbols for a uuid and load the required executable
        Usage: 
            addkext <uuid> : Load one kext based on uuid. eg. (lldb)addkext 4DD2344C0-4A81-3EAB-BDCF-FEAFED9EB73E
            addkext -F <abs/path/to/executable> <load_address> : Load kext executable at specified load address
            addkext -N <name> : Load one kext that matches the name provided. eg. (lldb) addkext -N corecrypto
            addkext all    : Will load all the kext symbols - SLOW 
    """
    

    if "-F" in cmd_options:
        exec_path = cmd_options["-F"]
        exec_full_path = ResolveFSPath(exec_path)
        if not os.path.exists(exec_full_path):
            raise ArgumentError("Unable to resolve {:s}".format(exec_path))
        
        if not os.path.isfile(exec_full_path):
            raise ArgumentError("Path is {:s} not a filepath. \nPlease check that path points to executable.\
\nFor ex. path/to/Symbols/IOUSBFamily.kext/Contents/PlugIns/AppleUSBHub.kext/Contents/MacOS/AppleUSBHub.\
\nNote: LLDB does not support adding kext based on directory paths like gdb used to.".format(exec_path))
        if not os.access(exec_full_path, os.X_OK):
            raise ArgumentError("Path is {:s} not an executable file".format(exec_path))

        slide_value = None
        if cmd_args:
            slide_value = cmd_args[0]
            debuglog("loading slide value from user input %s" % cmd_args[0])

        filespec = lldb.SBFileSpec(exec_full_path, False)
        print "target modules add %s" % exec_full_path
        print lldb_run_command("target modules add %s" % exec_full_path)
        loaded_module = LazyTarget.GetTarget().FindModule(filespec)
        if loaded_module.IsValid():
            uuid_str = loaded_module.GetUUIDString()
            debuglog("added module %s with uuid %s" % (exec_full_path, uuid_str))
            if slide_value is None:
                all_kexts_info = GetKextLoadInformation()
                for k in all_kexts_info:
                    debuglog(k[0])
                    if k[0].lower() == uuid_str.lower():
                        slide_value = k[1]
                        debuglog("found the slide %s for uuid %s" % (k[1], k[0]))
        
        if slide_value is None:
            raise ArgumentError("Unable to find load address for module described at %s " % exec_full_path)
        load_cmd = "target modules load --file %s --slide %s" % (exec_full_path, str(slide_value))
        print load_cmd
        print lldb_run_command(load_cmd)  
        kern.symbolicator = None
        return True

    all_kexts_info = GetKextLoadInformation()
    
    if "-N" in cmd_options:
        kext_name = cmd_options["-N"]
        kext_name_matches = GetLongestMatchOption(kext_name, [str(x[2]) for x in all_kexts_info], True)
        if len(kext_name_matches) != 1:
            print "Ambiguous match for name: {:s}".format(kext_name)
            if len(kext_name_matches) > 0:
                print  "Options are:\n\t" + "\n\t".join(kext_name_matches)
            return
        debuglog("matched the kext to name %s and uuid %s" % (kext_name_matches[0], kext_name))
        for x in all_kexts_info:
            if kext_name_matches[0] == x[2]:
                cur_uuid = x[0].lower()
                print "Fetching dSYM for {:s}".format(cur_uuid)
                info = dsymForUUID(cur_uuid)
                if info and 'DBGSymbolRichExecutable' in info:
                    print "Adding dSYM ({0:s}) for {1:s}".format(cur_uuid, info['DBGSymbolRichExecutable'])
                    addDSYM(cur_uuid, info)
                    loadDSYM(cur_uuid, int(x[1],16))
                else:
                    print "Failed to get symbol info for {:s}".format(cur_uuid)
                break
        kern.symbolicator = None
        return

    if len(cmd_args) < 1:
        raise ArgumentError("No arguments specified.")

    uuid = cmd_args[0].lower()

    load_all_kexts = False
    if uuid == "all":
        load_all_kexts = True
    
    if not load_all_kexts and len(uuid_regex.findall(uuid)) == 0:
        raise ArgumentError("Unknown argument {:s}".format(uuid))

    for k_info in all_kexts_info:
        cur_uuid = k_info[0].lower()
        if load_all_kexts or (uuid == cur_uuid):
            print "Fetching dSYM for %s" % cur_uuid
            info = dsymForUUID(cur_uuid)
            if info and 'DBGSymbolRichExecutable' in info:
                print "Adding dSYM (%s) for %s" % (cur_uuid, info['DBGSymbolRichExecutable'])
                addDSYM(cur_uuid, info)
                loadDSYM(cur_uuid, int(k_info[1],16))
            else:
                print "Failed to get symbol info for %s" % cur_uuid
        #end of for loop
    kern.symbolicator = None
    return True

    

lldb_alias('showkmod', 'showkmodaddr')
lldb_alias('showkext', 'showkmodaddr')
lldb_alias('showkextaddr', 'showkmodaddr')

@lldb_type_summary(['mount *'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: <12s} {4: <12s} {5: <12s} {6: >6s} {7: <30s} {8: <35s}".format('volume(mp)', 'mnt_data', 'mnt_devvp', 'flag', 'kern_flag', 'lflag', 'type', 'mnton', 'mntfrom'))
def GetMountSummary(mount):
    """ Display a summary of mount on the system 
    """
    out_string = ("{mnt: <#020x} {mnt.mnt_data: <#020x} {mnt.mnt_devvp: <#020x} {mnt.mnt_flag: <#012x} " +
                  "{mnt.mnt_kern_flag: <#012x} {mnt.mnt_lflag: <#012x} {vfs.f_fstypename: >6s} " +
                  "{vfs.f_mntonname: <30s} {vfs.f_mntfromname: <35s}").format(mnt=mount, vfs=mount.mnt_vfsstat)
    return out_string

@lldb_command('showallmounts')
def ShowAllMounts(cmd_args=None):
    """ Print all mount points
    """
    mntlist = kern.globals.mountlist
    print GetMountSummary.header
    for mnt in IterateTAILQ_HEAD(mntlist, 'mnt_list'):
        print GetMountSummary(mnt)
    return

lldb_alias('ShowAllVols', 'showallmounts')

@lldb_command('systemlog')
def ShowSystemLog(cmd_args=None):
    """ Display the kernel's printf ring buffer """
    msgbufp = kern.globals.msgbufp
    msg_size = int(msgbufp.msg_size)
    msg_bufx = int(msgbufp.msg_bufx)
    msg_bufr = int(msgbufp.msg_bufr)
    msg_bufc = msgbufp.msg_bufc
    msg_bufc_data = msg_bufc.GetSBValue().GetPointeeData(0, msg_size)

    # the buffer is circular; start at the write pointer to end,
    # then from beginning to write pointer
    line = ''
    err = lldb.SBError()
    for i in range(msg_bufx, msg_size) + range(0, msg_bufx) :
        err.Clear()
        cbyte = msg_bufc_data.GetUnsignedInt8(err, i)
        if not err.Success() :
            raise ValueError("Failed to read character at offset " + i + ": " + err.GetCString())
        c = chr(cbyte)
        if c == '\0' :  
            continue
        elif c == '\n' :
            print line
            line = ''
        else :
            line += c

    if len(line) > 0 :
        print line

    return

@static_var('output','')
def _GetVnodePathName(vnode, vnodename):
    """ Internal function to get vnode path string from vnode structure.
        params:
            vnode - core.value
            vnodename - str
        returns Nothing. The output will be stored in the static variable.
    """
    if not vnode:
        return
    if int(vnode.v_flag) & 0x1 and int(hex(vnode.v_mount), 16) !=0:
        if int(vnode.v_mount.mnt_vnodecovered):
            _GetVnodePathName(vnode.v_mount.mnt_vnodecovered, str(vnode.v_mount.mnt_vnodecovered.v_name) )
    else:
        _GetVnodePathName(vnode.v_parent, str(vnode.v_parent.v_name))
        _GetVnodePathName.output += "/%s" % vnodename 

def GetVnodePath(vnode):
    """ Get string representation of the vnode
        params: vnodeval - value representing vnode * in the kernel
        return: str - of format /path/to/something
    """
    out_str = ''
    if vnode:
            if (int(vnode.v_flag) & 0x000001) and int(hex(vnode.v_mount), 16) != 0 and (int(vnode.v_mount.mnt_flag) & 0x00004000) :
                out_str += "/"
            else:
                _GetVnodePathName.output = ''
                if abs(vnode.v_name) != 0:
                    _GetVnodePathName(vnode, str(vnode.v_name))
                    out_str += _GetVnodePathName.output
                else:
                    out_str += 'v_name = NULL'
                _GetVnodePathName.output = ''
    return out_str


@lldb_command('showvnodepath')
def ShowVnodePath(cmd_args=None):
    """ Prints the path for a vnode
        usage: showvnodepath <vnode>
    """
    if cmd_args != None and len(cmd_args) > 0 :
        vnode_val = kern.GetValueFromAddress(cmd_args[0], 'vnode *')
        if vnode_val:
            print GetVnodePath(vnode_val)
    return

# Macro: showvnodedev
def GetVnodeDevInfo(vnode):
    """ Internal function to get information from the device type vnodes
        params: vnode - value representing struct vnode *
        return: str - formatted output information for block and char vnode types passed as param
    """
    vnodedev_output = ""
    vblk_type = GetEnumValue('vtype::VBLK')
    vchr_type = GetEnumValue('vtype::VCHR')
    if (vnode.v_type == vblk_type) or (vnode.v_type == vchr_type):
        devnode = Cast(vnode.v_data, 'devnode_t *')
        devnode_dev = devnode.dn_typeinfo.dev
        devnode_major = (devnode_dev >> 24) & 0xff
        devnode_minor = devnode_dev & 0x00ffffff

        # boilerplate device information for a vnode 
        vnodedev_output += "Device Info:\n\t vnode:\t\t{:#x}".format(vnode)
        vnodedev_output += "\n\t type:\t\t"
        if (vnode.v_type == vblk_type):
            vnodedev_output += "VBLK"
        if (vnode.v_type == vchr_type):
            vnodedev_output += "VCHR"
        vnodedev_output += "\n\t name:\t\t{:<s}".format(vnode.v_name)
        vnodedev_output += "\n\t major, minor:\t{:d},{:d}".format(devnode_major, devnode_minor)
        vnodedev_output += "\n\t mode\t\t0{:o}".format(unsigned(devnode.dn_mode))
        vnodedev_output += "\n\t owner (u,g):\t{:d} {:d}".format(devnode.dn_uid, devnode.dn_gid)

        # decode device specific data
        vnodedev_output += "\nDevice Specific Information:\t"
        if (vnode.v_type == vblk_type):
            vnodedev_output += "Sorry, I do not know how to decode block devices yet!"
            vnodedev_output += "\nMaybe you can write me!"

        if (vnode.v_type == vchr_type):
            # Device information; this is scanty
            # range check
            if (devnode_major > 42) or (devnode_major < 0):
                vnodedev_output +=  "Invalid major #\n"
            # static assignments in conf
            elif (devnode_major == 0):
                vnodedev_output += "Console mux device\n"
            elif (devnode_major == 2):
                vnodedev_output += "Current tty alias\n"
            elif (devnode_major == 3):
                vnodedev_output += "NULL device\n"
            elif (devnode_major == 4):
                vnodedev_output += "Old pty slave\n"
            elif (devnode_major == 5):
                vnodedev_output += "Old pty master\n"
            elif (devnode_major == 6):
                vnodedev_output += "Kernel log\n"
            elif (devnode_major == 12):
                vnodedev_output += "Memory devices\n"
            # Statically linked dynamic assignments
            elif unsigned(kern.globals.cdevsw[devnode_major].d_open) == unsigned(kern.GetLoadAddressForSymbol('ptmx_open')):
                vnodedev_output += "Cloning pty master not done\n"
                #GetVnodeDevCpty(devnode_major, devnode_minor)
            elif unsigned(kern.globals.cdevsw[devnode_major].d_open) == unsigned(kern.GetLoadAddressForSymbol('ptsd_open')):
                vnodedev_output += "Cloning pty slave not done\n"
                #GetVnodeDevCpty(devnode_major, devnode_minor)
            else:
                vnodedev_output += "RESERVED SLOT\n"
    else:
        vnodedev_output += "{:#x} is not a device".format(vnode)
    return vnodedev_output

@lldb_command('showvnodedev')
def ShowVnodeDev(cmd_args=None):
    """  Routine to display details of all vnodes of block and character device types
         Usage: showvnodedev <address of vnode>
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowVnodeDev.__doc__
        return False
    vnode_val = kern.GetValueFromAddress(cmd_args[0], 'vnode *')
    if not vnode_val:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetVnodeDevInfo(vnode_val)

# EndMacro: showvnodedev

# Macro: showvnodelocks
def GetVnodeLock(lockf):
    """ Internal function to get information from the given advisory lock
        params: lockf - value representing v_lockf member in struct vnode *
        return: str - formatted output information for the advisory lock
    """
    vnode_lock_output = ''
    lockf_flags = lockf.lf_flags
    lockf_type = lockf.lf_type
    if lockf_flags & 0x20:
        vnode_lock_output += ("{: <8s}").format('flock')
    if lockf_flags & 0x40:
        vnode_lock_output += ("{: <8s}").format('posix')
    if lockf_flags & 0x80:
        vnode_lock_output += ("{: <8s}").format('prov')
    if lockf_flags & 0x10:
        vnode_lock_output += ("{: <4s}").format('W')
    else:
        vnode_lock_output += ("{: <4s}").format('.')

    # POSIX file vs advisory range locks
    if lockf_flags & 0x40:
        lockf_proc = Cast(lockf.lf_id, 'proc *')
        vnode_lock_output += ("PID {: <18d}").format(lockf_proc.p_pid)
    else:
        vnode_lock_output += ("ID {: <#019x}").format(int(lockf.lf_id))
        
    # lock type
    if lockf_type == 1:
        vnode_lock_output += ("{: <12s}").format('shared')
    else:
        if lockf_type == 3:
            vnode_lock_output += ("{: <12s}").format('exclusive')
        else:
            if lockf_type == 2:
                vnode_lock_output += ("{: <12s}").format('unlock')
            else:
                vnode_lock_output += ("{: <12s}").format('unknown')
    
    # start and stop values
    vnode_lock_output += ("{: #018x} ..").format(lockf.lf_start)
    vnode_lock_output += ("{: #018x}\n").format(lockf.lf_end)
    return vnode_lock_output

@header("{0: <3s} {1: <7s} {2: <3s} {3: <21s} {4: <11s} {5: ^19s} {6: ^17s}".format('*', 'type', 'W', 'held by', 'lock type', 'start', 'end'))
def GetVnodeLocksSummary(vnode):
    """ Internal function to get summary of advisory locks for the given vnode
        params: vnode - value representing the vnode object
        return: str - formatted output information for the summary of advisory locks
    """
    out_str = ''
    if vnode:
            lockf_list = vnode.v_lockf
            for lockf_itr in IterateLinkedList(lockf_list, 'lf_next'):
                out_str += ("{: <4s}").format('H')
                out_str += GetVnodeLock(lockf_itr)
                lockf_blocker = lockf_itr.lf_blkhd.tqh_first
                while lockf_blocker:
                    out_str += ("{: <4s}").format('>')
                    out_str += GetVnodeLock(lockf_blocker)
                    lockf_blocker = lockf_blocker.lf_block.tqe_next    
    return out_str

@lldb_command('showvnodelocks')
def ShowVnodeLocks(cmd_args=None):
    """  Routine to display list of advisory record locks for the given vnode address
         Usage: showvnodelocks <address of vnode>
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowVnodeLocks.__doc__
        return False
    vnode_val = kern.GetValueFromAddress(cmd_args[0], 'vnode *')
    if not vnode_val:
        print "unknown arguments:", str(cmd_args)
        return False
    print GetVnodeLocksSummary.header
    print GetVnodeLocksSummary(vnode_val)

# EndMacro: showvnodelocks

# Macro: showproclocks
            
@lldb_command('showproclocks')
def ShowProcLocks(cmd_args=None):
    """  Routine to display list of advisory record locks for the given process
         Usage: showproclocks <address of proc>
    """
    if not cmd_args:
        print "No arguments passed"
        print ShowProcLocks.__doc__
        return False
    proc = kern.GetValueFromAddress(cmd_args[0], 'proc *')
    if not proc:
        print "unknown arguments:", str(cmd_args)
        return False
    out_str = ''
    proc_filedesc = proc.p_fd
    fd_lastfile = proc_filedesc.fd_lastfile
    fd_ofiles = proc_filedesc.fd_ofiles
    count = 0
    seen = 0
    while count <= fd_lastfile:
        if fd_ofiles[count]:
            fglob = fd_ofiles[count].f_fglob
            fo_type = fglob.fg_ops.fo_type
            if fo_type == 1:
                fg_data = fglob.fg_data
                fg_vnode = Cast(fg_data, 'vnode *')
                name = fg_vnode.v_name
                lockf_itr = fg_vnode.v_lockf
                if lockf_itr:
                    if not seen:
                        print GetVnodeLocksSummary.header
                    seen = seen + 1
                    out_str += ("\n( fd {:d}, name ").format(count)
                    if not name:
                        out_str += "(null) )\n"
                    else:
                        out_str += "{:s} )\n".format(name)
                    print out_str  
                    print GetVnodeLocksSummary(fg_vnode)
        count = count + 1
    print "\n{0: d} total locks for {1: #018x}".format(seen, proc)

# EndMacro: showproclocks

@lldb_type_summary(['vnode_t', 'vnode *'])
@header("{0: <20s} {1: >8s} {2: >8s} {3: <20s} {4: <6s} {5: <20s} {6: <6s} {7: <35s}".format('vnode', 'usecount', 'iocount', 'v_data', 'vtype', 'parent', 'mapped', 'name'))
def GetVnodeSummary(vnode):
    """ Get a summary of important information out of vnode
    """
    out_str = ''
    format_string = "{0: <#020x} {1: >8d} {2: >8d} {3: <#020x} {4: <6s} {5: <#020x} {6: <6s} {7: <35s}"
    usecount = int(vnode.v_usecount)
    iocount = int(vnode.v_iocount)
    v_data_ptr = int(hex(vnode.v_data), 16)
    vtype = int(vnode.v_type)
    vtype_str = "%d" % vtype
    vnode_types = ['VNON', 'VREG', 'VDIR', 'VBLK', 'VCHR', 'VLNK', 'VSOCK', 'VFIFO', 'VBAD', 'VSTR', 'VCPLX']  # see vnode.h for enum type definition
    if vtype >= 0 and vtype < len(vnode_types):
        vtype_str = vnode_types[vtype]
    parent_ptr = int(hex(vnode.v_parent), 16)
    name_ptr = int(hex(vnode.v_name), 16)
    name =""
    if name_ptr != 0:
        name = str(vnode.v_name)
    elif int(vnode.v_tag) == 16 :
        cnode = Cast(vnode.v_data, 'cnode *')
        name = "hfs: %s" % str( Cast(cnode.c_desc.cd_nameptr, 'char *'))
    mapped = '-'
    if (vtype == 1) and (vnode.v_un.vu_ubcinfo != 0):
        # Check to see if vnode is mapped/unmapped 
        if (vnode.v_un.vu_ubcinfo.ui_flags & 0x8) != 0:
            mapped = '1'
        else:
            mapped = '0'
    out_str += format_string.format(vnode, usecount, iocount, v_data_ptr, vtype_str, parent_ptr, mapped, name)
    return out_str

@lldb_command('showallvnodes')
def ShowAllVnodes(cmd_args=None):
    """ Display info about all vnodes
    """
    mntlist = kern.globals.mountlist
    print GetVnodeSummary.header
    for mntval in IterateTAILQ_HEAD(mntlist, 'mnt_list'):
        for vnodeval in IterateTAILQ_HEAD(mntval.mnt_vnodelist, 'v_mntvnodes'):
            print GetVnodeSummary(vnodeval)
    return

@lldb_command('showvnode')
def ShowVnode(cmd_args=None):
    """ Display info about one vnode
        usage: showvnode <vnode>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print  "Please provide valid vnode argument. Type help showvnode for help."
        return
    vnodeval = kern.GetValueFromAddress(cmd_args[0],'vnode *')
    print GetVnodeSummary.header
    print GetVnodeSummary(vnodeval)
   
@lldb_command('showvolvnodes')
def ShowVolVnodes(cmd_args=None):
    """ Display info about all vnodes of a given mount_t
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Please provide a valide mount_t argument. Try 'help showvolvnodes' for help"
        return
    mntval = kern.GetValueFromAddress(cmd_args[0], 'mount_t')
    print GetVnodeSummary.header
    for vnodeval in IterateTAILQ_HEAD(mntval.mnt_vnodelist, 'v_mntvnodes'):
        print GetVnodeSummary(vnodeval)
    return

@lldb_command('showvolbusyvnodes')
def ShowVolBusyVnodes(cmd_args=None):
    """ Display info about busy (iocount!=0) vnodes of a given mount_t
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Please provide a valide mount_t argument. Try 'help showvolbusyvnodes' for help"
        return
    mntval = kern.GetValueFromAddress(cmd_args[0], 'mount_t')
    print GetVnodeSummary.header
    for vnodeval in IterateTAILQ_HEAD(mntval.mnt_vnodelist, 'v_mntvnodes'):
        if int(vnodeval.v_iocount) != 0:
            print GetVnodeSummary(vnodeval)

@lldb_command('showallbusyvnodes')
def ShowAllBusyVnodes(cmd_args=None):
    """ Display info about all busy (iocount!=0) vnodes
    """
    mntlistval = kern.globals.mountlist
    for mntval in IterateTAILQ_HEAD(mntlistval, 'mnt_list'):
        ShowVolBusyVnodes([hex(mntval)])

@lldb_command('print_vnode')
def PrintVnode(cmd_args=None):
    """ Prints out the fields of a vnode struct
        Usage: print_vnode <vnode>
    """
    if not cmd_args:
        print  "Please provide valid vnode argument. Type help print_vnode for help."
        return
    ShowVnode(cmd_args)

@lldb_command('showworkqvnodes')
def ShowWorkqVnodes(cmd_args=None):
    """ Print the vnode worker list
        Usage: showworkqvnodes <struct mount *>
    """
    if not cmd_args:
        print "Please provide valid mount argument. Type help showworkqvnodes for help."
        return

    mp = kern.GetValueFromAddress(cmd_args[0], 'mount *')
    vp = Cast(mp.mnt_workerqueue.tqh_first, 'vnode *')
    print GetVnodeSummary.header
    while int(vp) != 0:
        print GetVnodeSummary(vp)
        vp = vp.v_mntvnodes.tqe_next

@lldb_command('shownewvnodes')
def ShowNewVnodes(cmd_args=None):
    """ Print the new vnode list
        Usage: shownewvnodes <struct mount *>
    """
    if not cmd_args:
        print "Please provide valid mount argument. Type help shownewvnodes for help."
        return
    mp = kern.GetValueFromAddress(cmd_args[0], 'mount *')
    vp = Cast(mp.mnt_newvnodes.tqh_first, 'vnode *')
    print GetVnodeSummary.header
    while int(vp) != 0:
        print GetVnodeSummary(vp)
        vp = vp.v_mntvnodes.tqe_next


@lldb_command('showprocvnodes')
def ShowProcVnodes(cmd_args=None):
    """ Routine to print out all the open fds which are vnodes in a process
        Usage: showprocvnodes <proc *>
    """
    if not cmd_args:
        print "Please provide valid proc argument. Type help showprocvnodes for help."
        return
    procptr = kern.GetValueFromAddress(cmd_args[0], 'proc *')
    fdptr = Cast(procptr.p_fd, 'filedesc *')
    if int(fdptr.fd_cdir) != 0:
        print '{0: <25s}\n{1: <s}\n{2: <s}'.format('Current Working Directory:', GetVnodeSummary.header, GetVnodeSummary(fdptr.fd_cdir))
    if int(fdptr.fd_rdir) != 0:
        print '{0: <25s}\n{1: <s}\n{2: <s}'.format('Current Root Directory:', GetVnodeSummary.header, GetVnodeSummary(fdptr.fd_rdir))
    count = 0
    print '\n' + '{0: <5s} {1: <7s}'.format('fd', 'flags') + GetVnodeSummary.header 
    # Hack to get around <rdar://problem/12879494> llb fails to cast addresses to double pointers
    fpptr = Cast(fdptr.fd_ofiles, 'fileproc *')
    while count < fdptr.fd_nfiles:
        fpp = dereference(fpptr)
        fproc = Cast(fpp, 'fileproc *')
        if int(fproc) != 0:
            fglob = dereference(fproc).f_fglob
            flags = ""
            if (int(fglob) != 0) and (int(fglob.fg_ops.fo_type) == 1):
                if (fdptr.fd_ofileflags[count] & 1):    flags += 'E'
                if (fdptr.fd_ofileflags[count] & 2):    flags += 'F'
                if (fdptr.fd_ofileflags[count] & 4):    flags += 'R'
                if (fdptr.fd_ofileflags[count] & 8):    flags += 'C'
                print '{0: <5d} {1: <7s}'.format(count, flags) + GetVnodeSummary(Cast(fglob.fg_data, 'vnode *'))
        count += 1
        fpptr = kern.GetValueFromAddress(int(fpptr) + kern.ptrsize,'fileproc *')

@lldb_command('showallprocvnodes')
def ShowAllProcVnodes(cmd_args=None):
    """ Routine to print out all the open fds which are vnodes
    """

    procptr = Cast(kern.globals.allproc.lh_first, 'proc *')
    while procptr and int(procptr) != 0:
        print '{:<s}'.format("=" * 106)
        print GetProcInfo(procptr)
        ShowProcVnodes([int(procptr)])
        procptr = procptr.p_list.le_next

@xnudebug_test('test_vnode')
def TestShowAllVnodes(kernel_target, config, lldb_obj, isConnected ):
    """ Test the functionality of vnode related commands
        returns 
         - False on failure
         - True on success 
    """
    if not isConnected:
        print "Target is not connected. Cannot test memstats"
        return False
    res = lldb.SBCommandReturnObject()
    lldb_obj.debugger.GetCommandInterpreter().HandleCommand("showallvnodes", res)
    result = res.GetOutput()
    if len(result.split("\n")) > 2 and result.find('VREG') != -1 and len(result.splitlines()[2].split()) > 5:
        return True
    else: 
        return False

# Macro: showallmtx
@lldb_type_summary(['_lck_grp_ *'])
def GetMutexEntry(mtxg):
    """ Summarize a mutex group entry  with important information.
        params:
        mtxg: value - obj representing a mutex group in kernel
        returns:
        out_string - summary of the mutex group
        """
    out_string = ""

    if kern.ptrsize == 8:
        format_string = '{0:#018x} {1:10d} {2:10d} {3:10d} {4:10d} {5: <30s} '
    else:
        format_string = '{0:#010x} {1:10d} {2:10d} {3:10d} {4:10d} {5: <30s} '

    if mtxg.lck_grp_mtxcnt:
        out_string += format_string.format(mtxg, mtxg.lck_grp_mtxcnt,mtxg.lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_util_cnt,
                                           mtxg.lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_miss_cnt,
                                           mtxg.lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_cnt, mtxg.lck_grp_name)
    return out_string

@lldb_command('showallmtx')
def ShowAllMtx(cmd_args=None):
    """ Routine to print a summary listing of all mutexes
    """

    if kern.ptrsize == 8:
        hdr_format = '{:<18s} {:>10s} {:>10s} {:>10s} {:>10s} {:<30s} '
    else:
        hdr_format = '{:<10s} {:>10s} {:>10s} {:>10s} {:>10s} {:<30s} '
    
    print hdr_format.format('LCK GROUP', 'CNT', 'UTIL', 'MISS', 'WAIT', 'NAME')    

    mtxgrp_queue_head = kern.globals.lck_grp_queue
    mtxgrp_ptr_type = GetType('_lck_grp_ *')   
    
    for mtxgrp_ptr in IterateQueue(mtxgrp_queue_head, mtxgrp_ptr_type, "lck_grp_link"): 
       print GetMutexEntry(mtxgrp_ptr)
    return
# EndMacro: showallmtx

# Macro: showallrwlck
@lldb_type_summary(['_lck_grp_ *'])
def GetRWLEntry(rwlg):
    """ Summarize a reader writer lock group with important information.
        params:
        rwlg: value - obj representing a reader writer lock group in kernel
        returns:
        out_string - summary of the reader writer lock group
    """
    out_string = ""

    if kern.ptrsize == 8:
        format_string = '{0:#018x} {1:10d} {2:10d} {3:10d} {4:10d} {5: <30s} '
    else:
        format_string = '{0:#010x} {1:10d} {2:10d} {3:10d} {4:10d} {5: <30s} '

    if rwlg.lck_grp_rwcnt:
        out_string += format_string.format(rwlg, rwlg.lck_grp_rwcnt,rwlg.lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_util_cnt,
                                           rwlg.lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt,
                                           rwlg.lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cnt, rwlg.lck_grp_name)
    return out_string

#Macro: showlock
@lldb_type_summary(['lck_mtx_t *'])
@header("===== Mutex Lock Summary =====")
def GetMutexLockSummary(mtx):
    """ Summarize mutex lock with important information.
        params:
        mtx: value - obj representing a mutex lock in kernel
        returns:
        out_str - summary of the mutex lock
    """
    if not mtx:
        return "Invalid lock value: 0x0"

    if kern.arch == "x86_64":
        out_str = "Lock Type\t\t: MUTEX\n"
        mtxd = mtx.lck_mtx_sw.lck_mtxd
        out_str += "Owner Thread\t\t: {:#x}\n".format(mtxd.lck_mtxd_owner)
        cmd_str = "p/d ((lck_mtx_t*){:#x})->lck_mtx_sw.lck_mtxd.".format(mtx)
        cmd_out = lldb_run_command(cmd_str + "lck_mtxd_waiters")
        out_str += "Number of Waiters\t: {:s}\n".format(cmd_out.split()[-1])
        cmd_out = lldb_run_command(cmd_str + "lck_mtxd_ilocked")
        out_str += "ILocked\t\t\t: {:s}\n".format(cmd_out.split()[-1])
        cmd_out = lldb_run_command(cmd_str + "lck_mtxd_mlocked")
        out_str += "MLocked\t\t\t: {:s}\n".format(cmd_out.split()[-1])
        cmd_out = lldb_run_command(cmd_str + "lck_mtxd_promoted")
        out_str += "Promoted\t\t: {:s}\n".format(cmd_out.split()[-1])
        cmd_out = lldb_run_command(cmd_str + "lck_mtxd_spin")
        out_str += "Spin\t\t\t: {:s}\n".format(cmd_out.split()[-1])
        return out_str

    out_str = "Lock Type\t\t: MUTEX\n"
    out_str += "Owner Thread\t\t: {:#x}\n".format(mtx.lck_mtx_hdr.lck_mtxd_data & ~0x3)
    out_str += "Number of Waiters\t: {:d}\n".format(mtx.lck_mtx_sw.lck_mtxd.lck_mtxd_waiters)
    out_str += "Flags\t\t\t: "
    if mtx.lck_mtx_hdr.lck_mtxd_data & 0x1:
        out_str += "[Interlock Locked] "
    if mtx.lck_mtx_hdr.lck_mtxd_data & 0x2:
        out_str += "[Wait Flag]"
    if (mtx.lck_mtx_hdr.lck_mtxd_data & 0x3) == 0:
        out_str += "None"
    return out_str

@lldb_type_summary(['lck_spin_t *'])
@header("===== SpinLock Summary =====")
def GetSpinLockSummary(spinlock):
    """ Summarize spinlock with important information.
        params:
        spinlock: value - obj representing a spinlock in kernel
        returns:
        out_str - summary of the spinlock
    """
    if not spinlock:
        return "Invalid lock value: 0x0"

    out_str = "Lock Type\t\t: SPINLOCK\n"
    if kern.arch == "x86_64":
        out_str += "Interlock\t\t: {:#x}\n".format(spinlock.interlock)
        return out_str 

    out_str += "Owner Thread\t\t: {:#x}\n".format(spinlock.lck_spin_data & ~0x3)
    out_str += "Flags\t\t\t: "
    if spinlock.lck_spin_data & 0x1:
        out_str += "[Interlock Locked] "
    if spinlock.lck_spin_data & 0x2:
        out_str += "[Wait Flag]"
    if (spinlock.lck_spin_data & 0x3) == 0:
        out_str += "None" 
    return out_str

@lldb_command('showlock', 'MS')
def ShowLock(cmd_args=None, cmd_options={}):
    """ Show info about a lock - its state and owner thread details
        Usage: showlock <address of a lock>
        -M : to consider <addr> as lck_mtx_t 
        -S : to consider <addr> as lck_spin_t 
    """
    if not cmd_args:
        raise ArgumentError("Please specify the address of the lock whose info you want to view.")
        return

    summary_str = ""
    lock = kern.GetValueFromAddress(cmd_args[0], 'uintptr_t*')

    if kern.arch == "x86_64" and lock:
        if "-M" in cmd_options:
            lock_mtx = Cast(lock, 'lck_mtx_t *')
            summary_str = GetMutexLockSummary(lock_mtx)
        elif "-S" in cmd_options:
            lock_spin = Cast(lock, 'lck_spin_t *')
            summary_str = GetSpinLockSummary(lock_spin)
        else:
            summary_str = "Please specify supported lock option(-M/-S)"

        print summary_str
        return

    if lock:
        lock_mtx = Cast(lock, 'lck_mtx_t*')
        if lock_mtx.lck_mtx_type == 0x22:
            summary_str = GetMutexLockSummary(lock_mtx)

        lock_spin = Cast(lock, 'lck_spin_t*')
        if lock_spin.lck_spin_type == 0x11:
            summary_str = GetSpinLockSummary(lock_spin)

    if summary_str == "":
        summary_str = "Lock Type\t\t: INVALID LOCK" 
    print summary_str

#EndMacro: showlock

@lldb_command('showallrwlck')
def ShowAllRWLck(cmd_args=None):
    """ Routine to print a summary listing of all read/writer locks
    """
    if kern.ptrsize == 8:
        hdr_format = '{:<18s} {:>10s} {:>10s} {:>10s} {:>10s} {:<30s} '
    else:
        hdr_format = '{:<10s} {:>10s} {:>10s} {:>10s} {:>10s} {:<30s} '

    print hdr_format.format('LCK GROUP', 'CNT', 'UTIL', 'MISS', 'WAIT', 'NAME')

    rwlgrp_queue_head = kern.globals.lck_grp_queue
    rwlgrp_ptr_type = GetType('_lck_grp_ *')
    for rwlgrp_ptr in IterateQueue(rwlgrp_queue_head, rwlgrp_ptr_type, "lck_grp_link"):
       print GetRWLEntry(rwlgrp_ptr)
    return
# EndMacro: showallrwlck

#Macro: showbootermemorymap
@lldb_command('showbootermemorymap')
def ShowBooterMemoryMap(cmd_args=None):
    """ Prints out the phys memory map from kernelBootArgs
        Supported only on x86_64
    """
    if kern.arch == 'x86_64':
        voffset = unsigned(0xFFFFFF8000000000)
    else:
        print "showbootermemorymap not supported on this architecture"
        return
    
    out_string = ""
    
    # Memory type map
    memtype_dict = {
            0:  'Reserved',
            1:  'LoaderCode',
            2:  'LoaderData',
            3:  'BS_code',
            4:  'BS_data',
            5:  'RT_code',
            6:  'RT_data',
            7:  'Convention',
            8:  'Unusable',
            9:  'ACPI_recl',
            10: 'ACPI_NVS',
            11: 'MemMapIO',
            12: 'MemPortIO',
            13: 'PAL_code'
        }

    boot_args = kern.globals.kernelBootArgs
    msize = boot_args.MemoryMapDescriptorSize
    mcount = (boot_args.MemoryMapSize) / unsigned(msize)
    
    out_string += "{0: <12s} {1: <19s} {2: <19s} {3: <19s} {4: <10s}\n".format("Type", "Physical Start", "Number of Pages", "Virtual Start", "Attributes")
    
    i = 0
    while i < mcount:
        mptr = kern.GetValueFromAddress(unsigned(boot_args.MemoryMap) + voffset + unsigned(i*msize), 'EfiMemoryRange *')
        mtype = unsigned(mptr.Type)
        if mtype in memtype_dict:
            out_string += "{0: <12s}".format(memtype_dict[mtype])
        else:
            out_string += "{0: <12s}".format("UNKNOWN")

        if mptr.VirtualStart == 0:
            out_string += "{0: #019x} {1: #019x} {2: <19s} {3: #019x}\n".format(mptr.PhysicalStart, mptr.NumberOfPages, ' '*19, mptr.Attribute)
        else:
            out_string += "{0: #019x} {1: #019x} {2: #019x} {3: #019x}\n".format(mptr.PhysicalStart, mptr.NumberOfPages, mptr.VirtualStart, mptr.Attribute)
        i = i + 1
    
    print out_string
#EndMacro: showbootermemorymap

