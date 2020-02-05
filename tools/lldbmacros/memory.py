
""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""
from xnu import *
import sys
import shlex
from utils import *
import xnudefines
from process import *
import macho

# Macro: memstats
@lldb_command('memstats')
def Memstats(cmd_args=None):
    """ Prints out a summary of various memory statistics. In particular vm_page_wire_count should be greater than 2K or you are under memory pressure.
    """
    try:
        print "memorystatus_level: {: >10d}".format(kern.globals.memorystatus_level)
        print "memorystatus_available_pages: {: >10d}".format(kern.globals.memorystatus_available_pages)
        print "inuse_ptepages_count:    {: >10d}".format(kern.globals.inuse_ptepages_count)
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
    ledger_peak = long(phys_footprint_entry.le_credit) - long(phys_footprint_entry.le_debit)
    if hasattr(phys_footprint_entry._le._le_max, 'le_interval_max') and (long(phys_footprint_entry._le._le_max.le_interval_max) > ledger_peak):
        ledger_peak = long(phys_footprint_entry._le._le_max.le_interval_max)
    return ledger_peak

@header("{: >8s} {: >12s} {: >12s} {: >10s} {: >10s} {: >12s} {: >14s} {: >10s} {: >12s} {: >10s} {: >10s} {: >10s}  {: <20s}\n".format(
'pid', 'effective', 'requested', 'state', 'relaunch', 'user_data', 'physical', 'iokit', 'footprint',
'recent peak', 'lifemax', 'limit', 'command'))
def GetMemoryStatusNode(proc_val):
    """ Internal function to get memorystatus information from the given proc
        params: proc - value representing struct proc *
        return: str - formatted output information for proc object
    """
    out_str = ''
    task_val = Cast(proc_val.task, 'task *')
    task_ledgerp = task_val.ledger

    task_physmem_footprint_ledger_entry = task_ledgerp.l_entries[kern.globals.task_ledgers.phys_mem]
    task_iokit_footprint_ledger_entry = task_ledgerp.l_entries[kern.globals.task_ledgers.iokit_mapped]
    task_phys_footprint_ledger_entry = task_ledgerp.l_entries[kern.globals.task_ledgers.phys_footprint]
    page_size = kern.globals.page_size

    phys_mem_footprint = (long(task_physmem_footprint_ledger_entry.le_credit) - long(task_physmem_footprint_ledger_entry.le_debit)) / page_size
    iokit_footprint = (long(task_iokit_footprint_ledger_entry.le_credit) - long(task_iokit_footprint_ledger_entry.le_debit)) / page_size
    phys_footprint = (long(task_phys_footprint_ledger_entry.le_credit) - long(task_phys_footprint_ledger_entry.le_debit)) / page_size
    phys_footprint_limit = long(task_phys_footprint_ledger_entry.le_limit) / page_size
    ledger_peak = CalculateLedgerPeak(task_phys_footprint_ledger_entry)
    phys_footprint_spike = ledger_peak / page_size
    phys_footprint_lifetime_max = long(task_phys_footprint_ledger_entry._le._le_max.le_lifetime_max) / page_size

    format_string = '{0: >8d} {1: >12d} {2: >12d} {3: #011x} {4: >10d} {5: #011x} {6: >12d} {7: >10d} {8: >13d}'
    out_str += format_string.format(proc_val.p_pid, proc_val.p_memstat_effectivepriority,
        proc_val.p_memstat_requestedpriority, proc_val.p_memstat_state, proc_val.p_memstat_relaunch_flags, 
        proc_val.p_memstat_userdata, phys_mem_footprint, iokit_footprint, phys_footprint)
    if phys_footprint != phys_footprint_spike:
        out_str += "{: >12d}".format(phys_footprint_spike)
    else:
        out_str += "{: >12s}".format('-')

    out_str += "{: >10d}  ".format(phys_footprint_lifetime_max)
    out_str += "{: >10d}  {: <20s}\n".format(phys_footprint_limit, proc_val.p_comm)
    return out_str

@lldb_command('showmemorystatus')
def ShowMemoryStatus(cmd_args=None):
    """  Routine to display each entry in jetsam list with a summary of pressure statistics
         Usage: showmemorystatus
    """
    bucket_index = 0
    bucket_count = 20
    print GetMemoryStatusNode.header
    print "{: >21s} {: >12s} {: >38s} {: >10s} {: >12s} {: >10s} {: >10s}\n".format("priority", "priority", "(pages)", "(pages)", "(pages)",
        "(pages)", "(pages)", "(pages)")
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

def GetRealMetadata(meta):
    """ Get real metadata for a given metadata pointer
    """
    try:
        if unsigned(meta.zindex) != 0x03FF:
            return meta
        else:
            return kern.GetValueFromAddress(unsigned(meta) - unsigned(meta.real_metadata_offset), "struct zone_page_metadata *")
    except:
        return 0

def GetFreeList(meta):
    """ Get the free list pointer for a given metadata pointer
    """
    global kern
    zone_map_min_address = kern.GetGlobalVariable('zone_map_min_address')
    zone_map_max_address = kern.GetGlobalVariable('zone_map_max_address')
    try:
        if unsigned(meta.freelist_offset) == unsigned(0xffffffff):
            return 0
        else:
            if (unsigned(meta) >= unsigned(zone_map_min_address)) and (unsigned(meta) < unsigned(zone_map_max_address)):
                page_index = ((unsigned(meta) - unsigned(kern.GetGlobalVariable('zone_metadata_region_min'))) / sizeof('struct zone_page_metadata'))
                return (unsigned(zone_map_min_address) + (kern.globals.page_size * (page_index))) + meta.freelist_offset
            else:
                return (unsigned(meta) + meta.freelist_offset)
    except:
        return 0

@lldb_type_summary(['zone_page_metadata'])
@header("{:<18s} {:<18s} {:>8s} {:>8s} {:<18s} {:<20s}".format('ZONE_METADATA', 'FREELIST', 'PG_CNT', 'FREE_CNT', 'ZONE', 'NAME'))
def GetZoneMetadataSummary(meta):
    """ Summarize a zone metadata object
        params: meta - obj representing zone metadata in the kernel
        returns: str - summary of the zone metadata
    """
    out_str = ""
    global kern
    zinfo = 0
    try:
        out_str += 'Metadata Description:\n' + GetZoneMetadataSummary.header + '\n'
        meta = kern.GetValueFromAddress(meta, "struct zone_page_metadata *")
        if unsigned(meta.zindex) == 255:
            out_str += "{:#018x} {:#018x} {:8d} {:8d} {:#018x} {:s}\n".format(meta, 0, 0, 0, 0, '(fake multipage meta)')
            meta = GetRealMetadata(meta)
            if meta == 0:
                return ""
        zinfo = kern.globals.zone_array[unsigned(meta.zindex)]
        out_str += "{:#018x} {:#018x} {:8d} {:8d} {:#018x} {:s}".format(meta, GetFreeList(meta), meta.page_count, meta.free_count, addressof(zinfo), zinfo.zone_name)
        return out_str
    except:
        out_str = ""
        return out_str

@header("{:<18s} {:>18s} {:>18s} {:<18s}".format('ADDRESS', 'TYPE', 'OFFSET_IN_PG', 'METADATA'))
def WhatIs(addr):
    """ Information about kernel pointer
    """
    out_str = ""
    global kern
    pagesize = kern.globals.page_size
    zone_map_min_address = kern.GetGlobalVariable('zone_map_min_address')
    zone_map_max_address = kern.GetGlobalVariable('zone_map_max_address')
    if (unsigned(addr) >= unsigned(zone_map_min_address)) and (unsigned(addr) < unsigned(zone_map_max_address)):
        zone_metadata_region_min = kern.GetGlobalVariable('zone_metadata_region_min')
        zone_metadata_region_max = kern.GetGlobalVariable('zone_metadata_region_max')
        if (unsigned(addr) >= unsigned(zone_metadata_region_min)) and (unsigned(addr) < unsigned(zone_metadata_region_max)):
            metadata_offset = (unsigned(addr) - unsigned(zone_metadata_region_min)) % sizeof('struct zone_page_metadata')
            page_offset_str = "{:d}/{:d}".format((unsigned(addr) - (unsigned(addr) & ~(pagesize - 1))), pagesize)
            out_str += WhatIs.header + '\n'
            out_str += "{:#018x} {:>18s} {:>18s} {:#018x}\n\n".format(unsigned(addr), "Metadata", page_offset_str, unsigned(addr) - metadata_offset)
            out_str += GetZoneMetadataSummary((unsigned(addr) - metadata_offset)) + '\n\n'
        else:
            page_index = ((unsigned(addr) & ~(pagesize - 1)) - unsigned(zone_map_min_address)) / pagesize
            meta = unsigned(zone_metadata_region_min) + (page_index * sizeof('struct zone_page_metadata'))
            meta = kern.GetValueFromAddress(meta, "struct zone_page_metadata *")
            page_meta = GetRealMetadata(meta)
            if page_meta != 0:
                zinfo = kern.globals.zone_array[unsigned(page_meta.zindex)]
                page_offset_str = "{:d}/{:d}".format((unsigned(addr) - (unsigned(addr) & ~(pagesize - 1))), pagesize)
                out_str += WhatIs.header + '\n'
                out_str += "{:#018x} {:>18s} {:>18s} {:#018x}\n\n".format(unsigned(addr), "Element", page_offset_str, page_meta)
                out_str += GetZoneMetadataSummary(unsigned(page_meta)) + '\n\n'
            else:
                out_str += "Unmapped address within the zone_map ({:#018x}-{:#018x})".format(zone_map_min_address, zone_map_max_address)
    else:
        out_str += "Address {:#018x} is outside the zone_map ({:#018x}-{:#018x})\n".format(addr, zone_map_min_address, zone_map_max_address)
    print out_str
    return

@lldb_command('whatis')
def WhatIsHelper(cmd_args=None):
    """ Routine to show information about a kernel pointer
        Usage: whatis <address>
    """
    if not cmd_args:
        raise ArgumentError("No arguments passed")
    addr = kern.GetValueFromAddress(cmd_args[0], 'void *')
    WhatIs(addr)
    print "Hexdump:\n"
    try:
        data_array = kern.GetValueFromAddress(unsigned(addr) - 16, "uint8_t *")
        print_hex_data(data_array[0:48], unsigned(addr) - 16, "")
    except:
        pass
    return

# Macro: showzcache

@lldb_type_summary(['zone','zone_t'])
@header("{:^18s} {:<40s} {:>10s} {:>10s} {:>10s} {:>10s}".format(
'ZONE', 'NAME', 'CACHE_ELTS', 'DEP_VALID', 'DEP_EMPTY','DEP_FULL'))

def GetZoneCacheSummary(zone):
    """ Summarize a zone's cache with important information.
        params:
          zone: value - obj representing a zone in kernel
        returns:
          str - summary of the zone's cache contents
    """
    out_string = ""
    format_string = '{:#018x} {:<40s} {:>10d} {:>10s} {:>10d} {:>10d}'
    cache_elem_count = 0
    mag_capacity = kern.GetGlobalVariable('magazine_element_count')
    depot_capacity = kern.GetGlobalVariable('depot_element_count')


    if zone.__getattr__('cpu_cache_enabled') :
        for i in range(0, kern.globals.machine_info.physical_cpu):
            cache = zone.zcache[0].zcc_per_cpu_caches[i]
            cache_elem_count += cache.current.zcc_magazine_index
            cache_elem_count += cache.previous.zcc_magazine_index
        
        if zone.zcache[0].zcc_depot_index != -1:
            cache_elem_count += zone.zcache[0].zcc_depot_index * mag_capacity
            out_string += format_string.format(zone, zone.zone_name, cache_elem_count, "Y", depot_capacity - zone.zcache[0].zcc_depot_index, zone.zcache[0].zcc_depot_index)
        else:
            out_string += format_string.format(zone, zone.zone_name, cache_elem_count, "N", 0, 0)

    return out_string

@lldb_command('showzcache')
def ZcachePrint(cmd_args=None):
    """ Routine to print a summary listing of all the kernel zones cache contents
    All columns are printed in decimal
    """
    global kern
    print GetZoneCacheSummary.header
    for zval in kern.zones:
        if zval.__getattr__('cpu_cache_enabled') :
            print GetZoneCacheSummary(zval)

# EndMacro: showzcache

# Macro: showzcachecpu

@lldb_type_summary(['zone','zone_t'])
@header("{:^18s} {:40s} {:>10s} {:>10s}".format(
'ZONE', 'NAME', 'CACHE_ELTS', 'CPU_INFO'))

def GetZoneCacheCPUSummary(zone):
    """ Summarize a zone's cache broken up per cpu
        params:
          zone: value - obj representing a zone in kernel
        returns:
          str - summary of the zone's per CPU cache contents
    """
    out_string = ""
    format_string = '{:#018x} {:40s} {:10d} {cpuinfo:s}'
    cache_elem_count = 0
    cpu_info = ""
    per_cpu_count = 0
    mag_capacity = kern.GetGlobalVariable('magazine_element_count')
    depot_capacity = kern.GetGlobalVariable('depot_element_count')


    if zone.__getattr__('cpu_cache_enabled') :
        for i in range(0, kern.globals.machine_info.physical_cpu):
            if i != 0:
                cpu_info += ", "
            cache = zone.zcache[0].zcc_per_cpu_caches[i]
            per_cpu_count = cache.current.zcc_magazine_index
            per_cpu_count += cache.previous.zcc_magazine_index
            cache_elem_count += per_cpu_count
            cpu_info += "CPU {:d}: {:5}".format(i,per_cpu_count)
        if zone.zcache[0].zcc_depot_index != -1:
            cache_elem_count += zone.zcache[0].zcc_depot_index * mag_capacity

    out_string += format_string.format(zone, zone.zone_name, cache_elem_count,cpuinfo = cpu_info)

    return out_string

@lldb_command('showzcachecpu')
def ZcacheCPUPrint(cmd_args=None):
    """ Routine to print a summary listing of all the kernel zones cache contents
    All columns are printed in decimal
    """
    global kern
    print GetZoneCacheCPUSummary.header
    for zval in kern.zones:
        if zval.__getattr__('cpu_cache_enabled') :
            print GetZoneCacheCPUSummary(zval)

# EndMacro: showzcachecpu

# Macro: zprint

@lldb_type_summary(['zone','zone_t'])
@header(("{:<18s}  {:_^23s}  {:_^24s}  {:_^13s}  {:_^31s}\n"+
"{:<18s}  {:>11s} {:>11s}  {:>8s} {:>7s} {:>7s}  {:>6s} {:>6s}  {:>7s} {:>5s} {:>3s} {:>5s} {:>7s}   {:<15s} {:<20s}").format(
'', 'SIZE (bytes)', 'ELEMENTS (#)', 'PAGES', 'ALLOC CHUNK CONFIG',
'ZONE', 'ALLOC', 'FREE', 'ALLOC', 'FREE', 'CACHE', 'COUNT', 'FREE', 'SIZE', 'ELTS', 'PGS', 'WASTE', 'ELT_SZ', 'FLAGS', 'NAME'))
def GetZoneSummary(zone):
    """ Summarize a zone with important information. See help zprint for description of each field
        params:
          zone: value - obj representing a zone in kernel
        returns:
          str - summary of the zone
    """
    out_string = ""
    format_string = '{zone:#018x}  {zone.cur_size:11,d} {free_size:11,d}  {zone.count:8,d} {zone.countfree:7,d} {cache_elem_count:7,d}  {zone.page_count:6,d} {zone.count_all_free_pages:6,d}  {zone.alloc_size:7,d} {alloc_count:5,d} {alloc_pages:3,d} {alloc_waste:5,d} {zone.elem_size:7,d}   {markings:<15s} {zone.zone_name:<20s} '
    pagesize = kern.globals.page_size

    free_size = zone.countfree * zone.elem_size
    mag_capacity = kern.GetGlobalVariable('magazine_element_count')

    alloc_pages = zone.alloc_size / pagesize
    alloc_count = zone.alloc_size / zone.elem_size
    alloc_waste = zone.alloc_size % zone.elem_size

    marks = [
            ["collectable",                 "C"],
            ["expandable",                  "X"],
            ["noencrypt",                   "$"],
            ["caller_acct",                 "@"],
            ["exhaustible",                 "H"],
            ["allows_foreign",              "F"],
            ["async_prio_refill",           "R"],
            ["no_callout",                  "O"],
            ["zleak_on",                    "L"],
            ["doing_alloc_without_vm_priv", "A"],
            ["doing_alloc_with_vm_priv",    "S"],
            ["waiting",                     "W"],
            ["cpu_cache_enabled",           "E"]
            ]
    if kern.arch == 'x86_64':
        marks.append(["gzalloc_exempt",     "M"])
        marks.append(["alignment_required", "N"])

    markings=""
    if not zone.__getattr__("zone_valid") :
        markings+="I"
    for mark in marks:
        if zone.__getattr__(mark[0]) :
            markings+=mark[1]
        else:
            markings+=" "
    cache_elem_count = 0
    if zone.__getattr__('cpu_cache_enabled') :
        for i in range(0, kern.globals.machine_info.physical_cpu):
            cache = zone.zcache[0].zcc_per_cpu_caches[i]
            cache_elem_count += cache.current.zcc_magazine_index
            cache_elem_count += cache.previous.zcc_magazine_index
        if zone.zcache[0].zcc_depot_index != -1:
            cache_elem_count += zone.zcache[0].zcc_depot_index * mag_capacity

    out_string += format_string.format(zone=zone, free_size=free_size, alloc_count=alloc_count,
                    alloc_pages=alloc_pages, alloc_waste=alloc_waste, cache_elem_count=cache_elem_count, markings=markings)

    if zone.exhaustible :
            out_string += "(max: {:d})".format(zone.max_size)

    return out_string

@lldb_command('zprint', fancy=True)
def Zprint(cmd_args=None, cmd_options={}, O=None):
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
        A - currently trying to allocate more backing memory from kernel_memory_allocate without VM priv
        S - currently trying to allocate more backing memory from kernel_memory_allocate with VM priv
        W - another thread is waiting for more memory
        E - Per-cpu caching is enabled for this zone
        L - zone is being monitored by zleaks
        G - currently running GC
        I - zone was destroyed and is no longer valid
    """
    global kern
    with O.table(GetZoneSummary.header):
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

    scaled_factor = (unsigned(kern.globals.zp_factor) +
            (unsigned(zone.elem_size) >> unsigned(kern.globals.zp_scale)))

    out_str = ""
    out_str += "{0: <9s} {1: <12s} {2: <18s} {3: <18s} {4: <6s}\n".format('ELEM_SIZE', 'COUNT', 'NCOOKIE', 'PCOOKIE', 'FACTOR')
    out_str += "{0: <9d} {1: <12d} 0x{2:0>16x} 0x{3:0>16x} {4: <2d}/{5: <2d}\n\n".format(
                zone.elem_size, zone.count, kern.globals.zp_nopoison_cookie, kern.globals.zp_poisoned_cookie, zone.zp_count, scaled_factor)
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
        znext = (unsigned(znext) ^ unsigned(kern.globals.zp_nopoison_cookie))
        znext = kern.GetValueFromAddress(znext, 'vm_offset_t *')
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

    if unsigned(zone.allows_foreign) == 1:
        for free_page_meta in IterateQueue(zone.pages.any_free_foreign, 'struct zone_page_metadata *', 'pages'):
            if ShowZfreeList.elts_found == zlimit:
                break
            zfirst = kern.GetValueFromAddress(GetFreeList(free_page_meta), 'void *')
            if unsigned(zfirst) != 0:
                ShowZfreeListChain(zone, zfirst, zlimit)
    for free_page_meta in IterateQueue(zone.pages.intermediate, 'struct zone_page_metadata *', 'pages'):
        if ShowZfreeList.elts_found == zlimit:
            break
        zfirst = kern.GetValueFromAddress(GetFreeList(free_page_meta), 'void *')
        if unsigned(zfirst) != 0:
            ShowZfreeListChain(zone, zfirst, zlimit)
    for free_page_meta in IterateQueue(zone.pages.all_free, 'struct zone_page_metadata *', 'pages'):
        if ShowZfreeList.elts_found == zlimit:
            break
        zfirst = kern.GetValueFromAddress(GetFreeList(free_page_meta), 'void *')
        if unsigned(zfirst) != 0:
            ShowZfreeListChain(zone, zfirst, zlimit)

    if ShowZfreeList.elts_found == zlimit:
        print "Stopped at {0: <d} elements!".format(zlimit)
    else:
        print "Found {0: <d} elements!".format(ShowZfreeList.elts_found)

# EndMacro: showzfreelist

# Macro: zstack_showzonesbeinglogged

@lldb_command('zstack_showzonesbeinglogged')
def ZstackShowZonesBeingLogged(cmd_args=None):
    """ Show all zones which have BTLog enabled.
    """
    global kern
    for zval in kern.zones:
        if zval.zlog_btlog:
          print "Zone: %s with its BTLog at: 0x%lx" % (zval.zone_name, zval.zlog_btlog)

# EndMacro: zstack_showzonesbeinglogged

# Macro: zstack

@lldb_command('zstack')
def Zstack(cmd_args=None):
    """ Zone leak debugging: Print the stack trace logged at <index> in the stacks list. If a <count> is supplied, it prints <count> stacks starting at <index>.
        Usage: zstack <btlog addr> <index> [<count>]

        The suggested usage is to look at stacks with high percentage of refs (maybe > 25%).
        The stack trace that occurs the most is probably the cause of the leak. Use zstack_findleak for that.
    """
    if not cmd_args:
        print Zstack.__doc__
        return
    if int(kern.globals.log_records) == 0:
        print "Zone logging not enabled. Add 'zlog=<zone name>' to boot-args."
        return

    btlog_ptr = kern.GetValueFromAddress(cmd_args[0], 'btlog_t *')
    btrecords_total_size = unsigned(btlog_ptr.btlog_buffersize)
    btrecord_size = unsigned(btlog_ptr.btrecord_size)
    btrecords = unsigned(btlog_ptr.btrecords)
    btlog_size = unsigned(sizeof('struct btlog'))
    depth = unsigned(btlog_ptr.btrecord_btdepth)
    zstack_index = ArgumentStringToInt(cmd_args[1])
    count = 1
    if len(cmd_args) >= 3:
        count = ArgumentStringToInt(cmd_args[2])

    max_count = ((btrecords_total_size - btlog_size)/btrecord_size)

    if (zstack_index + count) > max_count:
       count = max_count - zstack_index

    while count and (zstack_index != 0xffffff):
        zstack_record_offset = zstack_index * btrecord_size
        zstack_record = kern.GetValueFromAddress(btrecords + zstack_record_offset, 'btlog_record_t *')
        if int(zstack_record.ref_count)!=0:
           ShowZStackRecord(zstack_record, zstack_index, depth, unsigned(btlog_ptr.active_element_count))
        zstack_index += 1
        count -= 1

# EndMacro : zstack

# Macro: zstack_inorder

@lldb_command('zstack_inorder')
def ZstackInOrder(cmd_args=None):
    """ Zone leak debugging: Print the stack traces starting from head to the tail.
        Usage: zstack_inorder <btlog addr>
    """
    if not cmd_args:
        print "Zone leak debugging: Print the stack traces starting from head to the tail. \nUsage: zstack_inorder <btlog addr>"
        return
    if int(kern.globals.log_records) == 0:
        print "Zone logging not enabled. Add 'zlog=<zone name>' to boot-args."
        return

    btlog_ptr = kern.GetValueFromAddress(cmd_args[0], 'btlog_t *')
    btrecords_total_size = unsigned(btlog_ptr.btlog_buffersize)
    btrecord_size = unsigned(btlog_ptr.btrecord_size)
    btrecords = unsigned(btlog_ptr.btrecords)
    btlog_size = unsigned(sizeof('struct btlog'))
    depth = unsigned(btlog_ptr.btrecord_btdepth)
    zstack_head = unsigned(btlog_ptr.head)
    zstack_index = zstack_head
    zstack_tail = unsigned(btlog_ptr.tail)
    count = ((btrecords_total_size - btlog_size)/btrecord_size)

    while count and (zstack_index != 0xffffff):
        zstack_record_offset = zstack_index * btrecord_size
        zstack_record = kern.GetValueFromAddress(btrecords + zstack_record_offset, 'btlog_record_t *')
        ShowZStackRecord(zstack_record, zstack_index, depth, unsigned(btlog_ptr.active_element_count))
        zstack_index = zstack_record.next
        count -= 1

# EndMacro : zstack_inorder

# Macro: findoldest

@lldb_command('findoldest')
def FindOldest(cmd_args=None):
    """
    """
    print "***** DEPRECATED ***** use 'zstack_findleak' macro instead."
    return
# EndMacro : findoldest

# Macro : zstack_findleak

@lldb_command('zstack_findleak')
def zstack_findleak(cmd_args=None):
    """ Zone leak debugging: search the log and print the stack with the most active references
        in the stack trace.
        Usage: zstack_findleak <btlog address>

        This is useful for verifying a suspected stack as being the source of
        the leak.
    """
    btlog_ptr = kern.GetValueFromAddress(cmd_args[0], 'btlog_t *')
    btrecord_size = unsigned(btlog_ptr.btrecord_size)
    btrecords = unsigned(btlog_ptr.btrecords)

    cpcs_index = unsigned(btlog_ptr.head)
    depth = unsigned(btlog_ptr.btrecord_btdepth)
    highref = 0
    highref_index = 0
    highref_record = 0

    while cpcs_index != 0xffffff:
        cpcs_record_offset = cpcs_index * btrecord_size
        cpcs_record = kern.GetValueFromAddress(btrecords + cpcs_record_offset, 'btlog_record_t *')
        if cpcs_record.ref_count > highref:
                highref_record = cpcs_record
                highref = cpcs_record.ref_count
                highref_index = cpcs_index
        cpcs_index = cpcs_record.next
    ShowZStackRecord(highref_record, highref_index, depth, unsigned(btlog_ptr.active_element_count))

# EndMacro: zstack_findleak

# Macro: findelem

@lldb_command('findelem')
def FindElem(cmd_args=None):
    """
    """
    print "***** DEPRECATED ***** use 'zstack_findelem' macro instead."
    return
# EndMacro: findelem

@lldb_command('zstack_findelem')
def ZStackFindElem(cmd_args=None):
    """ Zone corruption debugging: search the zone log and print out the stack traces for all log entries that
        refer to the given zone element.
        Usage: zstack_findelem <btlog addr> <elem addr>

        When the kernel panics due to a corrupted zone element, get the
        element address and use this command.  This will show you the stack traces of all logged zalloc and
        zfree operations which tells you who touched the element in the recent past.  This also makes
        double-frees readily apparent.
    """
    if not cmd_args:
        print ZStackFindElem.__doc__
        return
    if int(kern.globals.log_records) == 0 or unsigned(kern.globals.corruption_debug_flag) == 0:
        print "Zone logging with corruption detection not enabled. Add '-zc zlog=<zone name>' to boot-args."
        return

    btlog_ptr = kern.GetValueFromAddress(cmd_args[0], 'btlog_t *')
    target_element = unsigned(kern.GetValueFromAddress(cmd_args[1], 'void *'))

    btrecord_size = unsigned(btlog_ptr.btrecord_size)
    btrecords = unsigned(btlog_ptr.btrecords)
    depth = unsigned(btlog_ptr.btrecord_btdepth)

    prev_op = -1
    scan_items = 0
    hashelem = cast(btlog_ptr.elem_linkage_un.element_hash_queue.tqh_first, 'btlog_element_t *')
    if (target_element >> 32) != 0:
        target_element = target_element ^ 0xFFFFFFFFFFFFFFFF
    else:
        target_element = target_element ^ 0xFFFFFFFF
    while hashelem != 0:
        if unsigned(hashelem.elem) == target_element:
            recindex = hashelem.recindex
            recoffset = recindex * btrecord_size
            record = kern.GetValueFromAddress(btrecords + recoffset, 'btlog_record_t *')
            out_str = ('-' * 8)
            if record.operation == 1:
               out_str += "OP: ALLOC. "
            else:
               out_str += "OP: FREE.  "
            out_str += "Stack Index {0: <d} {1: <s}\n".format(recindex, ('-' * 8))
            print out_str
            print GetBtlogBacktrace(depth, record)
            print " \n"
            if int(record.operation) == prev_op:
                print "{0: <s} DOUBLE OP! {1: <s}".format(('*' * 8), ('*' * 8))
                return
            prev_op = int(record.operation)
            scan_items = 0
        hashelem = cast(hashelem.element_hash_link.tqe_next, 'btlog_element_t *')
        scan_items += 1
        if scan_items % 100 == 0:
           print "Scanning is ongoing. {0: <d} items scanned since last check." .format(scan_items)

# EndMacro: zstack_findelem

@lldb_command('zstack_findtop', 'N:')
def ShowZstackTop(cmd_args=None, cmd_options={}):
    """ Zone leak debugging: search the log and print the stacks with the most active references
        in the stack trace.

        Usage: zstack_findtop [-N <n-stacks>] <btlog-addr>
    """

    if not cmd_args:
        raise ArgumentError('Missing required btlog address argument')

    n = 5
    if '-N' in cmd_options:
        n = int(cmd_options['-N'])

    btlog_ptr = kern.GetValueFromAddress(cmd_args[0], 'btlog_t *')
    btrecord_size = unsigned(btlog_ptr.btrecord_size)
    btrecords = unsigned(btlog_ptr.btrecords)

    cpcs_index = unsigned(btlog_ptr.head)
    depth = unsigned(btlog_ptr.btrecord_btdepth)

    records = []
    while cpcs_index != 0xffffff:
        cpcs_record_offset = cpcs_index * btrecord_size
        cpcs_record = kern.GetValueFromAddress(btrecords + cpcs_record_offset, 'btlog_record_t *')
        cpcs_record.index = cpcs_index
        records.append(cpcs_record)
        cpcs_index = cpcs_record.next

    recs = sorted(records, key=lambda x: x.ref_count, reverse=True)

    for rec in recs[:n]:
        ShowZStackRecord(rec, rec.index, depth, unsigned(btlog_ptr.active_element_count))

# EndMacro: zstack_findtop

# Macro: btlog_find

@lldb_command('btlog_find', "AS")
def BtlogFind(cmd_args=None, cmd_options={}):
    """
    """
    print "***** DEPRECATED ***** use 'zstack_findelem' macro instead."
    return

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

def GetBtlogBacktrace(depth, zstack_record):
    """ Helper routine for getting a BT Log record backtrace stack.
        params:
            depth:int - The depth of the zstack record
            zstack_record:btlog_record_t * - A BTLog record
        returns:
            str - string with backtrace in it.
    """
    out_str = ''
    frame = 0
    if not zstack_record:
        return "Zstack record none!"

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
    return out_str

def ShowZStackRecord(zstack_record, zstack_index, btrecord_btdepth, elements_count):
    """ Helper routine for printing a single zstack record
        params:
            zstack_record:btlog_record_t * -  A BTLog record
            zstack_index:int - Index for the record in the BTLog table
        returns:
            None
    """
    out_str = ('-' * 8)
    if zstack_record.operation == 1:
        out_str += "ALLOC.  "
    else:
        out_str += "FREE.   "
    out_str += "Stack Index {0: <d} with active refs {1: <d} of {2: <d} {3: <s}\n".format(zstack_index, zstack_record.ref_count, elements_count, ('-' * 8))
    print out_str
    print GetBtlogBacktrace(btrecord_btdepth, zstack_record)
    print " \n"

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


# Macro: showselectmem
@lldb_command('showselectmem', "S:")
def ShowSelectMem(cmd_args=None, cmd_options={}):
    """ Show memory cached by threads on calls to select.

        usage: showselectmem [-v]
            -v        : print each thread's memory
                        (one line per thread with non-zero select memory)
            -S {addr} : Find the thread whose thread-local select set
                        matches the given address
    """
    verbose = False
    opt_wqs = 0
    if config['verbosity'] > vHUMAN:
        verbose = True
    if "-S" in cmd_options:
        opt_wqs = unsigned(kern.GetValueFromAddress(cmd_options["-S"], 'uint64_t *'))
        if opt_wqs == 0:
            raise ArgumentError("Invalid waitq set address: {:s}".format(cmd_options["-S"]))
    selmem = 0
    if verbose:
        print "{:18s} {:10s} {:s}".format('Task', 'Thread ID', 'Select Mem (bytes)')
    for t in kern.tasks:
        for th in IterateQueue(t.threads, 'thread *', 'task_threads'):
            uth = Cast(th.uthread, 'uthread *');
            wqs = 0
            if hasattr(uth, 'uu_allocsize'): # old style
                thmem = uth.uu_allocsize
                wqs = uth.uu_wqset
            elif hasattr(uth, 'uu_wqstate_sz'): # new style
                thmem = uth.uu_wqstate_sz
                wqs = uth.uu_wqset
            else:
                print "What kind of uthread is this?!"
                return
            if opt_wqs and opt_wqs == unsigned(wqs):
                print "FOUND: {:#x} in thread: {:#x} ({:#x})".format(opt_wqs, unsigned(th), unsigned(th.thread_id))
            if verbose and thmem > 0:
                print "{:<#18x} {:<#10x} {:d}".format(unsigned(t), unsigned(th.thread_id), thmem)
            selmem += thmem
    print '-'*40
    print "Total: {:d} bytes ({:d} kbytes)".format(selmem, selmem/1024)
# Endmacro: showselectmem


# Macro: showtaskvme
@lldb_command('showtaskvme', "PS")
def ShowTaskVmeHelper(cmd_args=None, cmd_options={}):
    """ Display a summary list of the specified vm_map's entries
        Usage: showtaskvme <task address>  (ex. showtaskvme 0x00ataskptr00 )
        Use -S flag to show VM object shadow chains
        Use -P flag to show pager info (mapped file, compressed pages, ...)
    """
    show_pager_info = False
    show_all_shadows = False
    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    ShowTaskVMEntries(task, show_pager_info, show_all_shadows)

@lldb_command('showallvme', "PS")
def ShowAllVME(cmd_args=None, cmd_options={}):
    """ Routine to print a summary listing of all the vm map entries
        Go Through each task in system and show the vm memory regions
        Use -S flag to show VM object shadow chains
        Use -P flag to show pager info (mapped file, compressed pages, ...)
    """
    show_pager_info = False
    show_all_shadows = False
    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    for task in kern.tasks:
        ShowTaskVMEntries(task, show_pager_info, show_all_shadows)

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
    page_size = kern.globals.page_size
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

    hdr_format = "{:>6s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s} {:<20s} {:1s}"
    print hdr_format.format('#ents', 'wired', 'vsize', 'rsize', 'NEW RSIZE', 'max rsize', 'internal', 'external', 'reusable', 'compressed', 'compressed', 'compressed', 'pid', 'command', '')
    print hdr_format.format('', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(current)', '(peak)', '(lifetime)', '', '', '')
    entry_format = "{m.hdr.nentries: >6d} {s.wired_count: >10d} {vsize: >10d} {s.resident_count: >10d} {s.new_resident_count: >10d} {s.resident_max: >10d} {s.internal: >10d} {s.external: >10d} {s.reusable: >10d} {s.compressed: >10d} {s.compressed_peak: >10d} {s.compressed_lifetime: >10d} {p.p_pid: >10d} {p.p_comm: <20s} {s.error}"

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

        print entry_format.format(p=proc, m=vmmap, vsize=(unsigned(vmmap.size) / page_size), t=task, s=vmstats)


def ShowTaskVMEntries(task, show_pager_info, show_all_shadows):
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
        print GetVMEntrySummary(vme, show_pager_info, show_all_shadows)
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
        print "Invalid argument.", ShowMapVME.__doc__
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
    first_free = 0
    if int(vmmap.holelistenabled) == 0: first_free = vmmap.f_s._first_free
    out_string += format_string.format(vmmap, vmmap.pmap, vm_size, vmmap.hdr.nentries, resident_pages, vmmap.hint, first_free)
    return out_string

@lldb_type_summary(['vm_map_entry'])
@header("{0: <20s} {1: <20s} {2: <5s} {3: >7s} {4: <20s} {5: <20s}".format("entry", "start", "prot", "#page", "object", "offset"))
def GetVMEntrySummary(vme):
    """ Display vm entry specific information. """
    page_size = kern.globals.page_size
    out_string = ""
    format_string = "{0: <#020x} {1: <#20x} {2: <1x}{3: <1x}{4: <3s} {5: >7d} {6: <#020x} {7: <#020x}"
    vme_protection = int(vme.protection)
    vme_max_protection = int(vme.max_protection)
    vme_extra_info_str ="SC-Ds"[int(vme.inheritance)]
    if int(vme.is_sub_map) != 0 :
        vme_extra_info_str +="s"
    elif int(vme.needs_copy) != 0 :
        vme_extra_info_str +="n"
    num_pages = (unsigned(vme.links.end) - unsigned(vme.links.start)) / page_size
    out_string += format_string.format(vme, vme.links.start, vme_protection, vme_max_protection, vme_extra_info_str, num_pages, vme.vme_object.vmo_object, vme.vme_offset)
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
@header("{0: <20s} {1: <20s} {2: <20s} {3: >3s} {4: >5s} {5: <20s} {6: <20s} {7: >20s} {8: <30s}".format('kmod_info', 'address', 'size', 'id', 'refs', 'TEXT exec', 'size', 'version', 'name'))
def GetKextSummary(kmod):
    """ returns a string representation of kext information
    """
    out_string = ""
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x} {3: >3d} {4: >5d} {5: <#020x} {6: <#020x} {7: >20s} {8: <30s}"
    segments, sections = GetAllSegmentsAndSectionsFromDataInMemory(unsigned(kmod.address), unsigned(kmod.size))
    text_segment = macho.get_text_segment(segments)
    if not text_segment:
        text_segment = segments[0]
    out_string += format_string.format(kmod, kmod.address, kmod.size, kmod.id, kmod.reference_count, text_segment.vmaddr, text_segment.vmsize, kmod.version, kmod.name)
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
    kextuuidinfo = GetKextLoadInformation(show_progress=(config['verbosity'] > vHUMAN))
    print "{: <36s} ".format("UUID") + GetKextSummary.header
    for kval in IterateLinkedList(kmod_val, 'next'):
        uuid = "........-....-....-....-............"
        kaddr = unsigned(kval.address)
        found_kext_summary = None
        for l in kextuuidinfo :
            if kaddr == int(l[3],16):
                uuid = l[0]
                found_kext_summary = l
                break
        if found_kext_summary:
            _ksummary = GetKextSummary(found_kext_summary[7])
        else:
            _ksummary = GetKextSummary(kval)
        print uuid + " " + _ksummary

def GetKmodWithAddr(addr):
    """ Go through kmod list and find one with begin_addr as addr
        returns: None if not found. else a cvalue of type kmod
    """
    kmod_val = kern.globals.kmod
    for kval in IterateLinkedList(kmod_val, 'next'):
        if addr == unsigned(kval.address):
                return kval
    return None

def GetAllSegmentsAndSectionsFromDataInMemory(address, size):
    """ reads memory at address and parses mach_header to get segment and section information
        returns: Tuple of (segments_list, sections_list) like ([MachOSegment,...], [MachOSegment, ...])
            where MachOSegment has fields like 'name vmaddr vmsize fileoff filesize'
            if TEXT segment is not found a dummy segment & section with address, size is returned.
    """
    cache_hash = "kern.kexts.segments.{}.{}".format(address, size)
    cached_result = caching.GetDynamicCacheData(cache_hash,())
    if cached_result:
        return cached_result

    defval = macho.MachOSegment('__TEXT', address, size, 0, size)
    if address == 0 or size == 0:
        return ([defval], [defval])

    ## if int(kern.globals.gLoadedKextSummaries.version) <= 2:
    # until we have separate version. we will pay penalty only on arm64 devices
    if not kern.arch.startswith('arm64'):
        return ([defval], [defval])

    restrict_size_to_read = 1536
    machoObject = None
    while machoObject is None:
        err = lldb.SBError()
        size_to_read = min(size, restrict_size_to_read)
        data = LazyTarget.GetProcess().ReadMemory(address, size_to_read, err)
        if not err.Success():
            print "Failed to read memory at {} and size {}".format(address, size_to_read)
            return ([defval], [defval])
        try:
            m = macho.MemMacho(data, len(data))
            machoObject = m
        except Exception as e:
            if str(e.message).find('unpack requires a string argument') >= 0:
                # this may be due to short read of memory. Lets do double read size.
                restrict_size_to_read *= 2
                debuglog("Bumping mach header read size to {}".format(restrict_size_to_read))
                continue
            else:
                print "Failed to read MachO for address {} errormessage: {}".format(address, e.message)
                return ([defval], [defval])
    # end of while loop. We have machoObject defined
    segments = machoObject.get_segments_with_name('')
    sections = machoObject.get_sections_with_name('')
    rval = (segments, sections)
    caching.SaveDynamicCacheData(cache_hash, rval)
    return rval

def GetKextLoadInformation(addr=0, show_progress=False):
    """ Extract the kext uuid and load address information from the kernel data structure.
        params:
            addr - int - optional integer that is the address to search for.
        returns:
            [] - array with each entry of format
                ( 'UUID', 'Hex Load Address of __TEXT or __TEXT_EXEC section', 'name',
                  'addr of macho header', [macho.MachOSegment,..], [MachoSection,...], kext, kmod_obj)
    """
    cached_result = caching.GetDynamicCacheData("kern.kexts.loadinformation", [])
    ## if specific addr is provided then ignore caching
    if cached_result and not addr:
        return cached_result

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
        if show_progress:
            print "progress: {}/{}".format(i, total_summaries)
        tmpaddress = unsigned(summaries_begin) + (i * entry_size)
        current_kext = kern.GetValueFromAddress(tmpaddress, 'OSKextLoadedKextSummary *')
        # code to extract macho information
        segments, sections = GetAllSegmentsAndSectionsFromDataInMemory(unsigned(current_kext.address), unsigned(current_kext.size))
        seginfo = macho.get_text_segment(segments)
        if not seginfo:
            seginfo = segments[0]
        kmod_obj = GetKmodWithAddr(unsigned(current_kext.address))
        if addr != 0 :
            if addr == unsigned(current_kext.address) or addr == seginfo.vmaddr:
                return [(GetUUIDSummary(current_kext.uuid) , hex(seginfo.vmaddr).rstrip('L'), str(current_kext.name), hex(current_kext.address), segments, seginfo, current_kext, kmod_obj)]
        retval.append((GetUUIDSummary(current_kext.uuid) , hex(seginfo.vmaddr).rstrip('L'), str(current_kext.name), hex(current_kext.address), segments, seginfo, current_kext, kmod_obj))

    if not addr:
        caching.SaveDynamicCacheData("kern.kexts.loadinformation", retval)
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

def FindKmodNameForAddr(addr):
    """ Given an address, return the name of the kext containing that address
    """
    addr = unsigned(addr)
    all_kexts_info = GetKextLoadInformation()
    for kinfo in all_kexts_info:
        segment = macho.get_segment_with_addr(kinfo[4], addr)
        if segment:
            return kinfo[7].name
    return None


@lldb_command('addkextaddr')
def AddKextAddr(cmd_args=[]):
    """ Given an address, load the kext which contains that address
        Syntax: (lldb) addkextaddr <addr>
    """
    if len(cmd_args) < 1:
        raise ArgumentError("Insufficient arguments")

    addr = ArgumentStringToInt(cmd_args[0])
    all_kexts_info = GetKextLoadInformation()
    kernel_uuid = str(kern.globals.kernel_uuid_string).lower()
    found_kinfo = None
    found_segment = None
    for kinfo in all_kexts_info:
        segment = macho.get_segment_with_addr(kinfo[4], addr)
        if segment:
            print GetKextSummary.header
            print GetKextSummary(kinfo[7]) + " segment: {} offset = {:#0x}".format(segment.name, (addr - segment.vmaddr))
            cur_uuid = kinfo[0].lower()
            if (kernel_uuid == cur_uuid):
                print "(builtin)"
            else:
                print "Fetching dSYM for %s" % cur_uuid
                info = dsymForUUID(cur_uuid)
                if info and 'DBGSymbolRichExecutable' in info:
                    print "Adding dSYM (%s) for %s" % (cur_uuid, info['DBGSymbolRichExecutable'])
                    addDSYM(cur_uuid, info)
                    loadDSYM(cur_uuid, int(kinfo[1],16), kinfo[4])
                else:
                    print "Failed to get symbol info for %s" % cur_uuid
            return


@lldb_command('showkmodaddr')
def ShowKmodAddr(cmd_args=[]):
    """ Given an address, print the offset and name for the kmod containing it
        Syntax: (lldb) showkmodaddr <addr>
    """
    if len(cmd_args) < 1:
        raise ArgumentError("Insufficient arguments")

    addr = ArgumentStringToInt(cmd_args[0])
    all_kexts_info = GetKextLoadInformation()
    found_kinfo = None
    found_segment = None
    for kinfo in all_kexts_info:
        s = macho.get_segment_with_addr(kinfo[4], addr)
        if s:
            found_segment = s
            found_kinfo = kinfo
            break
    if found_kinfo:
        print GetKextSummary.header
        print GetKextSummary(found_kinfo[7]) + " segment: {} offset = {:#0x}".format(found_segment.name, (addr - found_segment.vmaddr))
        return True
    return False


@lldb_command('addkext','AF:N:')
def AddKextSyms(cmd_args=[], cmd_options={}):
    """ Add kext symbols into lldb.
        This command finds symbols for a uuid and load the required executable
        Usage:
            addkext <uuid> : Load one kext based on uuid. eg. (lldb)addkext 4DD2344C0-4A81-3EAB-BDCF-FEAFED9EB73E
            addkext -F <abs/path/to/executable> <load_address> : Load kext executable at specified load address
            addkext -N <name> : Load one kext that matches the name provided. eg. (lldb) addkext -N corecrypto
            addkext -N <name> -A: Load all kext that matches the name provided. eg. to load all kext with Apple in name do (lldb) addkext -N Apple -A
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

        slide_value = None
        sections = None
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
                        sections = k[4]
                        debuglog("found the slide %s for uuid %s" % (k[1], k[0]))
        if slide_value is None:
            raise ArgumentError("Unable to find load address for module described at %s " % exec_full_path)

        if not sections:
            cmd_str = "target modules load --file %s --slide %s" % ( exec_full_path, str(slide_value))
            debuglog(cmd_str)
        else:
            cmd_str = "target modules load --file {}   ".format(exec_full_path)
            sections_str = ""
            for s in sections:
                sections_str += " {} {:#0x} ".format(s.name, s.vmaddr)
            cmd_str += sections_str
            debuglog(cmd_str)

        lldb.debugger.HandleCommand(cmd_str)

        kern.symbolicator = None
        return True

    all_kexts_info = GetKextLoadInformation()
    kernel_uuid = str(kern.globals.kernel_uuid_string).lower()

    if "-N" in cmd_options:
        kext_name = cmd_options["-N"]
        kext_name_matches = GetLongestMatchOption(kext_name, [str(x[2]) for x in all_kexts_info], True)
        if len(kext_name_matches) != 1 and "-A" not in cmd_options:
            print "Ambiguous match for name: {:s}".format(kext_name)
            if len(kext_name_matches) > 0:
                print  "Options are:\n\t" + "\n\t".join(kext_name_matches)
            return
        debuglog("matched the kext to name %s and uuid %s" % (kext_name_matches[0], kext_name))
        for cur_knm in kext_name_matches:
            for x in all_kexts_info:
                if cur_knm == x[2]:
                    cur_uuid = x[0].lower()
                    if (kernel_uuid == cur_uuid):
                        print "(builtin)"
                    else:
                        print "Fetching dSYM for {:s}".format(cur_uuid)
                        info = dsymForUUID(cur_uuid)
                        if info and 'DBGSymbolRichExecutable' in info:
                            print "Adding dSYM ({0:s}) for {1:s}".format(cur_uuid, info['DBGSymbolRichExecutable'])
                            addDSYM(cur_uuid, info)
                            loadDSYM(cur_uuid, int(x[1],16), x[4])
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
            if (kernel_uuid != cur_uuid):
                print "Fetching dSYM for %s" % cur_uuid
                info = dsymForUUID(cur_uuid)
                if info and 'DBGSymbolRichExecutable' in info:
                    print "Adding dSYM (%s) for %s" % (cur_uuid, info['DBGSymbolRichExecutable'])
                    addDSYM(cur_uuid, info)
                    loadDSYM(cur_uuid, int(k_info[1],16), k_info[4])
                else:
                    print "Failed to get symbol info for %s" % cur_uuid
        #end of for loop
    kern.symbolicator = None
    return True



lldb_alias('showkmod', 'showkmodaddr')
lldb_alias('showkext', 'showkmodaddr')
lldb_alias('showkextaddr', 'showkmodaddr')

@lldb_type_summary(['mount *'])
@header("{0: <20s} {1: <20s} {2: <20s} {3: <12s} {4: <12s} {5: <12s} {6: >6s} {7: <30s} {8: <35s} {9: <30s}".format('volume(mp)', 'mnt_data', 'mnt_devvp', 'flag', 'kern_flag', 'lflag', 'type', 'mnton', 'mntfrom', 'iosched supported'))
def GetMountSummary(mount):
    """ Display a summary of mount on the system
    """
    out_string = ("{mnt: <#020x} {mnt.mnt_data: <#020x} {mnt.mnt_devvp: <#020x} {mnt.mnt_flag: <#012x} " +
                  "{mnt.mnt_kern_flag: <#012x} {mnt.mnt_lflag: <#012x} {vfs.f_fstypename: >6s} " +
                  "{vfs.f_mntonname: <30s} {vfs.f_mntfromname: <35s} {iomode: <30s}").format(mnt=mount, vfs=mount.mnt_vfsstat, iomode=('Yes' if (mount.mnt_ioflags & 0x4) else 'No'))
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
            raise ValueError("Failed to read character at offset " + str(i) + ": " + err.GetCString())
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
    if lockf_flags & 0x400:
        vnode_lock_output += ("{: <8s}").format('ofd')
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
@header("{0: <20s} {1: >8s} {2: >8s} {3: <20s} {4: <6s} {5: <20s} {6: <6s} {7: <6s} {8: <35s}".format('vnode', 'usecount', 'iocount', 'v_data', 'vtype', 'parent', 'mapped', 'cs_version', 'name'))
def GetVnodeSummary(vnode):
    """ Get a summary of important information out of vnode
    """
    out_str = ''
    format_string = "{0: <#020x} {1: >8d} {2: >8d} {3: <#020x} {4: <6s} {5: <#020x} {6: <6s} {7: <6s} {8: <35s}"
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
    csblob_version = '-'
    if (vtype == 1) and (vnode.v_un.vu_ubcinfo != 0):
        csblob_version = '{: <6d}'.format(vnode.v_un.vu_ubcinfo.cs_add_gen)
        # Check to see if vnode is mapped/unmapped
        if (vnode.v_un.vu_ubcinfo.ui_flags & 0x8) != 0:
            mapped = '1'
        else:
            mapped = '0'
    out_str += format_string.format(vnode, usecount, iocount, v_data_ptr, vtype_str, parent_ptr, mapped, csblob_version, name)
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
    print '\n' + '{0: <5s} {1: <7s} {2: <20s} '.format('fd', 'flags', 'fileglob') + GetVnodeSummary.header
    # Hack to get around <rdar://problem/12879494> llb fails to cast addresses to double pointers
    fpptr = Cast(fdptr.fd_ofiles, 'uint64_t *')
    while count < fdptr.fd_nfiles:
        fpp = dereference(fpptr)
        fproc = kern.GetValueFromAddress(int(fpp), 'fileproc *')
        if int(fproc) != 0:
            fglob = dereference(fproc).f_fglob
            flags = ""
            if (int(fglob) != 0) and (int(fglob.fg_ops.fo_type) == 1):
                if (fdptr.fd_ofileflags[count] & 1):    flags += 'E'
                if (fdptr.fd_ofileflags[count] & 2):    flags += 'F'
                if (fdptr.fd_ofileflags[count] & 4):    flags += 'R'
                if (fdptr.fd_ofileflags[count] & 8):    flags += 'C'
                print '{0: <5d} {1: <7s} {2: <#020x} '.format(count, flags, fglob) + GetVnodeSummary(Cast(fglob.fg_data, 'vnode *'))
        count += 1
        fpptr = kern.GetValueFromAddress(int(fpptr) + kern.ptrsize,'uint64_t *')

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
        out_str = "Lock Type            : MUTEX\n"
        if mtx.lck_mtx_tag == 0x07ff1007 :
            out_str += "Tagged as indirect, printing ext lock at: {:#x}\n".format(mtx.lck_mtx_ptr)
            mtx = Cast(mtx.lck_mtx_ptr, 'lck_mtx_t *')

        if mtx.lck_mtx_tag == 0x07fe2007 :
            out_str += "*** Tagged as DESTROYED ({:#x}) ***\n".format(mtx.lck_mtx_tag)

        out_str += "Owner Thread        : {mtx.lck_mtx_owner:#x}\n".format(mtx=mtx)
        out_str += "Number of Waiters   : {mtx.lck_mtx_waiters:#x}\n".format(mtx=mtx)
        out_str += "ILocked             : {mtx.lck_mtx_ilocked:#x}\n".format(mtx=mtx)
        out_str += "MLocked             : {mtx.lck_mtx_mlocked:#x}\n".format(mtx=mtx)
        out_str += "Promoted            : {mtx.lck_mtx_promoted:#x}\n".format(mtx=mtx)
        out_str += "Pri                 : {mtx.lck_mtx_pri:#x}\n".format(mtx=mtx)
        out_str += "Spin                : {mtx.lck_mtx_spin:#x}\n".format(mtx=mtx)
        out_str += "Ext                 : {mtx.lck_mtx_is_ext:#x}\n".format(mtx=mtx)
        if mtx.lck_mtx_pad32 == 0xFFFFFFFF :
            out_str += "Canary (valid)      : {mtx.lck_mtx_pad32:#x}\n".format(mtx=mtx)
        else:
            out_str += "Canary (INVALID)    : {mtx.lck_mtx_pad32:#x}\n".format(mtx=mtx)
        return out_str

    out_str = "Lock Type\t\t: MUTEX\n"
    out_str += "Owner Thread\t\t: {:#x}".format(mtx.lck_mtx_data & ~0x3)
    if (mtx.lck_mtx_data & ~0x3) == 0xfffffff0:
        out_str += " Held as spinlock"
    out_str += "\nNumber of Waiters\t: {:d}\n".format(mtx.lck_mtx_waiters)
    out_str += "Flags\t\t\t: "
    if mtx.lck_mtx_data & 0x1:
        out_str += "[Interlock Locked] "
    if mtx.lck_mtx_data & 0x2:
        out_str += "[Wait Flag]"
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

    lock_data = spinlock.hwlock.lock_data
    if lock_data == 1:
        out_str += "Invalid state: interlock is locked but no owner\n"
        return out_str
    out_str += "Owner Thread\t\t: "
    if lock_data == 0:
        out_str += "None\n"
    else:
        out_str += "{:#x}\n".format(lock_data & ~0x1)
        if (lock_data & 1) == 0:
            out_str += "Invalid state: owned but interlock bit is not set\n"
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
    addr = cmd_args[0]
    # from osfmk/arm/locks.h
    LCK_SPIN_TYPE = 0x11
    LCK_MTX_TYPE = 0x22
    if kern.arch == "x86_64":
        if "-M" in cmd_options:
            lock_mtx = kern.GetValueFromAddress(addr, 'lck_mtx_t *')
            summary_str = GetMutexLockSummary(lock_mtx)
        elif "-S" in cmd_options:
            lock_spin = kern.GetValueFromAddress(addr, 'lck_spin_t *')
            summary_str = GetSpinLockSummary(lock_spin)
        else:
            summary_str = "Please specify supported lock option(-M/-S)"

        print summary_str
    else:
        lock = kern.GetValueFromAddress(addr, 'uintptr_t *')
        if lock:
            lock_mtx = Cast(lock, 'lck_mtx_t*')
            if lock_mtx.lck_mtx_type == LCK_MTX_TYPE:
                summary_str = GetMutexLockSummary(lock_mtx)

            lock_spin = Cast(lock, 'lck_spin_t*')
            if lock_spin.type == LCK_SPIN_TYPE:
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
    if kern.arch != 'x86_64':
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
        mptr = kern.GetValueFromAddress(unsigned(boot_args.MemoryMap) + kern.VM_MIN_KERNEL_ADDRESS + unsigned(i*msize), 'EfiMemoryRange *')
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

@lldb_command('show_all_purgeable_objects')
def ShowAllPurgeableVmObjects(cmd_args=None):
    """ Routine to print a summary listing of all the purgeable vm objects
    """
    print "\n--------------------    VOLATILE OBJECTS    --------------------\n"
    ShowAllPurgeableVolatileVmObjects()
    print "\n--------------------  NON-VOLATILE OBJECTS  --------------------\n"
    ShowAllPurgeableNonVolatileVmObjects()

@lldb_command('show_all_purgeable_nonvolatile_objects')
def ShowAllPurgeableNonVolatileVmObjects(cmd_args=None):
    """ Routine to print a summary listing of all the vm objects in
        the purgeable_nonvolatile_queue
    """

    nonvolatile_total = lambda:None
    nonvolatile_total.objects = 0
    nonvolatile_total.vsize = 0
    nonvolatile_total.rsize = 0
    nonvolatile_total.wsize = 0
    nonvolatile_total.csize = 0
    nonvolatile_total.disowned_objects = 0
    nonvolatile_total.disowned_vsize = 0
    nonvolatile_total.disowned_rsize = 0
    nonvolatile_total.disowned_wsize = 0
    nonvolatile_total.disowned_csize = 0

    queue_len = kern.globals.purgeable_nonvolatile_count
    queue_head = kern.globals.purgeable_nonvolatile_queue

    print 'purgeable_nonvolatile_queue:{: <#018x}  purgeable_volatile_count:{:d}\n'.format(kern.GetLoadAddressForSymbol('purgeable_nonvolatile_queue'),queue_len)
    print 'N:non-volatile  V:volatile  E:empty  D:deny\n'

    print '{:>6s} {:<6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s}   {:>3s} {:18s} {:>6s} {:<20s}\n'.format("#","#","object","P","refcnt","size (pages)","resid","wired","compressed","tag","owner","pid","process")
    idx = 0
    for object in IterateQueue(queue_head, 'struct vm_object *', 'objq'):
        idx += 1
        ShowPurgeableNonVolatileVmObject(object, idx, queue_len, nonvolatile_total)
    print "disowned objects:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(nonvolatile_total.disowned_objects, nonvolatile_total.disowned_vsize, nonvolatile_total.disowned_rsize, nonvolatile_total.disowned_wsize, nonvolatile_total.disowned_csize)
    print "     all objects:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(nonvolatile_total.objects, nonvolatile_total.vsize, nonvolatile_total.rsize, nonvolatile_total.wsize, nonvolatile_total.csize)


def ShowPurgeableNonVolatileVmObject(object, idx, queue_len, nonvolatile_total):
    """  Routine to print out a summary a VM object in purgeable_nonvolatile_queue
        params: 
            object - core.value : a object of type 'struct vm_object *'
        returns:
            None
    """
    page_size = kern.globals.page_size
    if object.purgable == 0:
        purgable = "N"
    elif object.purgable == 1:
        purgable = "V"
    elif object.purgable == 2:
        purgable = "E"
    elif object.purgable == 3:
        purgable = "D"
    else:
        purgable = "?"
    if object.pager == 0:
        compressed_count = 0
    else:
        compressor_pager = Cast(object.pager, 'compressor_pager *')
        compressed_count = compressor_pager.cpgr_num_slots_occupied

    print "{:>6d}/{:<6d} {: <#018x} {:1s} {:>6d} {:>16d} {:>10d} {:>10d} {:>10d}  {:>3d} {: <#018x} {:>6d} {:<20s}\n".format(idx,queue_len,object,purgable,object.ref_count,object.vo_un1.vou_size/page_size,object.resident_page_count,object.wired_page_count,compressed_count, object.vo_ledger_tag, object.vo_un2.vou_owner,GetProcPIDForObjectOwner(object.vo_un2.vou_owner),GetProcNameForObjectOwner(object.vo_un2.vou_owner))

    nonvolatile_total.objects += 1
    nonvolatile_total.vsize += object.vo_un1.vou_size/page_size
    nonvolatile_total.rsize += object.resident_page_count
    nonvolatile_total.wsize += object.wired_page_count
    nonvolatile_total.csize += compressed_count
    if object.vo_un2.vou_owner == 0:
        nonvolatile_total.disowned_objects += 1
        nonvolatile_total.disowned_vsize += object.vo_un1.vou_size/page_size
        nonvolatile_total.disowned_rsize += object.resident_page_count
        nonvolatile_total.disowned_wsize += object.wired_page_count
        nonvolatile_total.disowned_csize += compressed_count


@lldb_command('show_all_purgeable_volatile_objects')
def ShowAllPurgeableVolatileVmObjects(cmd_args=None):
    """ Routine to print a summary listing of all the vm objects in
        the purgeable queues
    """
    volatile_total = lambda:None
    volatile_total.objects = 0
    volatile_total.vsize = 0
    volatile_total.rsize = 0
    volatile_total.wsize = 0
    volatile_total.csize = 0
    volatile_total.disowned_objects = 0
    volatile_total.disowned_vsize = 0
    volatile_total.disowned_rsize = 0
    volatile_total.disowned_wsize = 0
    volatile_total.disowned_csize = 0

    purgeable_queues = kern.globals.purgeable_queues
    print "---------- OBSOLETE\n"
    ShowPurgeableQueue(purgeable_queues[0], volatile_total)
    print "\n\n---------- FIFO\n"
    ShowPurgeableQueue(purgeable_queues[1], volatile_total)
    print "\n\n---------- LIFO\n"
    ShowPurgeableQueue(purgeable_queues[2], volatile_total)

    print "disowned objects:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(volatile_total.disowned_objects, volatile_total.disowned_vsize, volatile_total.disowned_rsize, volatile_total.disowned_wsize, volatile_total.disowned_csize)
    print "     all objects:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(volatile_total.objects, volatile_total.vsize, volatile_total.rsize, volatile_total.wsize, volatile_total.csize)
    purgeable_count = kern.globals.vm_page_purgeable_count
    purgeable_wired_count = kern.globals.vm_page_purgeable_wired_count
    if purgeable_count != volatile_total.rsize or purgeable_wired_count != volatile_total.wsize:
        mismatch = "<---------  MISMATCH\n"
    else:
        mismatch = ""
    print "vm_page_purgeable_count:                           resident:{:<10d}  wired:{:<10d}  {:s}\n".format(purgeable_count, purgeable_wired_count, mismatch)


def ShowPurgeableQueue(qhead, volatile_total):
    print "----- GROUP 0\n"
    ShowPurgeableGroup(qhead.objq[0], volatile_total)
    print "----- GROUP 1\n"
    ShowPurgeableGroup(qhead.objq[1], volatile_total)
    print "----- GROUP 2\n"
    ShowPurgeableGroup(qhead.objq[2], volatile_total)
    print "----- GROUP 3\n"
    ShowPurgeableGroup(qhead.objq[3], volatile_total)
    print "----- GROUP 4\n"
    ShowPurgeableGroup(qhead.objq[4], volatile_total)
    print "----- GROUP 5\n"
    ShowPurgeableGroup(qhead.objq[5], volatile_total)
    print "----- GROUP 6\n"
    ShowPurgeableGroup(qhead.objq[6], volatile_total)
    print "----- GROUP 7\n"
    ShowPurgeableGroup(qhead.objq[7], volatile_total)

def ShowPurgeableGroup(qhead, volatile_total):
    idx = 0
    for object in IterateQueue(qhead, 'struct vm_object *', 'objq'):
        if idx == 0:
#            print "{:>6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s}   {:18s} {:>6s} {:<20s} {:18s} {:>6s} {:<20s} {:s}\n".format("#","object","P","refcnt","size (pages)","resid","wired","compressed","owner","pid","process","volatilizer","pid","process","")
            print "{:>6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s}   {:>3s} {:18s} {:>6s} {:<20s}\n".format("#","object","P","refcnt","size (pages)","resid","wired","compressed","tag","owner","pid","process")
        idx += 1
        ShowPurgeableVolatileVmObject(object, idx, volatile_total)

def ShowPurgeableVolatileVmObject(object, idx, volatile_total):
    """  Routine to print out a summary a VM object in a purgeable queue
        params: 
            object - core.value : a object of type 'struct vm_object *'
        returns:
            None
    """
##   if int(object.vo_un2.vou_owner) != int(object.vo_purgeable_volatilizer):
#        diff=" !="
##    else:
#        diff="  "
    page_size = kern.globals.page_size
    if object.purgable == 0:
        purgable = "N"
    elif object.purgable == 1:
        purgable = "V"
    elif object.purgable == 2:
        purgable = "E"
    elif object.purgable == 3:
        purgable = "D"
    else:
        purgable = "?"
    if object.pager == 0:
        compressed_count = 0
    else:
        compressor_pager = Cast(object.pager, 'compressor_pager *')
        compressed_count = compressor_pager.cpgr_num_slots_occupied
#    print "{:>6d} {: <#018x} {:1s} {:>6d} {:>16d} {:>10d} {:>10d} {:>10d} {: <#018x} {:>6d} {:<20s}   {: <#018x} {:>6d} {:<20s} {:s}\n".format(idx,object,purgable,object.ref_count,object.vo_un1.vou_size/page_size,object.resident_page_count,object.wired_page_count,compressed_count,object.vo_un2.vou_owner,GetProcPIDForObjectOwner(object.vo_un2.vou_owner),GetProcNameForObjectOwner(object.vo_un2.vou_owner),object.vo_purgeable_volatilizer,GetProcPIDForObjectOwner(object.vo_purgeable_volatilizer),GetProcNameForObjectOwner(object.vo_purgeable_volatilizer),diff)
    print "{:>6d} {: <#018x} {:1s} {:>6d} {:>16d} {:>10d} {:>10d} {:>10d}   {:>3d} {: <#018x} {:>6d} {:<20s}\n".format(idx,object,purgable,object.ref_count,object.vo_un1.vou_size/page_size,object.resident_page_count,object.wired_page_count,compressed_count, object.vo_ledger_tag, object.vo_un2.vou_owner,GetProcPIDForObjectOwner(object.vo_un2.vou_owner),GetProcNameForObjectOwner(object.vo_un2.vou_owner))
    volatile_total.objects += 1
    volatile_total.vsize += object.vo_un1.vou_size/page_size
    volatile_total.rsize += object.resident_page_count
    volatile_total.wsize += object.wired_page_count
    volatile_total.csize += compressed_count
    if object.vo_un2.vou_owner == 0:
        volatile_total.disowned_objects += 1
        volatile_total.disowned_vsize += object.vo_un1.vou_size/page_size
        volatile_total.disowned_rsize += object.resident_page_count
        volatile_total.disowned_wsize += object.wired_page_count
        volatile_total.disowned_csize += compressed_count


def GetCompressedPagesForObject(obj):
    """Stuff
    """
    pager = Cast(obj.pager, 'compressor_pager_t')
    return pager.cpgr_num_slots_occupied
    """  # commented code below
    if pager.cpgr_num_slots > 128:
        slots_arr = pager.cpgr_slots.cpgr_islots
        num_indirect_slot_ptr = (pager.cpgr_num_slots + 127) / 128
        index = 0
        compressor_slot = 0
        compressed_pages = 0
        while index < num_indirect_slot_ptr:
            compressor_slot = 0
            if slots_arr[index]:
                while compressor_slot < 128:
                    if slots_arr[index][compressor_slot]:
                        compressed_pages += 1
                    compressor_slot += 1
            index += 1
    else:
        slots_arr = pager.cpgr_slots.cpgr_dslots
        compressor_slot = 0
        compressed_pages = 0
        while compressor_slot < pager.cpgr_num_slots:
            if slots_arr[compressor_slot]:
                compressed_pages += 1
            compressor_slot += 1
    return compressed_pages
    """

def ShowTaskVMEntries(task, show_pager_info, show_all_shadows):
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
    showmapvme(task.map, 0, 0, show_pager_info, show_all_shadows, False)

@lldb_command("showmapvme", "A:B:PRST")
def ShowMapVME(cmd_args=None, cmd_options={}):
    """Routine to print out info about the specified vm_map and its vm entries
        usage: showmapvme <vm_map> [-A start] [-B end] [-S] [-P]
        Use -A <start> flag to start at virtual address <start>
        Use -B <end> flag to end at virtual address <end>
        Use -S flag to show VM object shadow chains
        Use -P flag to show pager info (mapped file, compressed pages, ...)
        Use -R flag to reverse order
        Use -T to show red-black tree pointers
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument.", ShowMapVME.__doc__
        return
    show_pager_info = False
    show_all_shadows = False
    show_rb_tree = False
    start_vaddr = 0
    end_vaddr = 0
    reverse_order = False
    if "-A" in cmd_options:
        start_vaddr = unsigned(int(cmd_options['-A'], 16))
    if "-B" in cmd_options:
        end_vaddr = unsigned(int(cmd_options['-B'], 16))
    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    if "-R" in cmd_options:
        reverse_order = True
    if "-T" in cmd_options:
        show_rb_tree = True
    map = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    showmapvme(map, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree)

@lldb_command("showvmobject", "A:B:PRST")
def ShowVMObject(cmd_args=None, cmd_options={}):
    """Routine to print out a VM object and its shadow chain
        usage: showvmobject <vm_object> [-S] [-P]
        -S: show VM object shadow chain
        -P: show pager info (mapped file, compressed pages, ...)
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument.", ShowMapVME.__doc__
        return
    show_pager_info = False
    show_all_shadows = False
    if "-P" in cmd_options:
        show_pager_info = True
    if "-S" in cmd_options:
        show_all_shadows = True
    object = kern.GetValueFromAddress(cmd_args[0], 'vm_object_t')
    showvmobject(object, 0, 0, show_pager_info, show_all_shadows)

def showvmobject(object, offset=0, size=0, show_pager_info=False, show_all_shadows=False):
    page_size = kern.globals.page_size
    vnode_pager_ops = kern.globals.vnode_pager_ops
    vnode_pager_ops_addr = unsigned(addressof(vnode_pager_ops))
    depth = 0
    if size == 0 and object != 0 and object.internal:
        size = object.vo_un1.vou_size
    while object != 0:
        depth += 1
        if show_all_shadows == False and depth != 1 and object.shadow != 0:
            offset += unsigned(object.vo_un2.vou_shadow_offset)
            object = object.shadow
            continue
        if object.copy_strategy == 0:
            copy_strategy="N"
        elif object.copy_strategy == 2:
            copy_strategy="D"
        elif object.copy_strategy == 4:
            copy_strategy="S"

        else:
            copy_strategy=str(object.copy_strategy)
        if object.internal:
            internal = "internal"
        else:
            internal = "external"
        purgeable = "NVED"[int(object.purgable)]
        pager_string = ""
        if object.phys_contiguous:
            pager_string = pager_string + "phys_contig {:#018x}:{:#018x} ".format(unsigned(object.vo_un2.vou_shadow_offset), unsigned(object.vo_un1.vou_size))
        pager = object.pager
        if show_pager_info and pager != 0:
            if object.internal:
                pager_string = pager_string + "-> compressed:{:d}".format(GetCompressedPagesForObject(object))
            elif unsigned(pager.mo_pager_ops) == vnode_pager_ops_addr:
                vnode_pager = Cast(pager,'vnode_pager *')
                pager_string = pager_string + "-> " + GetVnodePath(vnode_pager.vnode_handle)
            else:
                pager_string = pager_string + "-> {:s}:{: <#018x}".format(pager.mo_pager_ops.memory_object_pager_name, pager)
        print "{:>18d} {:#018x}:{:#018x} {: <#018x} ref:{:<6d} ts:{:1d} strat:{:1s} purg:{:1s} {:s} wtag:{:d} ({:d} {:d} {:d}) {:s}".format(depth,offset,offset+size,object,object.ref_count,object.true_share,copy_strategy,purgeable,internal,object.wire_tag,unsigned(object.vo_un1.vou_size)/page_size,object.resident_page_count,object.wired_page_count,pager_string)
#       print "        #{:<5d} obj {: <#018x} ref:{:<6d} ts:{:1d} strat:{:1s} {:s} size:{:<10d} wired:{:<10d} resident:{:<10d} reusable:{:<10d}".format(depth,object,object.ref_count,object.true_share,copy_strategy,internal,object.vo_un1.vou_size/page_size,object.wired_page_count,object.resident_page_count,object.reusable_page_count)
        offset += unsigned(object.vo_un2.vou_shadow_offset)
        object = object.shadow

def showmapvme(map, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order=False, show_rb_tree=False):
    rsize = 0
    if map.pmap != 0:
        rsize = int(map.pmap.stats.resident_count)
    print "{:<18s} {:<18s} {:<18s} {:>10s} {:>18s} {:>18s}:{:<18s}".format("vm_map","pmap","size","#ents","rsize","start","end")
    print "{: <#018x} {: <#018x} {:#018x} {:>10d} {:>18d} {:#018x}:{:#018x}".format(map,map.pmap,unsigned(map.size),map.hdr.nentries,rsize,map.hdr.links.start,map.hdr.links.end)
    showmaphdrvme(map.hdr, map.pmap, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree)

def showmapcopyvme(mapcopy, start_vaddr=0, end_vaddr=0, show_pager_info=True, show_all_shadows=True, reverse_order=False, show_rb_tree=False):
    print "{:<18s} {:<18s} {:<18s} {:>10s} {:>18s} {:>18s}:{:<18s}".format("vm_map_copy","pmap","size","#ents","rsize","start","end")
    print "{: <#018x} {:#018x} {:#018x} {:>10d} {:>18d} {:#018x}:{:#018x}".format(mapcopy,0,0,mapcopy.c_u.hdr.nentries,0,mapcopy.c_u.hdr.links.start,mapcopy.c_u.hdr.links.end)
    showmaphdrvme(mapcopy.c_u.hdr, 0, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree)

def showmaphdrvme(maphdr, pmap, start_vaddr, end_vaddr, show_pager_info, show_all_shadows, reverse_order, show_rb_tree):
    page_size = kern.globals.page_size
    vnode_pager_ops = kern.globals.vnode_pager_ops
    vnode_pager_ops_addr = unsigned(addressof(vnode_pager_ops))
    if hasattr(kern.globals, 'compressor_object'):
        compressor_object = kern.globals.compressor_object
    else:
        compressor_object = -1;
    vme_list_head = maphdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    print "{:<18s} {:>18s}:{:<18s} {:>10s} {:<8s} {:<16s} {:<18s} {:<18s}".format("entry","start","end","#pgs","tag.kmod","prot&flags","object","offset")
    last_end = unsigned(maphdr.links.start)
    skipped_entries = 0
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links", reverse_order):
        if start_vaddr != 0 and end_vaddr != 0:
            if unsigned(vme.links.start) > end_vaddr:
                break
            if unsigned(vme.links.end) <= start_vaddr:
                last_end = unsigned(vme.links.end)
                skipped_entries = skipped_entries + 1
                continue
            if skipped_entries != 0:
                print "... skipped {:d} entries ...".format(skipped_entries)
                skipped_entries = 0
        if unsigned(vme.links.start) != last_end:
            print "{:18s} {:#018x}:{:#018x} {:>10d}".format("------------------",last_end,vme.links.start,(unsigned(vme.links.start) - last_end)/page_size)
        last_end = unsigned(vme.links.end)
        size = unsigned(vme.links.end) - unsigned(vme.links.start)
        object = vme.vme_object.vmo_object
        if object == 0:
            object_str = "{: <#018x}".format(object)
        elif vme.is_sub_map:
            if object == kern.globals.bufferhdr_map:
                object_str = "BUFFERHDR_MAP"
            elif object == kern.globals.mb_map:
                object_str = "MB_MAP"
            elif object == kern.globals.bsd_pageable_map:
                object_str = "BSD_PAGEABLE_MAP"
            elif object == kern.globals.ipc_kernel_map:
                object_str = "IPC_KERNEL_MAP"
            elif object == kern.globals.ipc_kernel_copy_map:
                object_str = "IPC_KERNEL_COPY_MAP"
            elif object == kern.globals.kalloc_map:
                object_str = "KALLOC_MAP"
            elif object == kern.globals.zone_map:
                object_str = "ZONE_MAP"
            elif hasattr(kern.globals, 'compressor_map') and object == kern.globals.compressor_map:
                object_str = "COMPRESSOR_MAP"
            elif hasattr(kern.globals, 'gzalloc_map') and object == kern.globals.gzalloc_map:
                object_str = "GZALLOC_MAP"
            elif hasattr(kern.globals, 'g_kext_map') and object == kern.globals.g_kext_map:
                object_str = "G_KEXT_MAP"
            elif hasattr(kern.globals, 'vector_upl_submap') and object == kern.globals.vector_upl_submap:
                object_str = "VECTOR_UPL_SUBMAP"
            else:
                object_str = "submap:{: <#018x}".format(object)
        else:
            if object == kern.globals.kernel_object:
                object_str = "KERNEL_OBJECT"
            elif object == kern.globals.vm_submap_object:
                object_str = "VM_SUBMAP_OBJECT"
            elif object == compressor_object:
                object_str = "COMPRESSOR_OBJECT"
            else:
                object_str = "{: <#018x}".format(object)
        offset = unsigned(vme.vme_offset) & ~0xFFF
        tag = unsigned(vme.vme_offset & 0xFFF)
        protection = ""
        if vme.protection & 0x1:
            protection +="r"
        else:
            protection += "-"
        if vme.protection & 0x2:
            protection += "w"
        else:
            protection += "-"
        if vme.protection & 0x4:
            protection += "x"
        else:
            protection += "-"
        max_protection = ""
        if vme.max_protection & 0x1:
            max_protection +="r"
        else:
            max_protection += "-"
        if vme.max_protection & 0x2:
            max_protection += "w"
        else:
            max_protection += "-"
        if vme.max_protection & 0x4:
            max_protection += "x"
        else:
            max_protection += "-"
        vme_flags = ""
        if vme.is_sub_map:
            vme_flags += "s"
        if vme.needs_copy:
            vme_flags += "n"
        if vme.use_pmap:
            vme_flags += "p"
        if vme.wired_count:
            vme_flags += "w"
        if vme.used_for_jit:
            vme_flags += "j"
        tagstr = ""
        if pmap == kern.globals.kernel_pmap:
            xsite = Cast(kern.globals.vm_allocation_sites[tag],'OSKextAccount *')
            if xsite and xsite.site.flags & 0x0200:
                tagstr = ".{:<3d}".format(xsite.loadTag)
        rb_info = ""
        if show_rb_tree:
            rb_info = "l={: <#018x} r={: <#018x} p={: <#018x}".format(vme.store.entry.rbe_left, vme.store.entry.rbe_right, vme.store.entry.rbe_parent)
        print "{: <#018x} {:#018x}:{:#018x} {:>10d} {:>3d}{:<4s}  {:3s}/{:3s}/{:<8s} {:<18s} {:<#18x} {:s}".format(vme,vme.links.start,vme.links.end,(unsigned(vme.links.end)-unsigned(vme.links.start))/page_size,tag,tagstr,protection,max_protection,vme_flags,object_str,offset, rb_info)
        if (show_pager_info or show_all_shadows) and vme.is_sub_map == 0 and vme.vme_object.vmo_object != 0:
            object = vme.vme_object.vmo_object
        else:
            object = 0
        showvmobject(object, offset, size, show_pager_info, show_all_shadows)
    if start_vaddr != 0 or end_vaddr != 0:
        print "..."
    elif unsigned(maphdr.links.end) > last_end:
        print "{:18s} {:#018x}:{:#018x} {:>10d}".format("------------------",last_end,maphdr.links.end,(unsigned(maphdr.links.end) - last_end)/page_size)
    return None

def CountMapTags(map, tagcounts, slow):
    page_size = unsigned(kern.globals.page_size)
    vme_list_head = map.hdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links"):
        object = vme.vme_object.vmo_object
        tag = vme.vme_offset & 0xFFF
        if object == kern.globals.kernel_object:
            count = 0
            if not slow:
                count = unsigned(vme.links.end - vme.links.start) / page_size
            else:
                addr = unsigned(vme.links.start)
                while addr < unsigned(vme.links.end):
                    hash_id = _calc_vm_page_hash(object, addr)
                    page_list = kern.globals.vm_page_buckets[hash_id].page_list
                    page = _vm_page_unpack_ptr(page_list)
                    while (page != 0):
                        vmpage = kern.GetValueFromAddress(page, 'vm_page_t')
                        if (addr == unsigned(vmpage.vmp_offset)) and (object == vm_object_t(_vm_page_unpack_ptr(vmpage.vmp_object))):
                            if (not vmpage.vmp_local) and (vmpage.vmp_wire_count > 0):
                                count += 1
                            break
                        page = _vm_page_unpack_ptr(vmpage.vmp_next_m)
                    addr += page_size
            tagcounts[tag] += count
        elif vme.is_sub_map:
            CountMapTags(Cast(object,'vm_map_t'), tagcounts, slow)
    return None

def CountWiredObject(object, tagcounts):
    tagcounts[unsigned(object.wire_tag)] += object.wired_page_count
    return None

def GetKmodIDName(kmod_id):
    kmod_val = kern.globals.kmod
    for kmod in IterateLinkedList(kmod_val, 'next'):
        if (kmod.id == kmod_id):
            return "{:<50s}".format(kmod.name)
    return "??"

FixedTags = {
    0:  "VM_KERN_MEMORY_NONE",
    1:  "VM_KERN_MEMORY_OSFMK",
    2:  "VM_KERN_MEMORY_BSD",
    3:  "VM_KERN_MEMORY_IOKIT",
    4:  "VM_KERN_MEMORY_LIBKERN",
    5:  "VM_KERN_MEMORY_OSKEXT",
    6:  "VM_KERN_MEMORY_KEXT",
    7:  "VM_KERN_MEMORY_IPC",
    8:  "VM_KERN_MEMORY_STACK",
    9:  "VM_KERN_MEMORY_CPU",
    10: "VM_KERN_MEMORY_PMAP",
    11: "VM_KERN_MEMORY_PTE",
    12: "VM_KERN_MEMORY_ZONE",
    13: "VM_KERN_MEMORY_KALLOC",
    14: "VM_KERN_MEMORY_COMPRESSOR",
    15: "VM_KERN_MEMORY_COMPRESSED_DATA",
    16: "VM_KERN_MEMORY_PHANTOM_CACHE",
    17: "VM_KERN_MEMORY_WAITQ",
    18: "VM_KERN_MEMORY_DIAG",
    19: "VM_KERN_MEMORY_LOG",
    20: "VM_KERN_MEMORY_FILE",
    21: "VM_KERN_MEMORY_MBUF",
    22: "VM_KERN_MEMORY_UBC",
    23: "VM_KERN_MEMORY_SECURITY",
    24: "VM_KERN_MEMORY_MLOCK",
    25: "VM_KERN_MEMORY_REASON",
    26: "VM_KERN_MEMORY_SKYWALK",
    27: "VM_KERN_MEMORY_LTABLE",
    255:"VM_KERN_MEMORY_ANY",
}

def GetVMKernName(tag):
    """ returns the formatted name for a vmtag and
        the sub-tag for kmod tags.
    """
    if ((tag <= 27) or (tag == 255)):
        return (FixedTags[tag], "")
    site = kern.globals.vm_allocation_sites[tag]
    if site:
        if site.flags & 0x007F:
            cstr = addressof(site.subtotals[site.subtotalscount])
            return ("{:<50s}".format(str(Cast(cstr, 'char *'))), "")
        else:
            if site.flags & 0x0200:
                xsite = Cast(site,'OSKextAccount *')
                tagstr = ".{:<3d}".format(xsite.loadTag)
                return (GetKmodIDName(xsite.loadTag), tagstr);
            else:
                return (kern.Symbolicate(site), "")
    return ("", "")

@lldb_command("showvmtags", "AS")
def showvmtags(cmd_args=None, cmd_options={}):
    """Routine to print out info about kernel wired page allocations
        usage: showvmtags
               iterates kernel map and vm objects totaling allocations by tag.
        usage: showvmtags -S
               also iterates kernel object pages individually - slow.
        usage: showvmtags -A
               show all tags, even tags that have no wired count
    """
    slow = False
    if "-S" in cmd_options:
        slow = True
    all_tags = False
    if "-A" in cmd_options:
        all_tags = True
    page_size = unsigned(kern.globals.page_size)
    nsites = unsigned(kern.globals.vm_allocation_tag_highest)
    tagcounts = [0] * nsites
    tagpeaks = [0] * nsites
    tagmapped = [0] * nsites

    if kern.globals.vm_tag_active_update:
        for tag in range(nsites):
            site = kern.globals.vm_allocation_sites[tag]
            if site:
                tagcounts[tag] = unsigned(site.total)
                tagmapped[tag] = unsigned(site.mapped)
                tagpeaks[tag] = unsigned(site.peak)
    else:
        queue_head = kern.globals.vm_objects_wired
        for object in IterateQueue(queue_head, 'struct vm_object *', 'wired_objq'):
            if object != kern.globals.kernel_object:
                CountWiredObject(object, tagcounts)

        CountMapTags(kern.globals.kernel_map, tagcounts, slow)

    total = 0
    totalmapped = 0
    print " vm_allocation_tag_highest: {:<7d}  ".format(nsites)
    print " {:<7s}  {:>7s}   {:>7s}   {:>7s}  {:<50s}".format("tag.kmod", "peak", "size", "mapped", "name")
    for tag in range(nsites):
        if all_tags or tagcounts[tag] or tagmapped[tag]:
            total += tagcounts[tag]
            totalmapped += tagmapped[tag]
            (sitestr, tagstr) = GetVMKernName(tag)
            site = kern.globals.vm_allocation_sites[tag]
            print " {:>3d}{:<4s}  {:>7d}K  {:>7d}K  {:>7d}K  {:<50s}".format(tag, tagstr, tagpeaks[tag] / 1024, tagcounts[tag] / 1024, tagmapped[tag] / 1024, sitestr)

            for sub in range(site.subtotalscount):
                alloctag = unsigned(site.subtotals[sub].tag)
                amount = unsigned(site.subtotals[sub].total)
                subsite = kern.globals.vm_allocation_sites[alloctag]
                if alloctag and subsite:
                    if ((subsite.flags & 0x007f) == 0):
                        kind_str = "named"
                    else:
                        kind_str = "from"
                    (sitestr, tagstr) = GetVMKernName(alloctag)
                    print " {:>7s}  {:>7s}   {:>7s}   {:>7d}K      {:s} {:>3d}{:<4s} {:<50s}".format(" ", " ", " ", amount / 1024, kind_str, alloctag, tagstr, sitestr)

    print "Total:              {:>7d}K  {:>7d}K".format(total / 1024, totalmapped / 1024)
    return None


def FindVMEntriesForVnode(task, vn):
    """ returns an array of vme that have the vnode set to defined vnode
        each entry in array is of format (vme, start_addr, end_address, protection)
    """
    retval = []
    vmmap = task.map
    pmap = vmmap.pmap
    pager_ops_addr = unsigned(addressof(kern.globals.vnode_pager_ops))
    debuglog("pager_ops_addr %s" % hex(pager_ops_addr))

    if unsigned(pmap) == 0:
        return retval
    vme_list_head = vmmap.hdr.links
    vme_ptr_type = gettype('vm_map_entry *')
    for vme in IterateQueue(vme_list_head, vme_ptr_type, 'links'):
        #print vme
        if unsigned(vme.is_sub_map) == 0 and unsigned(vme.vme_object.vmo_object) != 0:
            obj = vme.vme_object.vmo_object
        else:
            continue

        while obj != 0:
            if obj.pager != 0:
                if obj.internal:
                    pass
                else:
                    vn_pager = Cast(obj.pager, 'vnode_pager *')
                    if unsigned(vn_pager.vn_pgr_hdr.mo_pager_ops) == pager_ops_addr and unsigned(vn_pager.vnode_handle) == unsigned(vn):
                        retval.append((vme, unsigned(vme.links.start), unsigned(vme.links.end), unsigned(vme.protection)))
            obj = obj.shadow
    return retval

@lldb_command('showtaskloadinfo')
def ShowTaskLoadInfo(cmd_args=None, cmd_options={}):
    """ Print the load address and uuid for the process
        Usage: (lldb)showtaskloadinfo <task_t>
    """
    if not cmd_args:
        raise ArgumentError("Insufficient arguments")
    t = kern.GetValueFromAddress(cmd_args[0], 'struct task *')
    print_format = "0x{0:x} - 0x{1:x} {2: <50s} (??? - ???) <{3: <36s}> {4: <50s}"
    p = Cast(t.bsd_info, 'struct proc *')
    uuid = p.p_uuid
    uuid_out_string = "{a[0]:02X}{a[1]:02X}{a[2]:02X}{a[3]:02X}-{a[4]:02X}{a[5]:02X}-{a[6]:02X}{a[7]:02X}-{a[8]:02X}{a[9]:02X}-{a[10]:02X}{a[11]:02X}{a[12]:02X}{a[13]:02X}{a[14]:02X}{a[15]:02X}".format(a=uuid)
    filepath = GetVnodePath(p.p_textvp)
    libname = filepath.split('/')[-1]
    #print "uuid: %s file: %s" % (uuid_out_string, filepath)
    mappings = FindVMEntriesForVnode(t, p.p_textvp)
    load_addr = 0
    end_addr = 0
    for m in mappings:
        if m[3] == 5:
            load_addr = m[1]
            end_addr = m[2]
            #print "Load address: %s" % hex(m[1])
    print print_format.format(load_addr, end_addr, libname, uuid_out_string, filepath)
    return None

@header("{0: <20s} {1: <20s} {2: <20s}".format("vm_page_t", "offset", "object"))
@lldb_command('vmpagelookup')
def VMPageLookup(cmd_args=None):
    """ Print the pages in the page bucket corresponding to the provided object and offset.
        Usage: (lldb)vmpagelookup <vm_object_t> <vm_offset_t>
    """
    if cmd_args == None or len(cmd_args) < 2:
        raise ArgumentError("Please specify an object and offset.")
    format_string = "{0: <#020x} {1: <#020x} {2: <#020x}\n"

    obj = kern.GetValueFromAddress(cmd_args[0],'unsigned long long')
    off = kern.GetValueFromAddress(cmd_args[1],'unsigned long long')

    hash_id = _calc_vm_page_hash(obj, off)

    page_list = kern.globals.vm_page_buckets[hash_id].page_list
    print("hash_id: 0x%x page_list: 0x%x\n" % (unsigned(hash_id), unsigned(page_list)))

    print VMPageLookup.header
    page = _vm_page_unpack_ptr(page_list)
    while (page != 0) :
        pg_t = kern.GetValueFromAddress(page, 'vm_page_t')
        print format_string.format(page, pg_t.vmp_offset, _vm_page_unpack_ptr(pg_t.vmp_object))
        page = _vm_page_unpack_ptr(pg_t.vmp_next_m)



@lldb_command('vmpage_get_phys_page')
def VmPageGetPhysPage(cmd_args=None):
    """ return the physical page for a vm_page_t
        usage: vm_page_get_phys_page <vm_page_t>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print  "Please provide valid vm_page_t. Type help vm_page_get_phys_page for help."
        return

    page = kern.GetValueFromAddress(cmd_args[0], 'vm_page_t')
    phys_page = _vm_page_get_phys_page(page)
    print("phys_page = 0x%x\n" % phys_page)


def _vm_page_get_phys_page(page):
    if kern.arch == 'x86_64':
        return page.vmp_phys_page

    if page == 0 :
        return 0

    m = unsigned(page)
    if m >= unsigned(kern.globals.vm_page_array_beginning_addr) and m < unsigned(kern.globals.vm_page_array_ending_addr) :
        return (m - unsigned(kern.globals.vm_page_array_beginning_addr)) / sizeof('struct vm_page') + unsigned(kern.globals.vm_first_phys_ppnum)

    page_with_ppnum = Cast(page, 'uint32_t *')
    ppnum_offset = sizeof('struct vm_page') / sizeof('uint32_t')
    return page_with_ppnum[ppnum_offset]


@lldb_command('vmpage_unpack_ptr')
def VmPageUnpackPtr(cmd_args=None):
    """ unpack a pointer
        usage: vm_page_unpack_ptr <packed_ptr>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print  "Please provide valid packed pointer argument. Type help vm_page_unpack_ptr for help."
        return

    packed = kern.GetValueFromAddress(cmd_args[0],'unsigned long')
    unpacked = _vm_page_unpack_ptr(packed)
    print("unpacked pointer = 0x%x\n" % unpacked)


def _vm_page_unpack_ptr(page):
    if kern.ptrsize == 4 :
        return page

    if page == 0 :
        return page

    min_addr = kern.globals.vm_min_kernel_and_kext_address
    ptr_shift = kern.globals.vm_packed_pointer_shift
    ptr_mask = kern.globals.vm_packed_from_vm_pages_array_mask
    #INTEL - min_addr = 0xffffff7f80000000
    #ARM - min_addr = 0x80000000
    #ARM64 - min_addr = 0xffffff8000000000
    if unsigned(page) & unsigned(ptr_mask) :
        masked_page = (unsigned(page) & ~ptr_mask)
        # can't use addressof(kern.globals.vm_pages[masked_page]) due to 32 bit limitation in SB bridge
        vm_pages_addr = unsigned(addressof(kern.globals.vm_pages[0]))
        element_size = unsigned(addressof(kern.globals.vm_pages[1])) - vm_pages_addr
        return (vm_pages_addr + masked_page * element_size)
    return ((unsigned(page) << unsigned(ptr_shift)) + unsigned(min_addr))

@lldb_command('calcvmpagehash')
def CalcVMPageHash(cmd_args=None):
    """ Get the page bucket corresponding to the provided object and offset.
        Usage: (lldb)calcvmpagehash <vm_object_t> <vm_offset_t>
    """
    if cmd_args == None or len(cmd_args) < 2:
        raise ArgumentError("Please specify an object and offset.")

    obj = kern.GetValueFromAddress(cmd_args[0],'unsigned long long')
    off = kern.GetValueFromAddress(cmd_args[1],'unsigned long long')

    hash_id = _calc_vm_page_hash(obj, off)

    print("hash_id: 0x%x page_list: 0x%x\n" % (unsigned(hash_id), unsigned(kern.globals.vm_page_buckets[hash_id].page_list)))
    return None

def _calc_vm_page_hash(obj, off):
    bucket_hash = (int) (kern.globals.vm_page_bucket_hash)
    hash_mask = (int) (kern.globals.vm_page_hash_mask)

    one = (obj * bucket_hash) & 0xFFFFFFFF
    two = off >> unsigned(kern.globals.page_shift)
    three = two ^ bucket_hash
    four = one + three
    hash_id = four & hash_mask

    return hash_id

def AddressIsFromZoneMap(addr):
    zone_map_min_address = kern.GetGlobalVariable('zone_map_min_address')
    zone_map_max_address = kern.GetGlobalVariable('zone_map_max_address')
    if (unsigned(addr) >= unsigned(zone_map_min_address)) and (unsigned(addr) < unsigned(zone_map_max_address)):
        return 1
    else:
        return 0

def ElementOffsetInForeignPage():
    zone_element_alignment = 32 # defined in zalloc.c
    zone_page_metadata_size = sizeof('struct zone_page_metadata')
    if zone_page_metadata_size % zone_element_alignment == 0:
        offset = zone_page_metadata_size
    else:
        offset = zone_page_metadata_size + (zone_element_alignment - (zone_page_metadata_size % zone_element_alignment))
    return unsigned(offset)

def ElementStartAddrFromZonePageMetadata(page_metadata):
    zone_metadata_region_min = kern.GetGlobalVariable('zone_metadata_region_min')
    zone_map_min_address = kern.GetGlobalVariable('zone_map_min_address')
    page_size = kern.GetGlobalVariable('page_size')
    if AddressIsFromZoneMap(page_metadata):
        page_index = (unsigned(page_metadata) - unsigned(zone_metadata_region_min)) / sizeof('struct zone_page_metadata')
        element_start_addr = unsigned(zone_map_min_address) + unsigned(page_index * page_size)
    else:
        element_start_addr = unsigned(page_metadata) + unsigned(ElementOffsetInForeignPage())

    return element_start_addr

def ZonePageStartAddrFromZonePageMetadata(page_metadata):
    zone_metadata_region_min = kern.GetGlobalVariable('zone_metadata_region_min')
    zone_map_min_address = kern.GetGlobalVariable('zone_map_min_address')
    page_size = kern.GetGlobalVariable('page_size')

    if AddressIsFromZoneMap(page_metadata):
        page_index = (unsigned(page_metadata) - unsigned(zone_metadata_region_min)) / sizeof('struct zone_page_metadata')
        zone_page_addr = unsigned(zone_map_min_address) + unsigned(page_index * page_size)
    else:
        zone_page_addr = unsigned(page_metadata)

    return unsigned(zone_page_addr)

def CreateFreeElementsList(zone, first_free):
    free_elements = []
    if unsigned(first_free) == 0:
        return free_elements
    current = first_free
    while True:
        free_elements.append(unsigned(current))
        next = dereference(Cast(current, 'vm_offset_t *'))
        next = (unsigned(next) ^ unsigned(kern.globals.zp_nopoison_cookie))
        next = kern.GetValueFromAddress(next, 'vm_offset_t *')
        if unsigned(next) == 0:
            break;
        current = Cast(next, 'void *')

    return free_elements

#Macro: showallocatedzoneelement
@lldb_command('showallocatedzoneelement')
def ShowAllocatedElementsInZone(cmd_args=None, cmd_options={}):
    """ Show all the allocated elements in a zone
        usage: showzoneallocelements <address of zone>
    """
    if len(cmd_args) < 1:
        raise ArgumentError("Please specify a zone")

    zone = kern.GetValueFromAddress(cmd_args[0], 'struct zone *')
    elements = FindAllocatedElementsInZone(zone)
    i = 1
    for elem in elements:
        print "{0: >10d}/{1:<10d} element: {2: <#20x}".format(i, len(elements), elem)
        i += 1

#EndMacro: showallocatedzoneelement

def FindAllocatedElementsInZone(zone):
    page_size = kern.GetGlobalVariable('page_size')
    elements = []
    page_queues = ["any_free_foreign", "intermediate", "all_used"]
    found_total = 0

    for queue in page_queues:
        found_in_queue = 0
        if queue == "any_free_foreign" and unsigned(zone.allows_foreign) != 1:
            continue

        for zone_page_metadata in IterateQueue(zone.pages.__getattr__(queue), 'struct zone_page_metadata *', 'pages'):
            free_elements = []
            first_free_element = kern.GetValueFromAddress(GetFreeList(zone_page_metadata))
            free_elements = CreateFreeElementsList(zone, first_free_element)

            chunk_page_count = zone_page_metadata.page_count
            element_addr_start = ElementStartAddrFromZonePageMetadata(zone_page_metadata)
            zone_page_start = ZonePageStartAddrFromZonePageMetadata(zone_page_metadata)
            next_page = zone_page_start + page_size
            element_addr_end = zone_page_start + (chunk_page_count * page_size)
            elem = unsigned(element_addr_start)
            while elem < element_addr_end:
                if elem not in free_elements:
                    elements.append(elem)
                    found_in_queue += 1
                elem += zone.elem_size

                if queue == "any_free_foreign":
                    if (elem + zone.elem_size) >= next_page:
                        zone_page_start = unsigned((elem + page_size) & ~(page_size - 1))
                        next_page = zone_page_start + page_size
                        elem = zone_page_start + unsigned(ElementOffsetInForeignPage())

        found_total += found_in_queue
#       print "Found {0: <d} allocated elements in the {1: <s} page queue".format(found_in_queue, queue)

#   print "Total number of allocated elements: {0: <d} in zone {1: <s}".format(found_total, zone.zone_name)
    return elements

def match_vm_page_attributes(page, matching_attributes):
    page_ptr = addressof(page)
    unpacked_vm_object = _vm_page_unpack_ptr(page.vmp_object)
    matched_attributes = 0
    if "vmp_q_state" in matching_attributes and (page.vmp_q_state == matching_attributes["vmp_q_state"]):
        matched_attributes += 1
    if "vm_object" in matching_attributes and (unsigned(unpacked_vm_object) == unsigned(matching_attributes["vm_object"])):
        matched_attributes += 1
    if "vmp_offset" in matching_attributes and (unsigned(page.vmp_offset) == unsigned(matching_attributes["vmp_offset"])):
        matched_attributes += 1
    if "phys_page" in matching_attributes and (unsigned(_vm_page_get_phys_page(page_ptr)) == unsigned(matching_attributes["phys_page"])):
        matched_attributes += 1
    if "bitfield" in matching_attributes and unsigned(page.__getattr__(matching_attributes["bitfield"])) == 1:
        matched_attributes += 1

    return matched_attributes

#Macro scan_vm_pages
@header("{0: >26s}{1: >20s}{2: >10s}{3: >20s}{4: >20s}{5: >16s}".format("vm_pages_index/zone", "vm_page", "q_state", "vm_object", "offset", "ppn", "bitfield", "from_zone_map"))
@lldb_command('scan_vm_pages', 'S:O:F:I:P:B:I:N:ZA')
def ScanVMPages(cmd_args=None, cmd_options={}):
    """ Scan the global vm_pages array (-A) and/or vmpages zone (-Z) for pages with matching attributes.
        usage: scan_vm_pages <matching attribute(s)> [-A start vm_pages index] [-N number of pages to scan] [-Z scan vm_pages zone]

            scan_vm_pages -A: scan vm pages in the global vm_pages array
            scan_vm_pages -Z: scan vm pages allocated from the vm.pages zone
            scan_vm_pages <-A/-Z> -S <vm_page_q_state value>: Find vm pages in the specified queue
            scan_vm_pages <-A/-Z> -O <vm_object>: Find vm pages in the specified vm_object
            scan_vm_pages <-A/-Z> -F <offset>: Find vm pages with the specified vmp_offset value
            scan_vm_pages <-A/-Z> -P <phys_page>: Find vm pages with the specified physical page number
            scan_vm_pages <-A/-Z> -B <bitfield>: Find vm pages with the bitfield set
            scan_vm_pages <-A> -I <start_index>: Start the scan from start_index
            scan_vm_pages <-A> -N <npages>: Scan at most npages
    """
    if (len(cmd_options) < 1):
        raise ArgumentError("Please specify at least one matching attribute")

    vm_pages = kern.globals.vm_pages
    vm_pages_count = kern.globals.vm_pages_count

    start_index = 0
    npages = vm_pages_count
    scan_vmpages_array = False
    scan_vmpages_zone = False
    attribute_count = 0

    if "-A" in cmd_options:
        scan_vmpages_array = True

    if "-Z" in cmd_options:
        scan_vmpages_zone = True

    if scan_vmpages_array == False and scan_vmpages_zone == False:
        raise ArgumentError("Please specify where to scan (-A: vm_pages array, -Z: vm.pages zone)")

    attribute_values = {}
    if "-S" in cmd_options:
        attribute_values["vmp_q_state"] = kern.GetValueFromAddress(cmd_options["-S"], 'int')
        attribute_count += 1

    if "-O" in cmd_options:
        attribute_values["vm_object"] = kern.GetValueFromAddress(cmd_options["-O"], 'vm_object_t')
        attribute_count += 1

    if "-F" in cmd_options:
        attribute_values["vmp_offset"] = kern.GetValueFromAddress(cmd_options["-F"], 'unsigned long long')
        attribute_count += 1

    if "-P" in cmd_options:
        attribute_values["phys_page"] = kern.GetValueFromAddress(cmd_options["-P"], 'unsigned int')
        attribute_count += 1

    if "-B" in cmd_options:
        valid_vmp_bitfields = [
            "vmp_in_background",
            "vmp_on_backgroundq",
            "vmp_gobbled",
            "vmp_laundry",
            "vmp_no_cache",
            "vmp_private",
            "vmp_reference",
            "vmp_busy",
            "vmp_wanted",
            "vmp_tabled",
            "vmp_hashed",
            "vmp_fictitious",
            "vmp_clustered",
            "vmp_pmapped",
            "vmp_xpmapped",
            "vmp_free_when_done",
            "vmp_absent",
            "vmp_error",
            "vmp_dirty",
            "vmp_cleaning",
            "vmp_precious",
            "vmp_overwriting",
            "vmp_restart",
            "vmp_unusual",
            "vmp_cs_validated",
            "vmp_cs_tainted",
            "vmp_cs_nx",
            "vmp_reusable",
            "vmp_lopage",
            "vmp_written_by_kernel",
            "vmp_unused_object_bits"
            ]
        attribute_values["bitfield"] = cmd_options["-B"]
        if attribute_values["bitfield"] in valid_vmp_bitfields:
            attribute_count += 1
        else:
            raise ArgumentError("Unknown bitfield: {0:>20s}".format(bitfield))

    if "-I" in cmd_options:
        start_index = kern.GetValueFromAddress(cmd_options["-I"], 'int')
        npages = vm_pages_count - start_index

    if "-N" in cmd_options:
        npages = kern.GetValueFromAddress(cmd_options["-N"], 'int')
        if npages == 0:
            raise ArgumentError("You specified -N 0, nothing to be scanned")

    end_index = start_index + npages - 1
    if end_index >= vm_pages_count:
        raise ArgumentError("Index range out of bound. vm_pages_count: {0:d}".format(vm_pages_count))

    header_after_n_lines = 40
    format_string = "{0: >26s}{1: >#20x}{2: >10d}{3: >#20x}{4: >#20x}{5: >#16x}"

    found_in_array = 0
    if scan_vmpages_array:
        print "Scanning vm_pages[{0:d} to {1:d}] for {2:d} matching attribute(s)......".format(start_index, end_index, attribute_count)
        i = start_index
        while i <= end_index:
            page = vm_pages[i]
            if match_vm_page_attributes(page, attribute_values) == attribute_count:
                if found_in_array % header_after_n_lines == 0:
                    print ScanVMPages.header

                print format_string.format(str(i), addressof(page), page.vmp_q_state, _vm_page_unpack_ptr(page.vmp_object), page.vmp_offset, _vm_page_get_phys_page(addressof(page)))
                found_in_array += 1

            i += 1

    found_in_zone = 0
    if scan_vmpages_zone:
        page_size = kern.GetGlobalVariable('page_size')
        num_zones = kern.GetGlobalVariable('num_zones')
        zone_array = kern.GetGlobalVariable('zone_array')
        print "Scanning vm.pages zone for {0:d} matching attribute(s)......".format(attribute_count)
        i = 0
        while i < num_zones:
            zone = zone_array[i]
            if str(zone.zone_name) == "vm pages":
                break;
            i += 1

        if i == num_zones:
            print "Cannot find vm_pages zone, skip the scan"
        else:
            print "Scanning page queues in the vm_pages zone..."
            elements = FindAllocatedElementsInZone(zone)
            for elem in elements:
                page = kern.GetValueFromAddress(elem, 'vm_page_t')

                if match_vm_page_attributes(page, attribute_values) == attribute_count:
                    if found_in_zone % header_after_n_lines == 0:
                        print ScanVMPages.header

                    vm_object = _vm_page_unpack_ptr(page.vmp_object)
                    phys_page = _vm_page_get_phys_page(page)
                    print format_string.format("vm_pages zone", elem, page.vmp_q_state, vm_object, page.vmp_offset, phys_page)
                    found_in_zone += 1

    total = found_in_array + found_in_zone
    print "Found {0:d} vm pages ({1:d} in array, {2:d} in zone) matching the requested {3:d} attribute(s)".format(total, found_in_array, found_in_zone, attribute_count)

#EndMacro scan_vm_pages

VM_PAGE_IS_WIRED = 1

@header("{0: <10s} of {1: <10s} {2: <20s} {3: <20s} {4: <20s} {5: <10s} {6: <5s}\t {7: <28s}\t{8: <50s}".format("index", "total", "vm_page_t", "offset", "next", "phys_page", "wire#", "first bitfield", "second bitfield"))
@lldb_command('vmobjectwalkpages', 'CSBNQP:O:')
def VMObjectWalkPages(cmd_args=None, cmd_options={}):
    """ Print the resident pages contained in the provided object. If a vm_page_t is provided as well, we
        specifically look for this page, highlighting it in the output or noting if it was not found. For
        each page, we confirm that it points to the object. We also keep track of the number of pages we
        see and compare this to the object's resident page count field.
        Usage:
            vmobjectwalkpages <vm_object_t> : Walk and print all the pages for a given object (up to 4K pages by default)
            vmobjectwalkpages <vm_object_t> -C : list pages in compressor after processing resident pages
            vmobjectwalkpages <vm_object_t> -B : Walk and print all the pages for a given object (up to 4K pages by default), traversing the memq backwards
            vmobjectwalkpages <vm_object_t> -N : Walk and print all the pages for a given object, ignore the page limit
            vmobjectwalkpages <vm_object_t> -Q : Walk all pages for a given object, looking for known signs of corruption (i.e. q_state == VM_PAGE_IS_WIRED && wire_count == 0)
            vmobjectwalkpages <vm_object_t> -P <vm_page_t> : Walk all the pages for a given object, annotate the specified page in the output with ***
            vmobjectwalkpages <vm_object_t> -P <vm_page_t> -S : Walk all the pages for a given object, stopping when we find the specified page
            vmobjectwalkpages <vm_object_t> -O <offset> : Like -P, but looks for given offset

    """

    if (cmd_args == None or len(cmd_args) < 1):
        raise ArgumentError("Please specify at minimum a vm_object_t and optionally a vm_page_t")

    out_string = ""

    obj = kern.GetValueFromAddress(cmd_args[0], 'vm_object_t')

    page = 0
    if "-P" in cmd_options:
        page = kern.GetValueFromAddress(cmd_options['-P'], 'vm_page_t')

    off = -1
    if "-O" in cmd_options:
        off = kern.GetValueFromAddress(cmd_options['-O'], 'vm_offset_t')

    stop = 0
    if "-S" in cmd_options:
        if page == 0 and off < 0:
            raise ArgumentError("-S can only be passed when a page is specified with -P or -O")
        stop = 1

    walk_backwards = False
    if "-B" in cmd_options:
        walk_backwards = True

    quiet_mode = False
    if "-Q" in cmd_options:
        quiet_mode = True

    if not quiet_mode:
        print VMObjectWalkPages.header
        format_string = "{0: <#10d} of {1: <#10d} {2: <#020x} {3: <#020x} {4: <#020x} {5: <#010x} {6: <#05d}\t"
        first_bitfield_format_string = "{0: <#2d}:{1: <#1d}:{2: <#1d}:{3: <#1d}:{4: <#1d}:{5: <#1d}:{6: <#1d}:{7: <#1d}\t"
        second_bitfield_format_string = "{0: <#1d}:{1: <#1d}:{2: <#1d}:{3: <#1d}:{4: <#1d}:{5: <#1d}:{6: <#1d}:"
        second_bitfield_format_string += "{7: <#1d}:{8: <#1d}:{9: <#1d}:{10: <#1d}:{11: <#1d}:{12: <#1d}:"
        second_bitfield_format_string += "{13: <#1d}:{14: <#1d}:{15: <#1d}:{16: <#1d}:{17: <#1d}:{18: <#1d}:{19: <#1d}:"
        second_bitfield_format_string +=  "{20: <#1d}:{21: <#1d}:{22: <#1d}:{23: <#1d}:{24: <#1d}:{25: <#1d}:{26: <#1d}\n"

    limit = 4096 #arbitrary limit of number of pages to walk
    ignore_limit = 0
    if "-N" in cmd_options:
        ignore_limit = 1

    show_compressed = 0
    if "-C" in cmd_options:
        show_compressed = 1

    page_count = 0
    res_page_count = unsigned(obj.resident_page_count)
    page_found = False
    pages_seen = set()

    for vmp in IterateQueue(obj.memq, "vm_page_t", "vmp_listq", walk_backwards, unpack_ptr_fn=_vm_page_unpack_ptr):
        page_count += 1
        out_string = ""
        if (page != 0 and not(page_found) and vmp == page):
            out_string += "******"
            page_found = True

        if (off > 0 and not(page_found) and vmp.vmp_offset == off):
            out_string += "******"
            page_found = True

        if page != 0 or off > 0 or quiet_mode:
             if (page_count % 1000) == 0:
                print "traversed %d pages ...\n" % (page_count)
        else:
                out_string += format_string.format(page_count, res_page_count, vmp, vmp.vmp_offset, _vm_page_unpack_ptr(vmp.vmp_listq.next), _vm_page_get_phys_page(vmp), vmp.vmp_wire_count)
                out_string += first_bitfield_format_string.format(vmp.vmp_q_state, vmp.vmp_in_background, vmp.vmp_on_backgroundq, vmp.vmp_gobbled, vmp.vmp_laundry, vmp.vmp_no_cache,
                                                                   vmp.vmp_private, vmp.vmp_reference)

                if hasattr(vmp,'slid'):
                    vmp_slid = vmp.slid
                else:
                    vmp_slid = 0
                out_string += second_bitfield_format_string.format(vmp.vmp_busy, vmp.vmp_wanted, vmp.vmp_tabled, vmp.vmp_hashed, vmp.vmp_fictitious, vmp.vmp_clustered,
                                                                    vmp.vmp_pmapped, vmp.vmp_xpmapped, vmp.vmp_wpmapped, vmp.vmp_free_when_done, vmp.vmp_absent,
                                                                    vmp.vmp_error, vmp.vmp_dirty, vmp.vmp_cleaning, vmp.vmp_precious, vmp.vmp_overwriting,
                                                                    vmp.vmp_restart, vmp.vmp_unusual, 0, 0,
                                                                    vmp.vmp_cs_validated, vmp.vmp_cs_tainted, vmp.vmp_cs_nx, vmp.vmp_reusable, vmp.vmp_lopage, vmp_slid,
                                                                    vmp.vmp_written_by_kernel)

        if (vmp in pages_seen):
            print out_string + "cycle detected! we've seen vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) + " twice. stopping...\n"
            return

        if (_vm_page_unpack_ptr(vmp.vmp_object) != unsigned(obj)):
            print out_string + " vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) +  " points to different vm_object_t: " + "{0: <#020x}".format(unsigned(_vm_page_unpack_ptr(vmp.vmp_object)))
            return

        if (vmp.vmp_q_state == VM_PAGE_IS_WIRED) and (vmp.vmp_wire_count == 0):
            print out_string + " page in wired state with wire_count of 0\n"
            print "vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) + "\n"
            print "stopping...\n"
            return

        if ((vmp.vmp_unused_page_bits != 0) or (vmp.vmp_unused_object_bits != 0)):
            print out_string + " unused bits not zero for vm_page_t: " + "{0: <#020x}".format(unsigned(vmp)) + " unused__pageq_bits: %d unused_object_bits : %d\n" % (vmp.vmp_unused_page_bits,
                                            vmp.vmp_unused_object_bits)
            print "stopping...\n"
            return

        pages_seen.add(vmp)

        if False:
            hash_id = _calc_vm_page_hash(obj, vmp.vmp_offset)
            hash_page_list = kern.globals.vm_page_buckets[hash_id].page_list
            hash_page = _vm_page_unpack_ptr(hash_page_list)
            hash_page_t = 0

            while (hash_page != 0):
                hash_page_t = kern.GetValueFromAddress(hash_page, 'vm_page_t')
                if hash_page_t == vmp:
                    break
                hash_page = _vm_page_unpack_ptr(hash_page_t.vmp_next_m)

            if (unsigned(vmp) != unsigned(hash_page_t)):
                print out_string + "unable to find page: " + "{0: <#020x}".format(unsigned(vmp)) + " from object in kernel page bucket list\n"
                print lldb_run_command("vm_page_info %s 0x%x" % (cmd_args[0], unsigned(vmp.vmp_offset)))
                return

        if (page_count >= limit and not(ignore_limit)):
            print out_string + "Limit reached (%d pages), stopping..." % (limit)
            break

        print out_string

        if page_found and stop:
            print("Object reports resident page count of: %d we stopped after traversing %d and finding the requested page.\n" % (unsigned(obj.res_page_count), unsigned(page_count)))
            return

    if (page != 0):
        print("page found? : %s\n" % page_found)

    if (off > 0):
        print("page found? : %s\n" % page_found)

    print("Object reports resident page count of %d, we saw %d pages when we walked the resident list.\n" % (unsigned(obj.resident_page_count), unsigned(page_count)))

    if show_compressed != 0 and obj.pager != 0 and unsigned(obj.pager.mo_pager_ops) == unsigned(addressof(kern.globals.compressor_pager_ops)):
        pager = Cast(obj.pager, 'compressor_pager *')
        chunks = pager.cpgr_num_slots / 128
        pagesize = kern.globals.page_size

        page_idx = 0
        while page_idx < pager.cpgr_num_slots:
            if chunks != 0:
                chunk = pager.cpgr_slots.cpgr_islots[page_idx / 128]
                slot = chunk[page_idx % 128]
            elif pager.cpgr_num_slots > 2:
                slot = pager.cpgr_slots.cpgr_dslots[page_idx]
            else:
                slot = pager.cpgr_slots.cpgr_eslots[page_idx]

            if slot != 0:
               print("compressed page for offset: %x slot %x\n" % ((page_idx * pagesize) - obj.paging_offset, slot))
            page_idx = page_idx + 1


@lldb_command("show_all_apple_protect_pagers")
def ShowAllAppleProtectPagers(cmd_args=None):
    """Routine to print all apple_protect pagers
        usage: show_all_apple_protect_pagers
    """
    print "{:>3s} {:<3s} {:<18s} {:>5s} {:>5s} {:>6s} {:<18s} {:<18s} {:<18s} {:<18s} {:<18s} {:<18s}\n".format("#", "#", "pager", "refs", "ready", "mapped", "mo_control", "object", "offset", "crypto_offset", "crypto_start", "crypto_end")
    qhead = kern.globals.apple_protect_pager_queue
    qtype = GetType('apple_protect_pager *')
    qcnt = kern.globals.apple_protect_pager_count
    idx = 0
    for pager in IterateQueue(qhead, qtype, "pager_queue"):
        idx = idx + 1
        show_apple_protect_pager(pager, qcnt, idx)

@lldb_command("show_apple_protect_pager")
def ShowAppleProtectPager(cmd_args=None):
    """Routine to print out info about an apple_protect pager
        usage: show_apple_protect_pager <pager>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument.", ShowAppleProtectPager.__doc__
        return
    pager = kern.GetValueFromAddress(cmd_args[0], 'apple_protect_pager_t')
    show_apple_protect_pager(pager, 1, 1)

def show_apple_protect_pager(pager, qcnt, idx):
    object = pager.backing_object
    shadow = object.shadow
    while shadow != 0:
        object = shadow
        shadow = object.shadow
    vnode_pager = Cast(object.pager,'vnode_pager *')
    filename = GetVnodePath(vnode_pager.vnode_handle)
    print "{:>3}/{:<3d} {: <#018x} {:>5d} {:>5d} {:>6d} {: <#018x} {: <#018x} {:#018x} {:#018x} {:#018x} {:#018x}\n\tcrypt_info:{: <#018x} <decrypt:{: <#018x} end:{:#018x} ops:{: <#018x} refs:{:<d}>\n\tvnode:{: <#018x} {:s}\n".format(idx, qcnt, pager, pager.ref_count, pager.is_ready, pager.is_mapped, pager.pager_control, pager.backing_object, pager.backing_offset, pager.crypto_backing_offset, pager.crypto_start, pager.crypto_end, pager.crypt_info, pager.crypt_info.page_decrypt, pager.crypt_info.crypt_end, pager.crypt_info.crypt_ops, pager.crypt_info.crypt_refcnt, vnode_pager.vnode_handle, filename)

@lldb_command("show_console_ring")
def ShowConsoleRingData(cmd_args=None):
    """ Print console ring buffer stats and data
    """
    cr = kern.globals.console_ring
    print "console_ring = {:#018x}  buffer = {:#018x}  length = {:<5d}  used = {:<5d}  read_ptr = {:#018x}  write_ptr = {:#018x}".format(addressof(cr), cr.buffer, cr.len, cr.used, cr.read_ptr, cr.write_ptr)
    pending_data = []
    for i in range(unsigned(cr.used)):
        idx = ((unsigned(cr.read_ptr) - unsigned(cr.buffer)) + i) % unsigned(cr.len)
        pending_data.append("{:c}".format(cr.buffer[idx]))

    if pending_data:
        print "Data:"
        print "".join(pending_data)

# Macro: showjetsamsnapshot

@lldb_command("showjetsamsnapshot", "DA")
def ShowJetsamSnapshot(cmd_args=None, cmd_options={}):
    """ Dump entries in the jetsam snapshot table
        usage: showjetsamsnapshot [-D] [-A]
        Use -D flag to print extra physfootprint details
        Use -A flag to print all entries (regardless of valid count)
    """

    # Not shown are uuid, user_data, cpu_time

    global kern

    show_footprint_details = False
    show_all_entries = False

    if "-D" in cmd_options:
        show_footprint_details = True

    if "-A" in cmd_options:
        show_all_entries = True

    valid_count = kern.globals.memorystatus_jetsam_snapshot_count
    max_count = kern.globals.memorystatus_jetsam_snapshot_max

    if (show_all_entries == True):
        count = max_count
    else:
        count = valid_count

    print "{:s}".format(valid_count)
    print "{:s}".format(max_count)

    if int(count) == 0:
        print "The jetsam snapshot is empty."
        print "Use -A to force dump all entries (regardless of valid count)"
        return

    # Dumps the snapshot header info
    print lldb_run_command('p *memorystatus_jetsam_snapshot')

    hdr_format = "{0: >32s} {1: >5s} {2: >4s} {3: >6s} {4: >6s} {5: >20s} {6: >20s} {7: >20s} {8: >5s} {9: >10s} {10: >6s} {11: >6s} {12: >10s} {13: >15s} {14: >15s} {15: >15s}"
    if (show_footprint_details == True):
        hdr_format += "{16: >15s} {17: >15s} {18: >12s} {19: >12s} {20: >17s} {21: >10s} {22: >13s} {23: >10s}"


    if (show_footprint_details == False):
        print hdr_format.format('command', 'index', 'pri', 'cid', 'pid', 'starttime', 'killtime', 'idletime', 'kill', '#ents', 'fds', 'gen', 'state', 'footprint', 'purgeable', 'lifetimeMax')
        print hdr_format.format('', '', '', '', '', '(abs)', '(abs)', '(abs)', 'cause', '', '', 'Count', '', '(pages)', '(pages)', '(pages)')
    else:
        print hdr_format.format('command', 'index', 'pri', 'cid', 'pid', 'starttime', 'killtime', 'idletime', 'kill', '#ents', 'fds', 'gen', 'state', 'footprint', 'purgeable', 'lifetimeMax', '|| internal', 'internal_comp', 'iokit_mapped', 'purge_nonvol', 'purge_nonvol_comp', 'alt_acct', 'alt_acct_comp', 'page_table')
        print hdr_format.format('', '', '', '', '', '(abs)', '(abs)', '(abs)', 'cause', '', '', 'Count', '', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)', '(pages)')


    entry_format = "{e.name: >32s} {index: >5d} {e.priority: >4d} {e.jse_coalition_jetsam_id: >6d} {e.pid: >6d} "\
                   "{e.jse_starttime: >20d} {e.jse_killtime: >20d} "\
                   "{e.jse_idle_delta: >20d} {e.killed: >5d} {e.jse_memory_region_count: >10d} "\
                   "{e.fds: >6d} {e.jse_gencount: >6d} {e.state: >10x} {e.pages: >15d} "\
                   "{e.purgeable_pages: >15d} {e.max_pages_lifetime: >15d}"

    if (show_footprint_details == True):
        entry_format += "{e.jse_internal_pages: >15d} "\
                        "{e.jse_internal_compressed_pages: >15d} "\
                        "{e.jse_iokit_mapped_pages: >12d} "\
                        "{e.jse_purgeable_nonvolatile_pages: >12d} "\
                        "{e.jse_purgeable_nonvolatile_compressed_pages: >17d} "\
                        "{e.jse_alternate_accounting_pages: >10d} "\
                        "{e.jse_alternate_accounting_compressed_pages: >13d} "\
                        "{e.jse_page_table_pages: >10d}"

    snapshot_list = kern.globals.memorystatus_jetsam_snapshot.entries
    idx = 0
    while idx < count:
        current_entry = dereference(Cast(addressof(snapshot_list[idx]), 'jetsam_snapshot_entry *'))
        print entry_format.format(index=idx, e=current_entry)
        idx +=1
    return

# EndMacro: showjetsamsnapshot

# Macro: showvnodecleanblk/showvnodedirtyblk

def _GetBufSummary(buf):
    """ Get a summary of important information out of a buf_t.
    """
    initial = "(struct buf) {0: <#0x} ="

    # List all of the fields in this buf summary.
    entries = [buf.b_hash, buf.b_vnbufs, buf.b_freelist, buf.b_timestamp, buf.b_whichq,
        buf.b_flags, buf.b_lflags, buf.b_error, buf.b_bufsize, buf.b_bcount, buf.b_resid,
        buf.b_dev, buf.b_datap, buf.b_lblkno, buf.b_blkno, buf.b_iodone, buf.b_vp,
        buf.b_rcred, buf.b_wcred, buf.b_upl, buf.b_real_bp, buf.b_act, buf.b_drvdata,
        buf.b_fsprivate, buf.b_transaction, buf.b_dirtyoff, buf.b_dirtyend, buf.b_validoff,
        buf.b_validend, buf.b_redundancy_flags, buf.b_proc, buf.b_attr]

    # Join an (already decent) string representation of each field
    # with newlines and indent the region.
    joined_strs = "\n".join([str(i).rstrip() for i in entries]).replace('\n', "\n    ")

    # Add the total string representation to our title and return it.
    out_str = initial.format(int(buf)) + " {\n    " + joined_strs + "\n}\n\n"
    return out_str

def _ShowVnodeBlocks(dirty=True, cmd_args=None):
    """ Display info about all [dirty|clean] blocks in a vnode.
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Please provide a valid vnode argument."
        return

    vnodeval = kern.GetValueFromAddress(cmd_args[0], 'vnode *')
    list_head = vnodeval.v_cleanblkhd;
    if dirty:
        list_head = vnodeval.v_dirtyblkhd

    print "Blocklist for vnode {}:".format(cmd_args[0])

    i = 0
    for buf in IterateListEntry(list_head, 'struct buf *', 'b_hash'):
        # For each block (buf_t) in the appropriate list,
        # ask for a summary and print it.
        print "---->\nblock {}: ".format(i) + _GetBufSummary(buf)
        i += 1
    return

@lldb_command('showvnodecleanblk')
def ShowVnodeCleanBlocks(cmd_args=None):
    """ Display info about all clean blocks in a vnode.
        usage: showvnodecleanblk <address of vnode>
    """
    _ShowVnodeBlocks(False, cmd_args)

@lldb_command('showvnodedirtyblk')
def ShowVnodeDirtyBlocks(cmd_args=None):
    """ Display info about all dirty blocks in a vnode.
        usage: showvnodedirtyblk <address of vnode>
    """
    _ShowVnodeBlocks(True, cmd_args)

# EndMacro: showvnodecleanblk/showvnodedirtyblk


@lldb_command("vm_page_lookup_in_map")
def VmPageLookupInMap(cmd_args=None):
    """Lookup up a page at a virtual address in a VM map
        usage: vm_page_lookup_in_map <map> <vaddr>
    """
    if cmd_args == None or len(cmd_args) < 2:
        print "Invalid argument.", VmPageLookupInMap.__doc__
        return
    map = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    vaddr = kern.GetValueFromAddress(cmd_args[1], 'vm_map_offset_t')
    print "vaddr {:#018x} in map {: <#018x}".format(vaddr, map)
    vm_page_lookup_in_map(map, vaddr)

def vm_page_lookup_in_map(map, vaddr):
    vaddr = unsigned(vaddr)
    vme_list_head = map.hdr.links
    vme_ptr_type = GetType('vm_map_entry *')
    for vme in IterateQueue(vme_list_head, vme_ptr_type, "links"):
        if unsigned(vme.links.start) > vaddr:
            break
        if unsigned(vme.links.end) <= vaddr:
            continue
        offset_in_vme = vaddr - unsigned(vme.links.start)
        print "  offset {:#018x} in map entry {: <#018x} [{:#018x}:{:#018x}] object {: <#018x} offset {:#018x}".format(offset_in_vme, vme, unsigned(vme.links.start), unsigned(vme.links.end), vme.vme_object.vmo_object, unsigned(vme.vme_offset) & ~0xFFF)
        offset_in_object = offset_in_vme + (unsigned(vme.vme_offset) & ~0xFFF)
        if vme.is_sub_map:
            print "vaddr {:#018x} in map {: <#018x}".format(offset_in_object, vme.vme_object.vmo_submap)
            vm_page_lookup_in_map(vme.vme_object.vmo_submap, offset_in_object)
        else:
            vm_page_lookup_in_object(vme.vme_object.vmo_object, offset_in_object)

@lldb_command("vm_page_lookup_in_object")
def VmPageLookupInObject(cmd_args=None):
    """Lookup up a page at a given offset in a VM object
        usage: vm_page_lookup_in_object <object> <offset>
    """
    if cmd_args == None or len(cmd_args) < 2:
        print "Invalid argument.", VmPageLookupInObject.__doc__
        return
    object = kern.GetValueFromAddress(cmd_args[0], 'vm_object_t')
    offset = kern.GetValueFromAddress(cmd_args[1], 'vm_object_offset_t')
    print "offset {:#018x} in object {: <#018x}".format(offset, object)
    vm_page_lookup_in_object(object, offset)

def vm_page_lookup_in_object(object, offset):
    offset = unsigned(offset)
    page_size = kern.globals.page_size
    trunc_offset = offset & ~(page_size - 1)
    print "    offset {:#018x} in VM object {: <#018x}".format(offset, object)
    hash_id = _calc_vm_page_hash(object, trunc_offset)
    page_list = kern.globals.vm_page_buckets[hash_id].page_list
    page = _vm_page_unpack_ptr(page_list)
    while page != 0:
        m = kern.GetValueFromAddress(page, 'vm_page_t')
        m_object_val = _vm_page_unpack_ptr(m.vmp_object)
        m_object = kern.GetValueFromAddress(m_object_val, 'vm_object_t')
        if unsigned(m_object) != unsigned(object) or unsigned(m.vmp_offset) != unsigned(trunc_offset):
            page = _vm_page_unpack_ptr(m.vmp_next_m)
            continue
        print "    resident page {: <#018x} phys {:#010x}".format(m, _vm_page_get_phys_page(m))
        return
    if object.pager and object.pager_ready:
        offset_in_pager = trunc_offset + unsigned(object.paging_offset)
        if not object.internal:
            print "    offset {:#018x} in external '{:s}' {: <#018x}".format(offset_in_pager, object.pager.mo_pager_ops.memory_object_pager_name, object.pager)
            return
        pager = Cast(object.pager, 'compressor_pager *')
        ret = vm_page_lookup_in_compressor_pager(pager, offset_in_pager)
        if ret:
            return
    if object.shadow and not object.phys_contiguous:
        offset_in_shadow = offset + unsigned(object.vo_un2.vou_shadow_offset)
        vm_page_lookup_in_object(object.shadow, offset_in_shadow)
        return
    print "    page is absent and will be zero-filled on demand"
    return

@lldb_command("vm_page_lookup_in_compressor_pager")
def VmPageLookupInCompressorPager(cmd_args=None):
    """Lookup up a page at a given offset in a compressor pager
        usage: vm_page_lookup_in_compressor_pager <pager> <offset>
    """
    if cmd_args == None or len(cmd_args) < 2:
        print "Invalid argument.", VmPageLookupInCompressorPager.__doc__
        return
    pager = kern.GetValueFromAddress(cmd_args[0], 'compressor_pager_t')
    offset = kern.GetValueFromAddress(cmd_args[1], 'memory_object_offset_t')
    print "offset {:#018x} in compressor pager {: <#018x}".format(offset, pager)
    vm_page_lookup_in_compressor_pager(pager, offset)

def vm_page_lookup_in_compressor_pager(pager, offset):
    offset = unsigned(offset)
    page_size = unsigned(kern.globals.page_size)
    page_num = unsigned(offset / page_size)
    if page_num > pager.cpgr_num_slots:
        print "      *** ERROR: vm_page_lookup_in_compressor_pager({: <#018x},{:#018x}): page_num {:#x} > num_slots {:#x}".format(pager, offset, page_num, pager.cpgr_num_slots)
        return 0
    slots_per_chunk = 512 / sizeof ('compressor_slot_t')
    num_chunks = unsigned((pager.cpgr_num_slots+slots_per_chunk-1) / slots_per_chunk)
    if num_chunks > 1:
        chunk_idx = unsigned(page_num / slots_per_chunk)
        chunk = pager.cpgr_slots.cpgr_islots[chunk_idx]
        slot_idx = unsigned(page_num % slots_per_chunk)
        slot = GetObjectAtIndexFromArray(chunk, slot_idx)
        slot_str = "islots[{:d}][{:d}]".format(chunk_idx, slot_idx)
    elif pager.cpgr_num_slots > 2:
        slot_idx = page_num
        slot = GetObjectAtIndexFromArray(pager.cpgr_slots.cpgr_dslots, slot_idx)
        slot_str = "dslots[{:d}]".format(slot_idx)
    else:
        slot_idx = page_num
        slot = GetObjectAtIndexFromArray(pager.cpgr_slots.cpgr_eslots, slot_idx)
        slot_str = "eslots[{:d}]".format(slot_idx)
    print "      offset {:#018x} in compressor pager {: <#018x} {:s} slot {: <#018x}".format(offset, pager, slot_str, slot)
    if slot == 0:
        return 0
    slot_value = dereference(slot)
    print " value {:#010x}".format(slot_value)
    vm_page_lookup_in_compressor(Cast(slot, 'c_slot_mapping_t'))
    return 1

@lldb_command("vm_page_lookup_in_compressor")
def VmPageLookupInCompressor(cmd_args=None):
    """Lookup up a page in a given compressor slot
        usage: vm_page_lookup_in_compressor <slot>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument.", VmPageLookupInCompressor.__doc__
        return
    slot = kern.GetValueFromAddress(cmd_args[0], 'compressor_slot_t *')
    print "compressor slot {: <#018x}".format(slot)
    vm_page_lookup_in_compressor(slot)

C_SV_CSEG_ID = ((1 << 22) - 1)

def vm_page_lookup_in_compressor(slot_ptr):
    slot_ptr = Cast(slot_ptr, 'compressor_slot_t *')
    slot_value = dereference(slot_ptr)
    slot = Cast(slot_value, 'c_slot_mapping')
    print slot
    print "compressor slot {: <#018x} -> {:#010x} cseg {:d} cindx {:d}".format(unsigned(slot_ptr), unsigned(slot_value), slot.s_cseg, slot.s_cindx)
    if slot_ptr == 0:
        return
    if slot.s_cseg == C_SV_CSEG_ID:
        sv = kern.globals.c_segment_sv_hash_table
        print "single value[{:#d}]: ref {:d} value {:#010x}".format(slot.s_cindx, sv[slot.s_cindx].c_sv_he_un.c_sv_he.c_sv_he_ref, sv[slot.s_cindx].c_sv_he_un.c_sv_he.c_sv_he_data)
        return
    if slot.s_cseg == 0 or unsigned(slot.s_cseg) > unsigned(kern.globals.c_segments_available):
        print "*** ERROR: s_cseg {:d} is out of bounds (1 - {:d})".format(slot.s_cseg, unsigned(kern.globals.c_segments_available))
        return
    c_segments = kern.globals.c_segments
    c_segments_elt = GetObjectAtIndexFromArray(c_segments, slot.s_cseg-1)
    c_seg = c_segments_elt.c_seg
    c_no_data = 0
    if hasattr(c_seg, 'c_state'):
        c_state = c_seg.c_state
        if c_state == 0:
            c_state_str = "C_IS_EMPTY"
            c_no_data = 1
        elif c_state == 1:
            c_state_str = "C_IS_FREE"
            c_no_data = 1
        elif c_state == 2:
            c_state_str = "C_IS_FILLING"
        elif c_state == 3:
            c_state_str = "C_ON_AGE_Q"
        elif c_state == 4:
            c_state_str = "C_ON_SWAPOUT_Q"
        elif c_state == 5:
            c_state_str = "C_ON_SWAPPEDOUT_Q"
            c_no_data = 1
        elif c_state == 6:
            c_state_str = "C_ON_SWAPPEDOUTSPARSE_Q"
            c_no_data = 1
        elif c_state == 7:
            c_state_str = "C_ON_SWAPPEDIN_Q"
        elif c_state == 8:
            c_state_str = "C_ON_MAJORCOMPACT_Q"
        elif c_state == 9:
            c_state_str = "C_ON_BAD_Q"
            c_no_data = 1
        else:
            c_state_str = "<unknown>"
    else:
        c_state = -1
        c_state_str = "<no c_state field>"
    print "c_segments[{:d}] {: <#018x} c_seg {: <#018x} c_state {:#x}={:s}".format(slot.s_cseg-1, c_segments_elt, c_seg, c_state, c_state_str)
    c_indx = unsigned(slot.s_cindx)
    if hasattr(c_seg, 'c_slot_var_array'):
        c_seg_fixed_array_len = kern.globals.c_seg_fixed_array_len
        if c_indx < c_seg_fixed_array_len:
            cs = c_seg.c_slot_fixed_array[c_indx]
        else:
            cs = GetObjectAtIndexFromArray(c_seg.c_slot_var_array, c_indx - c_seg_fixed_array_len)
    else:
        C_SEG_SLOT_ARRAY_SIZE = 64
        C_SEG_SLOT_ARRAY_MASK = C_SEG_SLOT_ARRAY_SIZE - 1
        cs = GetObjectAtIndexFromArray(c_seg.c_slots[c_indx / C_SEG_SLOT_ARRAY_SIZE], c_indx & C_SEG_SLOT_ARRAY_MASK)
    print cs
    c_slot_unpacked_ptr = (unsigned(cs.c_packed_ptr) << 2) + vm_min_kernel_and_kext_address()
    print "c_slot {: <#018x} c_offset {:#x} c_size {:#x} c_packed_ptr {:#x} (unpacked: {: <#018x})".format(cs, cs.c_offset, cs.c_size, cs.c_packed_ptr, unsigned(c_slot_unpacked_ptr))
    if unsigned(slot_ptr) != unsigned(c_slot_unpacked_ptr):
        print "*** ERROR: compressor slot {: <#018x} points back to {: <#018x} instead of itself".format(slot_ptr, c_slot_unpacked_ptr)
    if c_no_data == 0:
        c_data = c_seg.c_store.c_buffer + (4 * cs.c_offset)
        c_size = cs.c_size
        cmd = "memory read {: <#018x} {: <#018x} --force".format(c_data, c_data + c_size)
        print cmd
        print lldb_run_command(cmd)
    else:
        print "<no compressed data>"

def vm_min_kernel_and_kext_address(cmd_args=None):
    if hasattr(kern.globals, 'vm_min_kernel_and_kext_address'):
        return unsigned(kern.globals.vm_min_kernel_and_kext_address)
    elif kern.arch == 'x86_64':
        return unsigned(0xffffff7f80000000)
    elif kern.arch == 'arm64':
        return unsigned(0xffffff8000000000)
    elif kern.arch == 'arm':
        return unsigned(0x80000000)
    else:
        print "vm_min_kernel_and_kext_address(): unknown arch '{:s}'".format(kern.arch)
        return unsigned(0)

def print_hex_data(data, begin_offset=0, desc=""):
    """ print on stdout "hexdump -C < data" like output
        params:
            data - bytearray or array of int where each int < 255
            begin_offset - int offset that should be printed in left column
            desc - str optional description to print on the first line to describe data
    """
    if desc:
        print "{}:".format(desc)
    index = 0
    total_len = len(data)
    hex_buf = ""
    char_buf = ""
    while index < total_len:
        hex_buf += " {:02x}".format(data[index])
        if data[index] < 0x20 or data[index] > 0x7e:
            char_buf += "."
        else:
            char_buf += "{:c}".format(data[index])
        index += 1
        if index and index % 8 == 0:
            hex_buf += " "
        if index > 1 and (index % 16) == 0:
            print "{:08x} {: <50s} |{: <16s}|".format(begin_offset + index - 16, hex_buf, char_buf)
            hex_buf = ""
            char_buf = ""
    print "{:08x} {: <50s} |{: <16s}|".format(begin_offset + index - 16, hex_buf, char_buf)
    return

@lldb_command('vm_scan_all_pages')
def VMScanAllPages(cmd_args=None):
    """Scans the vm_pages[] array
    """
    vm_pages_count = kern.globals.vm_pages_count
    vm_pages = kern.globals.vm_pages

    free_count = 0
    local_free_count = 0
    active_count = 0
    local_active_count = 0
    inactive_count = 0
    speculative_count = 0
    throttled_count = 0
    wired_count = 0
    compressor_count = 0
    pageable_internal_count = 0
    pageable_external_count = 0
    secluded_count = 0
    secluded_free_count = 0
    secluded_inuse_count = 0

    i = 0
    while i < vm_pages_count:

        if i % 10000 == 0:
            print "{:d}/{:d}...\n".format(i,vm_pages_count)

        m = vm_pages[i]

        internal = 0
        external = 0
        m_object_val = _vm_page_unpack_ptr(m.vmp_object)

        if m_object:
            if m_object.internal:
                internal = 1
            else:
                external = 1

        if m.vmp_wire_count != 0 and m.vmp_local == 0:
            wired_count = wired_count + 1
            pageable = 0
        elif m.vmp_throttled:
            throttled_count = throttled_count + 1
            pageable = 0
        elif m.vmp_active:
            active_count = active_count + 1
            pageable = 1
        elif m.vmp_local:
            local_active_count = local_active_count + 1
            pageable = 0
        elif m.vmp_inactive:
            inactive_count = inactive_count + 1
            pageable = 1
        elif m.vmp_speculative:
            speculative_count = speculative_count + 1
            pageable = 0
        elif m.vmp_free:
            free_count = free_count + 1
            pageable = 0
        elif m.vmp_secluded:
            secluded_count = secluded_count + 1
            if m_object == 0:
                secluded_free_count = secluded_free_count + 1
            else:
                secluded_inuse_count = secluded_inuse_count + 1
            pageable = 0
        elif m_object == 0 and m.vmp_busy:
            local_free_count = local_free_count + 1
            pageable = 0
        elif m.vmp_compressor:
            compressor_count = compressor_count + 1
            pageable = 0
        else:
            print "weird page vm_pages[{:d}]?\n".format(i)
            pageable = 0

        if pageable:
            if internal:
                pageable_internal_count = pageable_internal_count + 1
            else:
                pageable_external_count = pageable_external_count + 1
        i = i + 1

    print "vm_pages_count = {:d}\n".format(vm_pages_count)

    print "wired_count = {:d}\n".format(wired_count)
    print "throttled_count = {:d}\n".format(throttled_count)
    print "active_count = {:d}\n".format(active_count)
    print "local_active_count = {:d}\n".format(local_active_count)
    print "inactive_count = {:d}\n".format(inactive_count)
    print "speculative_count = {:d}\n".format(speculative_count)
    print "free_count = {:d}\n".format(free_count)
    print "local_free_count = {:d}\n".format(local_free_count)
    print "compressor_count = {:d}\n".format(compressor_count)

    print "pageable_internal_count = {:d}\n".format(pageable_internal_count)
    print "pageable_external_count = {:d}\n".format(pageable_external_count)
    print "secluded_count = {:d}\n".format(secluded_count)
    print "secluded_free_count = {:d}\n".format(secluded_free_count)
    print "secluded_inuse_count = {:d}\n".format(secluded_inuse_count)


@lldb_command('show_all_vm_named_entries')
def ShowAllVMNamedEntries(cmd_args=None):
    """ Routine to print a summary listing of all the VM named entries
    """
    queue_len = kern.globals.vm_named_entry_count
    queue_head = kern.globals.vm_named_entry_list

    print 'vm_named_entry_list:{: <#018x}  vm_named_entry_count:{:d}\n'.format(kern.GetLoadAddressForSymbol('vm_named_entry_list'),queue_len)

    print '{:>6s} {:<6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s}   {:>3s} {:18s} {:>6s} {:<20s}\n'.format("#","#","object","P","refcnt","size (pages)","resid","wired","compressed","tag","owner","pid","process")
    idx = 0
    for entry in IterateQueue(queue_head, 'struct vm_named_entry *', 'named_entry_list'):
        idx += 1
        showmemoryentry(entry, idx, queue_len)

@lldb_command('show_vm_named_entry')
def ShowVMNamedEntry(cmd_args=None):
    """ Routine to print a VM named entry
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument.", ShowMapVMNamedEntry.__doc__
        return
    named_entry = kern.GetValueFromAddress(cmd_args[0], 'vm_named_entry_t')
    showmemoryentry(named_entry, 0, 0)

def showmemoryentry(entry, idx=0, queue_len=0):
    """  Routine to print out a summary a VM memory entry
        params: 
            entry - core.value : a object of type 'struct vm_named_entry *'
        returns:
            None
    """
    show_pager_info = True
    show_all_shadows = True

    backing = ""
    if entry.is_sub_map == 1:
        backing += "SUBMAP"
    if entry.is_copy == 1:
        backing += "COPY"
    if entry.is_sub_map == 0 and entry.is_copy == 0:
        backing += "OBJECT"
    prot=""
    if entry.protection & 0x1:
        prot += "r"
    else:
        prot += "-"
    if entry.protection & 0x2:
        prot += "w"
    else:
        prot += "-"
    if entry.protection & 0x4:
        prot += "x"
    else:
        prot += "-"
    extra_str = ""
    if hasattr(entry, 'named_entry_alias'):
        extra_str += " alias={:d}".format(entry.named_entry_alias)
    if hasattr(entry, 'named_entry_port'):
        extra_str += " port={:#016x}".format(entry.named_entry_port)
    print "{:>6d}/{:<6d} {: <#018x} ref={:d} prot={:d}/{:s} type={:s} backing={: <#018x} offset={:#016x} dataoffset={:#016x} size={:#016x}{:s}\n".format(idx,queue_len,entry,entry.ref_count,entry.protection,prot,backing,entry.backing.object,entry.offset,entry.data_offset,entry.size,extra_str)
    if entry.is_sub_map == 1:
        showmapvme(entry.backing.map, 0, 0, show_pager_info, show_all_shadows)
    if entry.is_copy == 1:
        showmapcopyvme(entry.backing.copy, 0, 0, 0, show_pager_info, show_all_shadows, 0)
    if entry.is_sub_map == 0 and entry.is_copy == 0:
        showvmobject(entry.backing.object, entry.offset, entry.size, show_pager_info, show_all_shadows)


def IterateRBTreeEntry2(element, element_type, field_name1, field_name2):
    """ iterate over a rbtree as defined with RB_HEAD in libkern/tree.h
            element      - value : Value object for rbh_root
            element_type - str   : Type of the link element
            field_name   - str   : Name of the field in link element's structure
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type) head->sle_next. Always a pointer object
    """
    elt = element.__getattr__('rbh_root')
    if type(element_type) == str:
        element_type = gettype(element_type)
    charp_type = gettype('char *');

    # Walk to find min
    parent = elt
    while unsigned(elt) != 0:
        parent = elt
        elt = cast(elt.__getattr__(field_name1).__getattr__(field_name2).__getattr__('rbe_left'), element_type)
    elt = parent

    # Now elt is min
    while unsigned(elt) != 0:
        yield elt
        # implementation cribbed from RB_NEXT in libkern/tree.h
        right = cast(elt.__getattr__(field_name1).__getattr__(fieldname2).__getattr__('rbe_right'), element_type)
        if unsigned(right) != 0:
            elt = right
            left = cast(elt.__getattr__(field_name1).__getattr__(field_name2).__getattr__('rbe_left'), element_type)
            while unsigned(left) != 0:
                elt = left
                left = cast(elt.__getattr__(field_name1).__getattr(__field_name2).__getattr__('rbe_left'), element_type)
        else:

            # avoid using GetValueFromAddress
            addr = elt.__getattr__(field_name1).__getattr__(field_name2).__getattr__('rbe_parent')&~1
            parent = value(elt.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
            parent = cast(parent, element_type)

            if unsigned(parent) != 0:
                left = cast(parent.__getattr__(field_name1).__getattr__(field_name2).__getattr__('rbe_left'), element_type)
            if (unsigned(parent) != 0) and (unsigned(elt) == unsigned(left)):
                elt = parent
            else:
                if unsigned(parent) != 0:
                    right = cast(parent.__getattr__(field_name1).__getattr__(field_name2).__getattr__('rbe_right'), element_type)
                while unsigned(parent) != 0 and (unsigned(elt) == unsigned(right)):
                    elt = parent

                    # avoid using GetValueFromAddress
                    addr = elt.__getattr__(field_name1).__getattr__(field_name2).__getattr__('rbe_parent')&~1
                    parent = value(elt.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
                    parent = cast(parent, element_type)

                    right = cast(parent.__getattr__(field_name1).__getattr__(field_name2).__getattr__('rbe_right'), element_type)

                # avoid using GetValueFromAddress
                addr = elt.__getattr__(field_name1).__getattr__(field_name2).__getattr__('rbe_parent')&~1
                elt = value(elt.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
                elt = cast(elt, element_type)


@lldb_command("showmaprb")
def ShowMapRB(cmd_args=None):
    """Routine to print out a VM map's RB tree
        usage: showmaprb <vm_map>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "Invalid argument.", ShowMapRB.__doc__
        return
    map_val = kern.GetValueFromAddress(cmd_args[0], 'vm_map_t')
    print GetVMMapSummary.header
    print GetVMMapSummary(map_val)
    vme_rb_root = map_val.hdr.rb_head_store
    vme_ptr_type = GetType('struct vm_map_entry *')
    print GetVMEntrySummary.header
    for vme in IterateRBTreeEntry2(vme_rb_root, 'struct vm_map_entry *', 'store', 'entry'):
        print GetVMEntrySummary(vme)
    return None

@lldb_command('show_all_owned_objects', 'T')
def ShowAllOwnedObjects(cmd_args=None, cmd_options={}):
    """ Routine to print the list of VM objects owned by each task
        -T: show only ledger-tagged objects
    """
    showonlytagged = False
    if "-T" in cmd_options:
        showonlytagged = True
    for task in kern.tasks:
        ShowTaskOwnedVmObjects(task, showonlytagged)

@lldb_command('show_task_owned_objects', 'T')
def ShowTaskOwnedObjects(cmd_args=None, cmd_options={}):
    """ Routine to print the list of VM objects owned by the specified task
        -T: show only ledger-tagged objects
    """
    showonlytagged = False
    if "-T" in cmd_options:
        showonlytagged = True
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    ShowTaskOwnedVmObjects(task, showonlytagged)

def ShowTaskOwnedVmObjects(task, showonlytagged=False):
    """  Routine to print out a summary listing of all the entries in a vm_map
        params:
            task - core.value : a object of type 'task *'
        returns:
            None
    """
    taskobjq_total = lambda:None
    taskobjq_total.objects = 0
    taskobjq_total.vsize = 0
    taskobjq_total.rsize = 0
    taskobjq_total.wsize = 0
    taskobjq_total.csize = 0
    vmo_list_head = task.task_objq
    vmo_ptr_type = GetType('vm_object *')
    idx = 0
    for vmo in IterateQueue(vmo_list_head, vmo_ptr_type, "task_objq"):
        idx += 1
        if not showonlytagged or vmo.vo_ledger_tag != 0:
            if taskobjq_total.objects == 0:
                print ' \n'
                print GetTaskSummary.header + ' ' + GetProcSummary.header
                print GetTaskSummary(task) + ' ' + GetProcSummary(Cast(task.bsd_info, 'proc *'))
                print '{:>6s} {:<6s} {:18s} {:1s} {:>6s} {:>16s} {:>10s} {:>10s} {:>10s} {:>2s} {:18s} {:>6s} {:<20s}\n'.format("#","#","object","P","refcnt","size (pages)","resid","wired","compressed","tg","owner","pid","process")
            ShowOwnedVmObject(vmo, idx, 0, taskobjq_total)
    if taskobjq_total.objects != 0:
        print "           total:{:<10d}  [ virtual:{:<10d}  resident:{:<10d}  wired:{:<10d}  compressed:{:<10d} ]\n".format(taskobjq_total.objects, taskobjq_total.vsize, taskobjq_total.rsize, taskobjq_total.wsize, taskobjq_total.csize)
    return None

def ShowOwnedVmObject(object, idx, queue_len, taskobjq_total):
    """  Routine to print out a VM object owned by a task
        params:
            object - core.value : a object of type 'struct vm_object *'
        returns:
            None
    """
    page_size = kern.globals.page_size
    if object.purgable == 0:
        purgable = "N"
    elif object.purgable == 1:
        purgable = "V"
    elif object.purgable == 2:
        purgable = "E"
    elif object.purgable == 3:
        purgable = "D"
    else:
        purgable = "?"
    if object.pager == 0:
        compressed_count = 0
    else:
        compressor_pager = Cast(object.pager, 'compressor_pager *')
        compressed_count = compressor_pager.cpgr_num_slots_occupied

    print "{:>6d}/{:<6d} {: <#018x} {:1s} {:>6d} {:>16d} {:>10d} {:>10d} {:>10d} {:>2d} {: <#018x} {:>6d} {:<20s}\n".format(idx,queue_len,object,purgable,object.ref_count,object.vo_un1.vou_size/page_size,object.resident_page_count,object.wired_page_count,compressed_count, object.vo_ledger_tag, object.vo_un2.vou_owner,GetProcPIDForObjectOwner(object.vo_un2.vou_owner),GetProcNameForObjectOwner(object.vo_un2.vou_owner))

    taskobjq_total.objects += 1
    taskobjq_total.vsize += object.vo_un1.vou_size/page_size
    taskobjq_total.rsize += object.resident_page_count
    taskobjq_total.wsize += object.wired_page_count
    taskobjq_total.csize += compressed_count

def GetProcPIDForObjectOwner(owner):
    """ same as GetProcPIDForTask() but deals with -1 for a disowned object
    """
    if unsigned(Cast(owner, 'int')) == unsigned(int(0xffffffff)):
        return -1
    return GetProcPIDForTask(owner)

def GetProcNameForObjectOwner(owner):
    """ same as GetProcNameForTask() but deals with -1 for a disowned object
    """
    if unsigned(Cast(owner, 'int')) == unsigned(int(0xffffffff)):
        return "<disowned>"
    return GetProcNameForTask(owner)

def GetDescForNamedEntry(mem_entry):
    out_str = "\n"
    out_str += "\t\tmem_entry {:#08x} ref:{:d} offset:{:#08x} size:{:#08x} prot{:d} backing {:#08x}".format(mem_entry, mem_entry.ref_count, mem_entry.offset, mem_entry.size, mem_entry.protection, mem_entry.backing.object)
    if mem_entry.is_sub_map:
        out_str += " is_sub_map"
    elif mem_entry.is_copy:
        out_str += " is_copy"
    else:
        out_str += " is_object"
    return out_str
