"""
    Triage Macros for zone related panics
    
    Supported panic strings from xnu/osfmk/kern/zalloc.c: 
        "a freed zone element has been modified in zone %s: expected %p but found %p, bits changed %p, at offset %d of %d in element %p, cookies %p %p" and
        "zalloc: zone map exhausted while allocating from zone %s, likely due to memory leak in zone %s (%lu total bytes, %d elements allocated)"
    These macros are dependant on the above panic strings. If the strings are modified in any way, this script must be updated to reflect the change.
    
    To support more zone panic strings:
        1.  Add the panic string regex to the globals and include in the named capture group 'zone' (the zone to be 
            logged) as well as any other info necessary to parse out of the panic string.
        2.  Add a check for the panic string regex in ZoneTriage(), which then calls into the function you create.
        3.  Add a check for the panic string regex in CheckZoneBootArgs() which sets the variable panic_string_regex to your 
            panic string regex if found.
        4.  Create a function that can be called either through the zonetriage macro ZoneTriage() or using its own macro. 
            This function should handle all lldb commands you want to run for this type of zone panic.
"""
from xnu import *
import sys, shlex
from utils import *
import xnudefines
import re
import os.path

## Globals
panic_string = None
## If the following panic strings are modified in xnu/osfmk/kern/zalloc.c, they must be updated here to reflect the change.
zone_element_modified = ".*a freed zone element has been modified in zone (?P<zone>.+): expected (0x)?([0-9A-Fa-f]*)? but found (0x)?([0-9A-Fa-f]*)?, bits changed (0x)?([0-9A-Fa-f]*)?, at offset ([0-9]*)? of ([0-9]*)? in element (?P<element>0x[0-9A-Fa-f]*), cookies (0x)?([0-9A-Fa-f]*)? (0x)?([0-9A-Fa-f]*)?.*"
zone_map_exhausted = ".*zalloc: zone map exhausted while allocating from zone .+, likely due to memory leak in zone (?P<zone>.+) \(([0-9]*)? total bytes, ([0-9]*)? elements allocated\).*"

# Macro: zonetriage, zonetriage_freedelement, zonetriage_memoryleak
@lldb_command('zonetriage')
def ZoneTriage(cmd_args=None):
    """ Calls function specific to type of zone panic based on the panic string
    """
    global panic_string
    if panic_string is None:
        try:
            panic_string = lldb_run_command("paniclog").split('\n', 1)[0]
        except:
            return
    if re.match(zone_element_modified, panic_string) is not None:
        ZoneTriageFreedElement()
    elif re.match(zone_map_exhausted, panic_string) is not None:
        ZoneTriageMemoryLeak()
    else:
        print "zonetriage does not currently support this panic string."

@lldb_command('zonetriage_freedelement')
def ZoneTriageFreedElement(cmd_args=None):
    """ Runs zstack_findelem on the element and zone being logged based on the panic string regex
    """
    global panic_string
    if panic_string is None:
        try:
            panic_string = lldb_run_command("paniclog").split('\n', 1)[0]
        except:
            return
    CheckZoneBootArgs()
    ## Run showzonesbeinglogged. 
    print "(lldb) zstack_showzonesbeinglogged\n%s\n" % lldb_run_command("zstack_showzonesbeinglogged")
    ## Capture zone and element from panic string.
    values = re.search(zone_element_modified, panic_string)
    if values is None or 'zone' not in values.group() or 'element' not in values.group():
        return
    element = values.group('element')
    zone = values.group('zone')
    btlog = FindZoneBTLog(zone)
    if btlog is not None:
        print "(lldb) zstack_findelem " + btlog + " " + element
        findelem_output = lldb_run_command("zstack_findelem " + btlog + " " + element)
        findelem_output = re.sub('Scanning is ongoing. [0-9]* items scanned since last check.\n', '', findelem_output)
        print findelem_output

@lldb_command('zonetriage_memoryleak')
def ZoneTriageMemoryLeak(cmd_args=None):
    """ Runs zstack_findtop and zstack_findleak on all zones being logged
    """
    global kern
    CheckZoneBootArgs()
    ## Run showzonesbeinglogged. 
    print "(lldb) zstack_showzonesbeinglogged\n%s\n" % lldb_run_command("zstack_showzonesbeinglogged")
    for zval in kern.zones:
        if zval.zlog_btlog:
            print '%s:' % zval.zone_name
            print "(lldb) zstack_findtop -N 5 0x%lx" % zval.zlog_btlog
            print lldb_run_command("zstack_findtop -N 5 0x%lx" % zval.zlog_btlog)
            print "(lldb) zstack_findleak 0x%lx" % zval.zlog_btlog
            print lldb_run_command("zstack_findleak 0x%lx" % zval.zlog_btlog)

def CheckZoneBootArgs(cmd_args=None):
    """ Check boot args to see if zone is being logged, if not, suggest new boot args
    """
    global panic_string
    if panic_string is None:
        try:
            panic_string = lldb_run_command("paniclog").split('\n', 1)[0]
        except:
            return
    panic_string_regex = ""
    if re.match(zone_element_modified, panic_string) is not None:
        panic_string_regex = zone_element_modified
    if re.match(zone_map_exhausted, panic_string) is not None:
        panic_string_regex = zone_map_exhausted
    values = re.search(panic_string_regex, panic_string)
    if values is None or 'zone' not in values.group():
        return
    zone = values.group('zone')
    bootargs = lldb_run_command("showbootargs")
    correct_boot_args = re.search('zlog([1-9]|10)?=' + re.sub(' ', '.', zone), bootargs)
    if correct_boot_args is None:
        print "Current boot-args:\n" + bootargs
        print "You may need to include: -zc -zp zlog([1-9]|10)?=" + re.sub(' ', '.', zone)

def FindZoneBTLog(zone):
    """ Returns the btlog address in the format 0x%lx for the zone name passed as a parameter
    """
    global kern
    for zval in kern.zones:
        if zval.zlog_btlog:
            if zone == "%s" % zval.zone_name:
                return "0x%lx" % zval.zlog_btlog
    return None
# EndMacro: zonetriage, zonetriage_freedelement, zonetriage_memoryleak
