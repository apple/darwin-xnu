from xnu import *
from utils import *


@lldb_type_summary(['atm_value', 'atm_value_t'])
@header("{0: <20s} {1: <16s} {2: <20s} {3: <16s}".format("atm_value", "aid", "voucher_value", "sync"))
def GetATMValueSummary(atm_value):
    """ Summarizes the atm_value
        params: atm_value = value object of type atm_value_t
        returns: string with the summary of the type.
    """
    format_str = "{0: <#020x} {1: <16d} {2: <#020x} {3: <16d}"
    out_string = format_str.format(atm_value, unsigned(atm_value.aid), atm_value, atm_value.sync)
    return out_string


@lldb_type_summary(['atm_task_descriptor', 'atm_task_descriptor_t'])
@header("{0: <20s} {1: <20s} {2: <16s} {3: <16s} {4: <10s}".format("task_descriptor", "trace_buffer", "buffer_size", "refcount", "flags"))
def GetATMTaskDescriptorSummary(descriptor):
    """ Summarizes atm_task_descriptor object
        params: descriptor - value object of type atm_task_descriptor_t
        returns: string - containing the description.
    """
    format_str = "{0: <#020x} {1: <#020x} {2: <#016x} {3: <16d} {4: <10s}"
    flags_str = ""
    if unsigned(descriptor.flags) & 0x1:
        flags_str = "DEAD"
    out_string = format_str.format(descriptor, descriptor.trace_buffer, descriptor.trace_buffer_size, descriptor.reference_count, flags_str)

    #if DEVELOPMENT
    if hasattr(descriptor, 'task'):
        out_string += "  " + GetTaskSummary(descriptor.task) + " "  + GetProcNameForTask(descriptor.task) 
    #endif

    return out_string

# Macro: showatmvaluelisteners
@lldb_command('showatmvaluelisteners')
def ShowATMValueListeners(cmd_args=None, cmd_options={}):
    """ show a list of listeners for an atm_value object.
        Usage: (lldb)showatmvaluelisteners <atm_value_t>
    """
    if not cmd_args:
        raise ArgumentError("Please provide arguments")

    atm_val = kern.GetValueFromAddress(cmd_args[0], 'atm_value_t')
    print GetATMValueSummary.header
    print GetATMValueSummary(atm_val)
    header_str = "{0: <20s} ".format("#guard") + GetATMTaskDescriptorSummary.header
    #if DEVELOPMENT
    header_str += "  " +  GetTaskSummary.header + " procname"
    #endif
    print header_str
    for listener in IterateQueue(atm_val.listeners, 'atm_link_object_t', 'listeners_element'):
        listener_summary = "{0: <#020x}".format(listener.guard)
        listener_summary += " " + GetATMTaskDescriptorSummary(listener.descriptor)
        print listener_summary
    return 
# EndMacro: showatmvaluelisteners


#if DEVELOPMENT

# Macro: showallatmallocatedvalueslist
@lldb_command('showallatmallocatedvalueslist')
def ShowAllATMAllocatedValuesList(cmd_args=None, cmd_options={}):
    """ A DEVELOPMENT macro that walks the list of all allocated atm_value objects
        and prints them.
        usage: (lldb) showallatmallocatedvalueslist
    """
    if not hasattr(kern.globals, 'atm_values_list'):
        print "It seems you are running a build of kernel that does not have the list of all atm_values_list."
        return False
    print GetATMValueSummary.header
    for v in IterateQueue(kern.globals.atm_values_list, 'atm_value_t', 'value_elt'):
        print GetATMValueSummary(v)
    return True
# EndMacro: showallatmallocatedvalueslist

# Macro: showallatmdescriptors
@lldb_command('showallatmdescriptors')
def ShowAllATMDescriptors(cmd_args=None, cmd_options={}):
    """ A DEVELOPMENT macro that walks the list of all atm_descriptors_list
        and prints the summary for each.
        usage: (lldb) showallatmdescriptors
    """
    if not hasattr(kern.globals, 'atm_descriptors_list'):
        print "It seems you are running a build of kernel that does not have the list of all atm_descriptors_list."
        return False

    print GetATMTaskDescriptorSummary.header
    for d in IterateQueue(kern.globals.atm_descriptors_list, 'atm_task_descriptor_t', 'descriptor_elt'):
        print GetATMTaskDescriptorSummary(d)
    return True 
# EndMacro
#endif
