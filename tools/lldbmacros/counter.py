from memory import IterateZPerCPU
from xnu import *

@lldb_type_summary(['scalable_counter_t'])
@header("Counter Value\n-------------")
def GetSimpleCounter(counter):
    """ Prints out the value of a percpu counter
        params: counter: value - value object representing counter
        returns: str - THe value of the counter as a string.
    """
    val = 0
    for v in IterateZPerCPU(counter, "uint64_t *"):
        val += dereference(v)
    return str(val)

@lldb_command('showcounter')
def ShowSimpleCounter(cmd_args=None):
    """ Show the value of a percpu counter.
        Usage: showcounter <address of counter>
    """
    if not cmd_args:
        raise ArgumentError("Please specify the address of the counter you want to read.")
        return
    print GetSimpleCounter(kern.GetValueFromAddress(cmd_args[0], "scalable_counter_t"))
