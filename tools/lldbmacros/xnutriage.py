"""
    XNU Triage commands
"""
from xnu import *
import sys, shlex
from utils import *
import xnudefines
import re
import os.path

# Macro: xi
def OutputAddress(cmd_args=None):
    """ Returns out address and symbol corresponding to it without newline
        Parameters: <address whose symbol is needed>
    """
    if not cmd_args:
        print "No arguments passed"
        print OutputAddress.__doc__
        return False
    a = unsigned(cmd_args[0])
    cmd_str = "image lookup -a {:#x}".format(a)
    cmd_out = lldb_run_command(cmd_str)
    if len(cmd_out) != 0 and cmd_out != "ERROR:":
        cmd_out1 = cmd_out.split('\n')
        if len(cmd_out1) != 0:
            cmd_out2 = cmd_out1[1].split('`')
            if cmd_out2 != 0:
                cmd_out3 = cmd_out2[1].split(' at')
                if len(cmd_out3) != 0:
                    symbol_str = "{:#x} <{:s}>".format(unsigned(a), cmd_out3[0])
                    return symbol_str
    return ""

@lldb_command('xi')
def SymbolicateWithInstruction(cmd_args=None):
    """ Prints out address and symbol similar to x/i
        Usage: xi <address whose symbol is needed>
    """
    if not cmd_args:
        print "No arguments passed"
        print SymbolicateWithInstruction.__doc__
        return False
    a = ArgumentStringToInt(cmd_args[0])
    print OutputAddress([a])

# Macro: xi

# Macro: newbt
@lldb_command('newbt')
def NewBt(cmd_args=None):
    """ Prints all the instructions by walking the given stack pointer
    """
    if not cmd_args:
        print "No arguments passed"
        print NewBt.__doc__
        return False
    a = ArgumentStringToInt(cmd_args[0])
    while a != 0:
        if kern.arch == "x86_64" or kern.arch.startswith("arm64"):
            offset = 8
        else:
            offset = 4
        link_register = dereference(kern.GetValueFromAddress(a + offset, 'uintptr_t *'))
        cmd_str = "di -s {:#x} -c 1".format(link_register)
        cmd_out = lldb_run_command(cmd_str)
        if len(cmd_out) != 0:
            cmd_out1 = cmd_out.split('\n')
            if len(cmd_out1) != 0:
                address = OutputAddress([unsigned(link_register)])
                if address is None:
                    address = '0x%x <???>' % unsigned(link_register)
                print address + ": " + cmd_out1[1].split(':', 1)[1]
        a = dereference(kern.GetValueFromAddress(unsigned(a), 'uintptr_t *'))

# EndMacro: newbt

# Macro: parseLR
@lldb_command('parseLR')
def parseLR(cmd_args=None):
    """ Decode the LR value from panic log into source code location
    """
    global paniclog_data
    panic_found = 1

    if not paniclog_data:
        if kern.arch == "x86_64":
            paniclog_data += returnfunc("\n(lldb) paniclog\n", "paniclog -v")
        else:
            paniclog_data += returnfunc("\n(lldb) paniclog\n", "paniclog")

    if panic_found == 1:
        srch_string = "lr:\s+0x[a-fA-F0-9]+\s"
        lr_pc_srch = re.findall(srch_string, paniclog_data)
        if lr_pc_srch:
            print paniclog_data, lr_pc_srch
            for match in lr_pc_srch:
                sp=match.strip("lr: ")
                print sp
                print "(lldb) list *{:s}".format(sp)
                print lldb_run_command("list *{:s}".format(sp))

    else:
        print "Currently unsupported on x86_64 architecture"
#EndMacro: parseLR

# Macro: parseLRfromfile
@lldb_command('parseLRfromfile')
def parseLRfromfile(cmd_args=None):
    """ Decode the LR value from file into source code location
    """
    f = open('/tmp/lrparsefile', 'r')
    parse_data= f.read()
    srch_string = "lr:\s+0x[a-fA-F0-9]+\s"
    lr_pc_srch = re.findall(srch_string, parse_data)
    if lr_pc_srch:
        print paniclog_data, lr_pc_srch
        for match in lr_pc_srch:
            sp=match.strip("lr: ")
            print sp
            print "(lldb) list *{:s}".format(sp)
            print lldb_run_command("list *{:s}".format(sp))

#EndMacro: parseLRfromfile

