import sys, subprocess, os, re, time, getopt, shlex
import lldb
from functools import wraps
from ctypes import c_ulonglong as uint64_t
from ctypes import c_void_p as voidptr_t
import code
import core
from core import caching
from core.standard import *
from core.configuration import *
from core.kernelcore import *
from utils import *
from core.lazytarget import *

MODULE_NAME=__name__ 

""" Kernel Debugging macros for lldb.
    Please make sure you read the README COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""

# End Utility functions
# Debugging specific utility functions 

#decorators. Not to be called directly.

def static_var(var_name, initial_value):
    def _set_var(obj):
        setattr(obj, var_name, initial_value)
        return obj
    return _set_var

def header(initial_value):
    def _set_header(obj):
        setattr(obj, 'header', initial_value)
        return obj
    return _set_header

# holds type declarations done by xnu. 
#DONOTTOUCHME: Exclusive use of lldb_type_summary only.
lldb_summary_definitions = {} 
def lldb_type_summary(types_list):
    """ A function decorator to register a summary for a type in lldb. 
        params: types_list - [] an array of types that you wish to register a summary callback function. (ex. ['task *', 'task_t'])
        returns: Nothing. This is a decorator.
    """
    def _get_summary(obj):
        def _internal_summary_function(lldbval, internal_dict):
            out_string= ""
            if internal_dict != None and len(obj.header) > 0 :
                out_string += "\n" + obj.header +"\n"
            out_string += obj( core.value(lldbval) )
            return out_string
        
        myglobals = globals()
        summary_function_name = "LLDBSummary" + obj.__name__
        myglobals[summary_function_name] = _internal_summary_function
        summary_function = myglobals[summary_function_name]
        summary_function.__doc__ = obj.__doc__
        
        global lldb_summary_definitions
        for single_type in types_list:
            if config['showTypeSummary']:
                if single_type in lldb_summary_definitions.keys():
                    lldb.debugger.HandleCommand("type summary delete --category kernel \""+ single_type + "\"")
                lldb.debugger.HandleCommand("type summary add \""+ single_type +"\" --category kernel --python-function " + MODULE_NAME + "." + summary_function_name)
            lldb_summary_definitions[single_type] = obj
            
        return obj
    return _get_summary

#global cache of documentation for lldb commands exported by this module 
#DONOTTOUCHME: Exclusive use of lldb_command only.
lldb_command_documentation = {}

def lldb_command(cmd_name, option_string = ''):
    """ A function decorator to define a command with namd 'cmd_name' in the lldb scope to call python function.
        params: cmd_name - str : name of command to be set in lldb prompt.
            option_string - str: getopt like option string. Only CAPITAL LETTER options allowed. 
                                 see README on Customizing command options.
    """
    if option_string != option_string.upper():
        raise RuntimeError("Cannot setup command with lowercase option args. %s" % option_string)

    def _cmd(obj):
        def _internal_command_function(debugger, command, result, internal_dict):
            global config, lldb_run_command_state
            stream = CommandOutput(result)
            # need to avoid printing on stdout if called from lldb_run_command.
            if 'active' in lldb_run_command_state and lldb_run_command_state['active']:
                debuglog('Running %s from lldb_run_command' % command)
            else:
                result.SetImmediateOutputFile(sys.__stdout__)

            command_args = shlex.split(command)
            lldb.debugger.HandleCommand('type category disable kernel' )
            def_verbose_level = config['verbosity']
            
            try:
                stream.setOptions(command_args, option_string)
                if stream.verbose_level != 0:
                    config['verbosity'] = stream.verbose_level 
                with RedirectStdStreams(stdout=stream) :
                    if option_string:
                        obj(cmd_args=stream.target_cmd_args, cmd_options=stream.target_cmd_options)
                    else:
                        obj(cmd_args=stream.target_cmd_args)
            except KeyboardInterrupt:
                print "Execution interrupted by user"
            except ArgumentError as arg_error:
                if str(arg_error) != "HELP":
                    print "Argument Error: " + str(arg_error)
                print "{0:s}:\n        {1:s}".format(cmd_name, obj.__doc__.strip())
                return False
            except Exception as exc:
                if not config['debug']:
                    print """
************ LLDB found an exception ************
There has been an uncaught exception. A possible cause could be that remote connection has been disconnected.
However, it is recommended that you report the exception to lldb/kernel debugging team about it.
************ Please run 'xnudebug debug enable' to start collecting logs. ************
                          """
                raise

            if config['showTypeSummary']:
                lldb.debugger.HandleCommand('type category enable kernel' )
            
            if stream.pluginRequired :
                plugin = LoadXNUPlugin(stream.pluginName)
                if plugin == None :
                    print "Could not load plugins."+stream.pluginName
                    return
                plugin.plugin_init(kern, config, lldb, kern.IsDebuggerConnected())
                return_data = plugin.plugin_execute(cmd_name, result.GetOutput())
                ProcessXNUPluginResult(return_data)
                plugin.plugin_cleanup()
            
            #restore the verbose level after command is complete
            config['verbosity'] = def_verbose_level
            
            return

        myglobals = globals()
        command_function_name = obj.__name__+"Command"
        myglobals[command_function_name] =  _internal_command_function
        command_function = myglobals[command_function_name]
        if not obj.__doc__ :
            print "ERROR: Cannot register command({:s}) without documentation".format(cmd_name)
            return obj
        command_function.__doc__ = obj.__doc__
        global lldb_command_documentation
        if cmd_name in lldb_command_documentation:
            lldb.debugger.HandleCommand("command script delete "+cmd_name)
        lldb_command_documentation[cmd_name] = (obj.__name__, obj.__doc__.lstrip(), option_string)
        lldb.debugger.HandleCommand("command script add -f " + MODULE_NAME + "." + command_function_name + " " + cmd_name)
        return obj
    return _cmd

def lldb_alias(alias_name, cmd_line):
    """ define an alias in the lldb command line. 
        A programatic way of registering an alias. This basically does
        (lldb)command alias alias_name "cmd_line"
        ex. 
        lldb_alias('readphys16', 'readphys 16')
    """
    alias_name = alias_name.strip()
    cmd_line = cmd_line.strip()
    lldb.debugger.HandleCommand("command alias " + alias_name + " "+ cmd_line)

def SetupLLDBTypeSummaries(reset=False):
    global lldb_summary_definitions, MODULE_NAME
    if reset == True:
            lldb.debugger.HandleCommand("type category delete  kernel ")
    for single_type in lldb_summary_definitions.keys():
        summary_function = lldb_summary_definitions[single_type]
        lldb_cmd = "type summary add \""+ single_type +"\" --category kernel --python-function " + MODULE_NAME + ".LLDBSummary" + summary_function.__name__
        debuglog(lldb_cmd)
        lldb.debugger.HandleCommand(lldb_cmd)
    if config['showTypeSummary']:
            lldb.debugger.HandleCommand("type category enable  kernel")
    else:
            lldb.debugger.HandleCommand("type category disable kernel")

    return

def LoadXNUPlugin(name):
    """ Try to load a plugin from the plugins directory. 
    """
    retval = None
    name=name.strip()
    try:
        module_obj = __import__('plugins.'+name, globals(), locals(), [], -1)
        module_obj = module_obj.__dict__[name]
        defs = dir(module_obj)
        if 'plugin_init' in defs and 'plugin_execute' in defs and 'plugin_cleanup' in defs:
            retval = module_obj
        else:
            print "Plugin is not correctly implemented. Please read documentation on implementing plugins"
    except:
        print "plugin not found :"+name
         
    return retval

def ProcessXNUPluginResult(result_data):
    """ Look at the returned data from plugin and see if anymore actions are required or not
        params: result_data - list of format (status, out_string, more_commands)
    """
    ret_status = result_data[0]
    ret_string = result_data[1]
    ret_commands = result_data[2]
    
    if ret_status == False:
        print "Plugin failed: " + ret_string
        return
    print ret_string
    if len(ret_commands) >= 0:
        for cmd in ret_commands:
            print "Running command on behalf of plugin:" + cmd
            lldb.debugger.HandleCommand(cmd)
    return

# holds tests registered with xnu.
#DONOTTOUCHME: Exclusive use of xnudebug_test only
lldb_command_tests = {}
def xnudebug_test(test_name):
    """ A function decoratore to register a test with the framework. Each test is supposed to be of format 
        def Test<name>(kernel_target, config, lldb_obj, isConnected )
        
        NOTE: The testname should start with "Test" else exception will be raised.
    """
    def _test(obj):
        global lldb_command_tests
        if obj.__name__.find("Test") != 0 :
            print "Test name ", obj.__name__ , " should start with Test" 
            raise ValueError
        lldb_command_tests[test_name] = (test_name, obj.__name__, obj, obj.__doc__)
        return obj
    return _test


# End Debugging specific utility functions
# Kernel Debugging specific classes and accessor methods 

# global access object for target kernel

def GetObjectAtIndexFromArray(array_base, index):
    """ Subscript indexing for arrays that are represented in C as pointers.
        for ex. int *arr = malloc(20*sizeof(int));
        now to get 3rd int from 'arr' you'd do 
        arr[2] in C
        GetObjectAtIndexFromArray(arr_val,2)
        params:
            array_base : core.value - representing a pointer type (ex. base of type 'ipc_entry *')
            index : int - 0 based index into the array
        returns:
            core.value : core.value of the same type as array_base_val but pointing to index'th element
    """
    array_base_val = array_base.GetSBValue()
    base_address = array_base_val.GetValueAsUnsigned()
    size = array_base_val.GetType().GetPointeeType().GetByteSize()
    obj_address = base_address + (index * size)
    obj = kern.GetValueFromAddress(obj_address, array_base_val.GetType().GetName())
    return Cast(obj, array_base_val.GetType())


kern = None

def GetLLDBThreadForKernelThread(thread_obj):
    """ Get a reference to lldb.SBThread representation for kernel thread.
        params:
            thread_obj : core.cvalue - thread object of type thread_t 
        returns 
            lldb.SBThread - lldb thread object for getting backtrace/registers etc.
    """
    tid = unsigned(thread_obj.thread_id)
    lldb_process = LazyTarget.GetProcess()
    sbthread = lldb_process.GetThreadByID(tid)
    if not sbthread.IsValid():
        # in case lldb doesnt know about this thread, create one
        if hasattr(lldb_process, "CreateOSPluginThread"):
            debuglog("creating os plugin thread on the fly for {0:d} 0x{1:x}".format(tid, thread_obj))
            lldb_process.CreateOSPluginThread(tid, unsigned(thread_obj))
        else:
            raise RuntimeError("LLDB process does not support CreateOSPluginThread.")
        sbthread = lldb_process.GetThreadByID(tid)

    if not sbthread.IsValid():
        raise RuntimeError("Unable to find lldb thread for tid={0:d} thread = {1:#018x}".format(tid, thread_obj))
    
    return sbthread

def GetThreadBackTrace(thread_obj, verbosity = vHUMAN, prefix = ""):
    """ Get a string to display back trace for a thread.
        params:
            thread_obj - core.cvalue : a thread object of type thread_t.
            verbosity - int : either of vHUMAN, vSCRIPT or vDETAIL to describe the verbosity of output
            prefix - str : a string prefix added before the line for each frame.
            isContinuation - bool : is thread a continuation?
        returns:
            str - a multi line string showing each frame in backtrace.
    """
    is_continuation = not bool(unsigned(thread_obj.kernel_stack))
    thread_val = GetLLDBThreadForKernelThread(thread_obj)
    out_string = ""
    kernel_stack = unsigned(thread_obj.kernel_stack)
    reserved_stack = unsigned(thread_obj.reserved_stack)
    if not is_continuation:
        if kernel_stack and reserved_stack:
            out_string += prefix + "reserved_stack = {:#018x}\n".format(reserved_stack)
        out_string += prefix + "kernel_stack = {:#018x}\n".format(kernel_stack)
    else:
        out_string += prefix + "continuation ="
    iteration = 0
    last_frame_p = 0
    for frame in thread_val.frames:
        addr = frame.GetPCAddress()
        load_addr = addr.GetLoadAddress(LazyTarget.GetTarget())
        function = frame.GetFunction()
        frame_p = frame.GetFP()
        mod_name = frame.GetModule().GetFileSpec().GetFilename()

        if iteration == 0 and not is_continuation:
            out_string += prefix +"stacktop = {:#018x}\n".format(frame_p)
        
        if not function:
            # No debug info for 'function'.
            symbol = frame.GetSymbol()
            file_addr = addr.GetFileAddress()
            start_addr = symbol.GetStartAddress().GetFileAddress()
            symbol_name = symbol.GetName()
            symbol_offset = file_addr - start_addr
            out_string += prefix 
            if not is_continuation:
                out_string += "{fp:#018x} ".format(fp = frame_p) 
            out_string += "{addr:#018x} {mod}`{symbol} + {offset} \n".format(addr=load_addr, mod=mod_name, symbol=symbol_name, offset=symbol_offset)
        else:
            # Debug info is available for 'function'.
            func_name = frame.GetFunctionName()
            file_name = frame.GetLineEntry().GetFileSpec().GetFilename()
            line_num = frame.GetLineEntry().GetLine()
            func_name = '%s [inlined]' % func_name if frame.IsInlined() else func_name
            if is_continuation and frame.IsInlined():
                debuglog("Skipping frame for thread {:#018x} since its inlined".format(thread_obj))
                continue 
            out_string += prefix 
            if not is_continuation:
                out_string += "{fp:#018x} ".format(fp=frame_p)
            out_string += "{addr:#018x} {func}{args} \n".format(addr=load_addr,
                                    func=func_name,
                                    file=file_name, line=line_num,
                                    args="(" + (str(frame.arguments).replace("\n", ", ") if len(frame.arguments) > 0 else "void") + ")")
        iteration += 1 
        if frame_p:
            last_frame_p = frame_p

    if not is_continuation and last_frame_p:
        out_string += prefix + "stackbottom = {:#018x}".format(last_frame_p)
    out_string = out_string.replace("variable not available","")
    return out_string

def GetSourceInformationForAddress(addr):
    """ convert and address to function +offset information. 
        params: addr - int address in the binary to be symbolicated
        returns: string of format "0xaddress: function + offset" 
    """
    symbols = kern.SymbolicateFromAddress(addr)
    format_string = "{0:#018x} <{1:s} + {2:#0x}>"
    offset = 0
    function_name = ""
    if len(symbols) > 0:
        s = symbols[0]
        function_name = str(s.name)
        offset = addr - s.GetStartAddress().GetLoadAddress(LazyTarget.GetTarget())
    if function_name == "":
        function_name = "???"
    return format_string.format(addr, function_name, offset)

def GetFrameLocalVariable(variable_name, frame_no=0):
    """ Find a local variable by name
        params:
          variable_name: str - name of variable to search for
        returns: 
          core.value - if the variable is found.
          None   - if not found or not Valid
    """
    retval = None
    sbval = None
    lldb_SBThread = LazyTarget.GetProcess().GetSelectedThread()
    frame = lldb_SBThread.GetSelectedFrame()
    if frame_no :
      frame = lldb_SBThread.GetFrameAtIndex(frame_no)
    if frame :
      sbval = frame.FindVariable(variable_name)
    if sbval and sbval.IsValid():
      retval = core.cvalue.value(sbval)
    return retval

# Begin Macros for kernel debugging

@lldb_command('kgmhelp')
def KernelDebugCommandsHelp(cmd_args=None):
    """ Show a list of registered commands for kenel debugging.
    """
    global lldb_command_documentation
    print "List of commands provided by " + MODULE_NAME + " for kernel debugging."
    cmds = lldb_command_documentation.keys()
    cmds.sort()
    for cmd in cmds:
        if type(lldb_command_documentation[cmd][-1]) == type(""):
            print " {0: <20s} - {1}".format(cmd , lldb_command_documentation[cmd][1].split("\n")[0].strip())
        else:
            print " {0: <20s} - {1}".format(cmd , "No help string found.")
    print """
    Each of the functions listed here accept the following common options. 
        -h  Show the help string for the command.
        -o <path/to/filename>   The output of this command execution will be saved to file. Parser information or errors will 
                                not be sent to file though. eg /tmp/output.txt
        -s <filter_string>      The "filter_string" param is parsed to python regex expression and each line of output 
                                will be printed/saved only if it matches the expression. 
        -v [-v...]  Each additional -v will increase the verbosity of the command.
        -p <plugin_name>        Send the output of the command to plugin. Please see README for usage of plugins.

    Additionally, each command implementation may have more options. "(lldb) help <command> " will show these options.
    """
    return None


@lldb_command('showraw')    
def ShowRawCommand(cmd_args=None):
    """ A command to disable the kernel summaries and show data as seen by the system. 
        This is useful when trying to read every field of a struct as compared to brief summary
    """
    command = " ".join(cmd_args)
    lldb.debugger.HandleCommand('type category disable kernel' )
    lldb.debugger.HandleCommand( command )
    lldb.debugger.HandleCommand('type category enable kernel' )
 

@lldb_command('xnudebug')
def XnuDebugCommand(cmd_args=None):
    """  command interface for operating on the xnu macros. Allowed commands are as follows
        reload:
            Reload a submodule from the xnu/tools/lldb directory. Do not include the ".py" suffix in modulename.
            usage: xnudebug reload <modulename> (eg. memory, process, stats etc)
        test:
            Start running registered test with <name> from various modules.
            usage: xnudebug test <name> (eg. test_memstats)
        testall:
            Go through all registered tests and run them
        debug:
            Toggle state of debug configuration flag.
    """
    global config
    command_args = cmd_args
    if len(command_args) == 0:
        raise ArgumentError("No command specified.")
    supported_subcommands = ['debug', 'reload', 'test', 'testall']
    subcommand = GetLongestMatchOption(command_args[0], supported_subcommands, True)

    if len(subcommand) == 0:
        raise ArgumentError("Subcommand (%s) is not a valid command. " % str(command_args[0]))
    
    subcommand = subcommand[0].lower()
    if subcommand == 'debug':
        if command_args[-1].lower().find('dis') >=0 and config['debug']:
            config['debug'] = False
            print "Disabled debug logging."
        elif command_args[-1].lower().find('dis') < 0 and not config['debug']:
            config['debug'] = True
            EnableLLDBAPILogging()  # provided by utils.py
            print "Enabled debug logging. \nPlease run 'xnudebug debug disable' to disable it again. "
 
    if subcommand == 'reload':
        module_name = command_args[-1]
        if module_name in sys.modules:
            reload(sys.modules[module_name])
            print module_name + " is reloaded from " + sys.modules[module_name].__file__
        else:
            print "Unable to locate module named ", module_name
    if subcommand == 'testall':
        for test_name in lldb_command_tests.keys():
            print "[BEGIN]", test_name
            res = lldb_command_tests[test_name][2](kern, config, lldb, True)
            if res:
                print "[PASSED] {:s}".format(test_name)
            else:
                print "[FAILED] {:s}".format(test_name)
    if subcommand == 'test':
        test_name = command_args[-1]
        if test_name in lldb_command_tests:
            test = lldb_command_tests[test_name]
            print "Running test {:s}".format(test[0])
            if test[2](kern, config, lldb, True) : 
                print "[PASSED] {:s}".format(test[0])
            else:
                print "[FAILED] {:s}".format(test[0])
            return ""    
        else:
            print "No such test registered with name: {:s}".format(test_name)
            print "XNUDEBUG Available tests are:"
            for i in lldb_command_tests.keys():
                print i
        return None
    
    return False

@lldb_command('showversion')
def ShowVersion(cmd_args=None):
    """ Read the kernel version string from a fixed address in low
        memory. Useful if you don't know which kernel is on the other end,
        and need to find the appropriate symbols. Beware that if you've
        loaded a symbol file, but aren't connected to a remote target,
        the version string from the symbol file will be displayed instead.
        This macro expects to be connected to the remote kernel to function
        correctly.

    """
    print kern.version


@lldb_command('paniclog')
def ShowPanicLog(cmd_args=None):
    """ Display the paniclog information
    """
    panic_buf = kern.globals.debug_buf
    panic_buf_start = addressof(panic_buf)
    panic_buf_end = unsigned(kern.globals.debug_buf_ptr)
    num_bytes = panic_buf_end - panic_buf_start
    if num_bytes == 0 :
        return
    panic_data = panic_buf.GetSBValue().GetData()
    err = lldb.SBError()
    line = ''
    for i in range(0, num_bytes):
        c = panic_data.GetUnsignedInt8(err, i)
        if chr(c) == '\n':
            if line =='':
                line = " "
            print line 
            line = ''
        else:
            line += chr(c)
    
    if len(line) > 0: 
        print line
    
    return

@lldb_command('showbootargs')
def ShowBootArgs(cmd_args=None):
    """ Display boot arguments passed to the target kernel
    """
    bootargs = Cast(kern.GetGlobalVariable('PE_state').bootArgs, 'boot_args *')
    bootargs_cmd = bootargs.CommandLine
    print str(bootargs_cmd)

@static_var("last_process_uniq_id", 1)
def GetDebuggerStopIDValue():
    """ Create a unique session identifier. 
        returns:
            int - a unique number identified by processid and stopid.
    """
    stop_id = 0
    process_obj = LazyTarget.GetProcess()
    if hasattr(process_obj, "GetStopID"):
        stop_id = process_obj.GetStopID()
    proc_uniq_id = 0
    if hasattr(process_obj, 'GetUniqueID'):
        proc_uniq_id = process_obj.GetUniqueID()
        #FIXME <rdar://problem/13034329> forces us to do this twice
        proc_uniq_id = process_obj.GetUniqueID()
    else:
        GetDebuggerStopIDValue.last_process_uniq_id +=1
        proc_uniq_id = GetDebuggerStopIDValue.last_process_uniq_id + 1

    stop_id_str = "{:d}:{:d}".format(proc_uniq_id, stop_id)        
    return hash(stop_id_str)

# The initialization code to add your commands
_xnu_framework_init = False
def __lldb_init_module(debugger, internal_dict):
    global kern, lldb_command_documentation, config, _xnu_framework_init
    if _xnu_framework_init:
        return
    _xnu_framework_init = True
    caching._GetDebuggerSessionID = GetDebuggerStopIDValue
    debugger.HandleCommand('type summary add --regex --summary-string "${var%s}" -C yes -p -v "char \[[0-9]*\]"')
    debugger.HandleCommand('type format add --format hex -C yes uintptr_t')
    kern = KernelTarget(debugger)
    print "xnu debug macros loaded successfully. Run showlldbtypesummaries to enable type summaries."

__lldb_init_module(lldb.debugger, None)

@lldb_command("showlldbtypesummaries")
def ShowLLDBTypeSummaries(cmd_args=[]):
    """ Enable/Disable kernel type summaries. Default is disabled.
        Usage: showlldbtypesummaries [enable|disable]
        default is enable
    """
    global config
    action = "enable"
    trailer_msg = ''
    if len(cmd_args) > 0 and cmd_args[0].lower().find('disable') >=0:
        action = "disable"
        config['showTypeSummary'] = False
        trailer_msg = "Please run 'showlldbtypesummaries enable' to enable the summary feature."
    else:
        config['showTypeSummary'] = True
        SetupLLDBTypeSummaries(True)
        trailer_msg = "Please run 'showlldbtypesummaries disable' to disable the summary feature."
    lldb_run_command("type category "+ action +" kernel")
    print "Successfully "+action+"d the kernel type summaries. %s" % trailer_msg

from memory import *
from process import *
from ipc import * 
from pmap import *
from ioreg import *
from mbufs import *
from net import *
from kdp import *
from userspace import *
from pci import *
from misc import *
from apic import *
from scheduler import *
