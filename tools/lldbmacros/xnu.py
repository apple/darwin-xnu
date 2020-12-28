import sys, subprocess, os, re, time, getopt, shlex, xnudefines
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

COMMON_HELP_STRING = """
    -h  Show the help string for the command.
    -c [always|auto|never|0|1]
                            Control the colorized output of certain commands
    -o <path/to/filename>   The output of this command execution will be saved to file. Parser information or errors will
                            not be sent to file though. eg /tmp/output.txt
    -s <filter_string>      The "filter_string" param is parsed to python regex expression and each line of output
                            will be printed/saved only if it matches the expression.
    -v [-v...]  Each additional -v will increase the verbosity of the command.
    -p <plugin_name>        Send the output of the command to plugin. Please see README for usage of plugins.
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

def lldb_command(cmd_name, option_string = '', fancy=False):
    """ A function decorator to define a command with namd 'cmd_name' in the lldb scope to call python function.
        params: cmd_name - str : name of command to be set in lldb prompt.
            option_string - str: getopt like option string. Only CAPITAL LETTER options allowed.
                                 see README on Customizing command options.
            fancy - bool       : whether the command will receive an 'O' object to do fancy output (tables, indent, color)
    """
    if option_string != option_string.upper():
        raise RuntimeError("Cannot setup command with lowercase option args. %s" % option_string)

    def _cmd(obj):
        def _internal_command_function(debugger, command, result, internal_dict):
            global config, lldb_run_command_state
            stream = CommandOutput(cmd_name, result)
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
                    config['verbosity'] +=  stream.verbose_level
                with RedirectStdStreams(stdout=stream) :
                    args = { 'cmd_args': stream.target_cmd_args }
                    if option_string:
                        args['cmd_options'] = stream.target_cmd_options
                    if fancy:
                        args['O'] = stream
                    obj(**args)
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
        obj.__doc__ += "\n" + COMMON_HELP_STRING
        command_function.__doc__ = obj.__doc__
        global lldb_command_documentation
        if cmd_name in lldb_command_documentation:
            lldb.debugger.HandleCommand("command script delete "+cmd_name)
        lldb_command_documentation[cmd_name] = (obj.__name__, obj.__doc__.lstrip(), option_string)
        lldb.debugger.HandleCommand("command script add -f " + MODULE_NAME + "." + command_function_name + " " + cmd_name)

        if fancy:
            def wrapped_fun(cmd_args=None, cmd_options={}, O=None):
                if O is None:
                    stream = CommandOutput(cmd_name, fhandle=sys.stdout)
                    with RedirectStdStreams(stdout=stream):
                        return obj(cmd_args, cmd_options, stream)
                else:
                    return obj(cmd_args, cmd_options, O)
            return wrapped_fun
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
        raise RuntimeError("Unable to find lldb thread for tid={0:d} thread = {1:#018x} (#16049947: have you put 'settings set target.load-script-from-symbol-file true' in your .lldbinit?)".format(tid, thread_obj))

    return sbthread

def GetKextSymbolInfo(load_addr):
    """ Get a string descriptiong load_addr <kextname> + offset
        params:
            load_addr - int address value of pc in backtrace.
        returns: str - kext name + offset string. If no cached data available, warning message is returned.
    """
    symbol_name = "None"
    symbol_offset = load_addr
    kmod_val = kern.globals.kmod
    if not kern.arch.startswith('arm64'):
        for kval in IterateLinkedList(kmod_val, 'next'):
            if load_addr >= unsigned(kval.address) and \
                load_addr <= (unsigned(kval.address) + unsigned(kval.size)):
                symbol_name = kval.name
                symbol_offset = load_addr - unsigned(kval.address)
                break
        return "{:#018x} {:s} + {:#x} \n".format(load_addr, symbol_name, symbol_offset)

    # only for arm64 we do lookup for split kexts.
    cached_kext_info = caching.GetDynamicCacheData("kern.kexts.loadinformation", [])
    if not cached_kext_info and str(GetConnectionProtocol()) == "core":
        cached_kext_info = GetKextLoadInformation()

    if not cached_kext_info:
        return "{:#018x} ~ kext info not available. please run 'showallkexts' once ~ \n".format(load_addr)

    for kval in cached_kext_info:
        text_seg = kval[5]
        if load_addr >= text_seg.vmaddr and \
            load_addr <= (text_seg.vmaddr + text_seg.vmsize):
            symbol_name = kval[2]
            symbol_offset = load_addr - text_seg.vmaddr
            break
    return "{:#018x} {:s} + {:#x} \n".format(load_addr, symbol_name, symbol_offset)

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
            out_string += prefix
            if not is_continuation:
                out_string += "{fp:#018x} ".format(fp = frame_p)

            symbol = frame.GetSymbol()
            if not symbol:
                out_string += GetKextSymbolInfo(load_addr)
            else:
                file_addr = addr.GetFileAddress()
                start_addr = symbol.GetStartAddress().GetFileAddress()
                symbol_name = symbol.GetName()
                symbol_offset = file_addr - start_addr
                out_string += "{addr:#018x} {mod}`{symbol} + {offset:#x} \n".format(addr=load_addr,
                    mod=mod_name, symbol=symbol_name, offset=symbol_offset)
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
    print 'Each of the functions listed here accept the following common options. '
    print COMMON_HELP_STRING
    print 'Additionally, each command implementation may have more options. "(lldb) help <command> " will show these options.'
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
        flushcache:
            remove any cached data held in static or dynamic data cache.
            usage: xnudebug flushcache
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
    supported_subcommands = ['debug', 'reload', 'test', 'testall', 'flushcache']
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
    if subcommand == 'flushcache':
        print "Current size of cache: {}".format(caching.GetSizeOfCache())
        caching.ClearAllCache()

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

def ProcessPanicStackshot(panic_stackshot_addr, panic_stackshot_len):
    """ Process the panic stackshot from the panic header, saving it to a file if it is valid
        params: panic_stackshot_addr : start address of the panic stackshot binary data
                panic_stackshot_len : length of the stackshot binary data
        returns: nothing
    """
    if not panic_stackshot_addr:
        print "No panic stackshot available (invalid addr)"
        return

    if not panic_stackshot_len:
        print "No panic stackshot available (zero length)"
        return;

    ts = int(time.time())
    ss_binfile = "/tmp/panic_%d.bin" % ts
    ss_ipsfile = "/tmp/stacks_%d.ips" % ts

    if not SaveDataToFile(panic_stackshot_addr, panic_stackshot_len, ss_binfile, None):
        print "Failed to save stackshot binary data to file"
        return

    self_path = str(__file__)
    base_dir_name = self_path[:self_path.rfind("/")]
    print "python %s/kcdata.py %s -s %s" % (base_dir_name, ss_binfile, ss_ipsfile)
    (c,so,se) = RunShellCommand("python %s/kcdata.py %s -s %s" % (base_dir_name, ss_binfile, ss_ipsfile))
    if c == 0:
        print "Saved ips stackshot file as %s" % ss_ipsfile
        return
    else:
        print "Failed to run command: exit code: %d, SO: %s SE: %s" % (c, so, se)
        return

def ParseEmbeddedPanicLog(panic_header, cmd_options={}):
    panic_buf = Cast(panic_header, 'char *')
    panic_log_magic = unsigned(panic_header.eph_magic)
    panic_log_begin_offset = unsigned(panic_header.eph_panic_log_offset)
    panic_log_len = unsigned(panic_header.eph_panic_log_len)
    other_log_begin_offset = unsigned(panic_header.eph_other_log_offset)
    other_log_len = unsigned(panic_header.eph_other_log_len)
    expected_panic_magic = xnudefines.EMBEDDED_PANIC_MAGIC
    panic_stackshot_addr = unsigned(panic_header) + unsigned(panic_header.eph_stackshot_offset)
    panic_stackshot_len = unsigned(panic_header.eph_stackshot_len)
    panic_header_flags = unsigned(panic_header.eph_panic_flags)

    warn_str = ""
    out_str = ""

    if panic_log_magic != 0 and panic_log_magic != expected_panic_magic:
        warn_str += "BAD MAGIC! Found 0x%x expected 0x%x" % (panic_log_magic,
                    expected_panic_magic)

    if warn_str:
        print "\n %s" % warn_str
        if panic_log_begin_offset == 0:
            return

    if "-S" in cmd_options:
        if panic_header_flags & xnudefines.EMBEDDED_PANIC_STACKSHOT_SUCCEEDED_FLAG:
            ProcessPanicStackshot(panic_stackshot_addr, panic_stackshot_len)
        else:
            print "No panic stackshot available"

    panic_log_curindex = 0
    while panic_log_curindex < panic_log_len:
        p_char = str(panic_buf[(panic_log_begin_offset + panic_log_curindex)])
        out_str += p_char
        panic_log_curindex += 1

    if other_log_begin_offset != 0:
        other_log_curindex = 0
        while other_log_curindex < other_log_len:
            p_char = str(panic_buf[(other_log_begin_offset + other_log_curindex)])
            out_str += p_char
            other_log_curindex += 1

    print out_str
    return

def ParseMacOSPanicLog(panic_header, cmd_options={}):
    panic_buf = Cast(panic_header, 'char *')
    panic_log_magic = unsigned(panic_header.mph_magic)
    panic_log_begin_offset = unsigned(panic_header.mph_panic_log_offset)
    panic_log_len = unsigned(panic_header.mph_panic_log_len)
    other_log_begin_offset = unsigned(panic_header.mph_other_log_offset)
    other_log_len = unsigned(panic_header.mph_other_log_len)
    cur_debug_buf_ptr_offset = (unsigned(kern.globals.debug_buf_ptr) - unsigned(panic_header))
    if other_log_begin_offset != 0 and (other_log_len == 0 or other_log_len < (cur_debug_buf_ptr_offset - other_log_begin_offset)):
        other_log_len = cur_debug_buf_ptr_offset - other_log_begin_offset
    expected_panic_magic = xnudefines.MACOS_PANIC_MAGIC
    panic_stackshot_addr = unsigned(panic_header) + unsigned(panic_header.mph_stackshot_offset)
    panic_stackshot_len = unsigned(panic_header.mph_stackshot_len)
    panic_header_flags = unsigned(panic_header.mph_panic_flags)

    warn_str = ""
    out_str = ""

    if panic_log_magic != 0 and panic_log_magic != expected_panic_magic:
        warn_str += "BAD MAGIC! Found 0x%x expected 0x%x" % (panic_log_magic,
                    expected_panic_magic)

    if warn_str:
        print "\n %s" % warn_str
        if panic_log_begin_offset == 0:
            return

    if "-S" in cmd_options:
        if panic_header_flags & xnudefines.MACOS_PANIC_STACKSHOT_SUCCEEDED_FLAG:
            ProcessPanicStackshot(panic_stackshot_addr, panic_stackshot_len)
        else:
            print "No panic stackshot available"

    panic_log_curindex = 0
    while panic_log_curindex < panic_log_len:
        p_char = str(panic_buf[(panic_log_begin_offset + panic_log_curindex)])
        out_str += p_char
        panic_log_curindex += 1

    if other_log_begin_offset != 0:
        other_log_curindex = 0
        while other_log_curindex < other_log_len:
            p_char = str(panic_buf[(other_log_begin_offset + other_log_curindex)])
            out_str += p_char
            other_log_curindex += 1

    print out_str
    return

def ParseAURRPanicLog(panic_header, cmd_options={}):
    reset_cause = {
        0x0: "OTHER",
        0x1: "CATERR",
        0x2: "SWD_TIMEOUT",
        0x3: "GLOBAL RESET",
        0x4: "STRAIGHT TO S5",
    }

    expected_panic_magic = xnudefines.AURR_PANIC_MAGIC

    panic_buf = Cast(panic_header, 'char *')

    try:
        # This line will blow up if there's not type info for this struct (older kernel)
        # We fall back to manual parsing below
        aurr_panic_header = Cast(panic_header, 'struct efi_aurr_panic_header *')
        panic_log_magic = unsigned(aurr_panic_header.efi_aurr_magic)
        panic_log_version = unsigned(aurr_panic_header.efi_aurr_version)
        panic_log_reset_cause = unsigned(aurr_panic_header.efi_aurr_reset_cause)
        panic_log_reset_log_offset = unsigned(aurr_panic_header.efi_aurr_reset_log_offset)
        panic_log_reset_log_len = unsigned(aurr_panic_header.efi_aurr_reset_log_len)
    except Exception as e:
        print "*** Warning: kernel symbol file has no type information for 'struct efi_aurr_panic_header'..."
        print "*** Warning: trying to manually parse..."
        aurr_panic_header = Cast(panic_header, "uint32_t *")
        panic_log_magic = unsigned(aurr_panic_header[0])
        # panic_log_crc = unsigned(aurr_panic_header[1])
        panic_log_version = unsigned(aurr_panic_header[2])
        panic_log_reset_cause = unsigned(aurr_panic_header[3])
        panic_log_reset_log_offset = unsigned(aurr_panic_header[4])
        panic_log_reset_log_len = unsigned(aurr_panic_header[5])

    if panic_log_magic != 0 and panic_log_magic != expected_panic_magic:
        print "BAD MAGIC! Found 0x%x expected 0x%x" % (panic_log_magic,
                    expected_panic_magic)
        return

    print "AURR Panic Version: %d" % (panic_log_version)

    # When it comes time to extend this in the future, please follow the
    # construct used below in ShowPanicLog()
    if panic_log_version in (xnudefines.AURR_PANIC_VERSION, xnudefines.AURR_CRASHLOG_PANIC_VERSION):
        # AURR Report Version 1 (AURR/MacEFI) or 2 (Crashlog)
        # see macefifirmware/Vendor/Apple/EfiPkg/AppleDebugSupport/Library/Debugger.h
        print "Reset Cause: 0x%x (%s)" % (panic_log_reset_cause, reset_cause.get(panic_log_reset_cause, "UNKNOWN"))

        # Adjust panic log string length (cap to maximum supported values)
        if panic_log_version == xnudefines.AURR_PANIC_VERSION:
            max_string_len = panic_log_reset_log_len and min(panic_log_reset_log_len, xnudefines.AURR_PANIC_STRING_LEN) or 0
        elif panic_log_version == xnudefines.AURR_CRASHLOG_PANIC_VERSION:
            max_string_len = xnudefines.CRASHLOG_PANIC_STRING_LEN

        panic_str_offset = 0
        out_str = ""

        while panic_str_offset < max_string_len:
            p_char = str(panic_buf[panic_log_reset_log_offset + panic_str_offset])
            out_str += p_char
            panic_str_offset += 1

        print out_str

        # Save Crashlog Binary Data (if available)
        if "-S" in cmd_options and panic_log_version == xnudefines.AURR_CRASHLOG_PANIC_VERSION:
            crashlog_binary_offset = panic_log_reset_log_offset + xnudefines.CRASHLOG_PANIC_STRING_LEN
            crashlog_binary_size = (panic_log_reset_log_len > xnudefines.CRASHLOG_PANIC_STRING_LEN) and (panic_log_reset_log_len - xnudefines.CRASHLOG_PANIC_STRING_LEN) or 0

            if 0 == crashlog_binary_size:
                print "No crashlog data found..."
                return

            # Save to file
            ts = int(time.time())
            ss_binfile = "/tmp/crashlog_%d.bin" % ts

            if not SaveDataToFile(panic_buf + crashlog_binary_offset, crashlog_binary_size, ss_binfile, None):
                print "Failed to save crashlog binary data to file"
                return
    else:
        return ParseUnknownPanicLog(panic_header, cmd_options)

    return

def ParseUnknownPanicLog(panic_header, cmd_options={}):
    magic_ptr = Cast(panic_header, 'uint32_t *')
    panic_log_magic = dereference(magic_ptr)
    print "Unrecognized panic header format. Magic: 0x%x..." % unsigned(panic_log_magic)
    print "Panic region starts at 0x%08x" % int(panic_header)
    print "Hint: To dump this panic header in order to try manually parsing it, use this command:"
    print " (lldb) memory read -fx -s4 -c64 0x%08x" % int(panic_header)
    print " ^ that will dump the first 256 bytes of the panic region"
    ## TBD: Hexdump some bits here to allow folks to poke at the region manually?
    return


@lldb_command('paniclog', 'SM')
def ShowPanicLog(cmd_args=None, cmd_options={}):
    """ Display the paniclog information
        usage: (lldb) paniclog
        options:
            -v : increase verbosity
            -S : parse stackshot data (if panic stackshot available)
            -M : parse macOS panic area (print panic string (if available), and/or capture crashlog info)
    """

    if "-M" in cmd_options:
        if not hasattr(kern.globals, "mac_panic_header"):
            print "macOS panic data requested but unavailable on this device"
            return
        panic_header = kern.globals.mac_panic_header
        # DEBUG HACK FOR TESTING
        #panic_header = kern.GetValueFromAddress(0xfffffff054098000, "uint32_t *")
    else:
        panic_header = kern.globals.panic_info

    if hasattr(panic_header, "eph_magic"):
        panic_log_magic = unsigned(panic_header.eph_magic)
    elif hasattr(panic_header, "mph_magic"):
        panic_log_magic = unsigned(panic_header.mph_magic)
    else:
        print "*** Warning: unsure of panic header format, trying anyway"
        magic_ptr = Cast(panic_header, 'uint32_t *')
        panic_log_magic = int(dereference(magic_ptr))

    if panic_log_magic == 0:
        # No panic here..
        return

    panic_parsers = {
        int(xnudefines.AURR_PANIC_MAGIC)     : ParseAURRPanicLog,
        int(xnudefines.MACOS_PANIC_MAGIC)    : ParseMacOSPanicLog,
        int(xnudefines.EMBEDDED_PANIC_MAGIC) : ParseEmbeddedPanicLog,
    }

    # Find the right parser (fall back to unknown parser above)
    parser = panic_parsers.get(panic_log_magic, ParseUnknownPanicLog)

    # execute it
    return parser(panic_header, cmd_options)

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
    if not hasattr(lldb.SBValue, 'GetValueAsAddress'):
        warn_str = "WARNING: lldb version is too old. Some commands may break. Please update to latest lldb."
        if os.isatty(sys.__stdout__.fileno()):
            warn_str = VT.DarkRed + warn_str + VT.Default
        print warn_str
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

@lldb_command('walkqueue_head', 'S')
def WalkQueueHead(cmd_args=[], cmd_options={}):
    """ walk a queue_head_t and list all members in it. Note this is for queue_head_t. refer to osfmk/kern/queue.h
        Option: -S - suppress summary output.
        Usage: (lldb) walkqueue_head  <queue_entry *> <struct type> <fieldname>
        ex:    (lldb) walkqueue_head  0x7fffff80 "thread *" "task_threads"

    """
    global lldb_summary_definitions
    if not cmd_args:
        raise ArgumentError("invalid arguments")
    if len(cmd_args) != 3:
        raise ArgumentError("insufficient arguments")
    queue_head = kern.GetValueFromAddress(cmd_args[0], 'struct queue_entry *')
    el_type = cmd_args[1]
    field_name = cmd_args[2]
    showsummary = False
    if el_type in lldb_summary_definitions:
        showsummary = True
    if '-S' in cmd_options:
        showsummary = False

    for i in IterateQueue(queue_head, el_type, field_name):
        if showsummary:
            print lldb_summary_definitions[el_type](i)
        else:
            print "{0: <#020x}".format(i)



@lldb_command('walklist_entry', 'SE')
def WalkList(cmd_args=[], cmd_options={}):
    """ iterate over a list as defined with LIST_ENTRY in bsd/sys/queue.h
        params:
            object addr  - value : address of object
            element_type - str   : Type of the next element
            field_name   - str   : Name of the field in next element's structure

        Options: -S - suppress summary output.
                 -E - Iterate using SLIST_ENTRYs

        Usage: (lldb) walklist_entry  <obj with list_entry *> <struct type> <fieldname>
        ex:    (lldb) walklist_entry  0x7fffff80 "struct proc *" "p_sibling"

    """
    global lldb_summary_definitions
    if not cmd_args:
        raise ArgumentError("invalid arguments")
    if len(cmd_args) != 3:
        raise ArgumentError("insufficient arguments")
    el_type = cmd_args[1]
    queue_head = kern.GetValueFromAddress(cmd_args[0], el_type)
    field_name = cmd_args[2]
    showsummary = False
    if el_type in lldb_summary_definitions:
        showsummary = True
    if '-S' in cmd_options:
        showsummary = False
    if '-E' in cmd_options:
        prefix = 's'
    else:
        prefix = ''
    elt = queue_head
    while unsigned(elt) != 0:
        i = elt
        elt = elt.__getattr__(field_name).__getattr__(prefix + 'le_next')
        if showsummary:
            print lldb_summary_definitions[el_type](i)
        else:
            print "{0: <#020x}".format(i)

def trace_parse_Copt(Copt):
    """Parses the -C option argument and returns a list of CPUs
    """
    cpusOpt = Copt
    cpuList = cpusOpt.split(",")
    chosen_cpus = []
    for cpu_num_string in cpuList:
        try:
            if '-' in cpu_num_string:
                parts = cpu_num_string.split('-')
                if len(parts) != 2 or not (parts[0].isdigit() and parts[1].isdigit()):
                    raise ArgumentError("Invalid cpu specification: %s" % cpu_num_string)
                firstRange = int(parts[0])
                lastRange = int(parts[1])
                if firstRange >= kern.globals.real_ncpus or lastRange >= kern.globals.real_ncpus:
                    raise ValueError()
                if lastRange < firstRange:
                    raise ArgumentError("Invalid CPU range specified: `%s'" % cpu_num_string)
                for cpu_num in range(firstRange, lastRange + 1):
                    if cpu_num not in chosen_cpus:
                        chosen_cpus.append(cpu_num)
            else:
                chosen_cpu = int(cpu_num_string)
                if chosen_cpu < 0 or chosen_cpu >= kern.globals.real_ncpus:
                    raise ValueError()
                if chosen_cpu not in chosen_cpus:
                    chosen_cpus.append(chosen_cpu)
        except ValueError:
            raise ArgumentError("Invalid CPU number specified.  Valid range is 0..%d" % (kern.globals.real_ncpus - 1))

    return chosen_cpus


IDX_CPU = 0
IDX_RINGPOS = 1
IDX_RINGENTRY = 2
def Trace_cmd(cmd_args=[], cmd_options={}, headerString=lambda:"", entryString=lambda x:"", ring=[], entries_per_cpu=0, max_backtraces=0):
    """Generic trace dumper helper function
    """

    if '-S' in cmd_options:
        field_arg = cmd_options['-S']
        try:
            getattr(ring[0][0], field_arg)
            sort_key_field_name = field_arg
        except AttributeError:
            raise ArgumentError("Invalid sort key field name `%s'" % field_arg)
    else:
            sort_key_field_name = 'start_time_abs'

    if '-C' in cmd_options:
        chosen_cpus = trace_parse_Copt(cmd_options['-C'])
    else:
        chosen_cpus = [x for x in range(kern.globals.real_ncpus)]

    try:
        limit_output_count = int(cmd_options['-N'])
    except ValueError:
        raise ArgumentError("Invalid output count `%s'" % cmd_options['-N']);
    except KeyError:
        limit_output_count = None
        
    reverse_sort = '-R' in cmd_options
    backtraces = '-B' in cmd_options

    # entries will be a list of 3-tuples, each holding the CPU on which the iotrace entry was collected,
    # the original ring index, and the iotrace entry. 
    entries = []
    for x in chosen_cpus:
        ring_slice = [(x, y, ring[x][y]) for y in range(entries_per_cpu)]
        entries.extend(ring_slice)

    total_entries = len(entries)

    entries.sort(key=lambda x: getattr(x[IDX_RINGENTRY], sort_key_field_name), reverse=reverse_sort)

    if limit_output_count is not None and limit_output_count > total_entries:
        print ("NOTE: Output count `%d' is too large; showing all %d entries" % (limit_output_count, total_entries));
        limit_output_count = total_entries

    if len(chosen_cpus) < kern.globals.real_ncpus:
        print "NOTE: Limiting to entries from cpu%s %s" % ("s" if len(chosen_cpus) > 1 else "", str(chosen_cpus))

    if limit_output_count is not None and limit_output_count < total_entries:
        entries_to_display = limit_output_count
        print "NOTE: Limiting to the %s" % ("first entry" if entries_to_display == 1 else ("first %d entries" % entries_to_display))
    else:
        entries_to_display = total_entries

    print headerString()

    for x in xrange(entries_to_display):
        print entryString(entries[x])

        if backtraces:
            for btidx in range(max_backtraces):
                nextbt = entries[x][IDX_RINGENTRY].backtrace[btidx]
                if nextbt == 0:
                    break
                print "\t" + GetSourceInformationForAddress(nextbt)


@lldb_command('iotrace', 'C:N:S:RB')
def IOTrace_cmd(cmd_args=[], cmd_options={}):
    """ Prints the iotrace ring buffers for all CPUs by default.
        Arguments:
          -B                              : Print backtraces for each ring entry
          -C <cpuSpec#>[,...,<cpuSpec#N>] : Limit trace entries to those generated by the specified CPUs (each cpuSpec can be a
                                            single CPU number or a range separated by a dash (e.g. "0-3"))
          -N <count>                      : Limit output to the first <count> entries (across all chosen CPUs)
          -R                              : Display results in reverse-sorted order (oldest first; default is newest-first)
          -S <sort_key_field_name>        : Sort output by specified iotrace_entry_t field name (instead of by timestamp)
    """
    MAX_IOTRACE_BACKTRACES = 16

    if kern.arch != "x86_64":
        print "Sorry, iotrace is an x86-only command."
        return

    hdrString = lambda : "%-19s %-8s %-10s %-20s SZ  %-18s %-17s DATA" % (
        "START TIME",
        "DURATION",
        "CPU#[RIDX]",
        "      TYPE",
        "   VIRT ADDR",
        "   PHYS ADDR")

    entryString = lambda x : "%-20u(%6u) %6s[%02d] %-20s %-2d 0x%016x 0x%016x 0x%x" % (
        x[IDX_RINGENTRY].start_time_abs,
        x[IDX_RINGENTRY].duration,
        "CPU%d" % x[IDX_CPU],
        x[IDX_RINGPOS],
        str(x[IDX_RINGENTRY].iotype).split("=")[1].strip(),
        x[IDX_RINGENTRY].size,
        x[IDX_RINGENTRY].vaddr,
        x[IDX_RINGENTRY].paddr,
        x[IDX_RINGENTRY].val)

    Trace_cmd(cmd_args, cmd_options, hdrString, entryString, kern.globals.iotrace_ring, kern.globals.iotrace_entries_per_cpu, MAX_IOTRACE_BACKTRACES)


@lldb_command('ttrace', 'C:N:S:RB')
def TrapTrace_cmd(cmd_args=[], cmd_options={}):
    """ Prints the iotrace ring buffers for all CPUs by default.
        Arguments:
          -B                              : Print backtraces for each ring entry
          -C <cpuSpec#>[,...,<cpuSpec#N>] : Limit trace entries to those generated by the specified CPUs (each cpuSpec can be a
                                            single CPU number or a range separated by a dash (e.g. "0-3"))
          -N <count>                      : Limit output to the first <count> entries (across all chosen CPUs)
          -R                              : Display results in reverse-sorted order (oldest first; default is newest-first)
          -S <sort_key_field_name>        : Sort output by specified traptrace_entry_t field name (instead of by timestamp)
    """
    MAX_TRAPTRACE_BACKTRACES = 8

    if kern.arch != "x86_64":
        print "Sorry, ttrace is an x86-only command."
        return

    hdrString = lambda : "%-30s CPU#[RIDX] VECT INTERRUPTED_THREAD PREMLV INTRLV INTERRUPTED_PC" % (
        "START TIME   (DURATION [ns])")
    entryString = lambda x : "%-20u(%6s) %8s[%02d] 0x%02x 0x%016x %6d %6d %s" % (
        x[IDX_RINGENTRY].start_time_abs,
        str(x[IDX_RINGENTRY].duration) if hex(x[IDX_RINGENTRY].duration) != "0xffffffffffffffff" else 'inprog',
        "CPU%d" % x[IDX_CPU],
        x[IDX_RINGPOS],
        int(x[IDX_RINGENTRY].vector),
        x[IDX_RINGENTRY].curthread,
        x[IDX_RINGENTRY].curpl,
        x[IDX_RINGENTRY].curil,
        GetSourceInformationForAddress(x[IDX_RINGENTRY].interrupted_pc))

    Trace_cmd(cmd_args, cmd_options, hdrString, entryString, kern.globals.traptrace_ring,
        kern.globals.traptrace_entries_per_cpu, MAX_TRAPTRACE_BACKTRACES)
                

@lldb_command('showsysctls', 'P:')
def ShowSysctls(cmd_args=[], cmd_options={}):
    """ Walks the list of sysctl data structures, printing out each during traversal.
        Arguments:
          -P <string> : Limit output to sysctls starting with the specified prefix.
    """
    if '-P' in cmd_options:
        _ShowSysctl_prefix = cmd_options['-P']
        allowed_prefixes = _ShowSysctl_prefix.split('.')
        if allowed_prefixes:
            for x in xrange(1, len(allowed_prefixes)):
                allowed_prefixes[x] = allowed_prefixes[x - 1] + "." + allowed_prefixes[x]
    else:
        _ShowSysctl_prefix = ''
        allowed_prefixes = []
    def IterateSysctls(oid, parent_str, i):
        headp = oid
        parentstr = "<none>" if parent_str is None else parent_str
        for pp in IterateListEntry(headp, 'struct sysctl_oid *', 'oid_link', 's'):
            type = pp.oid_kind & 0xf
            next_parent = str(pp.oid_name)
            if parent_str is not None:
                next_parent = parent_str + "." + next_parent
            st = (" " * i) + str(pp.GetSBValue().Dereference()).replace("\n", "\n" + (" " * i))
            if type == 1 and pp.oid_arg1 != 0:
                # Check allowed_prefixes to see if we can recurse from root to the allowed prefix.
                # To recurse further, we need to check only the the next parent starts with the user-specified
                # prefix
                if next_parent not in allowed_prefixes and next_parent.startswith(_ShowSysctl_prefix) is False:
                    continue
                print 'parent = "%s"' % parentstr, st[st.find("{"):]
                IterateSysctls(Cast(pp.oid_arg1, "struct sysctl_oid_list *"), next_parent, i + 2)
            elif _ShowSysctl_prefix == '' or next_parent.startswith(_ShowSysctl_prefix):
                print ('parent = "%s"' % parentstr), st[st.find("{"):]
    IterateSysctls(kern.globals.sysctl__children, None, 0)



from memory import *
from process import *
from ipc import *
from pmap import *
from ioreg import *
from mbufs import *
from net import *
from skywalk import *
from kdp import *
from userspace import *
from pci import *
from misc import *
from apic import *
from scheduler import *
from atm import *
from structanalyze import *
from ipcimportancedetail import *
from bank import *
from turnstile import *
from kasan import *
from kauth import *
from waitq import *
from usertaskgdbserver import *
from ktrace import *
from pgtrace import *
from xnutriage import *
from kevent import *
from workqueue import *
from ulock import *
from ntstat import *
from zonetriage import *
from sysreg import *
