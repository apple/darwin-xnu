#General Utility functions for debugging or introspection

""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""
import sys, re, time, getopt, shlex, os, time
import lldb
import struct
from core.cvalue import *
from core.configuration import *
from core.lazytarget import *

#DONOTTOUCHME: exclusive use for lldb_run_command only. 
lldb_run_command_state = {'active':False}

def lldb_run_command(cmdstring):
    """ Run a lldb command and get the string output.
        params: cmdstring - str : lldb command string which could be executed at (lldb) prompt. (eg. "register read")
        returns: str - output of command. it may be "" in case if command did not return any output.
    """
    global lldb_run_command_state
    retval =""
    res = lldb.SBCommandReturnObject()
    # set special attribute to notify xnu framework to not print on stdout
    lldb_run_command_state['active'] = True
    lldb.debugger.GetCommandInterpreter().HandleCommand(cmdstring, res)
    lldb_run_command_state['active'] = False
    if res.Succeeded():
        retval = res.GetOutput()
    else:
        retval = "ERROR:" + res.GetError()
    return retval

def EnableLLDBAPILogging():
    """ Enable file based logging for lldb and also provide essential information about what information
        to include when filing a bug with lldb or xnu.
    """
    logfile_name = "/tmp/lldb.%d.log" % int(time.time())
    enable_log_base_cmd = "log enable --file %s " % logfile_name
    cmd_str = enable_log_base_cmd + ' lldb api'
    print cmd_str
    print lldb_run_command(cmd_str)
    cmd_str = enable_log_base_cmd + ' gdb-remote packets'
    print cmd_str
    print lldb_run_command(cmd_str)
    cmd_str = enable_log_base_cmd + ' kdp-remote packets'
    print cmd_str
    print lldb_run_command(cmd_str)
    print lldb_run_command("version")
    print "Please collect the logs from %s for filing a radar. If you had encountered an exception in a lldbmacro command please re-run it." % logfile_name
    print "Please make sure to provide the output of 'version', 'image list' and output of command that failed."
    return

def GetConnectionProtocol():
    """ Returns a string representing what kind of connection is used for debugging the target.
        params: None
        returns:
            str - connection type. One of ("core","kdp","gdb", "unknown")
    """
    retval = "unknown"
    process_plugin_name = LazyTarget.GetProcess().GetPluginName().lower()
    if "kdp" in process_plugin_name:
        retval = "kdp"
    elif "gdb" in process_plugin_name:
        retval = "gdb"
    elif "mach-o" in process_plugin_name and "core" in process_plugin_name:
        retval = "core"
    return retval

def SBValueToPointer(sbval):
    """ Helper function for getting pointer value from an object of pointer type. 
        ex. void *astring = 0x12345
        use SBValueToPointer(astring_val) to get 0x12345
        params: sbval - value object of type '<type> *'
        returns: int - pointer value as an int. 
    """
    if type(sbval) == core.value:
        sbval = sbval.GetSBValue()
    if sbval.IsPointerType():
        return sbval.GetValueAsUnsigned()
    else:
        return int(sbval.GetAddress())

def ArgumentStringToInt(arg_string):
    """ convert '1234' or '0x123' to int
        params:
          arg_string: str - typically string passed from commandline. ex '1234' or '0xA12CD'
        returns:
          int - integer representation of the string
    """
    arg_string = arg_string.strip()
    if arg_string.find('0x') >=0:
        return int(arg_string, 16)
    else:
        return int(arg_string)

def GetLongestMatchOption(searchstr, options=[], ignore_case=True):
    """ Get longest matched string from set of options. 
        params:
            searchstr : string of chars to be matched
            options : array of strings that are to be matched
        returns:
            [] - array of matched options. The order of options is same as the arguments.
                 empty array is returned if searchstr does not match any option.
        example:
            subcommand = LongestMatch('Rel', ['decode', 'enable', 'reload'], ignore_case=True)
            print subcommand # prints ['reload']
    """
    if ignore_case:
        searchstr = searchstr.lower()
    found_options = []
    for o in options:
        so = o
        if ignore_case:
            so = o.lower()
        if so == searchstr:
            return [o]
        if so.find(searchstr) >=0 :
            found_options.append(o)
    return found_options

def GetType(target_type):
    """ type cast an object to new type.
        params:
            target_type - str, ex. 'char', 'uint32_t' etc
        returns:
            lldb.SBType - a new Type that can be used as param to  lldb.SBValue.Cast()
        raises:
            NameError  - Incase the type is not identified
    """
    return gettype(target_type)

    
def Cast(obj, target_type):
    """ Type cast an object to another C type.
        params:
            obj - core.value  object representing some C construct in lldb
            target_type - str : ex 'char *'
                        - lldb.SBType :
    """
    return cast(obj, target_type)

def ContainerOf(obj, target_type, field_name):
    """ Type cast an object to another C type from a pointer to a field.
        params:
            obj - core.value  object representing some C construct in lldb
            target_type - str : ex 'struct thread'
                        - lldb.SBType :
            field_name - the field name within the target_type obj is a pointer to
    """
    return containerof(obj, target_type, field_name)

def loadLLDB():
    """ Util function to load lldb python framework in case not available in common include paths.
    """
    try:
        import lldb
        print 'Found LLDB on path'
    except:
        platdir = subprocess.check_output('xcodebuild -version -sdk iphoneos PlatformPath'.split())
        offset = platdir.find("Contents/Developer")
        if offset == -1:
            lldb_py = os.path.join(os.path.dirname(os.path.dirname(platdir)), 'Library/PrivateFrameworks/LLDB.framework/Versions/A/Resources/Python')
        else:
            lldb_py = os.path.join(platdir[0:offset+8], 'SharedFrameworks/LLDB.framework/Versions/A/Resources/Python')
        if os.path.isdir(lldb_py):
            sys.path.append(lldb_py)
            global lldb
            lldb = __import__('lldb')
            print 'Found LLDB in SDK'
        else:
            print 'Failed to locate lldb.py from', lldb_py
            sys.exit(-1)
    return True

class Logger():
    """ A logging utility """
    def __init__(self, log_file_path="/tmp/xnu.log"):
        self.log_file_handle = open(log_file_path, "w+")
        self.redirect_to_stdout = False
        
    def log_debug(self, *args):
        current_timestamp = time.time()
        debug_line_str = "DEBUG:" + str(current_timestamp) + ":"
        for arg in args:
            debug_line_str += " " + str(arg).replace("\n", " ") + ", "
        
        self.log_file_handle.write(debug_line_str + "\n")
        if self.redirect_to_stdout :
            print debug_line_str
    
    def write(self, line):
        self.log_debug(line)


def sizeof_fmt(num, unit_str='B'):
    """ format large number into human readable values.
        convert any number into Kilo, Mega, Giga, Tera format for human understanding.
        params:
            num - int : number to be converted
            unit_str - str : a suffix for unit. defaults to 'B' for bytes.
        returns:
            str - formatted string for printing.
    """
    for x in ['','K','M','G','T']:
        if num < 1024.0:
            return "%3.1f%s%s" % (num, x,unit_str)
        num /= 1024.0
    return "%3.1f%s%s" % (num, 'P', unit_str)

def WriteStringToMemoryAddress(stringval, addr):
    """ write a null terminated string to address. 
        params:
            stringval: str- string to be written to memory. a '\0' will be added at the end
            addr : int - address where data is to be written
        returns:
            bool - True if successfully written
    """
    serr = lldb.SBError()
    length = len(stringval) + 1
    format_string = "%ds" % length
    sdata = struct.pack(format_string,stringval)
    numbytes = LazyTarget.GetProcess().WriteMemory(addr, sdata, serr)
    if numbytes == length and serr.Success():
        return True
    return False

def WriteInt64ToMemoryAddress(intval, addr):
    """ write a 64 bit integer at an address.
        params:
          intval - int - an integer value to be saved
          addr - int - address where int is to be written
        returns:
          bool - True if successfully written.
    """
    serr = lldb.SBError()
    sdata = struct.pack('Q', intval)
    addr = int(hex(addr).rstrip('L'), 16)
    numbytes = LazyTarget.GetProcess().WriteMemory(addr,sdata, serr)
    if numbytes == 8 and serr.Success():
        return True
    return False 

def WritePtrDataToMemoryAddress(intval, addr):
    """ Write data to pointer size memory. 
        This is equivalent of doing *(&((struct pmap *)addr)) = intval
        It will identify 32/64 bit kernel and write memory accordingly.
        params:
          intval - int - an integer value to be saved
          addr - int - address where int is to be written
        returns:
          bool - True if successfully written.
    """
    if kern.ptrsize == 8:
        return WriteInt64ToMemoryAddress(intval, addr)
    else:
        return WriteInt32ToMemoryAddress(intval, addr)

def WriteInt32ToMemoryAddress(intval, addr):
    """ write a 32 bit integer at an address.
        params:
          intval - int - an integer value to be saved
          addr - int - address where int is to be written
        returns:
          bool - True if successfully written.
    """
    serr = lldb.SBError()
    sdata = struct.pack('I', intval)
    addr = int(hex(addr).rstrip('L'), 16)
    numbytes = LazyTarget.GetProcess().WriteMemory(addr,sdata, serr)
    if numbytes == 4 and serr.Success():
        return True
    return False 

def WriteInt16ToMemoryAddress(intval, addr):
    """ write a 16 bit integer at an address.
        params:
          intval - int - an integer value to be saved
          addr - int - address where int is to be written
        returns:
          bool - True if successfully written.
    """
    serr = lldb.SBError()
    sdata = struct.pack('H', intval)
    addr = int(hex(addr).rstrip('L'), 16)
    numbytes = LazyTarget.GetProcess().WriteMemory(addr,sdata, serr)
    if numbytes == 2 and serr.Success():
        return True
    return False 

def WriteInt8ToMemoryAddress(intval, addr):
    """ write a 8 bit integer at an address.
        params:
          intval - int - an integer value to be saved
          addr - int - address where int is to be written
        returns:
          bool - True if successfully written.
    """
    serr = lldb.SBError()
    sdata = struct.pack('B', intval)
    addr = int(hex(addr).rstrip('L'), 16)
    numbytes = LazyTarget.GetProcess().WriteMemory(addr,sdata, serr)
    if numbytes == 1 and serr.Success():
        return True
    return False 

_enum_cache = {}
def GetEnumValue(name):
    """ Finds the value of a particular enum define. Ex kdp_req_t::KDP_VERSION  => 0x3
        params:
            name : str - name of enum in the format type::name
        returns:
            int - value of the particular enum.
        raises:
            TypeError - if the enum is not found
    """
    name = name.strip()
    global _enum_cache
    if name not in _enum_cache:
        res = lldb.SBCommandReturnObject()
        lldb.debugger.GetCommandInterpreter().HandleCommand("p/x (`%s`)" % name, res)
        if not res.Succeeded():
            raise TypeError("Enum not found with name: " + name)
        # the result is of format '(int) $481 = 0x00000003\n'
        _enum_cache[name] = int( res.GetOutput().split('=')[-1].strip(), 16)
    return _enum_cache[name]

def ResolveFSPath(path):
    """ expand ~user directories and return absolute path.
        params: path - str - eg "~rc/Software"
        returns:
                str - abs path with user directories and symlinks expanded.
                str - if path resolution fails then returns the same string back
    """
    expanded_path = os.path.expanduser(path)
    norm_path = os.path.normpath(expanded_path)
    return norm_path

_dsymlist = {}
uuid_regex = re.compile("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",re.IGNORECASE|re.DOTALL)
def addDSYM(uuid, info):
    """ add a module by dsym into the target modules. 
        params: uuid - str - uuid string eg. 4DD2344C0-4A81-3EAB-BDCF-FEAFED9EB73E
                info - dict - info dictionary passed from dsymForUUID
    """
    global _dsymlist
    if "DBGSymbolRichExecutable" not in info:
        print "Error: Unable to find syms for %s" % uuid
        return False
    if not uuid in _dsymlist:
        # add the dsym itself
        cmd_str = "target modules add --uuid %s" % uuid
        debuglog(cmd_str)
        lldb.debugger.HandleCommand(cmd_str)
        # set up source path
        #lldb.debugger.HandleCommand("settings append target.source-map %s %s" % (info["DBGBuildSourcePath"], info["DBGSourcePath"]))
        # modify the list to show we loaded this
        _dsymlist[uuid] = True

def loadDSYM(uuid, load_address, sections=[]):
    """ Load an already added symbols to a particular load address
        params: uuid - str - uuid string
                load_address - int - address where to load the symbols
        returns bool:
            True - if successful
            False - if failed. possible because uuid is not presently loaded.
    """
    if uuid not in _dsymlist:
        return False
    if not sections:
        cmd_str = "target modules load --uuid %s --slide %d" % ( uuid, load_address)
        debuglog(cmd_str)
    else:
        cmd_str = "target modules load --uuid {}   ".format(uuid)
        sections_str = ""
        for s in sections:
            sections_str += " {} {:#0x} ".format(s.name, s.vmaddr)
        cmd_str += sections_str
        debuglog(cmd_str)

    lldb.debugger.HandleCommand(cmd_str)
    return True


def RunShellCommand(command):
    """ Run a shell command in subprocess.
        params: command with arguments to run
        returns: (exit_code, stdout, stderr)
    """
    import shlex, subprocess
    cmd_args = shlex.split(command)
    output_str = ""
    exit_code = 0
    try:
        output_str = subprocess.check_output(cmd_args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError, e:
        exit_code = e.returncode
    finally:
        return (exit_code, output_str, '')

def dsymForUUID(uuid):
    """ Get dsym informaiton by calling dsymForUUID 
        params: uuid - str - uuid string from executable. eg. 4DD2344C0-4A81-3EAB-BDCF-FEAFED9EB73E
        returns:
            {} - a dictionary holding dsym information printed by dsymForUUID. 
            None - if failed to find information
    """
    import subprocess
    import plistlib
    output = subprocess.check_output(["/usr/local/bin/dsymForUUID", "--copyExecutable", uuid])
    if output:
        # because of <rdar://12713712>
        #plist = plistlib.readPlistFromString(output)
        #beginworkaround
        keyvalue_extract_re = re.compile("<key>(.*?)</key>\s*<string>(.*?)</string>",re.IGNORECASE|re.MULTILINE|re.DOTALL)
        plist={}
        plist[uuid] = {}
        for item in keyvalue_extract_re.findall(output):
            plist[uuid][item[0]] = item[1]
        #endworkaround
        if plist and plist[uuid]:
            return plist[uuid]
    return None

def debuglog(s):
    """ Print a object in the debug stream
    """
    global config
    if config['debug']:
      print "DEBUG:",s
    return None

def IsAppleInternal():
    """ check if apple_internal modules are available
        returns: True if apple_internal module is present
    """
    import imp
    try:
        imp.find_module("apple_internal")
        retval = True
    except ImportError:
        retval = False
    return retval

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
        if index and index < total_len and index % 8 == 0:
            hex_buf += " "
        if index > 1 and index < total_len and (index % 16) == 0:
            print "{:08x} {: <50s} |{: <16s}|".format(begin_offset + index - 16, hex_buf, char_buf)
            hex_buf = ""
            char_buf = ""
    print "{:08x} {: <50s} |{: <16s}|".format(begin_offset + index - 16, hex_buf, char_buf)
    return

def Ones(x):
    return (1 << x)-1

