from xnu import *
from utils import *
from process import *
from pmap import *
import struct

def GetBinaryNameForPC(pc_val, user_lib_info = None):
    """ find the binary in user_lib_info that the passed pc_val falls in range of.
        params:
            pc_val : int - integer form of the pc address
            user_lib_info: [] of [] which hold start, end, binary name
        returns:
            str - Name of binary or "unknown" if not found.
    """
    retval = "unknown"
    if not user_lib_info:
        return retval
    matches = []
    for info in user_lib_info:
        if pc_val >= info[0] and pc_val <= info[1]:
            matches.append((pc_val - info[0], info[2]))
    matches.sort()
    if matches:
        retval = matches[0][1]
    return retval

def ShowX86UserStack(thread, user_lib_info = None):
    """ Display user space stack frame and pc addresses.
        params:
            thread: obj referencing thread value
        returns:
            Nothing
    """
    iss = Cast(thread.machine.iss, 'x86_saved_state_t *')
    abi = int(iss.flavor)
    user_ip = 0
    user_frame = 0
    user_abi_ret_offset = 0
    if abi == 0xf:
        debuglog("User process is 64 bit")
        user_ip = iss.uss.ss_64.isf.rip
        user_frame = iss.uss.ss_64.rbp
        user_abi_ret_offset = 8
        user_abi_type = "uint64_t"
    else:
        debuglog("user process is 32 bit")
        user_ip = iss.uss.ss_32.eip
        user_frame = iss.uss.ss_32.ebp
        user_abi_ret_offset = 4
        user_abi_type = "uint32_t"

    if user_ip == 0:
        print "This activation does not appear to have a valid user context."
        return False

    cur_ip = user_ip
    cur_frame = user_frame
    debuglog("ip= 0x%x , fr = 0x%x " % (cur_ip, cur_frame))

    frameformat = "{0:d} FP: 0x{1:x} PC: 0x{2:x}"
    if user_lib_info is not None:
        frameformat = "{0:d} {3: <30s} 0x{2:x}"
    print frameformat.format(0, cur_frame, cur_ip, GetBinaryNameForPC(cur_ip, user_lib_info))

    print kern.Symbolicate(cur_ip)

    frameno = 0
    while True:
        frameno = frameno + 1
        frame = GetUserDataAsString(thread.task, unsigned(cur_frame), user_abi_ret_offset*2)
        cur_ip = _ExtractDataFromString(frame, user_abi_ret_offset, user_abi_type)
        cur_frame = _ExtractDataFromString(frame, 0, user_abi_type)
        if not cur_frame or cur_frame == 0x0000000800000008:
            break
        print frameformat.format(frameno, cur_frame, cur_ip, GetBinaryNameForPC(cur_ip, user_lib_info))
        print kern.Symbolicate(cur_ip)
    return

def _PrintARMUserStack(task, cur_pc, cur_fp, framesize, frametype, frameformat, user_lib_info=None):
    if cur_pc == 0:
        "No valid user context for this activation."
        return
    frameno = 0
    print frameformat.format(frameno, cur_fp, cur_pc, GetBinaryNameForPC(cur_pc, user_lib_info))
    while True:
        frameno = frameno + 1
        frame = GetUserDataAsString(task, cur_fp, framesize)
        cur_fp = _ExtractDataFromString(frame, 0, frametype)
        cur_pc = _ExtractDataFromString(frame, (framesize / 2), frametype)
        if not cur_fp:
            break
        print frameformat.format(frameno, cur_fp, cur_pc, GetBinaryNameForPC(cur_pc, user_lib_info))

def ShowARMUserStack(thread, user_lib_info = None):
    cur_pc = unsigned(thread.machine.PcbData.pc)
    cur_fp = unsigned(thread.machine.PcbData.r[7])
    frameformat = "{0:>2d} FP: 0x{1:x}  PC: 0x{2:x}"
    if user_lib_info is not None:
        frameformat = "{0:>2d} {3: <30s}  0x{2:0>8x}"
    framesize = 8
    frametype = "uint32_t"
    _PrintARMUserStack(thread.task, cur_pc, cur_fp, framesize, frametype, frameformat, user_lib_info=user_lib_info)

def ShowARM64UserStack(thread, user_lib_info = None):
    SAVED_STATE_FLAVOR_ARM=20
    SAVED_STATE_FLAVOR_ARM64=21
    upcb = thread.machine.upcb
    flavor = upcb.ash.flavor
    frameformat = "{0:>2d} FP: 0x{1:x}  PC: 0x{2:x}"
    if flavor == SAVED_STATE_FLAVOR_ARM64:
        cur_pc = unsigned(upcb.uss.ss_64.pc)
        cur_fp = unsigned(upcb.uss.ss_64.fp)
        if user_lib_info is not None:
            frameformat = "{0:>2d} {3: <30s}  0x{2:x}"
        framesize = 16
        frametype = "uint64_t"
    elif flavor == SAVED_STATE_FLAVOR_ARM:
        cur_pc = unsigned(upcb.uss.ss_32.pc)
        cur_fp = unsigned(upcb.uss.ss_32.r[7])
        if user_lib_info is not None:
            frameformat = "{0:>2d}: {3: <30s}  0x{2:x}"
        framesize = 8
        frametype = "uint32_t"
    else:
        raise RuntimeError("Thread {0} has an invalid flavor {1}".format(unsigned(thread), flavor))

    _PrintARMUserStack(thread.task, cur_pc, cur_fp, framesize, frametype, frameformat, user_lib_info=user_lib_info)


@lldb_command('showthreaduserstack')
def ShowThreadUserStack(cmd_args=None):
    """ Show user stack for a given thread.
        Syntax: (lldb) showthreaduserstack <thread_ptr>
    """
    if not cmd_args:
        raise ArgumentError("Insufficient arguments")

    thread = kern.GetValueFromAddress(ArgumentStringToInt(cmd_args[0]), 'thread *')
    if kern.arch == "x86_64":
        ShowX86UserStack(thread)
    elif kern.arch == "arm":
        ShowARMUserStack(thread)
    elif kern.arch.startswith("arm64"):
        ShowARM64UserStack(thread)
    return True

@lldb_command('printuserdata','XO:')
def PrintUserspaceData(cmd_args=None, cmd_options={}):
    """ Read userspace data for given task and print based on format provided.
        Syntax: (lldb) printuserdata <task_t> <uspace_address> <format_specifier>
        params:
            <task_t> : pointer to task
            <uspace_address> : address to user space memory
            <format_specifier> : String representation for processing the data and printing it.
                                 e.g Q -> unsigned long long, q -> long long, I -> unsigned int, i -> int
                                 10i -> 10 ints, 20s -> 20 character string, s -> null terminated string
                                 See: https://docs.python.org/2/library/struct.html#format-characters
        options:
            -X : print all values in hex.
            -O <file path>: Save data to file 
    """

    if not cmd_args or len(cmd_args) < 3:
        raise ArgumentError("Insufficient arguments")
    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    uspace_addr = ArgumentStringToInt(cmd_args[1])
    format_specifier_str = cmd_args[2]
    user_data_len = 0
    if format_specifier_str == "s":
        print "0x%x: " % uspace_addr + GetUserspaceString(task, uspace_addr)
        return True

    try:
        user_data_len = struct.calcsize(format_specifier_str)
    except Exception, e:
        raise ArgumentError("Invalid format specifier provided.")

    user_data_string = GetUserDataAsString(task, uspace_addr, user_data_len)
    if not user_data_string:
        print "Could not read any data from userspace address."
        return False
    if "-O" in cmd_options:
        fh = open(cmd_options["-O"],"w")
        fh.write(user_data_string)
        fh.close()
        print "Written %d bytes to %s." % (user_data_len, cmd_options['-O'])
        return True
    upacked_data = struct.unpack(format_specifier_str, user_data_string)
    element_size = user_data_len / len(upacked_data)
    for i in range(len(upacked_data)):
        if "-X" in cmd_options:
            print "0x%x: " % (uspace_addr + i*element_size) + hex(upacked_data[i])
        else:
            print "0x%x: " % (uspace_addr + i*element_size) + str(upacked_data[i])

    return True


@lldb_command('showtaskuserargs')
def ShowTaskUserArgs(cmd_args=None, cmd_options={}):
    """ Read the process argv, env, and apple strings from the user stack
        Syntax: (lldb) showtaskuserargs <task_t>
        params:
            <task_t> : pointer to task
    """
    if not cmd_args or len(cmd_args) != 1:
        raise ArgumentError("Insufficient arguments")

    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    proc = Cast(task.bsd_info, 'proc *')

    format_string = "Q" if kern.ptrsize == 8 else "I"

    string_area_size = proc.p_argslen
    string_area_addr = proc.user_stack - string_area_size

    string_area = GetUserDataAsString(task, string_area_addr, string_area_size)
    if not string_area:
        print "Could not read any data from userspace address."
        return False

    i = 0
    pos = string_area_addr - kern.ptrsize

    for name in ["apple", "env", "argv"] :
        while True:
            if name == "argv" :
                if i == proc.p_argc:
                    break
                i += 1

            pos -= kern.ptrsize

            user_data_string = GetUserDataAsString(task, pos, kern.ptrsize)
            ptr = struct.unpack(format_string, user_data_string)[0]          

            if ptr == 0:
                break

            if string_area_addr <= ptr and ptr < string_area_addr+string_area_size :
                string_offset = ptr - string_area_addr
                string = string_area[string_offset:];
            else:
                string = GetUserspaceString(task, ptr)

            print name + "[]: " + string

    return True

def ShowTaskUserStacks(task):
    #print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(task.bsd_info, 'proc *')
    #print GetTaskSummary(task) + " " + GetProcSummary(pval) + "\n \n"
    crash_report_format_string = """\
Process:         {pname:s} [{pid:d}]
Path:            {path: <50s}
Identifier:      {pname: <30s}
Version:         ??? (???)
Code Type:       {parch: <20s}
Parent Process:  {ppname:s} [{ppid:d}]

Date/Time:       {timest:s}.000 -0800
OS Version:      {osversion: <20s}
Report Version:  8

Exception Type:  n/a
Exception Codes: n/a
Crashed Thread:  0

Application Specific Information:
Synthetic crash log generated from Kernel userstacks

"""
    user_lib_rex = re.compile("([0-9a-fx]+)\s-\s([0-9a-fx]+)\s+(.*?)\s", re.IGNORECASE|re.MULTILINE)
    from datetime import datetime
    if pval:
        ts = datetime.fromtimestamp(int(pval.p_start.tv_sec))
        date_string = ts.strftime('%Y-%m-%d %H:%M:%S')
    else:
        date_string = "none"
    is_64 = True
    if pval and (pval.p_flag & 0x4) == 0 :
        is_64 = False

    parch_s = ""
    if kern.arch == "x86_64" or kern.arch == "i386":
        osversion = "Mac OS X 10.8"
        parch_s = "I386 (32 bit)"
        if is_64:
            parch_s = "X86-64 (Native)"
    else:
        parch_s = kern.arch
        osversion = "iOS"
    osversion += " ({:s})".format(kern.globals.osversion)
    if pval:
        pid = pval.p_pid
        pname = pval.p_comm
        path = pval.p_comm
        ppid = pval.p_ppid
    else:
        pid = 0
        pname = "unknown"
        path = "unknown"
        ppid = 0

    print crash_report_format_string.format(pid = pid,
            pname = pname,
            path = path,
            ppid = ppid,
            ppname = GetProcNameForPid(ppid),
            timest = date_string,
            parch = parch_s,
            osversion = osversion
        )
    print "Binary Images:"
    ShowTaskUserLibraries([hex(task)])
    usertask_lib_info = [] # will host [startaddr, endaddr, lib_name] entries
    for entry in ShowTaskUserLibraries.found_images:
        #print "processing line %s" % line
        arr = user_lib_rex.findall(entry[3])
        #print "%r" % arr
        if len(arr) == 0 :
            continue
        usertask_lib_info.append([int(arr[0][0],16), int(arr[0][1],16), str(arr[0][2]).strip()])

    printthread_user_stack_ptr = ShowX86UserStack
    if kern.arch == "arm":
        printthread_user_stack_ptr = ShowARMUserStack
    elif kern.arch.startswith("arm64"):
        printthread_user_stack_ptr = ShowARM64UserStack

    counter = 0
    for thval in IterateQueue(task.threads, 'thread *', 'task_threads'):
        print "\nThread {0:d} name:0x{1:x}\nThread {0:d}:".format(counter, thval)
        counter += 1
        try:
            printthread_user_stack_ptr(thval, usertask_lib_info)
        except Exception as exc_err:
            print "Failed to show user stack for thread 0x{0:x}".format(thval)
            if config['debug']:
                raise exc_err
            else:
                print "Enable debugging ('(lldb) xnudebug debug') to see detailed trace."
    return

@lldb_command('showtaskuserstacks', "P:F:")
def ShowTaskUserStacksCmdHelper(cmd_args=None, cmd_options={}):
    """ Print out the user stack for each thread in a task, followed by the user libraries.
        Syntax: (lldb) showtaskuserstacks <task_t>
            or: (lldb) showtaskuserstacks -P <pid>
            or: (lldb) showtaskuserstacks -F <task_name>
        The format is compatible with CrashTracer. You can also use the speedtracer plugin as follows
        (lldb) showtaskuserstacks <task_t> -p speedtracer

        Note: the address ranges are approximations. Also the list may not be completely accurate. This command expects memory read failures
        and hence will skip a library if unable to read information. Please use your good judgement and not take the output as accurate
    """
    task_list = []
    if "-F" in cmd_options:
        task_list = FindTasksByName(cmd_options["-F"])
    elif "-P" in cmd_options:
        pidval = ArgumentStringToInt(cmd_options["-P"])
        for t in kern.tasks:
            pval = Cast(t.bsd_info, 'proc *')
            if pval and pval.p_pid == pidval:
                task_list.append(t)
                break
    elif cmd_args:
        t = kern.GetValueFromAddress(cmd_args[0], 'task *')
        task_list.append(t)
    else:
        raise ArgumentError("Insufficient arguments")

    for task in task_list:
        ShowTaskUserStacks(task)

def GetUserDataAsString(task, addr, size):
    """ Get data from task's address space as a string of bytes
        params:
            task: task object from which to extract information
            addr: int - start address to get data from.
            size: int - no of bytes to read.
        returns:
            str - a stream of bytes. Empty string if read fails.
    """
    err = lldb.SBError()
    if GetConnectionProtocol() == "kdp":
        kdp_pmap_addr = unsigned(addressof(kern.globals.kdp_pmap))
        if not WriteInt64ToMemoryAddress(unsigned(task.map.pmap), kdp_pmap_addr):
            debuglog("Failed to write in kdp_pmap from GetUserDataAsString.")
            return ""
        content = LazyTarget.GetProcess().ReadMemory(addr, size, err)
        if not err.Success():
            debuglog("Failed to read process memory. Error: " + err.description)
            return ""
        if not WriteInt64ToMemoryAddress(0, kdp_pmap_addr):
            debuglog("Failed to reset in kdp_pmap from GetUserDataAsString.")
            return ""
    elif (kern.arch == 'x86_64' or kern.arch.startswith('arm')) and (long(size) < (2 * kern.globals.page_size)):
        # Without the benefit of a KDP stub on the target, try to
        # find the user task's physical mapping and memcpy the data.
        # If it straddles a page boundary, copy in two passes
        range1_addr = long(addr)
        range1_size = long(size)
        if kern.StraddlesPage(range1_addr, range1_size):
            range2_addr = long(kern.TruncPage(range1_addr + range1_size))
            range2_size = long(range1_addr + range1_size - range2_addr)
            range1_size = long(range2_addr - range1_addr)
        else:
            range2_addr = 0
            range2_size = 0
            range2_in_kva = 0

        paddr_range1 = PmapWalk(task.map.pmap, range1_addr, vSILENT)
        if not paddr_range1:
            debuglog("Not mapped task 0x{:x} address 0x{:x}".format(task, addr))
            return ""

        range1_in_kva = kern.PhysToKernelVirt(paddr_range1)
        content = LazyTarget.GetProcess().ReadMemory(range1_in_kva, range1_size, err)
        if not err.Success():
            raise RuntimeError("Failed to read process memory. Error: " + err.description)

        if range2_addr:
            paddr_range2 = PmapWalk(task.map.pmap, range2_addr, vSILENT)
            if not paddr_range2:
                debuglog("Not mapped task 0x{:x} address 0x{:x}".format(task, addr))
                return ""
            range2_in_kva = kern.PhysToKernelVirt(paddr_range2)
            content += LazyTarget.GetProcess().ReadMemory(range2_in_kva, range2_size, err)
            if not err.Success():
                raise RuntimeError("Failed to read process memory. Error: " + err.description)
    else:
        raise NotImplementedError("GetUserDataAsString does not support this configuration")

    return content

def _ExtractDataFromString(strdata, offset, data_type, length=0):
    """ Extract specific data from string buffer
        params:
            strdata: str - string data give from GetUserDataAsString
            offset: int - 0 based offset into the data.
            data_type: str - defines what type to be read as. Supported values are:
                             'uint64_t', 'uint32_t', 'string'
            length: int - used when data_type=='string'
        returns
            None - if extraction failed.
            obj - based on what is requested in data_type
    """
    unpack_str = "s"
    if data_type == 'uint64_t':
        length = 8
        unpack_str = "Q"
    elif data_type == "uint32_t":
        length = 4
        unpack_str = "I"
    else:
        unpack_str= "%ds" % length

    data_len = len(strdata)
    if offset > data_len or (offset + length) > data_len or offset < 0:
        debuglog("Invalid arguments to _ExtractDataFromString.")
        return 0
    return struct.unpack(unpack_str, strdata[offset:(offset + length)])[0]

def GetUserspaceString(task, string_address):
    """ Maps 32 bytes at a time and packs as string
        params:
            task: obj - referencing task to read data from
            string_address: int - address where the image path is stored
        returns:
            str - string path of the file. "" if failed to read.
    """
    done = False
    retval = ""

    if string_address == 0:
        done = True

    while not done:
        str_data = GetUserDataAsString(task, string_address, 32)
        if len(str_data) == 0:
            break
        i = 0
        while i < 32:
            if ord(str_data[i]):
                retval += str_data[i]
            else:
                break
            i += 1
        if i < 32:
            done = True
        else:
            string_address += 32
    return retval

def GetImageInfo(task, mh_image_address, mh_path_address, approx_end_address=None):
    """ Print user library informaiton.
        params:
            task : obj referencing the task for which Image info printed
            mh_image_address : int - address which has image info
            mh_path_address : int - address which holds path name string
            approx_end_address: int - address which lldbmacros think is end address.
        returns:
            str - string representing image info. "" if failure to read data.
    """
    if approx_end_address:
        image_end_load_address = int(approx_end_address) -1
    else:
        image_end_load_address = int(mh_image_address) + 0xffffffff

    print_format = "0x{0:x} - 0x{1:x} {2: <50s} (??? - ???) <{3: <36s}> {4: <50s}"
    # 32 bytes enough for mach_header/mach_header_64
    mh_data = GetUserDataAsString(task, mh_image_address, 32)
    if len(mh_data) == 0:
        debuglog("unable to get userdata for task 0x{:x} img_addr 0x{:x} path_address 0x{:x}".format(
            task, mh_image_address, mh_path_address))
        return ""
    mh_magic = _ExtractDataFromString(mh_data, (4 * 0), "uint32_t")
    mh_cputype = _ExtractDataFromString(mh_data,(4 * 1), "uint32_t")
    mh_cpusubtype = _ExtractDataFromString(mh_data,(4 * 2), "uint32_t")
    mh_filetype = _ExtractDataFromString(mh_data,(4 * 3), "uint32_t")
    mh_ncmds = _ExtractDataFromString(mh_data,(4 * 4), "uint32_t")
    mh_sizeofcmds = _ExtractDataFromString(mh_data,(4 * 5), "uint32_t")
    mh_flags = _ExtractDataFromString(mh_data,(4 * 6), "uint32_t")

    if mh_magic == 0xfeedfacf:
        mh_64 = True
        lc_address = mh_image_address + 32
    else:
        mh_64 = False
        lc_address = mh_image_address + 28

    lc_idx = 0
    uuid_data = 0
    found_uuid_data = False
    retval = None
    while lc_idx < mh_ncmds:
        # 24 bytes is the size of uuid_command
        lcmd_data = GetUserDataAsString(task, lc_address, 24)
        lc_cmd = _ExtractDataFromString(lcmd_data, 4 * 0, "uint32_t")
        lc_cmd_size = _ExtractDataFromString(lcmd_data, 4 * 1, "uint32_t")
        lc_data = _ExtractDataFromString(lcmd_data, 4*2, "string", 16)

        uuid_out_string = ""
        path_out_string = ""

        if lc_cmd == 0x1b:
            # need to print the uuid now.
            uuid_data = [ord(x) for x in lc_data]
            found_uuid_data = True
            uuid_out_string = "{a[0]:02X}{a[1]:02X}{a[2]:02X}{a[3]:02X}-{a[4]:02X}{a[5]:02X}-{a[6]:02X}{a[7]:02X}-{a[8]:02X}{a[9]:02X}-{a[10]:02X}{a[11]:02X}{a[12]:02X}{a[13]:02X}{a[14]:02X}{a[15]:02X}".format(a=uuid_data)
            #also print image path
            path_out_string = GetUserspaceString(task, mh_path_address)
            path_base_name = path_out_string.split("/")[-1]
            retval = print_format.format(mh_image_address, image_end_load_address, path_base_name, uuid_out_string, path_out_string)
        elif lc_cmd == 0xe:
            ShowTaskUserLibraries.exec_load_path = lc_address + _ExtractDataFromString(lcmd_data, 4*2, "uint32_t")
            debuglog("Found load command to be 0xe for address %s" % hex(ShowTaskUserLibraries.exec_load_path))
        lc_address = lc_address + lc_cmd_size
        lc_idx += 1

    if not found_uuid_data:
        path_out_string = GetUserspaceString(task, mh_path_address)
        path_base_name = path_out_string.split("/")[-1]
        uuid_out_string = ""

        retval = print_format.format(mh_image_address, image_end_load_address, path_base_name, uuid_out_string, path_out_string)
    return retval

@static_var("found_images", []) # holds entries of format (startaddr, endaddr, image_path_addr, infostring)
@static_var("exec_load_path", 0)
@lldb_command("showtaskuserlibraries")
def ShowTaskUserLibraries(cmd_args=None):
    """ Show binary images known by dyld in target task
        For a given user task, inspect the dyld shared library state and print information about all Mach-O images.
        Syntax: (lldb)showtaskuserlibraries <task_t>
        Note: the address ranges are approximations. Also the list may not be completely accurate. This command expects memory read failures
        and hence will skip a library if unable to read information. Please use your good judgement and not take the output as accurate
    """
    if not cmd_args:
        raise ArgumentError("Insufficient arguments")

    #reset the found_images array
    ShowTaskUserLibraries.found_images = []

    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')
    is_task_64 = int(task.t_flags) & 0x1
    dyld_all_image_infos_address = unsigned(task.all_image_info_addr)
    debuglog("dyld_all_image_infos_address = %s" % hex(dyld_all_image_infos_address))

    cur_data_offset = 0
    if dyld_all_image_infos_address == 0:
        print "No dyld shared library information available for task"
        return False
    
    debuglog("Extracting version information.")
    vers_info_data = GetUserDataAsString(task, dyld_all_image_infos_address, 112)
    version = _ExtractDataFromString(vers_info_data, cur_data_offset, "uint32_t")
    cur_data_offset += 4
    if version > 14:
        print "Unknown dyld all_image_infos version number %d" % version
    image_info_count = _ExtractDataFromString(vers_info_data, cur_data_offset, "uint32_t")
    debuglog("version = %d count = %d is_task_64 = %s" % (version, image_info_count, repr(is_task_64)))

    ShowTaskUserLibraries.exec_load_path = 0
    if is_task_64:
        image_info_size = 24
        image_info_array_address = _ExtractDataFromString(vers_info_data, 8, "uint64_t")
        dyld_load_address = _ExtractDataFromString(vers_info_data, 8*4, "uint64_t")
        dyld_all_image_infos_address_from_struct = _ExtractDataFromString(vers_info_data, 8*13, "uint64_t")
    else:
        image_info_size = 12
        image_info_array_address = _ExtractDataFromString(vers_info_data, 4*2, "uint32_t")
        dyld_load_address = _ExtractDataFromString(vers_info_data, 4*5, "uint32_t")
        dyld_all_image_infos_address_from_struct = _ExtractDataFromString(vers_info_data, 4*14, "uint32_t")
    # Account for ASLR slide before dyld can fix the structure
    dyld_load_address = dyld_load_address + (dyld_all_image_infos_address - dyld_all_image_infos_address_from_struct)

    i = 0
    image_info_list = []
    while i < image_info_count:
        image_info_address = image_info_array_address + i * image_info_size
        debuglog("i = %d, image_info_address = %s, image_info_size = %d" % (i, hex(image_info_address), image_info_size))
        n_im_info_addr = None
        img_data = ""
        try:
            img_data = GetUserDataAsString(task, image_info_address, image_info_size)
        except Exception, e:
            debuglog("Failed to read user data for task 0x{:x} addr 0x{:x}, exception {:s}".format(task, image_info_address, str(e)))
            pass

        if is_task_64:
            image_info_addr = _ExtractDataFromString(img_data, 0, "uint64_t")
            image_info_path = _ExtractDataFromString(img_data, 8, "uint64_t")
        else:
            image_info_addr = _ExtractDataFromString(img_data, 0, "uint32_t")
            image_info_path = _ExtractDataFromString(img_data, 4, "uint32_t")

        if image_info_addr :
            debuglog("Found image: image_info_addr = %s, image_info_path= %s" % (hex(image_info_addr), hex(image_info_path)))
            image_info_list.append((image_info_addr, image_info_path))
        i += 1

    image_info_list.sort()
    num_images_found = len(image_info_list)

    for ii in range(num_images_found):
        n_im_info_addr = dyld_load_address
        if ii + 1 < num_images_found:
            n_im_info_addr = image_info_list[ii+1][0]

        image_info_addr = image_info_list[ii][0]
        image_info_path = image_info_list[ii][1]
        try:
            image_print_s = GetImageInfo(task, image_info_addr, image_info_path, approx_end_address=n_im_info_addr)
            if len(image_print_s) > 0:
                print image_print_s
                ShowTaskUserLibraries.found_images.append((image_info_addr, n_im_info_addr, image_info_path, image_print_s))
            else:
                debuglog("Failed to print image info for task 0x{:x} image_info 0x{:x}".format(task, image_info_addr))
        except Exception,e:
            if config['debug']:
                raise e

    # load_path might get set when the main executable is processed.
    if ShowTaskUserLibraries.exec_load_path != 0:
        debuglog("main executable load_path is set.")
        image_print_s = GetImageInfo(task, dyld_load_address, ShowTaskUserLibraries.exec_load_path)
        if len(image_print_s) > 0:
            print image_print_s
            ShowTaskUserLibraries.found_images.append((dyld_load_address, dyld_load_address + 0xffffffff,
                    ShowTaskUserLibraries.exec_load_path, image_print_s))
        else:
            debuglog("Failed to print image for main executable for task 0x{:x} dyld_load_addr 0x{:x}".format(task, dyld_load_address))
    else:
        debuglog("Falling back to vm entry method for finding executable load address")
        print "# NOTE: Failed to find executable using all_image_infos. Using fuzzy match to find best possible load address for executable."
        ShowTaskLoadInfo([cmd_args[0]])
    return

@lldb_command("showtaskuserdyldinfo")
def ShowTaskUserDyldInfo(cmd_args=None):
    """ Inspect the dyld global info for the given user task & print out all fields including error messages
        Syntax: (lldb)showtaskuserdyldinfo <task_t>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print "No arguments passed"
        print ShowTaskUserDyldInfo.__doc__.strip()
        return

    out_str = ""
    task = kern.GetValueFromAddress(cmd_args[0], 'task_t')
    is_task_64 = int(task.t_flags) & 0x1
    dyld_all_image_infos_address = unsigned(task.all_image_info_addr)
    if dyld_all_image_infos_address == 0:
        print "No dyld shared library information available for task"
        return False
    vers_info_data = GetUserDataAsString(task, dyld_all_image_infos_address, 112)
    dyld_all_image_infos_version = _ExtractDataFromString(vers_info_data, 0, "uint32_t")
    if dyld_all_image_infos_version > 14:
        out_str += "Unknown dyld all_image_infos version number %d" % dyld_all_image_infos_version

    # Find fields by byte offset. We assume at least version 9 is supported
    if is_task_64:
        dyld_all_image_infos_infoArrayCount = _ExtractDataFromString(vers_info_data, 4, "uint32_t")
        dyld_all_image_infos_infoArray = _ExtractDataFromString(vers_info_data, 8, "uint64_t")
        dyld_all_image_infos_notification = _ExtractDataFromString(vers_info_data, 16, "uint64_t")
        dyld_all_image_infos_processDetachedFromSharedRegion = _ExtractDataFromString(vers_info_data, 24, "string")
        dyld_all_image_infos_libSystemInitialized = _ExtractDataFromString(vers_info_data, 25, "string")
        dyld_all_image_infos_dyldImageLoadAddress = _ExtractDataFromString(vers_info_data, 32, "uint64_t")
        dyld_all_image_infos_jitInfo = _ExtractDataFromString(vers_info_data, 40, "uint64_t")
        dyld_all_image_infos_dyldVersion = _ExtractDataFromString(vers_info_data, 48, "uint64_t")
        dyld_all_image_infos_errorMessage = _ExtractDataFromString(vers_info_data, 56, "uint64_t")
        dyld_all_image_infos_terminationFlags = _ExtractDataFromString(vers_info_data, 64, "uint64_t")
        dyld_all_image_infos_coreSymbolicationShmPage = _ExtractDataFromString(vers_info_data, 72, "uint64_t")
        dyld_all_image_infos_systemOrderFlag = _ExtractDataFromString(vers_info_data, 80, "uint64_t")
        dyld_all_image_infos_uuidArrayCount = _ExtractDataFromString(vers_info_data, 88, "uint64_t")
        dyld_all_image_infos_uuidArray = _ExtractDataFromString(vers_info_data, 96, "uint64_t")
        dyld_all_image_infos_dyldAllImageInfosAddress = _ExtractDataFromString(vers_info_data, 104, "uint64_t")
    else:
        dyld_all_image_infos_infoArrayCount = _ExtractDataFromString(vers_info_data, 4, "uint32_t")
        dyld_all_image_infos_infoArray = _ExtractDataFromString(vers_info_data, 8, "uint32_t")
        dyld_all_image_infos_notification = _ExtractDataFromString(vers_info_data, 12, "uint32_t")
        dyld_all_image_infos_processDetachedFromSharedRegion = _ExtractDataFromString(vers_info_data, 16, "string")
        dyld_all_image_infos_libSystemInitialized = _ExtractDataFromString(vers_info_data, 17, "string")
        dyld_all_image_infos_dyldImageLoadAddress = _ExtractDataFromString(vers_info_data, 20, "uint32_t")
        dyld_all_image_infos_jitInfo = _ExtractDataFromString(vers_info_data, 24, "uint32_t")
        dyld_all_image_infos_dyldVersion = _ExtractDataFromString(vers_info_data, 28, "uint32_t")
        dyld_all_image_infos_errorMessage = _ExtractDataFromString(vers_info_data, 32, "uint32_t")
        dyld_all_image_infos_terminationFlags = _ExtractDataFromString(vers_info_data, 36, "uint32_t")
        dyld_all_image_infos_coreSymbolicationShmPage = _ExtractDataFromString(vers_info_data, 40, "uint32_t")
        dyld_all_image_infos_systemOrderFlag = _ExtractDataFromString(vers_info_data, 44, "uint32_t")
        dyld_all_image_infos_uuidArrayCount = _ExtractDataFromString(vers_info_data, 48, "uint32_t")
        dyld_all_image_infos_uuidArray = _ExtractDataFromString(vers_info_data, 52, "uint32_t")
        dyld_all_image_infos_dyldAllImageInfosAddress = _ExtractDataFromString(vers_info_data, 56, "uint32_t")

    dyld_all_imfo_infos_slide = (dyld_all_image_infos_address - dyld_all_image_infos_dyldAllImageInfosAddress)
    dyld_all_image_infos_dyldVersion_postslide = (dyld_all_image_infos_dyldVersion + dyld_all_imfo_infos_slide)

    path_out = GetUserspaceString(task, dyld_all_image_infos_dyldVersion_postslide)
    out_str += "[dyld-{:s}]\n".format(path_out)
    out_str += "version \t\t\t\t: {:d}\n".format(dyld_all_image_infos_version)
    out_str += "infoArrayCount \t\t\t\t: {:d}\n".format(dyld_all_image_infos_infoArrayCount)
    out_str += "infoArray \t\t\t\t: {:#x}\n".format(dyld_all_image_infos_infoArray)
    out_str += "notification \t\t\t\t: {:#x}\n".format(dyld_all_image_infos_notification)
    
    out_str += "processDetachedFromSharedRegion \t: "
    if dyld_all_image_infos_processDetachedFromSharedRegion != "":
        out_str += "TRUE\n".format(dyld_all_image_infos_processDetachedFromSharedRegion)
    else:
        out_str += "FALSE\n"
    
    out_str += "libSystemInitialized \t\t\t: "
    if dyld_all_image_infos_libSystemInitialized != "":
        out_str += "TRUE\n".format(dyld_all_image_infos_libSystemInitialized)
    else:
        out_str += "FALSE\n"
        
    out_str += "dyldImageLoadAddress \t\t\t: {:#x}\n".format(dyld_all_image_infos_dyldImageLoadAddress)
    out_str += "jitInfo \t\t\t\t: {:#x}\n".format(dyld_all_image_infos_jitInfo)
    out_str += "\ndyldVersion \t\t\t\t: {:#x}".format(dyld_all_image_infos_dyldVersion)
    if (dyld_all_imfo_infos_slide != 0):
        out_str += " (currently {:#x})\n".format(dyld_all_image_infos_dyldVersion_postslide)
    else:
        out_str += "\n"

    out_str += "errorMessage \t\t\t\t: {:#x}\n".format(dyld_all_image_infos_errorMessage)
    if dyld_all_image_infos_errorMessage != 0:
        out_str += GetUserspaceString(task, dyld_all_image_infos_errorMessage)

    out_str += "terminationFlags \t\t\t: {:#x}\n".format(dyld_all_image_infos_terminationFlags)
    out_str += "coreSymbolicationShmPage \t\t: {:#x}\n".format(dyld_all_image_infos_coreSymbolicationShmPage)
    out_str += "systemOrderFlag \t\t\t: {:#x}\n".format(dyld_all_image_infos_systemOrderFlag)
    out_str += "uuidArrayCount \t\t\t\t: {:#x}\n".format(dyld_all_image_infos_uuidArrayCount)
    out_str += "uuidArray \t\t\t\t: {:#x}\n".format(dyld_all_image_infos_uuidArray)
    out_str += "dyldAllImageInfosAddress \t\t: {:#x}".format(dyld_all_image_infos_dyldAllImageInfosAddress)
    if (dyld_all_imfo_infos_slide != 0):
        out_str += " (currently {:#x})\n".format(dyld_all_image_infos_address)
    else:
        out_str += "\n"

    if is_task_64:
        dyld_all_image_infos_address = dyld_all_image_infos_address + 112
        dyld_all_image_infos_v10 = GetUserDataAsString(task, dyld_all_image_infos_address, 64)
        dyld_all_image_infos_initialImageCount = _ExtractDataFromString(dyld_all_image_infos_v10, 112-112, "uint64_t")
        dyld_all_image_infos_errorKind = _ExtractDataFromString(dyld_all_image_infos_v10, 120-112, "uint64_t")
        dyld_all_image_infos_errorClientOfDylibPath = _ExtractDataFromString(dyld_all_image_infos_v10, 128-112, "uint64_t")
        dyld_all_image_infos_errorTargetDylibPath = _ExtractDataFromString(dyld_all_image_infos_v10, 136-112, "uint64_t")
        dyld_all_image_infos_errorSymbol = _ExtractDataFromString(dyld_all_image_infos_v10, 144-112, "uint64_t")
        dyld_all_image_infos_sharedCacheSlide = _ExtractDataFromString(dyld_all_image_infos_v10, 152-112, "uint64_t")
        dyld_all_image_infos_sharedCacheUUID = _ExtractDataFromString(dyld_all_image_infos_v10, 160-112, "string")
    else:
        dyld_all_image_infos_address = dyld_all_image_infos_address + 60
        dyld_all_image_infos_v10 = GetUserDataAsString(task, dyld_all_image_infos_address, 40)
        dyld_all_image_infos_initialImageCount = _ExtractDataFromString(dyld_all_image_infos_v10, 60-60, "uint32_t")
        dyld_all_image_infos_errorKind = _ExtractDataFromString(dyld_all_image_infos_v10, 64-60, "uint32_t")
        dyld_all_image_infos_errorClientOfDylibPath = _ExtractDataFromString(dyld_all_image_infos_v10, 68-60, "uint32_t")
        dyld_all_image_infos_errorTargetDylibPath = _ExtractDataFromString(dyld_all_image_infos_v10, 72-60, "uint32_t")
        dyld_all_image_infos_errorSymbol = _ExtractDataFromString(dyld_all_image_infos_v10, 76-60, "uint32_t")
        dyld_all_image_infos_sharedCacheSlide = _ExtractDataFromString(dyld_all_image_infos_v10, 80-60, "uint32_t")
        dyld_all_image_infos_sharedCacheUUID = _ExtractDataFromString(dyld_all_image_infos_v10, 84-60, "string")

    if dyld_all_image_infos_version >= 10:
        out_str += "\ninitialImageCount \t\t\t: {:#x}\n".format(dyld_all_image_infos_initialImageCount)

    if dyld_all_image_infos_version >= 11:
        out_str += "errorKind \t\t\t\t: {:#x}\n".format(dyld_all_image_infos_errorKind)
        out_str += "errorClientOfDylibPath \t\t\t: {:#x}\n".format(dyld_all_image_infos_errorClientOfDylibPath)
        if dyld_all_image_infos_errorClientOfDylibPath != 0:
            out_str += "\t\t\t\t"
            out_str += GetUserspaceString(task, dyld_all_image_infos_errorClientOfDylibPath)
            out_str += "\n"
        out_str += "errorTargetDylibPath \t\t\t: {:#x}\n".format(dyld_all_image_infos_errorTargetDylibPath)
        if dyld_all_image_infos_errorTargetDylibPath != 0:
            out_str += "\t\t\t\t"
            out_str += GetUserspaceString(task, dyld_all_image_infos_errorTargetDylibPath)
            out_str += "\n"
        out_str += "errorSymbol \t\t\t\t: {:#x}\n".format(dyld_all_image_infos_errorSymbol)
        if dyld_all_image_infos_errorSymbol != 0:
            out_str += "\t\t\t\t"
            out_str += GetUserspaceString(task, dyld_all_image_infos_errorSymbol)
            out_str += "\n"

        if dyld_all_image_infos_version >= 12:
            out_str += "sharedCacheSlide \t\t\t: {:#x}\n".format(dyld_all_image_infos_sharedCacheSlide)
        if dyld_all_image_infos_version >= 13 and dyld_all_image_infos_sharedCacheUUID != "":
            out_str += "sharedCacheUUID \t\t\t: {:s}\n".format(dyld_all_image_infos_sharedCacheUUID)
    else:
        out_str += "No dyld information available for task\n"
    print out_str

# Macro: showosmalloc
@lldb_type_summary(['OSMallocTag'])
@header("{0: <20s} {1: >5s} {2: ^16s} {3: <5s} {4: <40s}".format("TAG", "COUNT", "STATE", "ATTR", "NAME"))
def GetOSMallocTagSummary(malloc_tag):
    """ Summarize the given OSMalloc tag.
        params:
          malloc_tag : value - value representing a _OSMallocTag_ * in kernel
        returns:
          out_str - string summary of the OSMalloc tag.
    """
    if not malloc_tag:
        return "Invalid malloc tag value: 0x0"

    out_str = "{: <#20x} {: >5d} {: ^#16x} {: <5d} {: <40s}\n".format(malloc_tag,
        malloc_tag.OSMT_refcnt, malloc_tag.OSMT_state, malloc_tag.OSMT_attr, malloc_tag.OSMT_name)
    return out_str

@lldb_command('showosmalloc')
def ShowOSMalloc(cmd_args=None):
    """ Print the outstanding allocation count of OSMalloc tags
        Usage: showosmalloc
    """
    summary_str = ""
    tag_headp = Cast(addressof(kern.globals.OSMalloc_tag_list), 'struct _OSMallocTag_ *')
    tagp = Cast(tag_headp.OSMT_link.next, 'struct _OSMallocTag_ *')
    summary_str += GetOSMallocTagSummary.header + "\n"
    while tagp != tag_headp:
        summary_str += GetOSMallocTagSummary(tagp)
        tagp = Cast(tagp.OSMT_link.next, 'struct _OSMallocTag_ *')

    print summary_str

# EndMacro: showosmalloc


@lldb_command('savekcdata', 'T:O:')
def SaveKCDataToFile(cmd_args=None, cmd_options={}):
    """ Save the data referred by the kcdata_descriptor structure.
        options:
            -T: <task_t> pointer to task if memory referenced is in userstask.
            -O: <output file path> path to file to save data. default: /tmp/kcdata.<timestamp>.bin
        Usage: (lldb) savekcdata <kcdata_descriptor_t> -T <task_t> -O /path/to/outputfile.bin
    """
    if not cmd_args:
        raise ArgumentError('Please provide the kcdata descriptor.')

    kcdata = kern.GetValueFromAddress(cmd_args[0], 'kcdata_descriptor_t')

    outputfile = '/tmp/kcdata.{:s}.bin'.format(str(time.time()))
    task = None
    if '-O' in cmd_options:
        outputfile = cmd_options['-O']
    if '-T' in cmd_options:
        task = kern.GetValueFromAddress(cmd_options['-T'], 'task_t')

    memory_begin_address = unsigned(kcdata.kcd_addr_begin)
    memory_size = 16 + unsigned(kcdata.kcd_addr_end) - memory_begin_address
    flags_copyout = unsigned(kcdata.kcd_flags)
    if flags_copyout:
        if not task:
            raise ArgumentError('Invalid task pointer provided.')
        memory_data = GetUserDataAsString(task, memory_begin_address, memory_size)
    else:
        data_ptr = kern.GetValueFromAddress(memory_begin_address, 'uint8_t *')
        if data_ptr == 0:
            print "Kcdata descriptor is NULL"
            return False
        memory_data = []
        for i in range(memory_size):
            memory_data.append(chr(data_ptr[i]))
            if i % 50000 == 0:
                print "%d of %d            \r" % (i, memory_size),
        memory_data = ''.join(memory_data)

    if len(memory_data) != memory_size:
        print "Failed to read {:d} bytes from address {: <#020x}".format(memory_size, memory_begin_address)
        return False

    fh = open(outputfile, 'w')
    fh.write(memory_data)
    fh.close()
    print "Saved {:d} bytes to file {:s}".format(memory_size, outputfile)
    return True



