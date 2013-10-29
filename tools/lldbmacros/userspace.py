from xnu import *
from utils import *
from process import *
from pmap import *

def _GetIntegerDataFromTask(u_ptr, task_abi):
    """
        params:
            u_ptr : int - pointer in user memory
            task_abi : int - what kind of user program is running
        returns:
            int - value stored at specified u_ptr.
    """
    if kern.arch != "x86_64":
        raise ValueError("This function does not work for non x86_64 arch")
    if task_abi == 0xf :
        return unsigned(dereference(kern.GetValueFromAddress(u_ptr, 'uint64_t *')))
    else:
        return unsigned(dereference(kern.GetValueFromAddress(u_ptr, 'uint32_t *')))

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
    else:
        debuglog("user process is 32 bit")
        user_ip = iss.uss.ss_32.eip
        user_frame = iss.uss.ss_32.ebp
        user_abi_ret_offset = 4
    
    if user_ip == 0:
        print "This activation does not appear to have a valid user context."
        return False

    cur_ip = user_ip
    cur_frame = user_frame
    debuglog("ip= 0x%x , fr = 0x%x " % (cur_ip, cur_frame))
    kdp_pmap_addr = unsigned(addressof(kern.globals.kdp_pmap))
    if not WriteInt64ToMemoryAddress(unsigned(thread.task.map.pmap), kdp_pmap_addr):
        print "Failed to write in kdp_pmap = 0x{0:0>16x} value.".format(thread.task.map.pmap)
        return False
    debuglog("newpmap = 0x{:x}".format(kern.globals.kdp_pmap))

    frameformat = "{0:d} FP: 0x{1:x} PC: 0x{2:x}"
    if user_lib_info is not None:
        frameformat = "{0:d} {3: <30s} 0x{2:x}"
    print frameformat.format(0, cur_frame, cur_ip, GetBinaryNameForPC(cur_ip, user_lib_info))

    print kern.Symbolicate(cur_ip)
    tmp_frame = unsigned(cur_frame)
    prev_frame = _GetIntegerDataFromTask(tmp_frame, abi)
    prev_ip = _GetIntegerDataFromTask(tmp_frame + user_abi_ret_offset, abi)
    frameno = 1
    while prev_frame and prev_frame != 0x0000000800000008:
        print frameformat.format(frameno, prev_frame, prev_ip, GetBinaryNameForPC(prev_ip, user_lib_info))
        print kern.Symbolicate(prev_ip)
        prev_ip = _GetIntegerDataFromTask(prev_frame + user_abi_ret_offset, abi)
        prev_frame = _GetIntegerDataFromTask(prev_frame, abi)
        frameno +=1
    if not WriteInt64ToMemoryAddress(0, kdp_pmap_addr):
        print "Failed to write in kdp_pmap = 0"
        return False
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
    return True

@lldb_command('showtaskuserstacks')
def ShowTaskUserStacks(cmd_args=None):
    """ Print out the user stack for each thread in a task, followed by the user libraries.
        Syntax: (lldb) showtaskuserstacks <task_t>
        The format is compatible with CrashTracer. You can also use the speedtracer plugin as follows
        (lldb) showtaskuserstacks <task_t> -p speedtracer
        
        Note: the address ranges are approximations. Also the list may not be completely accurate. This command expects memory read failures
        and hence will skip a library if unable to read information. Please use your good judgement and not take the output as accurate
    """
    if not cmd_args:
        raise ArgumentError("Insufficient arguments")

    task = kern.GetValueFromAddress(cmd_args[0], 'task *')
    #print GetTaskSummary.header + " " + GetProcSummary.header
    pval = Cast(task.bsd_info, 'proc *')
    #print GetTaskSummary(task) + " " + GetProcSummary(pval) + "\n \n"
    crash_report_format_string = """\
Process:         {pid: <10d}
Path:            {path: <50s}
Identifier:      {pname: <30s}                       
Version:         ??? (???)
Code Type:       {parch: <20s}
Parent Process:  {ppname: >20s}[{ppid:d}]

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
    ts = datetime.fromtimestamp(int(pval.p_start.tv_sec))
    date_string = ts.strftime('%Y-%m-%d %H:%M:%S')
    is_64 = False
    if pval.p_flag & 0x4 :
        is_64 = True
    
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
    print crash_report_format_string.format(pid = pval.p_pid,
            pname = pval.p_comm,
            path = pval.p_comm,
            ppid = pval.p_ppid,
            ppname = GetProcNameForPid(pval.p_ppid),
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
    elif kern.arch in ['arm'] and long(size) < (2 * kern.globals.page_size):
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
            content += LazyTarget.GetProcess().ReadMemory(range1_in_kva, range1_size, err)
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

def GetPathForImage(task, path_address):
    """ Maps 32 bytes at a time and packs as string 
        params:
            task: obj - referencing task to read data from
            path_address: int - address where the image path is stored
        returns:
            str - string path of the file. "" if failed to read.
    """
    done = False
    retval = ""

    if path_address == 0:
        done = True

    while not done:
        path_str_data = GetUserDataAsString(task, path_address, 32)
        if len(path_str_data) == 0:
            break
        i = 0
        while i < 32:
            if ord(path_str_data[i]):
                retval += path_str_data[i]
            else:
                break
            i += 1
        if i < 32:
            done = True
        else:
            path_address += 32
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
            path_out_string = GetPathForImage(task, mh_path_address)
            path_base_name = path_out_string.split("/")[-1]
            retval = print_format.format(mh_image_address, image_end_load_address, path_base_name, uuid_out_string, path_out_string)
        elif lc_cmd == 0xe:
            ShowTaskUserLibraries.exec_load_path = lc_address + _ExtractDataFromString(lcmd_data, 4*2, "uint32_t")
        lc_address = lc_address + lc_cmd_size
        lc_idx += 1

    if not found_uuid_data:
        path_out_string = GetPathForImage(task, mh_path_address)
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
    cur_data_offset = 0
    if dyld_all_image_infos_address == 0:
        print "No dyld shared library information available for task"
        return False
    vers_info_data = GetUserDataAsString(task, dyld_all_image_infos_address, 112)
    version = _ExtractDataFromString(vers_info_data, cur_data_offset, "uint32_t")
    cur_data_offset += 4
    if version > 12:
        print "Unknown dyld all_image_infos version number %d" % version
    image_info_count = _ExtractDataFromString(vers_info_data, cur_data_offset, "uint32_t")
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
        image_print_s = GetImageInfo(task, dyld_load_address, ShowTaskUserLibraries.exec_load_path)
        if len(image_print_s) > 0:
            print image_print_s
            ShowTaskUserLibraries.found_images.append((dyld_load_address, dyld_load_address + 0xffffffff,
                    ShowTaskUserLibraries.exec_load_path, image_print_s))
        else:
            debuglog("Failed to print image for main executable for task 0x{:x} dyld_load_addr 0x{:x}".format(task, dyld_load_address))
    return



