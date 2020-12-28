import logging
import target
import struct

from xnu import *
from core.operating_system import Armv8_RegisterSet, Armv7_RegisterSet, I386_RegisterSet, X86_64RegisterSet

""" these defines should come from an authoritative header file """
CPU_TYPE_I386 = 0x00000007
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM = 0x0000000c
CPU_TYPE_ARM64 = 0x0100000c
CPU_TYPE_ARM64_32 = 0x0200000c

def GetRegisterSetForCPU(cputype, subtype):
    if cputype == CPU_TYPE_ARM64:
        retval = Armv8_RegisterSet
    elif cputype == CPU_TYPE_ARM64_32:
        retval = Armv8_RegisterSet
    elif cputype == CPU_TYPE_ARM:
        retval = Armv7_RegisterSet
    elif cputype == CPU_TYPE_I386:
        retval = I386_RegisterSet
    elif cputype == CPU_TYPE_X86_64:
        retval = X86_64RegisterSet
    
    """ crash if unknown cputype """

    return retval.register_info['registers']


class UserThreadObject(object):
    """representation of userspace thread"""
    def __init__(self, thr_obj, cputype, cpusubtype, is_kern_64bit):
        super(UserThreadObject, self).__init__()
        self.thread = thr_obj
        self.registerset = GetRegisterSetForCPU(cputype, cpusubtype)
        self.thread_id = unsigned(self.thread.thread_id)
        self.is64Bit = bool(cputype & 0x01000000)

        if self.is64Bit:
            if cputype == CPU_TYPE_X86_64:
                self.reg_type = "x86_64"
                self.saved_state = Cast(self.thread.machine.iss, 'x86_saved_state_t *').uss.ss_64
            if cputype == CPU_TYPE_ARM64:
                self.reg_type = "arm64"
                self.saved_state = self.thread.machine.upcb.uss.ss_64
        else:
            if cputype == CPU_TYPE_I386:
                self.reg_type = "i386"
                self.saved_state = Cast(self.thread.machine.iss, 'x86_saved_state_t *').uss.ss_32
            if cputype == CPU_TYPE_ARM:
                self.reg_type = "arm"
                if not is_kern_64bit:
                    self.saved_state = self.thread.machine.PcbData
                else:
                    self.saved_state = self.thread.machine.contextData.ss.uss.ss_32
            if cputype == CPU_TYPE_ARM64_32:
                self.reg_type = "arm64"
                self.saved_state = self.thread.machine.upcb.uss.ss_64

        logging.debug("created thread id 0x%x of type %s, is_kern_64bit 0x%x cputype 0x%x"
                      % (self.thread_id, self.reg_type, is_kern_64bit, cputype))

    def getRegisterValueByName(self, name):
        if self.reg_type == 'arm64':
            if name in ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28'):
                return unsigned(getattr(self.saved_state, 'x')[int(name.strip('x'))])

            return unsigned(getattr(self.saved_state, name))

        if self.reg_type == "x86_64":
            if name in ('rip', 'rflags', 'cs', 'rsp', 'cpu'):
                return unsigned(getattr(self.saved_state.isf, name))
            return unsigned(getattr(self.saved_state, name))

        if self.reg_type == "arm":
            if name in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12'):
                retval = unsigned(getattr(self.saved_state, 'r')[int(name.strip('r'))])
            else:
                retval = unsigned(getattr(self.saved_state, name))
            return retval

        #TODO for i386

    def getName(self):
        return str(self.thread_id)

    def getRegisterData(self, reg_num):
        """ returns None if there is error """
        if reg_num < 0 or reg_num >= len(self.registerset):
            logging.warning("regnum %d is not defined for thread_id 0x%x" % (reg_num, self.thread_id))
            return None
        return self.getRegisterValueByName(self.registerset[reg_num]['name'])


class UserProcess(target.Process):
    """ Represent a user process and thread states """
    def __init__(self, task):
        self.task = task
        self.proc = Cast(task.bsd_info, 'proc_t')
        dataregisters64bit = False
        ptrsize = 4

        if task.t_flags & 0x1:
            ptrsize = 8
        if task.t_flags & 0x2:
            dataregisters64bit = True

        is_kern_64bit = kern.arch in ['x86_64', 'x86_64h', 'arm64', 'arm64e']

        self.cputype = unsigned(self.proc.p_cputype)
        self.cpusubtype = unsigned(self.proc.p_cpusubtype)

        super(UserProcess, self).__init__(self.cputype, self.cpusubtype, ptrsize)

        self.hinfo['ostype'] = 'macosx'
        if self.cputype != CPU_TYPE_X86_64 and self.cputype != CPU_TYPE_I386:
            self.hinfo['ostype'] = 'ios'

        self.registerset = GetRegisterSetForCPU(self.cputype, self.cpusubtype)
        logging.debug("process %s is64bit: %d ptrsize: %d cputype: %d  cpusubtype:%d",
                      hex(self.proc), int(dataregisters64bit), ptrsize,
                      self.cputype, self.cpusubtype
                      )
        self.threads = {}
        self.threads_ids_list = []
        logging.debug("iterating over threads in process")
        for thval in IterateQueue(task.threads, 'thread *', 'task_threads'):
            self.threads[unsigned(thval.thread_id)] = UserThreadObject(thval, self.cputype, self.cpusubtype, is_kern_64bit)
            self.threads_ids_list.append(unsigned(thval.thread_id))

    def getRegisterDataForThread(self, th_id, reg_num):
        if th_id not in self.threads:
            logging.critical("0x%x thread id is not found in this task")
            return ''
        if reg_num < 0 or reg_num >= len(self.registerset):
            logging.warning("regnum %d is not defined for thread_id 0x%x" % (reg_num, th_id))
            return ''
        value = self.threads[th_id].getRegisterData(reg_num)
        return self.encodeRegisterData(value, bytesize=self.registerset[reg_num]['bitsize']/8)

    def getRegisterCombinedDataForThread(self, th_id):
        if th_id not in self.threads:
            logging.critical("0x%x thread id is not found in this task" % th_id)
            return ''
        cur_thread = self.threads[th_id]
        retval = 'thread:%s;name:%s;' % (self.encodeThreadID(th_id), cur_thread.getName())
        pos = 0
        for rinfo in self.registerset:
            name = rinfo['name']
            format = "%02x:%s;"
            value = cur_thread.getRegisterValueByName(name)
            value_endian_correct_str = self.encodeRegisterData(value, bytesize=(rinfo['bitsize']/8))
            retval += format % (pos, value_endian_correct_str)
            pos += 1
        return retval

    def getThreadStopInfo(self, th_id):
        if th_id not in self.threads:
            logging.critical("0x%x thread id is not found in this task")
            return ''
        return 'T02' + self.getRegisterCombinedDataForThread(th_id) + 'threads:' + self.getThreadsInfo()+';'

    def getRegisterInfo(self, regnum):
        #something similar to
        #"name:x1;bitsize:64;offset:8;encoding:uint;format:hex;gcc:1;dwarf:1;set:General Purpose Registers;"
        if regnum > len(self.registerset):
            logging.debug("No register_info for number %d." % regnum)
            return 'E45'

        rinfo = self.registerset[regnum]
        retval = ''
        for i in rinfo.keys():
            i_val = str(rinfo[i])
            if i == 'set':
                i_val = 'General Purpose Registers'
            retval += '%s:%s;' % (str(i), i_val)

        return retval

    def getProcessInfo(self):
        retval = ''
        #pid:d22c;parent-pid:d34d;real-uid:ecf;real-gid:b;effective-uid:ecf;effective-gid:b;cputype:1000007;cpusubtype:3;
        #ostype:macosx;vendor:apple;endian:little;ptrsize:8;
        pinfo = {'effective-uid': 'ecf', 'effective-gid': 'b', 'endian': 'little', 'vendor': 'apple'}
        pinfo['pid'] = "%x" % (GetProcPIDForTask(self.task))
        pinfo['parent-pid'] = "%x" % (unsigned(self.proc.p_ppid))
        pinfo['ptrsize'] = str(self.ptrsize)
        pinfo['ostype'] = 'macosx'
        pinfo['cputype'] = "%x" % self.cputype
        pinfo['cpusubtype'] = "%x" % self.cpusubtype
        pinfo['real-uid'] = "%x" % (unsigned(self.proc.p_ruid))
        pinfo['real-gid'] = "%x" % (unsigned(self.proc.p_rgid))
        if str(kern.arch).find('arm') >= 0:
            pinfo['ostype'] = 'ios'
        for i in pinfo.keys():
            i_val = str(pinfo[i])
            retval += '%s:%s;' % (str(i), i_val)
        return retval

    def readMemory(self, address, size):
        data = GetUserDataAsString(self.task, address, size)
        if not data:
            logging.error("Failed to read memory task:{: <#018x} {: <#018x} {:d}".format(self.task, address, size))
        return self.encodeByteString(data)

    def getSharedLibInfoAddress(self):
        return unsigned(self.task.all_image_info_addr)
