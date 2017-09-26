import logging
import struct


class Process(object):
    """Base interface for process being debugged. Provides basic functions for gdbserver to interact.
       Create a class object for your backing system to provide functionality

       Here is the list of must implement functions:
        + please update hinfo['ostype'] and hinfo['vendor'] if its not in (macosx, ios)
        + please populate threads_ids_list with ids of threads.
        - getThreadStopInfo
        - getProcessInfo
        - getRegisterDataForThread
        - getRegisterInfo
        - readMemory
    """
    def __init__(self, cputype, cpusubtype, ptrsize):
        super(Process, self).__init__()
        self.hinfo = {
            'cputype': cputype, 'cpusubtype': cpusubtype,
            'triple': None, 'vendor': 'apple', 'ostype': 'macosx',
            'endian': 'little', 'ptrsize': ptrsize, 'hostname': None, 'os_build': None,
            'os_kernel': None, 'os_version': None, 'watchpoint_exceptions_received': None,
            'default_packet_timeout': '10', 'distribution_id': None
        }

        ## if cputype is arm assume its ios
        if (cputype & 0xc) != 0xc:
            self.hinfo['ostype'] = 'ios'
        self.ptrsize = ptrsize
        self.threads = {}
        self.threads_ids_list = []

    def getHostInfo(self):
        retval = ''
        for i in self.hinfo.keys():
            if self.hinfo[i] is None:
                continue
            retval += '%s:%s;' % (str(i), str(self.hinfo[i]))
        return retval

    def getRegisterDataForThread(self, th_id, reg_num):
        logging.critical("Not Implemented: getRegisterDataForThread")
        return ''

    def readMemory(self, address, size):
        logging.critical("readMemory: Not Implemented: readMemory")
        #E08 means read failed
        return 'E08'

    def writeMemory(self, address, data, size):
        """ Unimplemented. address in ptr to save data to. data is native endian stream of bytes,
        """
        return 'E09'

    def getRegisterInfo(regnum):
        #something similar to
        #"name:x1;bitsize:64;offset:8;encoding:uint;format:hex;gcc:1;dwarf:1;set:General Purpose Registers;"
        logging.critical("getRegisterInfo: Not Implemented: getRegisterInfo")
        return 'E45'

    def getProcessInfo(self):
        logging.critical("Not Implemented: qProcessInfo")
        return ''

    def getFirstThreadInfo(self):
        """ describe all thread ids in the process.
        """
        thinfo_str = self.getThreadsInfo()
        if not thinfo_str:
            logging.warning('getFirstThreadInfo: Process has no threads')
            return ''
        return 'm' + thinfo_str

    def getSubsequestThreadInfo(self):
        """ return 'l' for last because all threads are listed in getFirstThreadInfo call.
        """
        return 'l'

    def getSharedLibInfoAddress(self):
        """ return int data of a hint where shared library is loaded.
        """
        logging.critical("Not Implemented: qShlibInfoAddr")
        raise NotImplementedError('getSharedLibInfoAddress is not Implemented')

    def getSignalInfo(self):
        # return the signal info in required format.
        return "T02" + "threads:" + self.getThreadsInfo() + ';'

    def getThreadsInfo(self):
        """ returns ',' separeted values of thread ids """
        retval = ''
        first = True
        for tid in self.threads_ids_list:
            if first is True:
                first = False
                retval += self.encodeThreadID(tid)
            else:
                retval += ',%s' % self.encodeThreadID(tid)
        return retval

    def getCurrentThreadID(self):
        """ returns int thread id of the first stopped thread
            if subclass supports thread switching etc then
            make sure to re-implement this funciton
        """
        if self.threads_ids_list:
            return self.threads_ids_list[0]
        return 0

    def getThreadStopInfo(self, th_id):
        """ returns stop signal and some thread register info.
        """
        logging.critical("getThreadStopInfo: Not Implemented. returning basic info.")

        return 'T02thread:%s' % self.encodeThreadID(th_id)

    def encodeRegisterData(self, intdata, bytesize=None):
        """ return an encoded string for unsigned int intdata
            based on the bytesize and endianness value
        """
        if not bytesize:
            bytesize = self.ptrsize

        format = '<I'
        if bytesize > 4:
            format = '<Q'
        packed_data = struct.pack(format, intdata)
        return packed_data.encode('hex')

    def encodePointerRegisterData(self, ptrdata):
        """ encodes pointer data based on ptrsize defined for the target """
        return self.encodeRegisterData(ptrdata, bytesize=self.ptrsize)

    def encodeThreadID(self, intdata):
        format = '>Q'
        return struct.pack(format, intdata).encode('hex')

    def encodeByteString(self, bytestr):
        return bytestr.encode('hex')
