#!/usr/bin/env python
import sys
import struct
import mmap
import json
import cgitb
import copy
import re
import base64
import argparse
import os
import shlex
import subprocess
import logging
import contextlib
import base64
import zlib

class Globals(object):
    pass
G = Globals()
G.accept_incomplete_data = False
G.data_was_incomplete = False

kcdata_type_def = {
    'KCDATA_TYPE_INVALID':              0x0,
    'KCDATA_TYPE_STRING_DESC':          0x1,
    'KCDATA_TYPE_UINT32_DESC':          0x2,
    'KCDATA_TYPE_UINT64_DESC':          0x3,
    'KCDATA_TYPE_INT32_DESC':           0x4,
    'KCDATA_TYPE_INT64_DESC':           0x5,
    'KCDATA_TYPE_BINDATA_DESC':         0x6,
    'KCDATA_TYPE_ARRAY':                0x11,
    'KCDATA_TYPE_TYPEDEFINITION':       0x12,
    'KCDATA_TYPE_CONTAINER_BEGIN':      0x13,
    'KCDATA_TYPE_CONTAINER_END':        0x14,

    'KCDATA_TYPE_ARRAY_PAD0':           0x20,
    'KCDATA_TYPE_ARRAY_PAD1':           0x21,
    'KCDATA_TYPE_ARRAY_PAD2':           0x22,
    'KCDATA_TYPE_ARRAY_PAD3':           0x23,
    'KCDATA_TYPE_ARRAY_PAD4':           0x24,
    'KCDATA_TYPE_ARRAY_PAD5':           0x25,
    'KCDATA_TYPE_ARRAY_PAD6':           0x26,
    'KCDATA_TYPE_ARRAY_PAD7':           0x27,
    'KCDATA_TYPE_ARRAY_PAD8':           0x28,
    'KCDATA_TYPE_ARRAY_PAD9':           0x29,
    'KCDATA_TYPE_ARRAY_PADa':           0x2a,
    'KCDATA_TYPE_ARRAY_PADb':           0x2b,
    'KCDATA_TYPE_ARRAY_PADc':           0x2c,
    'KCDATA_TYPE_ARRAY_PADd':           0x2d,
    'KCDATA_TYPE_ARRAY_PADe':           0x2e,
    'KCDATA_TYPE_ARRAY_PADf':           0x2f,

    'KCDATA_TYPE_LIBRARY_LOADINFO':     0x30,
    'KCDATA_TYPE_LIBRARY_LOADINFO64':   0x31,
    'KCDATA_TYPE_TIMEBASE':             0x32,
    'KCDATA_TYPE_MACH_ABSOLUTE_TIME':   0x33,
    'KCDATA_TYPE_TIMEVAL':              0x34,
    'KCDATA_TYPE_USECS_SINCE_EPOCH':    0x35,
    'KCDATA_TYPE_PID':                  0x36,
    'KCDATA_TYPE_PROCNAME':             0x37,
    'KCDATA_TYPE_NESTED_KCDATA':        0x38,

    'STACKSHOT_KCCONTAINER_TASK':       0x903,
    'STACKSHOT_KCCONTAINER_THREAD':     0x904,
    'STACKSHOT_KCTYPE_DONATING_PIDS':   0x907,
    'STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO': 0x908,
    'STACKSHOT_KCTYPE_THREAD_NAME':     0x909,
    'STACKSHOT_KCTYPE_KERN_STACKFRAME': 0x90A,
    'STACKSHOT_KCTYPE_KERN_STACKFRAME64': 0x90B,
    'STACKSHOT_KCTYPE_USER_STACKFRAME': 0x90C,
    'STACKSHOT_KCTYPE_USER_STACKFRAME64': 0x90D,
    'STACKSHOT_KCTYPE_BOOTARGS':        0x90E,
    'STACKSHOT_KCTYPE_OSVERSION':       0x90F,
    'STACKSHOT_KCTYPE_KERN_PAGE_SIZE':  0x910,
    'STACKSHOT_KCTYPE_JETSAM_LEVEL':    0x911,
    'STACKSHOT_KCTYPE_DELTA_SINCE_TIMESTAMP': 0x912,
    'STACKSHOT_KCTYPE_KERN_STACKLR':  0x913,
    'STACKSHOT_KCTYPE_KERN_STACKLR64':  0x914,
    'STACKSHOT_KCTYPE_USER_STACKLR':  0x915,
    'STACKSHOT_KCTYPE_USER_STACKLR64':  0x916,
    'STACKSHOT_KCTYPE_NONRUNNABLE_TIDS':  0x917,
    'STACKSHOT_KCTYPE_NONRUNNABLE_TASKS':  0x918,
    'STACKSHOT_KCTYPE_CPU_TIMES': 0x919,
    'STACKSHOT_KCTYPE_STACKSHOT_DURATION': 0x91a,
    'STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS': 0x91b,
    'STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO': 0x91c,
    'STACKSHOT_KCTYPE_THREAD_WAITINFO' : 0x91d,
    'STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT' : 0x91e,
    'STACKSHOT_KCTYPE_THREAD_GROUP' : 0x91f,
    'STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT' : 0x920,
    'STACKSHOT_KCTYPE_JETSAM_COALITION' : 0x921,
    'STACKSHOT_KCTYPE_THREAD_POLICY_VERSION': 0x922,
    'STACKSHOT_KCTYPE_INSTRS_CYCLES' : 0x923,
    'STACKSHOT_KCTYPE_USER_STACKTOP' : 0x924,
    'STACKSHOT_KCTYPE_ASID' : 0x925,
    'STACKSHOT_KCTYPE_PAGE_TABLES' : 0x926,
    'STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT' : 0x927,
    'STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL' : 0x928,
    'STACKSHOT_KCTYPE_THREAD_TURNSTILEINFO' : 0x929,
    'STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE' : 0x92a,
    'STACKSHOT_KCTYPE_LATENCY_INFO' : 0x92b,
    'STACKSHOT_KCTYPE_LATENCY_INFO_TASK' : 0x92c,
    'STACKSHOT_KCTYPE_LATENCY_INFO_THREAD' : 0x92d,
    'STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC' : 0x92e,

    'STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT': 0x940,
    'STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT': 0x941,



    'KCDATA_TYPE_BUFFER_END':      0xF19158ED,


    'TASK_CRASHINFO_EXTMODINFO':           0x801,
    'TASK_CRASHINFO_BSDINFOWITHUNIQID':    0x802,
    'TASK_CRASHINFO_TASKDYLD_INFO':        0x803,
    'TASK_CRASHINFO_UUID':                 0x804,
    'TASK_CRASHINFO_PID':                  0x805,
    'TASK_CRASHINFO_PPID':                 0x806,

    # Don't want anyone using this.  It's struct rusage from whatever machine generated the data
    #'TASK_CRASHINFO_RUSAGE':               0x807,
    'Type_0x807':               0x807,

    'TASK_CRASHINFO_RUSAGE_INFO':          0x808,
    'TASK_CRASHINFO_PROC_NAME':            0x809,
    'TASK_CRASHINFO_PROC_STARTTIME':       0x80B,
    'TASK_CRASHINFO_USERSTACK':            0x80C,
    'TASK_CRASHINFO_ARGSLEN':              0x80D,
    'TASK_CRASHINFO_EXCEPTION_CODES':      0x80E,
    'TASK_CRASHINFO_PROC_PATH':            0x80F,
    'TASK_CRASHINFO_PROC_CSFLAGS':         0x810,
    'TASK_CRASHINFO_PROC_STATUS':          0x811,
    'TASK_CRASHINFO_UID':                  0x812,
    'TASK_CRASHINFO_GID':                  0x813,
    'TASK_CRASHINFO_PROC_ARGC':            0x814,
    'TASK_CRASHINFO_PROC_FLAGS':           0x815,
    'TASK_CRASHINFO_CPUTYPE':              0x816,
    'TASK_CRASHINFO_WORKQUEUEINFO':        0x817,
    'TASK_CRASHINFO_RESPONSIBLE_PID':      0x818,
    'TASK_CRASHINFO_DIRTY_FLAGS':          0x819,
    'TASK_CRASHINFO_CRASHED_THREADID':     0x81A,
    'TASK_CRASHINFO_COALITION_ID':         0x81B,
    'EXIT_REASON_SNAPSHOT':                0x1001,
    'EXIT_REASON_USER_DESC':               0x1002,
    'EXIT_REASON_USER_PAYLOAD':            0x1003,
    'EXIT_REASON_CODESIGNING_INFO':        0x1004,
    'EXIT_REASON_WORKLOOP_ID':             0x1005,
    'EXIT_REASON_DISPATCH_QUEUE_NO':       0x1006,
    'KCDATA_BUFFER_BEGIN_CRASHINFO':       0xDEADF157,
    'KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT': 0xDE17A59A,
    'KCDATA_BUFFER_BEGIN_STACKSHOT':       0x59a25807,
    'KCDATA_BUFFER_BEGIN_COMPRESSED':      0x434f4d50,
    'KCDATA_BUFFER_BEGIN_OS_REASON':       0x53A20900,
    'KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG':  0x1E21C09F
}
kcdata_type_def_rev = dict((v, k) for k, v in kcdata_type_def.iteritems())

KNOWN_TYPES_COLLECTION = {}

KNOWN_TOPLEVEL_CONTAINER_TYPES = ()

def enum(**args):
    return type('enum', (), args)

KCSUBTYPE_TYPE = enum(KC_ST_CHAR=1, KC_ST_INT8=2, KC_ST_UINT8=3, KC_ST_INT16=4, KC_ST_UINT16=5, KC_ST_INT32=6, KC_ST_UINT32=7, KC_ST_INT64=8, KC_ST_UINT64=9)


LEGAL_OLD_STYLE_ARRAY_TYPE_NAMES = ['KCDATA_TYPE_LIBRARY_LOADINFO',
                                    'KCDATA_TYPE_LIBRARY_LOADINFO64',
                                    'STACKSHOT_KCTYPE_KERN_STACKFRAME',
                                    'STACKSHOT_KCTYPE_USER_STACKFRAME',
                                    'STACKSHOT_KCTYPE_KERN_STACKFRAME64',
                                    'STACKSHOT_KCTYPE_USER_STACKFRAME64',
                                    'STACKSHOT_KCTYPE_DONATING_PIDS',
                                    'STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT']

KCDATA_FLAGS_STRUCT_PADDING_MASK = 0xf
KCDATA_FLAGS_STRUCT_HAS_PADDING = 0x80

class KCSubTypeElement(object):
    """convert kcdata_subtype_descriptor to """
    _unpack_formats = (None, 'c', 'b', 'B', 'h', 'H', 'i', 'I', 'q', 'Q')
    _ctypes = ('Unknown', 'char', 'int8_t', 'uint8_t', 'int16_t', 'uint16_t', 'int32_t', 'uint32_t', 'int64_t', 'uint64_t')

    def __init__(self, st_name, st_type, st_size, st_offset=0, st_flag=0, custom_repr=None):
        self.name = st_name
        self.offset = st_offset
        self.type_id = st_type
        if st_type <= 0 or st_type > KCSUBTYPE_TYPE.KC_ST_UINT64:
            raise ValueError("Invalid type passed %d" % st_type)
        self.unpack_fmt = KCSubTypeElement._unpack_formats[self.type_id]
        self.size = st_size
        self.totalsize = st_size
        self.count = 1
        self.is_array_type = False
        self.custom_JsonRepr = custom_repr
        if (st_flag & 0x1) == 0x1:
            self.is_array_type = True
            self.size = st_size & 0xffff
            self.count = (st_size >> 16) & 0xffff
            self.totalsize = self.size * self.count

    @staticmethod
    def GetSizeForArray(el_count, el_size):
        return ((el_count & 0xffff) << 16) | (el_size & 0xffff)

    @staticmethod
    def FromBinaryTypeData(byte_data):
        (st_flag, st_type, st_offset, st_size, st_name) = struct.unpack_from('=BBHI32s', byte_data)
        st_name = st_name.rstrip('\x00')
        return KCSubTypeElement(st_name, st_type, st_size, st_offset, st_flag)

    @staticmethod
    def FromBasicCtype(st_name, st_type, st_offset=0, legacy_size=None):
        if st_type <= 0 or st_type > KCSUBTYPE_TYPE.KC_ST_UINT64:
            raise ValueError("Invalid type passed %d" % st_type)
        st_size = struct.calcsize(KCSubTypeElement._unpack_formats[st_type])
        st_flag = 0
        retval = KCSubTypeElement(st_name, st_type, st_size, st_offset, st_flag, KCSubTypeElement._get_naked_element_value)
        if legacy_size:
            retval.legacy_size = legacy_size
        return retval

    @staticmethod
    def FromKCSubTypeElement(other, name_override=''):
        _copy = copy.copy(other)
        if name_override:
            _copy.name = name_override
        return copy

    def GetName(self):
        return self.name

    def GetTotalSize(self):
        return self.totalsize

    def GetValueAsString(self, base_data, array_pos=0):
        return str(self.GetValue(base_data, array_pos))

    def GetValue(self, base_data, array_pos=0):
        return struct.unpack_from(self.unpack_fmt, base_data[self.offset + (array_pos * self.size):])[0]

    @staticmethod
    def _get_naked_element_value(elementValue, elementName):
        return json.dumps(elementValue)

    def __str__(self):
        if self.is_array_type:
            return '[%d,%d] %s  %s[%d];' % (self.offset, self.totalsize, self.GetCTypeDesc(), self.name, self.count)
        return '[%d,%d] %s  %s;' % (self.offset, self.totalsize, self.GetCTypeDesc(), self.name)

    def __repr__(self):
        return str(self)

    def GetCTypeDesc(self):
        return KCSubTypeElement._ctypes[self.type_id]

    def GetStringRepr(self, base_data):
        if not self.is_array_type:
            return self.GetValueAsString(base_data)
        if self.type_id == KCSUBTYPE_TYPE.KC_ST_CHAR:
            str_len = self.count
            if len(base_data) < str_len:
                str_len = len(base_data)
            str_arr = []
            for i in range(str_len):
                _v = self.GetValue(base_data, i)
                if ord(_v) == 0:
                    break
                str_arr.append(self.GetValueAsString(base_data, i))
            return json.dumps(''.join(str_arr))

        count = self.count
        if count > len(base_data)/self.size:
            count = len(base_data)/self.size

        o = '[' + ','.join([self.GetValueAsString(base_data, i) for i in range(count)]) + ']'

        return o

    def GetJsonRepr(self, base_data, flags=0):
        if (flags & (KCDATA_FLAGS_STRUCT_HAS_PADDING | KCDATA_FLAGS_STRUCT_PADDING_MASK)) != 0:
            padding = (flags & KCDATA_FLAGS_STRUCT_PADDING_MASK)
            if padding:
                base_data = base_data[:-padding]
        if self.custom_JsonRepr:
            if self.is_array_type:
                e_data = [self.GetValue(base_data, i) for i in range(self.count)]
            else:
                e_data = self.GetValue(base_data)
            return self.custom_JsonRepr(e_data, self.name)
        return self.GetStringRepr(base_data)

    def sizeof(self):
        return self.totalsize

    def ShouldSkip(self, data):
        return len(data) < self.offset + self.totalsize

    def ShouldMerge(self):
        return False


class KCTypeDescription(object):
    def __init__(self, t_type_id, t_elements=[], t_name='anon', custom_repr=None, legacy_size=None, merge=False, naked=False):
        self.type_id = t_type_id
        self.elements = t_elements
        self.name = t_name
        self.totalsize = 0
        self.custom_JsonRepr = custom_repr
        if legacy_size:
            self.legacy_size = legacy_size
        self.merge = merge
        self.naked = naked
        for e in self.elements:
            self.totalsize += e.GetTotalSize()

    def ValidateData(self, base_data):
        if len(base_data) >= self.totalsize:
            return True
        return False

    def GetTypeID(self):
        return self.type_id

    def GetName(self):
        return self.name

    def __str__(self):
        o = '%s {\n\t' % self.name + "\n\t".join([str(e) for e in self.elements]) + '\n};'
        return o

    @staticmethod
    def FromKCTypeDescription(other, t_type_id, t_name):
        retval = KCTypeDescription(t_type_id, other.elements, t_name, other.custom_JsonRepr,
                                   legacy_size=getattr(other, 'legacy_size', None))
        return retval

    def ShouldMerge(self):
        return self.merge

    def GetJsonRepr(self, base_data, flags):
        if (flags & (KCDATA_FLAGS_STRUCT_HAS_PADDING | KCDATA_FLAGS_STRUCT_PADDING_MASK)) != 0:
            padding = (flags & KCDATA_FLAGS_STRUCT_PADDING_MASK)
            if padding:
                base_data = base_data[:-padding]
        elif hasattr(self, 'legacy_size') and len(base_data) == self.legacy_size + ((-self.legacy_size) & 0xf):
            base_data = base_data[:self.legacy_size]
        if self.custom_JsonRepr:
            return self.custom_JsonRepr([e.GetValue(base_data) for e in self.elements])
        if self.naked:
            o = ", ".join([e.GetJsonRepr(base_data) for e in self.elements if not e.ShouldSkip(base_data)])
        else:
            o = ", ".join(['"%s": %s' % (e.GetName(), e.GetJsonRepr(base_data)) for e in self.elements if not e.ShouldSkip(base_data)])
        if not self.merge:
            o = '{' + o + '}'
        return o

    def sizeof(self):
        return max(st.totalsize + st.offset for st in self.elements)


def GetTypeNameForKey(k):
    retval = "0x%x" % k
    if k in KNOWN_TYPES_COLLECTION:
        retval = KNOWN_TYPES_COLLECTION[k].GetName()
    elif k in kcdata_type_def_rev:
        retval = kcdata_type_def_rev[k]
    return retval


def GetTypeForName(n):
    ret = 0
    if n in kcdata_type_def:
        ret = kcdata_type_def[n]
    return ret


LEGAL_OLD_STYLE_ARRAY_TYPES = map(GetTypeForName, LEGAL_OLD_STYLE_ARRAY_TYPE_NAMES)

kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_STACKSHOT')] = 'kcdata_stackshot'
kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT')] = 'kcdata_delta_stackshot'
kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_CRASHINFO')] = 'kcdata_crashinfo'
kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_OS_REASON')] = 'kcdata_reason'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_TASK')] = 'task_snapshots'
kcdata_type_def_rev[GetTypeForName('STACKSHOT_KCCONTAINER_THREAD')] = 'thread_snapshots'
kcdata_type_def_rev[GetTypeForName('KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG')] = 'xnupost_testconfig'

class Indent(object):
    def __init__(self):
        self.n = 0
    def __call__(self, end=False):
        if end:
            return " " * (self.n-4)
        else:
            return " " * self.n
    @contextlib.contextmanager
    def indent(self):
        self.n += 4
        try:
            yield
        finally:
            self.n -= 4

INDENT = Indent()

class KCObject(object):

    def __init__(self, type_code, data, offset, flags=0):

        self.i_type = type_code
        self.i_data = data
        self.offset = offset
        self.i_size = len(data)
        self.i_flags = flags
        self.obj_collection = []
        self.obj = {}
        self.is_container_type = False
        self.is_array_type = False
        self.is_naked_type = False
        self.nested_kcdata = None
        self.i_name = GetTypeNameForKey(type_code)

        self.ParseData()

        if self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_BEGIN'):
            self.__class__ = KCContainerObject
        elif self.i_type == GetTypeForName('KCDATA_BUFFER_BEGIN_COMPRESSED'):
            self.__class__ = KCCompressedBufferObject
        elif self.i_type in KNOWN_TOPLEVEL_CONTAINER_TYPES:
            self.__class__ = KCBufferObject

        self.InitAfterParse()

    def __str__(self):
        return "<KCObject at 0x%x>" % self.offset

    def InitAfterParse(self):
        pass

    @staticmethod
    def FromKCItem(kcitem):
        return KCObject(kcitem.i_type, kcitem.i_data, kcitem.i_offset, kcitem.i_flags)

    def IsContainerEnd(self):
        return self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_END')

    def IsBufferEnd(self):
        return self.i_type == GetTypeForName('KCDATA_TYPE_BUFFER_END')

    def IsArray(self):
        return self.is_array_type

    def ShouldMerge(self):
        if self.nested_kcdata:
            return True
        elif not self.is_array_type and self.i_type in KNOWN_TYPES_COLLECTION:
            return KNOWN_TYPES_COLLECTION[self.i_type].ShouldMerge()
        else:
            return False

    def GetJsonRepr(self):
        if self.is_array_type:
            return '[' + ', '.join([i.GetJsonRepr() for i in self.obj_collection]) + ']'
        if self.i_type in KNOWN_TYPES_COLLECTION:
            return KNOWN_TYPES_COLLECTION[self.i_type].GetJsonRepr(self.i_data, self.i_flags)
        if self.is_naked_type:
            return json.dumps(self.obj)
        if self.nested_kcdata:
            return self.nested_kcdata.GetJsonRepr()

        raise NotImplementedError("Broken GetJsonRepr implementation")

    def ParseData(self):


        if self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_BEGIN'):
            self.obj['uniqID'] = self.i_flags
            self.i_name = str(self.obj['uniqID'])
            self.obj['typeID'] = struct.unpack_from('I', self.i_data)[0]
            logging.info("0x%08x: %sCONTAINER: %s(%x)" % (self.offset, INDENT(), GetTypeNameForKey(self.obj['typeID']), self.i_flags))

        elif self.i_type in (KNOWN_TOPLEVEL_CONTAINER_TYPES):
            self.obj['uniqID'] = self.i_name
            self.obj['typeID'] = self.i_type
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_END'):
            self.obj['uniqID'] = self.i_flags
            logging.info("0x%08x: %sEND" % (self.offset, INDENT(end=True)))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_BUFFER_END'):
            self.obj = ''
            logging.info("0x%08x: %sEND_BUFFER" % (self.offset, INDENT(end=True)))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_UINT32_DESC'):
            self.is_naked_type = True
            u_d = struct.unpack_from('32sI', self.i_data)
            self.i_name = u_d[0].strip(chr(0))
            self.obj = u_d[1]
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_UINT64_DESC'):
            self.is_naked_type = True
            u_d = struct.unpack_from('32sQ', self.i_data)
            self.i_name = u_d[0].strip(chr(0))
            self.obj = u_d[1]
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_TYPEDEFINITION'):
            self.is_naked_type = True
            u_d = struct.unpack_from('II32s', self.i_data)
            self.obj['name'] = u_d[2].split(chr(0))[0]
            self.i_name = "typedef[%s]" % self.obj['name']
            self.obj['typeID'] = u_d[0]
            self.obj['numOfFields'] = u_d[1]
            element_arr = []
            for i in range(u_d[1]):
                e = KCSubTypeElement.FromBinaryTypeData(self.i_data[40+(i*40):])
                element_arr.append(e)
            type_desc = KCTypeDescription(u_d[0], element_arr, self.obj['name'])
            self.obj['fields'] = [str(e) for e in element_arr]
            KNOWN_TYPES_COLLECTION[type_desc.GetTypeID()] = type_desc
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))

        elif self.i_type == GetTypeForName('KCDATA_TYPE_ARRAY'):
            self.is_array_type = True
            e_t = (self.i_flags >> 32) & 0xffffffff
            if e_t not in LEGAL_OLD_STYLE_ARRAY_TYPES:
                raise Exception, "illegal old-style array type: %s (0x%x)" % (GetTypeNameForKey(e_t), e_t)
            e_c = self.i_flags & 0xffffffff
            e_s = KNOWN_TYPES_COLLECTION[e_t].legacy_size
            if e_s * e_c > self.i_size:
                raise Exception("array too small for its count")
            self.obj['typeID'] = e_t
            self.i_name = GetTypeNameForKey(e_t)
            self.i_type = e_t
            self.obj['numOfElements'] = e_c
            self.obj['sizeOfElement'] = e_s
            logging.info("0x%08x: %sARRAY: %s" % (self.offset, INDENT(), self.i_name))
            #populate the array here by recursive creation of KCObject
            with INDENT.indent():
                for _i in range(e_c):
                    _o = KCObject(e_t, self.i_data[(_i * e_s):(_i * e_s) + e_s], self.offset + _i*e_s)
                    self.obj_collection.append(_o)

        elif self.i_type >= GetTypeForName('KCDATA_TYPE_ARRAY_PAD0') and self.i_type <= GetTypeForName('KCDATA_TYPE_ARRAY_PADf'):
            self.is_array_type = True
            e_t = (self.i_flags >> 32) & 0xffffffff
            e_c = self.i_flags & 0xffffffff
            e_s = (self.i_size - (self.i_type & 0xf)) / e_c if e_c != 0 else None
            self.obj['typeID'] = e_t
            self.i_name = GetTypeNameForKey(e_t)
            self.i_type = e_t
            self.obj['numOfElements'] = e_c
            self.obj['sizeOfElement'] = e_s
            logging.info("0x%08x: %sARRAY: %s" % (self.offset, INDENT(), self.i_name))
            #populate the array here by recursive creation of KCObject
            with INDENT.indent():
                for _i in range(e_c):
                    _o = KCObject(e_t, self.i_data[(_i * e_s):(_i * e_s) + e_s], self.offset + _i*e_s)
                    self.obj_collection.append(_o)

        elif self.i_type == GetTypeForName('KCDATA_TYPE_NESTED_KCDATA'):
            logging.info("0x%08x: %sNESTED_KCDATA" % (self.offset, INDENT()))
            with INDENT.indent():
                nested_iterator = kcdata_item_iterator(self.i_data[:self.i_size])
                nested_buffer = KCObject.FromKCItem(nested_iterator.next())
                if not isinstance(nested_buffer, KCBufferObject):
                    raise Exception, "nested buffer isn't a KCBufferObject"
                nested_buffer.ReadItems(nested_iterator)
            self.nested_kcdata = nested_buffer

        elif self.i_type in KNOWN_TYPES_COLLECTION:
            self.i_name = KNOWN_TYPES_COLLECTION[self.i_type].GetName()
            self.is_naked_type = True
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))
        else:
            self.is_naked_type = True
            #self.obj = "data of len %d" % len(self.i_data)
            #self.obj = ''.join(["%x" % ki for ki in struct.unpack('%dB' % len(self.i_data), self.i_data)])
            self.obj = map(ord, self.i_data)
            logging.info("0x%08x: %s%s" % (self.offset, INDENT(), self.i_name))


class KCContainerObject(KCObject):
    def __init__(self, *args, **kwargs):
        assert False

    def InitAfterParse(self):
        self.obj_container_dict = {}
        self.obj_nested_objs = {}

    def ShouldMerge(self):
        return True

    def GetJsonRepr(self):
        # o = '"%s"' % self.obj['uniqID'] + ' : { "typeID" : %d ,' % self.obj['typeID']
        o = '"%s"' % self.obj['uniqID'] + ' : { '
        for (k, v) in self.obj_container_dict.items():
            if v.ShouldMerge():
                o += v.GetJsonRepr() + ","
            else:
                o += ' "%s" : ' % k + v.GetJsonRepr() + ","

        for (k, v) in self.obj_nested_objs.items():
            o += '"%s" : {' % k + ",".join([vi.GetJsonRepr() for vi in v.values()]) + "} ,"

        o = o.rstrip(',') + "}"

        return o

    def AddObject(self, kco):
        assert not kco.IsContainerEnd()
        if isinstance(kco, KCContainerObject):
            type_name = GetTypeNameForKey(kco.obj['typeID'])
            if type_name not in self.obj_nested_objs:
                self.obj_nested_objs[type_name] = {}
            self.obj_nested_objs[type_name][kco.i_name] = kco
            return
        if kco.i_name in self.obj_container_dict:
            if kco.IsArray() and self.obj_container_dict[kco.i_name].IsArray():
                self.obj_container_dict[kco.i_name].obj_collection.extend( kco.obj_collection )
        else:
            self.obj_container_dict[kco.i_name] = kco

    def IsEndMarker(self, o):
        if not o.IsContainerEnd():
            return False
        if o.i_flags != self.i_flags:
            raise Exception, "container end marker doesn't match"
        return True

    no_end_message = "could not find container end marker"

    def ReadItems(self, iterator):
        found_end = False
        with INDENT.indent():
            for i in iterator:
                o = KCObject.FromKCItem(i)
                if self.IsEndMarker(o):
                    found_end = True
                    break
                if o.IsBufferEnd():
                    break
                if isinstance(o, KCContainerObject):
                    o.ReadItems(iterator)
                self.AddObject(o)
        if not found_end:
            if G.accept_incomplete_data:
                if not G.data_was_incomplete:
                    print >>sys.stderr, "kcdata.py WARNING: data is incomplete!"
                    G.data_was_incomplete = True
            else:
                raise Exception, self.no_end_message



class KCBufferObject(KCContainerObject):

    def IsEndMarker(self,o):
        if o.IsContainerEnd():
            raise Exception, "container end marker at the toplevel"
        return o.IsBufferEnd()

    no_end_message = "could not find buffer end marker"

class KCCompressedBufferObject(KCContainerObject):

    def ReadItems(self, iterator):
        self.header = dict()
        with INDENT.indent():
            for i in iterator:
                o = KCObject.FromKCItem(i)
                if self.IsEndMarker(o):
                    self.compressed_type = o.i_type
                    self.blob_start = o.offset + 16
                    break
                o.ParseData()
                self.header[o.i_name] = o.obj

    def IsEndMarker(self, o):
        return o.i_type in KNOWN_TOPLEVEL_CONTAINER_TYPES

    def GetCompressedBlob(self, data):
        if self.header['kcd_c_type'] != 1:
            raise NotImplementedError
        blob = data[self.blob_start:self.blob_start+self.header['kcd_c_totalout']]
        if len(blob) != self.header['kcd_c_totalout']:
            raise ValueError
        return blob

    def Decompress(self, data):
        start_marker = struct.pack('<IIII', self.compressed_type, 0, 0, 0)
        end_marker = struct.pack('<IIII', GetTypeForName('KCDATA_TYPE_BUFFER_END'), 0, 0, 0)
        decompressed = zlib.decompress(self.GetCompressedBlob(data))
        if len(decompressed) != self.header['kcd_c_totalin']:
            raise ValueError, "length of decompressed: %d vs expected %d" % (len(decompressed), self.header['kcd_c_totalin'])
        alignbytes = b'\x00' * (-len(decompressed) % 16)
        return start_marker + decompressed + alignbytes + end_marker


class KCData_item:
    """ a basic kcdata_item type object.
    """
    header_size = 16  # (uint32_t + uint32_t + uint64_t)

    def __init__(self, item_type, item_size, item_flags, item_data):
        self.i_type = item_type
        self.i_size = item_size
        self.i_flags = item_flags
        self.i_data = item_data
        self.i_offset = None

    def __init__(self, barray, pos=0):
        """ create an object by parsing data from bytes array
            returns : obj - if data is readable
                      raises ValueError if something is not ok.
        """
        self.i_type = struct.unpack('I', barray[pos:pos+4])[0]     # int.from_bytes(barray[pos:pos+4])
        self.i_size = struct.unpack('I', barray[pos+4:pos+8])[0]   # int.from_bytes(barray[pos+4:pos+8])
        self.i_flags = struct.unpack('Q', barray[pos+8:pos+16])[0]  # int.from_bytes(barray[pos+8:pos+16])
        self.i_data = barray[pos+16: (pos + 16 + self.i_size)]
        self.i_offset = pos

    def __len__(self):
        return self.i_size + KCData_item.header_size

    def GetHeaderDescription(self):
        outs = "type: 0x%x size: 0x%x flags: 0x%x  (%s)" % (self.i_type, self.i_size, self.i_flags, GetTypeNameForKey(self.i_type))
        if not self.i_offset is None:
            outs = "pos: 0x%x" % self.i_offset + outs
        return outs

    def __str__(self):
        return self.GetHeaderDescription()

def kcdata_item_iterator(data):
    file_len = len(data)
    curpos = 0
    while curpos < file_len:
        item = KCData_item(data, curpos)
        yield item
        curpos += len(item)

def _get_data_element(elementValues):
    return json.dumps(elementValues[-1])

KNOWN_TOPLEVEL_CONTAINER_TYPES = map(GetTypeForName, ('KCDATA_BUFFER_BEGIN_COMPRESSED', 'KCDATA_BUFFER_BEGIN_CRASHINFO', 'KCDATA_BUFFER_BEGIN_STACKSHOT', 'KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT', 'KCDATA_BUFFER_BEGIN_OS_REASON','KCDATA_BUFFER_BEGIN_XNUPOST_CONFIG'))

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_UINT32_DESC')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_UINT32_DESC'), (
    KCSubTypeElement('desc', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(32, 1), 0, 1),
    KCSubTypeElement('data', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 32, 0)
),
    'KCDATA_TYPE_UINT32_DESC',
    _get_data_element
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_UINT64_DESC')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_UINT64_DESC'), (
    KCSubTypeElement('desc', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(32, 1), 0, 1),
    KCSubTypeElement('data', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 32, 0)
),
    'KCDATA_TYPE_UINT64_DESC',
    _get_data_element
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_TIMEBASE')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_TIMEBASE'), (
    KCSubTypeElement('numer', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0),
    KCSubTypeElement('denom', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4, 0)
),
    'mach_timebase_info'
)


STACKSHOT_IO_NUM_PRIORITIES = 4
KNOWN_TYPES_COLLECTION[0x901] = KCTypeDescription(0x901, (
    KCSubTypeElement.FromBasicCtype('ss_disk_reads_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('ss_disk_reads_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('ss_disk_writes_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('ss_disk_writes_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement('ss_io_priority_count', KCSUBTYPE_TYPE.KC_ST_UINT64, KCSubTypeElement.GetSizeForArray(STACKSHOT_IO_NUM_PRIORITIES, 8), 32, 1),
    KCSubTypeElement('ss_io_priority_size', KCSUBTYPE_TYPE.KC_ST_UINT64, KCSubTypeElement.GetSizeForArray(STACKSHOT_IO_NUM_PRIORITIES, 8), 32 + (STACKSHOT_IO_NUM_PRIORITIES * 8), 1),
    KCSubTypeElement.FromBasicCtype('ss_paging_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 32 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_paging_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 40 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_non_paging_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 48 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_non_paging_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 56 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_data_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 64 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_data_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 72 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_metadata_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 80 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('ss_metadata_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 88 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8))
),
    'io_statistics'
)

KNOWN_TYPES_COLLECTION[0x902] = KCTypeDescription(0x902, (
    KCSubTypeElement('snapshot_magic', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 0, 0),
    KCSubTypeElement('free_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 1, 0),
    KCSubTypeElement('active_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 2, 0),
    KCSubTypeElement('inactive_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 3, 0),
    KCSubTypeElement('purgeable_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 4, 0),
    KCSubTypeElement('wired_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 5, 0),
    KCSubTypeElement('speculative_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 6, 0),
    KCSubTypeElement('throttled_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 7, 0),
    KCSubTypeElement('filebacked_pages', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 8, 0),
    KCSubTypeElement('compressions', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 9, 0),
    KCSubTypeElement('decompressions', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 10, 0),
    KCSubTypeElement('compressor_size', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 11, 0),
    KCSubTypeElement('busy_buffer_count', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 4 * 12, 0),
    KCSubTypeElement('pages_wanted', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 13, 0),
    KCSubTypeElement('pages_reclaimed', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 4 * 14, 0),
    KCSubTypeElement('pages_wanted_reclaimed_valid', KCSUBTYPE_TYPE.KC_ST_UINT8, 1, 4 * 15, 0)
),
    'mem_and_io_snapshot'
)


KNOWN_TYPES_COLLECTION[0x905] = KCTypeDescription(0x905, (
    KCSubTypeElement.FromBasicCtype('ts_unique_pid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('ts_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('ts_user_time_in_terminated_thre', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('ts_system_time_in_terminated_th', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('ts_p_start_sec', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    KCSubTypeElement.FromBasicCtype('ts_task_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
    KCSubTypeElement.FromBasicCtype('ts_max_resident_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
    KCSubTypeElement.FromBasicCtype('ts_suspend_count', KCSUBTYPE_TYPE.KC_ST_UINT32, 56),
    KCSubTypeElement.FromBasicCtype('ts_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 60),
    KCSubTypeElement.FromBasicCtype('ts_pageins', KCSUBTYPE_TYPE.KC_ST_UINT32, 64),
    KCSubTypeElement.FromBasicCtype('ts_cow_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 68),
    KCSubTypeElement.FromBasicCtype('ts_was_throttled', KCSUBTYPE_TYPE.KC_ST_UINT32, 72),
    KCSubTypeElement.FromBasicCtype('ts_did_throttle', KCSUBTYPE_TYPE.KC_ST_UINT32, 76),
    KCSubTypeElement.FromBasicCtype('ts_latency_qos', KCSUBTYPE_TYPE.KC_ST_UINT32, 80),
    KCSubTypeElement.FromBasicCtype('ts_pid', KCSUBTYPE_TYPE.KC_ST_INT32, 84),
    KCSubTypeElement('ts_p_comm', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(32, 1), 88, 1)
),
    'task_snapshot'
)

KNOWN_TYPES_COLLECTION[0x906] = KCTypeDescription(0x906, (
    KCSubTypeElement.FromBasicCtype('ths_thread_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('ths_wait_event', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('ths_continuation', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('ths_total_syscalls', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('ths_voucher_identifier', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    KCSubTypeElement.FromBasicCtype('ths_dqserialnum', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
    KCSubTypeElement.FromBasicCtype('ths_user_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
    KCSubTypeElement.FromBasicCtype('ths_sys_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
    KCSubTypeElement.FromBasicCtype('ths_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
    KCSubTypeElement.FromBasicCtype('ths_last_run_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 72),
    KCSubTypeElement.FromBasicCtype('ths_last_made_runnable_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 80),
    KCSubTypeElement.FromBasicCtype('ths_state', KCSUBTYPE_TYPE.KC_ST_UINT32, 88),
    KCSubTypeElement.FromBasicCtype('ths_sched_flags', KCSUBTYPE_TYPE.KC_ST_UINT32, 92),
    KCSubTypeElement.FromBasicCtype('ths_base_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 96),
    KCSubTypeElement.FromBasicCtype('ths_sched_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 98),
    KCSubTypeElement.FromBasicCtype('ths_eqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 100),
    KCSubTypeElement.FromBasicCtype('ths_rqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 101),
    KCSubTypeElement.FromBasicCtype('ths_rqos_override', KCSUBTYPE_TYPE.KC_ST_UINT8, 102),
    KCSubTypeElement.FromBasicCtype('ths_io_tier', KCSUBTYPE_TYPE.KC_ST_UINT8, 103),
    KCSubTypeElement.FromBasicCtype('ths_thread_t', KCSUBTYPE_TYPE.KC_ST_UINT64, 104),
    KCSubTypeElement.FromBasicCtype('ths_requested_policy', KCSUBTYPE_TYPE.KC_ST_UINT64, 112),
    KCSubTypeElement.FromBasicCtype('ths_effective_policy', KCSUBTYPE_TYPE.KC_ST_UINT64, 120),
),
    'thread_snapshot',
    legacy_size = 0x68
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL')] = KCSubTypeElement('dispatch_queue_label', KCSUBTYPE_TYPE.KC_ST_CHAR,
                          KCSubTypeElement.GetSizeForArray(64, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT'), (
    KCSubTypeElement.FromBasicCtype('tds_thread_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('tds_voucher_identifier', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('tds_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('tds_last_made_runnable_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('tds_state', KCSUBTYPE_TYPE.KC_ST_UINT32, 32),
    KCSubTypeElement.FromBasicCtype('tds_sched_flags', KCSUBTYPE_TYPE.KC_ST_UINT32, 36),
    KCSubTypeElement.FromBasicCtype('tds_base_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 40),
    KCSubTypeElement.FromBasicCtype('tds_sched_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 42),
    KCSubTypeElement.FromBasicCtype('tds_eqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 44),
    KCSubTypeElement.FromBasicCtype('tds_rqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 45),
    KCSubTypeElement.FromBasicCtype('tds_rqos_override', KCSUBTYPE_TYPE.KC_ST_UINT8, 46),
    KCSubTypeElement.FromBasicCtype('tds_io_tier', KCSUBTYPE_TYPE.KC_ST_UINT8, 47),
    KCSubTypeElement.FromBasicCtype('tds_requested_policy', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
    KCSubTypeElement.FromBasicCtype('tds_effective_policy', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
),
    'thread_delta_snapshot',
    legacy_size = 48
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT'), (
    KCSubTypeElement.FromBasicCtype('tds_unique_pid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('tds_ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('tds_user_time_in_terminated_thr', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('tds_system_time_in_terminated_t', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('tds_task_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    KCSubTypeElement.FromBasicCtype('tds_max_resident_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
    KCSubTypeElement.FromBasicCtype('tds_suspend_count', KCSUBTYPE_TYPE.KC_ST_UINT32, 48),
    KCSubTypeElement.FromBasicCtype('tds_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 52),
    KCSubTypeElement.FromBasicCtype('tds_pageins', KCSUBTYPE_TYPE.KC_ST_UINT32, 56),
    KCSubTypeElement.FromBasicCtype('tds_cow_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 60),
    KCSubTypeElement.FromBasicCtype('tds_was_throttled', KCSUBTYPE_TYPE.KC_ST_UINT32, 64),
    KCSubTypeElement.FromBasicCtype('tds_did_throttle', KCSUBTYPE_TYPE.KC_ST_UINT32, 68),
    KCSubTypeElement.FromBasicCtype('tds_latency_qos', KCSUBTYPE_TYPE.KC_ST_UINT32, 72),
),
    'task_delta_snapshot'
)


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_NAME')] = KCSubTypeElement('pth_name', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(64, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1)
),
    'system_shared_cache_layout'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO64')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO64'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1)
),
    'dyld_load_info',
    legacy_size = 24
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 4, 1)
),
    'dyld_load_info',
    legacy_size = 20
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1),
),
    'dyld_load_info_text_exec'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1),
    KCSubTypeElement('imageSlidBaseAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 24, 0),
),
    'shared_cache_dyld_load_info',
    legacy_size = 0x18
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO'), (
    KCSubTypeElement('imageLoadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1),
),
    'kernelcache_load_info'
)

KNOWN_TYPES_COLLECTION[0x33] = KCSubTypeElement('mach_absolute_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)
KNOWN_TYPES_COLLECTION[0x907] = KCSubTypeElement.FromBasicCtype('donating_pids', KCSUBTYPE_TYPE.KC_ST_INT32, legacy_size=4)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_USECS_SINCE_EPOCH')] = KCSubTypeElement('usecs_since_epoch', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT32),
    KCSubTypeElement.FromBasicCtype('sp', KCSUBTYPE_TYPE.KC_ST_UINT32, 4)
),
    'kernel_stack_frames',
    legacy_size = 8
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT32),
),
    'kernel_stack_frames'
)


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME'),
    'user_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKLR')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKLR'),
    'user_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT64),
    KCSubTypeElement.FromBasicCtype('sp', KCSUBTYPE_TYPE.KC_ST_UINT64, 8)
),
    'kernel_stack_frames',
    legacy_size = 16
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME64')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME64'),
    'user_stack_frames'
)


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR64')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR64'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT64),
),
    'kernel_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKLR64')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKLR64')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKLR64'),
    'user_stack_frames'
)


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_NONRUNNABLE_TIDS')] = KCSubTypeElement.FromBasicCtype('nonrunnable_threads', KCSUBTYPE_TYPE.KC_ST_INT64)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_NONRUNNABLE_TASKS')] = KCSubTypeElement.FromBasicCtype('nonrunnable_tasks', KCSUBTYPE_TYPE.KC_ST_INT64)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_OSVERSION')] = KCSubTypeElement('osversion', KCSUBTYPE_TYPE.KC_ST_CHAR,
                          KCSubTypeElement.GetSizeForArray(256, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_BOOTARGS')] = KCSubTypeElement('boot_args', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(256, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_PAGE_SIZE')] = KCSubTypeElement('kernel_page_size', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_POLICY_VERSION')] = KCSubTypeElement('thread_policy_version', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_JETSAM_LEVEL')] = KCSubTypeElement('jetsam_level', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_DELTA_SINCE_TIMESTAMP')] = KCSubTypeElement("stackshot_delta_since_timestamp", KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS'),
            (
                        KCSubTypeElement.FromBasicCtype('sfs_pages_faulted_in', KCSUBTYPE_TYPE.KC_ST_UINT32, 0),
                        KCSubTypeElement.FromBasicCtype('sfs_time_spent_faulting', KCSUBTYPE_TYPE.KC_ST_UINT64, 4),
                        KCSubTypeElement.FromBasicCtype('sfs_system_max_fault_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 12),
                        KCSubTypeElement.FromBasicCtype('sfs_stopped_faulting', KCSUBTYPE_TYPE.KC_ST_UINT8, 20)
            ),
            'stackshot_fault_stats')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_WAITINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_THREAD_WAITINFO'),
            (
                        KCSubTypeElement.FromBasicCtype('owner', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('waiter', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('context', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('wait_type', KCSUBTYPE_TYPE.KC_ST_UINT8, 24)
            ),
            'thread_waitinfo')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_TURNSTILEINFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_THREAD_TURNSTILEINFO'),
            (
                        KCSubTypeElement.FromBasicCtype('waiter', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('turnstile_context', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('turnstile_priority', KCSUBTYPE_TYPE.KC_ST_UINT8, 16),
                        KCSubTypeElement.FromBasicCtype('number_of_hops', KCSUBTYPE_TYPE.KC_ST_UINT8, 17),
                        KCSubTypeElement.FromBasicCtype('turnstile_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 18),
            ),
            'thread_turnstileinfo')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_THREAD_GROUP'),
            (
                        KCSubTypeElement.FromBasicCtype('tgs_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement('tgs_name', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(16, 1),
                            8, 1),
                        KCSubTypeElement.FromBasicCtype('tgs_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
            ),
            'thread_group_snapshot')


KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_THREAD_GROUP')] = KCSubTypeElement('thread_group', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT'),
            (
                        KCSubTypeElement.FromBasicCtype('jcs_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('jcs_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('jcs_thread_group', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('jcs_leader_task_uniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 24)
            ),
            'jetsam_coalition_snapshot')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_JETSAM_COALITION')] = KCSubTypeElement('jetsam_coalition', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_INSTRS_CYCLES')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_INSTRS_CYCLES'),
            (
                        KCSubTypeElement.FromBasicCtype('ics_instructions', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('ics_cycles', KCSUBTYPE_TYPE.KC_ST_UINT64, 8)
            ),
            'instrs_cycles_snapshot')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE'),
            (
                        KCSubTypeElement.FromBasicCtype('cputype', KCSUBTYPE_TYPE.KC_ST_INT32, 0),
                        KCSubTypeElement.FromBasicCtype('cpusubtype', KCSUBTYPE_TYPE.KC_ST_INT32, 4)
            ),
            'task_cpu_architecture')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO'),
            (
                        KCSubTypeElement.FromBasicCtype('latency_version', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('setup_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('total_task_iteration_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('total_terminated_task_iteration_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 24)
            ),
            'stackshot_latency_collection')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_TASK')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_TASK'),
            (
                        KCSubTypeElement.FromBasicCtype('task_uniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('setup_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('task_thread_count_loop_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('task_thread_data_loop_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
                        KCSubTypeElement.FromBasicCtype('cur_tsnap_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
                        KCSubTypeElement.FromBasicCtype('pmap_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
                        KCSubTypeElement.FromBasicCtype('bsd_proc_ids_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
                        KCSubTypeElement.FromBasicCtype('misc_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
                        KCSubTypeElement.FromBasicCtype('misc2_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
                        KCSubTypeElement.FromBasicCtype('end_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 72)
            ),
            'stackshot_latency_task')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_THREAD')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_LATENCY_INFO_THREAD'),
            (
                        KCSubTypeElement.FromBasicCtype('thread_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                        KCSubTypeElement.FromBasicCtype('cur_thsnap1_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
                        KCSubTypeElement.FromBasicCtype('dispatch_serial_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
                        KCSubTypeElement.FromBasicCtype('dispatch_label_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
                        KCSubTypeElement.FromBasicCtype('cur_thsnap2_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
                        KCSubTypeElement.FromBasicCtype('thread_name_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
                        KCSubTypeElement.FromBasicCtype('sur_times_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
                        KCSubTypeElement.FromBasicCtype('user_stack_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
                        KCSubTypeElement.FromBasicCtype('kernel_stack_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
                        KCSubTypeElement.FromBasicCtype('misc_latency', KCSUBTYPE_TYPE.KC_ST_UINT64, 72),
            ),
            'stackshot_latency_thread')

def set_type(name, *args):
    typ = GetTypeForName(name)
    KNOWN_TYPES_COLLECTION[typ] = KCTypeDescription(GetTypeForName(typ), *args)


set_type('STACKSHOT_KCTYPE_USER_STACKTOP',
         (
             KCSubTypeElement.FromBasicCtype('sp', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
             KCSubTypeElement('stack_contents', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(8, 1), 8, 1),
         ),
         'user_stacktop')

#KNOWN_TYPES_COLLECTION[0x907] = KCSubTypeElement('donating_pids', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PID')] = KCSubTypeElement('pid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PPID')] = KCSubTypeElement('ppid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_NAME')] = KCSubTypeElement('p_comm', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(32, 1), 0, 1)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_USERSTACK')] = KCSubTypeElement('userstack_ptr', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_ARGSLEN')] = KCSubTypeElement('p_argslen', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_PATH')] = KCSubTypeElement('p_path', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(1024, 1), 0, 1)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_CSFLAGS')] = KCSubTypeElement('p_csflags', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_UID')] = KCSubTypeElement('uid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_GID')] = KCSubTypeElement('gid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_ARGC')] = KCSubTypeElement('argc', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_FLAGS')] = KCSubTypeElement('p_flags', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CPUTYPE')] = KCSubTypeElement('cputype', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_RESPONSIBLE_PID')] = KCSubTypeElement('responsible_pid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_DIRTY_FLAGS')] = KCSubTypeElement('dirty_flags', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_CRASHED_THREADID')] = KCSubTypeElement('crashed_threadid', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0)
KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_COALITION_ID')] = KCSubTypeElement('coalition_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_STATUS')] = KCSubTypeElement('p_status', KCSUBTYPE_TYPE.KC_ST_UINT8, 1, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_BSDINFOWITHUNIQID')] = KCTypeDescription(GetTypeForName('TASK_CRASHINFO_BSDINFOWITHUNIQID'),
    (   KCSubTypeElement('p_uuid', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 0, 1),
        KCSubTypeElement.FromBasicCtype('p_uniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
        KCSubTypeElement.FromBasicCtype('p_puniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 24)
    ),
    'proc_uniqidentifierinfo')

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_EXCEPTION_CODES')] = (
    KCTypeDescription(GetTypeForName('TASK_CRASHINFO_EXCEPTION_CODES'),
                      (KCSubTypeElement.FromBasicCtype('code_0', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                       KCSubTypeElement.FromBasicCtype('code_1', KCSUBTYPE_TYPE.KC_ST_UINT64, 8)),
                      'mach_exception_data_t'))


KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_STARTTIME')] = (
    KCTypeDescription(GetTypeForName('TASK_CRASHINFO_PROC_STARTTIME'),
                      (KCSubTypeElement.FromBasicCtype('tv_sec', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
                       KCSubTypeElement.FromBasicCtype('tv_usec', KCSUBTYPE_TYPE.KC_ST_UINT64, 8)),
                      'proc_starttime'))


KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_RUSAGE_INFO')] = KCTypeDescription(GetTypeForName('TASK_CRASHINFO_RUSAGE_INFO'),
    (
        KCSubTypeElement('ri_uuid', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 0, 1),
            KCSubTypeElement.FromBasicCtype('ri_user_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
            KCSubTypeElement.FromBasicCtype('ri_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
            KCSubTypeElement.FromBasicCtype('ri_pkg_idle_wkups', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
            KCSubTypeElement.FromBasicCtype('ri_interrupt_wkups', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
            KCSubTypeElement.FromBasicCtype('ri_pageins', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
            KCSubTypeElement.FromBasicCtype('ri_wired_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
            KCSubTypeElement.FromBasicCtype('ri_resident_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
            KCSubTypeElement.FromBasicCtype('ri_phys_footprint', KCSUBTYPE_TYPE.KC_ST_UINT64, 72),
            KCSubTypeElement.FromBasicCtype('ri_proc_start_abstime', KCSUBTYPE_TYPE.KC_ST_UINT64, 80),
            KCSubTypeElement.FromBasicCtype('ri_proc_exit_abstime', KCSUBTYPE_TYPE.KC_ST_UINT64, 88),
            KCSubTypeElement.FromBasicCtype('ri_child_user_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 96),
            KCSubTypeElement.FromBasicCtype('ri_child_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 104),
            KCSubTypeElement.FromBasicCtype('ri_child_pkg_idle_wkups', KCSUBTYPE_TYPE.KC_ST_UINT64, 112),
            KCSubTypeElement.FromBasicCtype('ri_child_interrupt_wkups', KCSUBTYPE_TYPE.KC_ST_UINT64, 120),
            KCSubTypeElement.FromBasicCtype('ri_child_pageins', KCSUBTYPE_TYPE.KC_ST_UINT64, 128),
            KCSubTypeElement.FromBasicCtype('ri_child_elapsed_abstime', KCSUBTYPE_TYPE.KC_ST_UINT64, 136),
            KCSubTypeElement.FromBasicCtype('ri_diskio_bytesread', KCSUBTYPE_TYPE.KC_ST_UINT64, 144),
            KCSubTypeElement.FromBasicCtype('ri_diskio_byteswritten', KCSUBTYPE_TYPE.KC_ST_UINT64, 152),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_default', KCSUBTYPE_TYPE.KC_ST_UINT64, 160),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_maintenance', KCSUBTYPE_TYPE.KC_ST_UINT64, 168),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_background', KCSUBTYPE_TYPE.KC_ST_UINT64, 176),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_utility', KCSUBTYPE_TYPE.KC_ST_UINT64, 184),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_legacy', KCSUBTYPE_TYPE.KC_ST_UINT64, 192),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_user_initiated', KCSUBTYPE_TYPE.KC_ST_UINT64, 200),
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_user_interactiv', KCSUBTYPE_TYPE.KC_ST_UINT64, 208),
            KCSubTypeElement.FromBasicCtype('ri_billed_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 216),
            KCSubTypeElement.FromBasicCtype('ri_serviced_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 224)
    ),
    'rusage_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_CPU_TIMES')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_CPU_TIMES'),
    (
        KCSubTypeElement.FromBasicCtype('user_usec', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('system_usec', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
        KCSubTypeElement.FromBasicCtype('runnable_usec', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    ), 'cpu_times')

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_STACKSHOT_DURATION')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_STACKSHOT_DURATION'),
    (
        KCSubTypeElement.FromBasicCtype('stackshot_duration', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('stackshot_duration_outer', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    ), 'stackshot_duration', merge=True
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_PROCNAME')] = (
    KCSubTypeElement("proc_name", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(-1, 1), 0, 1))

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_PID')] = (
    KCSubTypeElement('pid', KCSUBTYPE_TYPE.KC_ST_INT32, 4, 0, 0))

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_SNAPSHOT')] = KCTypeDescription(GetTypeForName('EXIT_REASON_SNAPSHOT'),
    (
        KCSubTypeElement.FromBasicCtype('ers_namespace', KCSUBTYPE_TYPE.KC_ST_UINT32, 0),
        KCSubTypeElement.FromBasicCtype('ers_code', KCSUBTYPE_TYPE.KC_ST_UINT64, 4),
        KCSubTypeElement.FromBasicCtype('ers_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 12),
    ), 'exit_reason_basic_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_USER_DESC')] = (
    KCSubTypeElement("exit_reason_user_description", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(-1, 1), 0, 1))

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_USER_PAYLOAD')] = KCSubTypeElement('exit_reason_user_payload',
        KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(-1, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_CODESIGNING_INFO')] = KCTypeDescription(GetTypeForName('EXIT_REASON_CODESIGNING_INFO'),
    (
        KCSubTypeElement.FromBasicCtype('ceri_virt_addr', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
        KCSubTypeElement.FromBasicCtype('ceri_file_offset', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
        KCSubTypeElement("ceri_pathname", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(1024, 1), 16, 1),
        KCSubTypeElement("ceri_filename", KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(1024, 1), 1040, 1),
        KCSubTypeElement.FromBasicCtype('ceri_codesig_modtime_secs', KCSUBTYPE_TYPE.KC_ST_UINT64, 2064),
        KCSubTypeElement.FromBasicCtype('ceri_codesig_modtime_nsecs', KCSUBTYPE_TYPE.KC_ST_UINT64, 2072),
        KCSubTypeElement.FromBasicCtype('ceri_page_modtime_secs', KCSUBTYPE_TYPE.KC_ST_UINT64, 2080),
        KCSubTypeElement.FromBasicCtype('ceri_page_modtime_nsecs', KCSUBTYPE_TYPE.KC_ST_UINT64, 2088),
        KCSubTypeElement.FromBasicCtype('ceri_path_truncated', KCSUBTYPE_TYPE.KC_ST_UINT8, 2096),
        KCSubTypeElement.FromBasicCtype('ceri_object_codesigned', KCSUBTYPE_TYPE.KC_ST_UINT8, 2097),
        KCSubTypeElement.FromBasicCtype('ceri_page_codesig_validated', KCSUBTYPE_TYPE.KC_ST_UINT8, 2098),
        KCSubTypeElement.FromBasicCtype('ceri_page_codesig_tainted', KCSUBTYPE_TYPE.KC_ST_UINT8, 2099),
        KCSubTypeElement.FromBasicCtype('ceri_page_codesig_nx', KCSUBTYPE_TYPE.KC_ST_UINT8, 2100),
        KCSubTypeElement.FromBasicCtype('ceri_page_wpmapped', KCSUBTYPE_TYPE.KC_ST_UINT8, 2101),
        KCSubTypeElement.FromBasicCtype('ceri_page_slid', KCSUBTYPE_TYPE.KC_ST_UINT8, 2102),
        KCSubTypeElement.FromBasicCtype('ceri_page_dirty', KCSUBTYPE_TYPE.KC_ST_UINT8, 2103),
        KCSubTypeElement.FromBasicCtype('ceri_page_shadow_depth', KCSUBTYPE_TYPE.KC_ST_UINT32, 2104),
    ), 'exit_reason_codesigning_info')

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_WORKLOOP_ID')] = (
        KCSubTypeElement('exit_reason_workloop_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value))

KNOWN_TYPES_COLLECTION[GetTypeForName('EXIT_REASON_DISPATCH_QUEUE_NO')] = (
        KCSubTypeElement('exit_reason_dispatch_queue_no', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value))

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_ASID')] = (
    KCSubTypeElement('ts_asid', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0))

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_PAGE_TABLES')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_PAGE_TABLES'), (
    KCSubTypeElement(None, KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value), ),
    'ts_pagetable',
    merge=True,
    naked=True
)

def GetSecondsFromMATime(mat, tb):
    return (float(long(mat) * tb['numer']) / tb['denom']) / 1e9

def FindLibraryForAddress(liblist, address):
    current_lib = None
    for l in liblist:
        if address >= l[1]:
            current_lib = l
    return current_lib

def FindIndexOfLibInCatalog(catalog, lib):
    index = None
    i = 0
    for l in catalog:
        if l[0] == lib[0] and l[1] == lib[1]:
            index = i
            break
        i += 1

    if index is None:
        catalog.append(lib)
        index = len(catalog) - 1

    return index

def GetOffsetOfAddressForLib(lib, address):
    return (address - lib[1])

def GetSymbolInfoForFrame(catalog, liblist, address):
    lib = FindLibraryForAddress(liblist, address)
    if not lib:
        lib = ["00000000000000000000000000000000",0,"A"]
    offset = GetOffsetOfAddressForLib(lib, address)
    index = FindIndexOfLibInCatalog(catalog, lib)
    return [index, offset]

def GetStateDescription(s):
    retval = []
    TH_WAIT = 0x01
    TH_SUSP = 0x02
    TH_RUN = 0x04
    TH_UNINT = 0x08
    TH_TERMINATE = 0x10
    TH_TERMINATE2 = 0x20
    TH_WAIT_REPORT = 0x40
    TH_IDLE = 0x80
    if (s & TH_WAIT):
        retval.append("TH_WAIT")
    if (s & TH_SUSP):
        retval.append("TH_SUSP")
    if (s & TH_RUN):
        retval.append("TH_RUN")
    if (s & TH_UNINT):
        retval.append("TH_UNINT")
    if (s & TH_TERMINATE):
        retval.append("TH_TERMINATE")
    if (s & TH_TERMINATE2):
        retval.append("TH_TERMINATE2")
    if (s & TH_WAIT_REPORT):
        retval.append("TH_WAIT_REPORT")
    if (s & TH_IDLE):
        retval.append("TH_IDLE")
    return retval


def format_uuid(elementValues):
    return ''.join("%02x" % i for i in elementValues)

kThreadWaitNone			= 0x00
kThreadWaitKernelMutex          = 0x01
kThreadWaitPortReceive          = 0x02
kThreadWaitPortSetReceive       = 0x03
kThreadWaitPortSend             = 0x04
kThreadWaitPortSendInTransit    = 0x05
kThreadWaitSemaphore            = 0x06
kThreadWaitKernelRWLockRead     = 0x07
kThreadWaitKernelRWLockWrite    = 0x08
kThreadWaitKernelRWLockUpgrade  = 0x09
kThreadWaitUserLock             = 0x0a
kThreadWaitPThreadMutex         = 0x0b
kThreadWaitPThreadRWLockRead    = 0x0c
kThreadWaitPThreadRWLockWrite   = 0x0d
kThreadWaitPThreadCondVar       = 0x0e
kThreadWaitParkedWorkQueue      = 0x0f
kThreadWaitWorkloopSyncWait     = 0x10
kThreadWaitOnProcess            = 0x11
kThreadWaitSleepWithInheritor   = 0x12
kThreadWaitEventlink            = 0x13
kThreadWaitCompressor           = 0x14


UINT64_MAX = 0xffffffffffffffff
STACKSHOT_WAITOWNER_KERNEL      = (UINT64_MAX - 1)
STACKSHOT_WAITOWNER_PORT_LOCKED = (UINT64_MAX - 2)
STACKSHOT_WAITOWNER_PSET_LOCKED = (UINT64_MAX - 3)
STACKSHOT_WAITOWNER_INTRANSIT   = (UINT64_MAX - 4)
STACKSHOT_WAITOWNER_MTXSPIN     = (UINT64_MAX - 5)
STACKSHOT_WAITOWNER_THREQUESTED = (UINT64_MAX - 6)
STACKSHOT_WAITOWNER_SUSPENDED   = (UINT64_MAX - 7)

STACKSHOT_TURNSTILE_STATUS_UNKNOWN         = 0x01
STACKSHOT_TURNSTILE_STATUS_LOCKED_WAITQ    = 0x02
STACKSHOT_TURNSTILE_STATUS_WORKQUEUE       = 0x04
STACKSHOT_TURNSTILE_STATUS_THREAD          = 0x08
STACKSHOT_TURNSTILE_STATUS_BLOCKED_ON_TASK = 0x10
STACKSHOT_TURNSTILE_STATUS_HELD_IPLOCK     = 0x20

def formatWaitInfo(info):
    s = 'thread %d: ' % info['waiter'];
    type = info['wait_type']
    context = info['context']
    owner = info['owner']
    if type == kThreadWaitKernelMutex:
        s += 'kernel mutex %x' % context
        if owner == STACKSHOT_WAITOWNER_MTXSPIN:
            s += " in spin mode"
        elif owner:
            s += " owned by thread %u" % owner
        else:
            s += "with unknown owner"
    elif type == kThreadWaitPortReceive:
        s += "mach_msg receive on "
        if owner == STACKSHOT_WAITOWNER_PORT_LOCKED:
            s += "locked port %x" % context
        elif owner == STACKSHOT_WAITOWNER_INTRANSIT:
            s += "intransit port %x" % context
        elif owner:
            s += "port %x name %x" % (context, owner)
        else:
            s += "port %x" % context
    elif type == kThreadWaitPortSetReceive:
        if owner == STACKSHOT_WAITOWNER_PSET_LOCKED:
            s += "mach_msg receive on locked port set %x" % context
        else:
            s += "mach_msg receive on port set %x" % context
    elif type == kThreadWaitPortSend:
        s += "mach_msg send on "
        if owner == STACKSHOT_WAITOWNER_PORT_LOCKED:
            s += "locked port %x" % context
        elif owner == STACKSHOT_WAITOWNER_INTRANSIT:
            s += "intransit port %x" % context
        elif owner == STACKSHOT_WAITOWNER_KERNEL:
            s += "port %x owned by kernel" % context
        elif owner:
            s += "port %x owned by pid %d" % (context, owner)
        else:
            s += "port %x with unknown owner" % context
    elif type == kThreadWaitPortSendInTransit:
        s += "mach_msg send on port %x in transit to " % context
        if owner:
            s += "port %x" % owner
        else:
            s += "unknown port"
    elif type == kThreadWaitSemaphore:
        s += "semaphore port %x " % context
        if owner:
            s += "owned by pid %d" % owner
        else:
            s += "with unknown owner"
    elif type == kThreadWaitKernelRWLockRead:
        s += "krwlock %x for reading" % context
    elif type == kThreadWaitKernelRWLockWrite:
        s += "krwlock %x for writing" % context
    elif type == kThreadWaitKernelRWLockUpgrade:
        s += "krwlock %x for upgrading" % context
    elif type == kThreadWaitUserLock:
        if owner:
            s += "unfair lock %x owned by thread %d" % (context, owner)
        else:
            s += "spin lock %x" % context
    elif type == kThreadWaitPThreadMutex:
        s += "pthread mutex %x" % context
        if owner:
            s += " owned by thread %d" % owner
        else:
            s += " with unknown owner"
    elif type == kThreadWaitPThreadRWLockRead:
        s += "pthread rwlock %x for reading" % context
    elif type == kThreadWaitPThreadRWLockWrite:
        s += "pthread rwlock %x for writing" % context
    elif type == kThreadWaitPThreadCondVar:
        s += "pthread condvar %x" % context
    elif type == kThreadWaitWorkloopSyncWait:
        s += "workloop sync wait"
        if owner == STACKSHOT_WAITOWNER_SUSPENDED:
            s += ", suspended"
        elif owner == STACKSHOT_WAITOWNER_THREQUESTED:
            s += ", thread requested"
        elif owner != 0:
            s += ", owned by thread %u" % owner
        else:
            s += ", unknown owner"
        s += ", workloop id %x" % context
    elif type == kThreadWaitOnProcess:
        if owner == 2**64-1:
            s += "waitpid, for any children"
        elif 2**32 <= owner and owner < 2**64-1:
            s += "waitpid, for process group %d" % abs(owner - 2**64)
        else:
            s += "waitpid, for pid %d" % owner
    elif type == kThreadWaitSleepWithInheritor:
        if owner == 0:
            s += "turnstile, held waitq"
        else:
            s += "turnstile, pushing thread %d" % owner
    elif type == kThreadWaitEventlink:
        if owner == 0:
            s += "eventlink, held waitq"
        else:
            s += "eventlink, signaled by thread %d" % owner
    elif type == kThreadWaitCompressor:
        s += "in compressor segment %x, busy for thread %d" % (context, owner)

    else:
        s += "unknown type %d (owner %d, context %x)" % (type, owner, context)

    return s

def formatTurnstileInfo(ti):
    if ti is None:
        return " [no turnstile]"

    ts_flags = int(ti['turnstile_flags'])
    ctx = int(ti['turnstile_context'])
    hop = int(ti['number_of_hops'])
    prio = int(ti['turnstile_priority'])
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_HELD_IPLOCK:
        return " [turnstile blocked on task, but ip_lock was held]"
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_BLOCKED_ON_TASK:
        return " [turnstile blocked on task pid %d, hops: %d, priority: %d]" % (ctx, hop, prio)
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_LOCKED_WAITQ:
        return " [turnstile was in process of being updated]"
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_WORKQUEUE:
        return " [blocked on workqueue: 0x%x, hops: %x, priority: %d]" % (ctx, hop, prio)
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_THREAD:
        return " [blocked on: %d, hops: %x, priority: %d]" % (ctx, hop, prio)
    if ts_flags & STACKSHOT_TURNSTILE_STATUS_UNKNOWN:
        return " [turnstile with unknown inheritor]"

    return " [unknown turnstile status!]"
        
def formatWaitInfoWithTurnstiles(waitinfos, tsinfos):
    wis_tis = []
    for w in waitinfos:
        found_pair = False
        for t in tsinfos:
            if int(w['waiter']) == int(t['waiter']):
                wis_tis.append((w, t))
                found_pair = True
                break
        if not found_pair:
            wis_tis.append((w, None))

    return map(lambda (wi, ti): formatWaitInfo(wi) + formatTurnstileInfo(ti), wis_tis)

def SaveStackshotReport(j, outfile_name, incomplete):
    import time
    from operator import itemgetter, attrgetter
    ss = j.get('kcdata_stackshot')
    if not ss:
        print "No KCDATA_BUFFER_BEGIN_STACKSHOT object found. Skipping writing report."
        return

    timestamp = ss.get('usecs_since_epoch')
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S +0000",time.gmtime(timestamp / 1000000 if timestamp else None))
    except ValueError, e:
        print "couldn't convert timestamp:", str(e)
        timestamp = None

    os_version = ss.get('osversion', 'Unknown')
    timebase = ss.get('mach_timebase_info', {"denom": 1, "numer": 1})

    dsc_common = None
    shared_cache_info = ss.get('shared_cache_dyld_load_info')
    if shared_cache_info:
        shared_cache_base_addr = shared_cache_info['imageSlidBaseAddress']
        dsc_common = [format_uuid(shared_cache_info['imageUUID']), shared_cache_info['imageSlidBaseAddress'], "S" ]
        print "Shared cache UUID found from the binary data is <%s> " % str(dsc_common[0])

    dsc_layout = ss.get('system_shared_cache_layout')

    dsc_libs = []
    if dsc_layout:
        print "Found in memory system shared cache layout with {} images".format(len(dsc_layout))
        slide = ss.get('shared_cache_dyld_load_info')['imageLoadAddress']

        for image in dsc_layout:
            dsc_libs.append([format_uuid(image['imageUUID']), image['imageLoadAddress'] + slide, "C"])

    AllImageCatalog = []
    obj = {}
    obj["kernel"] = os_version
    if timestamp is not None:
        obj["date"] = timestamp
    obj["reason"] = "kernel panic stackshot"
    obj["incident"] = "ABCDEFGH-1234-56IJ-789K-0LMNOPQRSTUV"
    obj["crashReporterKey"] = "12ab34cd45aabbccdd6712ab34cd45aabbccdd67"
    obj["bootArgs"] = ss.get('boot_args','')
    obj["frontmostPids"] = [0]
    obj["exception"] = "0xDEADF157"
    obj["processByPid"] = {}

    if incomplete:
        obj["reason"] = "!!!INCOMPLETE!!! kernel panic stackshot"
        obj["notes"] = "This stackshot report generated from incomplete data!   Some information is missing! "
        
    processByPid = obj["processByPid"]
    ssplist = ss.get('task_snapshots', {})
    kern_load_info = []
    if "0" in ssplist:
        kc_uuid = ssplist["0"].get('kernelcache_load_info', None)
        if kc_uuid:
            kernelcache_uuid = [format_uuid(kc_uuid['imageUUID']), kc_uuid['imageLoadAddress'], "U" ]
            kern_load_info.append(kernelcache_uuid)

        kl_infos = ssplist["0"].get("dyld_load_info", [])
        for dlinfo in kl_infos:
            kern_load_info.append([format_uuid(dlinfo['imageUUID']), dlinfo['imageLoadAddress'], "K"])

        kl_infos_text_exec = ssplist["0"].get("dyld_load_info_text_exec", [])
        for dlinfo in kl_infos_text_exec:
            kern_load_info.append([format_uuid(dlinfo['imageUUID']), dlinfo['imageLoadAddress'], "T"])

    for pid,piddata in ssplist.iteritems():
        processByPid[str(pid)] = {}
        tsnap = processByPid[str(pid)]
        pr_lib_dsc = dsc_common
        if 'shared_cache_dyld_load_info' in tsnap:
            if 'imageSlidBaseAddress' in tsnap.get('shared_cache_dyld_load_info'):
                shared_cache_base_addr = tsnap.get('shared_cache_dyld_load_info')['imageSlidBaseAddress']
            else:
                print "Specific task shared cache format does not include slid shared cache base address. Skipping writing report."
                return

            pr_lib_dsc = [format_uuid(tsnap.get('shared_cache_dyld_load_info')['imageUUID']),
                          tsnap.get('shared_cache_dyld_load_info')['imageSlidBaseAddress'],
                          "S"]

        pr_libs = []
        if len(dsc_libs) == 0 and pr_lib_dsc:
            pr_libs.append(pr_lib_dsc)
        _lib_type = "P"
        if int(pid) == 0:
            _lib_type = "K"
            pr_libs = []
        else:
            for dlinfo in piddata.get('dyld_load_info',[]):
                pr_libs.append([format_uuid(dlinfo['imageUUID']), dlinfo['imageLoadAddress'], _lib_type])

        pr_libs.extend(kern_load_info)
        pr_libs.extend(dsc_libs)

        pr_libs.sort(key=itemgetter(1))

        if 'task_snapshot' not in piddata:
            continue
        tasksnap = piddata['task_snapshot']
        tsnap["pid"] = tasksnap["ts_pid"]
        if 'ts_asid' in piddata:
            tsnap["asid"] = piddata["ts_asid"]

        if 'ts_pagetable' in piddata:
            pagetables = []
            for tte in piddata["ts_pagetable"]:
                pagetables.append(tte)
            tsnap["pageTables"] = pagetables

        tsnap["residentMemoryBytes"] = tasksnap["ts_task_size"]
        tsnap["timesDidThrottle"] = tasksnap["ts_did_throttle"]
        tsnap["systemTimeTask"] = GetSecondsFromMATime(tasksnap["ts_system_time_in_terminated_th"], timebase)
        tsnap["pageIns"] = tasksnap["ts_pageins"]
        tsnap["pageFaults"] = tasksnap["ts_faults"]
        tsnap["userTimeTask"] = GetSecondsFromMATime(tasksnap[  "ts_user_time_in_terminated_thre"], timebase)
        tsnap["procname"] = tasksnap["ts_p_comm"]
        tsnap["copyOnWriteFaults"] = tasksnap["ts_cow_faults"]
        tsnap["timesThrottled"] = tasksnap["ts_was_throttled"]
        tsnap["threadById"] = {}
        threadByID = tsnap["threadById"]
        thlist = piddata.get('thread_snapshots', {})
        for tid,thdata in thlist.iteritems():
            threadByID[str(tid)] = {}
            thsnap = threadByID[str(tid)]
            if "thread_snapshot" not in thdata:
                print "Found broken thread state for thread ID: %s." % tid
                break
            threadsnap = thdata["thread_snapshot"]
            thsnap["userTime"] = GetSecondsFromMATime(threadsnap["ths_user_time"], timebase)
            thsnap["id"] = threadsnap["ths_thread_id"]
            thsnap["basePriority"] = threadsnap["ths_base_priority"]
            thsnap["systemTime"] = threadsnap["ths_sys_time"]
            thsnap["schedPriority"] = threadsnap["ths_sched_priority"]
            thsnap["state"] = GetStateDescription(threadsnap['ths_state'])
            thsnap["qosEffective"] = threadsnap["ths_eqos"]
            thsnap["qosRequested"] = threadsnap["ths_rqos"]

            if "pth_name" in thdata:
                thsnap["name"] = thdata["pth_name"];

            if threadsnap['ths_continuation']:
                thsnap["continuation"] = GetSymbolInfoForFrame(AllImageCatalog, pr_libs, threadsnap['ths_continuation'])
            if "kernel_stack_frames" in thdata:
                kuserframes = []
                for f in thdata["kernel_stack_frames"]:
                    kuserframes.append(GetSymbolInfoForFrame(AllImageCatalog, pr_libs, f['lr']))
                thsnap["kernelFrames"] = kuserframes

            if "user_stack_frames" in thdata:
                uframes = []
                for f in thdata["user_stack_frames"]:
                    uframes.append(GetSymbolInfoForFrame(AllImageCatalog, pr_libs, f['lr']))
                thsnap["userFrames"] = uframes

            if "user_stacktop" in thdata:
                (address,) = struct.unpack("<Q", struct.pack("B"*8, *thdata["user_stacktop"]["stack_contents"]))
                thsnap["userStacktop"] = GetSymbolInfoForFrame(AllImageCatalog, pr_libs, address)

            if threadsnap['ths_wait_event']:
                thsnap["waitEvent"] = GetSymbolInfoForFrame(AllImageCatalog, pr_libs, threadsnap['ths_wait_event'])

        if 'thread_waitinfo' in piddata and 'thread_turnstileinfo' in piddata:
            tsnap['waitInfo'] = formatWaitInfoWithTurnstiles(piddata['thread_waitinfo'] , piddata['thread_turnstileinfo'])
        elif 'thread_waitinfo' in piddata:
            tsnap['waitInfo'] = map(formatWaitInfo, piddata['thread_waitinfo'])

    obj['binaryImages'] = AllImageCatalog
    if outfile_name == '-':
        fh = sys.stdout
    else:
        fh = open(outfile_name, "w")

    header = {}
    header['bug_type'] = 288
    if timestamp is not None:
        header['timestamp'] = timestamp
    header['os_version'] = os_version
    fh.write(json.dumps(header))
    fh.write("\n")

    fh.write(json.dumps(obj, sort_keys=False, indent=2, separators=(',', ': ')))
    fh.close()

## Base utils for interacting with shell ##
def RunCommand(bash_cmd_string, get_stderr = True):
    """
        returns: (int,str) : exit_code and output_str
    """
    print "RUNNING: %s" % bash_cmd_string
    cmd_args = shlex.split(bash_cmd_string)
    output_str = ""
    exit_code = 0
    try:
        if get_stderr:
            output_str = subprocess.check_output(cmd_args, stderr=subprocess.STDOUT)
        else:
            output_str = subprocess.check_output(cmd_args, stderr=None)
    except subprocess.CalledProcessError, e:
        exit_code = e.returncode
    finally:
        return (exit_code, output_str)


parser = argparse.ArgumentParser(description="Decode a kcdata binary file.")
parser.add_argument("-l", "--listtypes", action="store_true", required=False, default=False,
                    help="List all known types",
                    dest="list_known_types")

parser.add_argument("-s", "--stackshot", required=False, default=False,
                    help="Generate a stackshot report file",
                    dest="stackshot_file")

parser.add_argument("--multiple", help="look for multiple stackshots in a single file", action='store_true')

parser.add_argument("-p", "--plist", required=False, default=False,
                    help="output as plist", action="store_true")

parser.add_argument("-S", "--sdk", required=False, default="", help="sdk property passed to xcrun command to find the required tools. Default is empty string.", dest="sdk")
parser.add_argument("--pretty", default=False, action='store_true', help="make the output a little more human readable")
parser.add_argument("--incomplete", action='store_true', help="accept incomplete data")
parser.add_argument("kcdata_file", type=argparse.FileType('r'), help="Path to a kcdata binary file.")

class VerboseAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='%(message)s')
parser.add_argument('-v', "--verbose", action=VerboseAction, nargs=0)

@contextlib.contextmanager
def data_from_stream(stream):
    try:
        fmap = mmap.mmap(stream.fileno(), 0, mmap.MAP_SHARED, mmap.PROT_READ)
    except:
        yield stream.read()
    else:
        try:
            yield fmap
        finally:
            fmap.close()

def iterate_kcdatas(kcdata_file):
    with data_from_stream(kcdata_file) as data:
        iterator = kcdata_item_iterator(data)
        kcdata_buffer = KCObject.FromKCItem(iterator.next())

        if isinstance(kcdata_buffer, KCCompressedBufferObject):
            kcdata_buffer.ReadItems(iterator)
            decompressed = kcdata_buffer.Decompress(data)
            iterator = kcdata_item_iterator(decompressed)
            kcdata_buffer = KCObject.FromKCItem(iterator.next())

        if not isinstance(kcdata_buffer, KCBufferObject):
            # ktrace stackshot chunk
            iterator = kcdata_item_iterator(data[16:])
            kcdata_buffer = KCObject.FromKCItem(iterator.next())

        if not isinstance(kcdata_buffer, KCBufferObject):
            try:
                decoded = base64.b64decode(data)
            except:
                pass
            else:
                iterator = kcdata_item_iterator(decoded)
                kcdata_buffer = KCObject.FromKCItem(iterator.next())
        if not isinstance(kcdata_buffer, KCBufferObject):
            import gzip
            from io import BytesIO
            try:
                decompressed = gzip.GzipFile(fileobj=BytesIO(data[:])).read()
            except:
                pass
            else:
                iterator = kcdata_item_iterator(decompressed)
                kcdata_buffer = KCObject.FromKCItem(iterator.next())

        if not isinstance(kcdata_buffer, KCBufferObject):
            raise Exception, "unknown file type"


        kcdata_buffer.ReadItems(iterator)
        yield kcdata_buffer

        for magic in iterator:
            kcdata_buffer = KCObject.FromKCItem(magic)
            if kcdata_buffer.i_type == 0:
                continue
            if not isinstance(kcdata_buffer, KCBufferObject):
                raise Exception, "unknown file type"
            kcdata_buffer.ReadItems(iterator)
            yield kcdata_buffer


def prettify(data):
    if isinstance(data, list):
        return map(prettify, data);

    elif isinstance(data, dict):
        newdata = dict()
        for key, value in data.items():
            if 'uuid' in key.lower() and isinstance(value, list) and len(value) == 16:
                value = '%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X' % tuple(value)
            elif 'address' in key.lower() and isinstance(value, (int, long)):
                value = '0x%X' % value
            elif key == 'lr':
                value = '0x%X' % value
            elif key == 'thread_waitinfo':
                value = map(formatWaitInfo, value)
            elif key == 'stack_contents':
                (address,) = struct.unpack("<Q", struct.pack("B"*8, *value))
                value = '0x%X' % address
            else:
                value = prettify(value);
            newdata[key] = value

        return newdata

    else:
        return data


if __name__ == '__main__':
    args = parser.parse_args()

    if args.multiple and args.stackshot_file:
        raise NotImplementedError

    if args.list_known_types:
        for (n, t) in KNOWN_TYPES_COLLECTION.items():
            print "%d : %s " % (n, str(t))
        sys.exit(1)

    if args.incomplete or args.stackshot_file:
        G.accept_incomplete_data = True

    for i,kcdata_buffer in enumerate(iterate_kcdatas(args.kcdata_file)):
        if i > 0 and not args.multiple:
            break

        str_data = "{" + kcdata_buffer.GetJsonRepr() + "}"
        str_data = str_data.replace("\t", "    ")

        try:
            json_obj = json.loads(str_data)
        except:
            print >>sys.stderr, "JSON reparsing failed!  Printing string data!\n"
            import textwrap
            print textwrap.fill(str_data, 100)
            raise

        if args.pretty:
            json_obj = prettify(json_obj)

        if args.stackshot_file:
            SaveStackshotReport(json_obj, args.stackshot_file, G.data_was_incomplete)
        elif args.plist:
            import Foundation
            plist = Foundation.NSPropertyListSerialization.dataWithPropertyList_format_options_error_(
                json_obj, Foundation.NSPropertyListXMLFormat_v1_0, 0, None)[0].bytes().tobytes()
            #sigh.  on some pythons long integers are getting output with L's in the plist.
            plist = re.sub(r'^(\s*<integer>\d+)L(</integer>\s*)$', r"\1\2", plist, flags=re.MULTILINE)
            print plist,
        else:
            print json.dumps(json_obj, sort_keys=True, indent=4, separators=(',', ': '))
