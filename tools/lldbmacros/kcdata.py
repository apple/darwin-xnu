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

cgitb.enable(format='text')

kcdata_type_def = {
    'KCDATA_TYPE_INVALID':              0x0,
    'KCDATA_TYPE_STRING_DESC':          0x1,
    'KCDATA_TYPE_UINT32_DESC':          0x2,
    'KCDATA_TYPE_UINT64_DESC':          0x3,
    'KCDATA_TYPE_INT32_DESC':           0x4,
    'KCDATA_TYPE_INT64_DESC':           0x5,
    'KCDATA_TYPE_BINDATA_DESC':         0x6,
    'KCDATA_TYPE_ARRAY':                0x11,
    'KCDATA_TYPE_TYPEDEFINTION':        0x12,
    'KCDATA_TYPE_CONTAINER_BEGIN':      0x13,
    'KCDATA_TYPE_CONTIANER_END':        0x14,
    'KCDATA_TYPE_LIBRARY_LOADINFO':     0x30,
    'KCDATA_TYPE_LIBRARY_LOADINFO64':   0x31,
    'KCDATA_TYPE_TIMEBASE':             0x32,
    #'KCDATA_TYPE_MACH_ABSOLUTE_TIME':   0x33,
    'KCDATA_TYPE_TIMEVAL':              0x34,
    'KCDATA_TYPE_USECS_SINCE_EPOCH':    0x35,
    'STACKSHOT_KCCONTAINER_TASK':       0x903,
    'STACKSHOT_KCCONTAINER_THREAD':     0x904,
    'STACKSHOT_KCTYPE_KERN_STACKFRAME': 0x90A,
    'STACKSHOT_KCTYPE_KERN_STACKFRAME64': 0x90B,
    'STACKSHOT_KCTYPE_USER_STACKFRAME': 0x90C,
    'STACKSHOT_KCTYPE_USER_STACKFRAME64': 0x90D,
    'STACKSHOT_KCTYPE_BOOTARGS':        0x90E,
    'STACKSHOT_KCTYPE_OSVERSION':       0x90F,
    'STACKSHOT_KCTYPE_KERN_PAGE_SIZE':  0x910,
    'STACKSHOT_KCTYPE_JETSAM_LEVEL':    0x911,
    'KCDATA_TYPE_BUFFER_END':      0xF19158ED,


    'TASK_CRASHINFO_EXTMODINFO':           0x801,
    'TASK_CRASHINFO_BSDINFOWITHUNIQID':    0x802,
    'TASK_CRASHINFO_TASKDYLD_INFO':        0x803,
    'TASK_CRASHINFO_UUID':                 0x804,
    'TASK_CRASHINFO_PID':                  0x805,
    'TASK_CRASHINFO_PPID':                 0x806,
    'TASK_CRASHINFO_RUSAGE':               0x807,
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

    'KCDATA_BUFFER_BEGIN_CRASHINFO':  0xDEADF157,
    'KCDATA_BUFFER_BEGIN_STACKSHOT':  0x59a25807
}
kcdata_type_def_rev = dict((v, k) for k, v in kcdata_type_def.iteritems())

KNOWN_TYPES_COLLECTION = {}


def enum(**args):
    return type('enum', (), args)

KCSUBTYPE_TYPE = enum(KC_ST_CHAR=1, KC_ST_INT8=2, KC_ST_UINT8=3, KC_ST_INT16=4, KC_ST_UINT16=5, KC_ST_INT32=6, KC_ST_UINT32=7, KC_ST_INT64=8, KC_ST_UINT64=9)


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
    def FromBasicCtype(st_name, st_type, st_offset=0):
        if st_type <= 0 or st_type > KCSUBTYPE_TYPE.KC_ST_UINT64:
            raise ValueError("Invalid type passed %d" % st_type)
        st_size = struct.calcsize(KCSubTypeElement._unpack_formats[st_type])
        st_flag = 0
        retval = KCSubTypeElement(st_name, st_type, st_size, st_offset, st_flag, KCSubTypeElement._get_naked_element_value)
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

            return '"' + ''.join(str_arr) + '"'
        o = '[' + ','.join([self.GetValueAsString(base_data, i) for i in range(self.count)]) + ']'
        return o

    def GetJsonRepr(self, base_data):
        if self.custom_JsonRepr:
            if self.is_array_type:
                e_data = [self.GetValue(base_data, i) for i in range(self.count)]
            else:
                e_data = self.GetValue(base_data)
            return self.custom_JsonRepr(e_data, self.name)
        return self.GetStringRepr(base_data)


class KCTypeDescription(object):
    def __init__(self, t_type_id, t_elements=[], t_name='anon', custom_repr=None):
        self.type_id = t_type_id
        self.elements = t_elements
        self.name = t_name
        self.totalsize = 0
        self.custom_JsonRepr = custom_repr
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
        retval = KCTypeDescription(t_type_id, other.elements, t_name, other.custom_JsonRepr)
        return retval

    def GetJsonRepr(self, base_data):
        if self.custom_JsonRepr:
            return self.custom_JsonRepr([e.GetValue(base_data) for e in self.elements])
        o = '{' + ", ".join(['"%s": %s' % (e.GetName(), e.GetJsonRepr(base_data)) for e in self.elements]) + '}'
        return o


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


class KCObject(object):
    """
    """
    def __init__(self, type_code, data, flags=0, field_name=''):
        self.i_type = type_code
        self.i_data = data
        self.i_size = len(data)
        self.i_name = field_name
        self.i_flags = flags
        self.obj_collection = []
        self.obj = {}
        self.is_container_type = False
        self.is_array_type = False
        self.is_naked_type = False
        if not field_name:
            self.i_name = GetTypeNameForKey(type_code)
        self.ParseData()

    @staticmethod
    def FromKCItem(kcitem):
        return KCObject(kcitem.i_type, kcitem.i_data, kcitem.i_flags)

    def IsContainerType(self):
        return self.is_container_type

    def IsContainerEnd(self):
        if self.i_type in (GetTypeForName('KCDATA_TYPE_CONTIANER_END'), GetTypeForName('KCDATA_TYPE_BUFFER_END')):
            return True
        return False

    def GetJsonRepr(self):
        if self.is_array_type:
            return '[' + ', '.join([i.GetJsonRepr() for i in self.obj_collection]) + ']'
        #if self.is_array_type:
        #    return '"%s" : [' % self.i_name + ', '.join([i.GetJsonRepr() for i in self.obj_collection]) + ']'
        if self.is_container_type:
            raise NotImplementedError("Containter types should not have come here")
        if self.i_type in KNOWN_TYPES_COLLECTION:
            return KNOWN_TYPES_COLLECTION[self.i_type].GetJsonRepr(self.i_data)
        if self.is_naked_type:
            return json.dumps(self.obj)

        raise NotImplementedError("Broken GetJsonRepr implementation")

    def ParseData(self):
        if self.i_type == GetTypeForName('KCDATA_TYPE_CONTAINER_BEGIN'):
            self.is_container_type = True
            self.obj['uniqID'] = self.i_flags
            self.i_name = str(self.obj['uniqID'])
            self.obj['typeID'] = struct.unpack_from('I', self.i_data)[0]

        elif self.i_type in (GetTypeForName('KCDATA_BUFFER_BEGIN_CRASHINFO'), GetTypeForName('KCDATA_BUFFER_BEGIN_STACKSHOT')):
            self.is_container_type = True
            self.obj['uniqID'] = self.i_name
            self.obj['typeID'] = self.i_type

        elif self.i_type == GetTypeForName('KCDATA_TYPE_CONTIANER_END'):
            self.obj['uniqID'] = self.i_flags

        elif self.i_type == GetTypeForName('KCDATA_TYPE_BUFFER_END'):
            self.obj = ''

        elif self.i_type == GetTypeForName('KCDATA_TYPE_UINT32_DESC'):
            self.is_naked_type = True
            u_d = struct.unpack_from('32sI', self.i_data)
            self.i_name = u_d[0].strip(chr(0))
            self.obj = u_d[1]

        elif self.i_type == GetTypeForName('KCDATA_TYPE_UINT64_DESC'):
            self.is_naked_type = True
            u_d = struct.unpack_from('32sQ', self.i_data)
            self.i_name = u_d[0].strip(chr(0))
            self.obj = u_d[1]

        elif self.i_type == GetTypeForName('KCDATA_TYPE_TYPEDEFINTION'):
            self.is_naked_type = True
            u_d = struct.unpack_from('II32s', self.i_data)
            self.obj['name'] = u_d[2].strip(chr(0))
            self.i_name = "typedef<%s>" % self.obj['name']
            self.obj['typeID'] = u_d[0]
            self.obj['numOfFields'] = u_d[1]
            element_arr = []
            for i in range(u_d[1]):
                e = KCSubTypeElement.FromBinaryTypeData(self.i_data[40+(i*40):])
                #print str(e)
                element_arr.append(e)
            type_desc = KCTypeDescription(u_d[0], element_arr, self.obj['name'])
            #print str(type_desc)
            self.obj['fields'] = [str(e) for e in element_arr]
            KNOWN_TYPES_COLLECTION[type_desc.GetTypeID()] = type_desc

        elif self.i_type == GetTypeForName('KCDATA_TYPE_ARRAY'):
            self.is_array_type = True
            e_t = (self.i_flags >> 32) & 0xffffffff
            e_c = self.i_flags & 0xffffffff
            e_s = self.i_size / e_c
            self.obj['typeID'] = e_t
            self.i_name = GetTypeNameForKey(e_t)
            self.i_type = e_t
            self.obj['numOfElements'] = e_c
            self.obj['sizeOfElement'] = e_s
            #populate the array here by recursive creation of KCObject
            for _i in range(e_c):
                _o = KCObject(e_t, self.i_data[(_i * e_s):(_i * e_s) + e_s])
                self.obj_collection.append(_o)
        elif self.i_type in KNOWN_TYPES_COLLECTION:
            self.i_name = KNOWN_TYPES_COLLECTION[self.i_type].GetName()
            self.is_naked_type = True
        else:
            self.is_naked_type = True
            #self.obj = "data of len %d" % len(self.i_data)
            #self.obj = ''.join(["%x" % ki for ki in struct.unpack('%dB' % len(self.i_data), self.i_data)])
            self.obj = base64.b64encode(self.i_data)


class KCContainerObject(KCObject):
    def __init__(self, *args, **kwargs):
        KCObject.__init__(self, *args, **kwargs)
        self.obj_container_dict = {}
        self.obj_nested_objs = {}

    def GetJsonRepr(self):
        o = '"%s"' % self.obj['uniqID'] + ' : { "typeID" : %d ,' % self.obj['typeID']
        for (k, v) in self.obj_container_dict.items():
            if v.IsContainerType():
                o += v.GetJsonRepr() + ","
            else:
                o += ' "%s" : ' % k + v.GetJsonRepr() + ","

        for (k, v) in self.obj_nested_objs.items():
            o += '"%s" : {' % k + ",".join([vi.GetJsonRepr() for vi in v.values()]) + "} ,"

        o = o.rstrip(',') + "}"

        return o

    def AddObject(self, kco):
        if kco.IsContainerEnd():
            return
        if kco.IsContainerType():
            type_name = GetTypeNameForKey(kco.obj['typeID'])
            if type_name not in self.obj_nested_objs:
                self.obj_nested_objs[type_name] = {}
            self.obj_nested_objs[type_name][kco.i_name] = kco
            return
        self.obj_container_dict[kco.i_name] = kco


class KCData_item:
    """ a basic kcdata_item type object.
    """
    header_size = 16  # (uint32_t + uint32_t + uint64_t)

    def __init__(self, item_type, item_size, item_flags, item_data):
        self.i_type = item_type
        self.i_size = item_size
        self.i_flags = item_flags
        self.i_data = item_data
        self._buf_pos = None

    def __init__(self, barray, pos=0):
        """ create an object by parsing data from bytes array
            returns : obj - if data is readable
                      raises ValueError if something is not ok.
        """
        self.i_type = struct.unpack('I', barray[pos:pos+4])[0]     # int.from_bytes(barray[pos:pos+4])
        self.i_size = struct.unpack('I', barray[pos+4:pos+8])[0]   # int.from_bytes(barray[pos+4:pos+8])
        self.i_flags = struct.unpack('Q', barray[pos+8:pos+16])[0]  # int.from_bytes(barray[pos+8:pos+16])
        self.i_data = barray[pos+16: (pos + 16 + self.i_size)]
        self._buf_pos = pos

    def __len__(self):
        return self.i_size + KCData_item.header_size

    def GetHeaderDescription(self):
        outs = "type: 0x%x size: 0x%x flags: 0x%x" % (self.i_type, self.i_size, self.i_flags)
        if not self._buf_pos is None:
            outs = "pos: 0x%x" % self._buf_pos + outs
        return outs

    def __str__(self):
        return self.GetHeaderDescription()


def kcdata_item_iterator(filename):
    if not filename:
        return
    with open(filename, "r+b") as f:
        fmap = mmap.mmap(f.fileno(), 0)
        file_len = len(fmap)
        curpos = 0
        while curpos < file_len:
            item = KCData_item(fmap, curpos)
            yield item
            curpos += len(item)
        fmap.close()


def _get_data_element(elementValues):
    return json.dumps(elementValues[-1])

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
    KCSubTypeElement('numerator', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0),
    KCSubTypeElement('denominator', KCSUBTYPE_TYPE.KC_ST_UINT32, 8, 4, 0)
),
    'timebase_info'
)


STACKSHOT_IO_NUM_PRIORITIES = 4
KNOWN_TYPES_COLLECTION[0x901] = KCTypeDescription(0x901, (
    KCSubTypeElement.FromBasicCtype('disk_reads_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('disk_reads_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('disk_writes_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('disk_writes_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement('io_priority_count', KCSUBTYPE_TYPE.KC_ST_UINT64, KCSubTypeElement.GetSizeForArray(STACKSHOT_IO_NUM_PRIORITIES, 8), 32, 1),
    KCSubTypeElement('io_priority_size', KCSUBTYPE_TYPE.KC_ST_UINT64, KCSubTypeElement.GetSizeForArray(STACKSHOT_IO_NUM_PRIORITIES, 8), 32 + (STACKSHOT_IO_NUM_PRIORITIES * 8), 1),
    KCSubTypeElement.FromBasicCtype('paging_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 32 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('paging_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 40 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('non_paging_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 48 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('non_paging_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 56 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('data_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 64 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('data_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 72 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('metadata_count', KCSUBTYPE_TYPE.KC_ST_UINT64, 80 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8)),
    KCSubTypeElement.FromBasicCtype('metadata_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 88 + 2 * (STACKSHOT_IO_NUM_PRIORITIES * 8))
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
    KCSubTypeElement.FromBasicCtype('unique_pid', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('user_time_in_terminated_threads', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('system_time_in_terminated_threads', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('p_start_sec', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    KCSubTypeElement.FromBasicCtype('task_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
    KCSubTypeElement.FromBasicCtype('task_max_resident_size', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
    KCSubTypeElement.FromBasicCtype('suspend_count', KCSUBTYPE_TYPE.KC_ST_UINT32, 56),
    KCSubTypeElement.FromBasicCtype('faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 60),
    KCSubTypeElement.FromBasicCtype('pageins', KCSUBTYPE_TYPE.KC_ST_UINT32, 64),
    KCSubTypeElement.FromBasicCtype('cow_faults', KCSUBTYPE_TYPE.KC_ST_UINT32, 68),
    KCSubTypeElement.FromBasicCtype('was_throttled', KCSUBTYPE_TYPE.KC_ST_UINT32, 72),
    KCSubTypeElement.FromBasicCtype('did_throttle', KCSUBTYPE_TYPE.KC_ST_UINT32, 76),
    KCSubTypeElement.FromBasicCtype('latency_qos', KCSUBTYPE_TYPE.KC_ST_UINT32, 80),
    KCSubTypeElement.FromBasicCtype('pid', KCSUBTYPE_TYPE.KC_ST_INT32, 84),
    KCSubTypeElement('p_comm', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(32, 1), 88, 1)
),
    'task_snapshot_v2'
)

KNOWN_TYPES_COLLECTION[0x906] = KCTypeDescription(0x906, (
    KCSubTypeElement.FromBasicCtype('thread_id', KCSUBTYPE_TYPE.KC_ST_UINT64, 0),
    KCSubTypeElement.FromBasicCtype('wait_event', KCSUBTYPE_TYPE.KC_ST_UINT64, 8),
    KCSubTypeElement.FromBasicCtype('continuation', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
    KCSubTypeElement.FromBasicCtype('total_syscalls', KCSUBTYPE_TYPE.KC_ST_UINT64, 24),
    KCSubTypeElement.FromBasicCtype('voucher_identifier', KCSUBTYPE_TYPE.KC_ST_UINT64, 32),
    KCSubTypeElement.FromBasicCtype('dqserialnum', KCSUBTYPE_TYPE.KC_ST_UINT64, 40),
    KCSubTypeElement.FromBasicCtype('user_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 48),
    KCSubTypeElement.FromBasicCtype('sys_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 56),
    KCSubTypeElement.FromBasicCtype('ss_flags', KCSUBTYPE_TYPE.KC_ST_UINT64, 64),
    KCSubTypeElement.FromBasicCtype('last_run_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 72),
    KCSubTypeElement.FromBasicCtype('last_made_runnable_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 80),
    KCSubTypeElement.FromBasicCtype('state', KCSUBTYPE_TYPE.KC_ST_UINT32, 88),
    KCSubTypeElement.FromBasicCtype('sched_flags', KCSUBTYPE_TYPE.KC_ST_UINT32, 92),
    KCSubTypeElement.FromBasicCtype('base_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 96),
    KCSubTypeElement.FromBasicCtype('sched_priority', KCSUBTYPE_TYPE.KC_ST_INT16, 98),
    KCSubTypeElement.FromBasicCtype('ts_eqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 100),
    KCSubTypeElement.FromBasicCtype('ts_rqos', KCSUBTYPE_TYPE.KC_ST_UINT8, 101),
    KCSubTypeElement.FromBasicCtype('ts_rqos_override', KCSUBTYPE_TYPE.KC_ST_UINT8, 102),
    KCSubTypeElement.FromBasicCtype('io_tier', KCSUBTYPE_TYPE.KC_ST_UINT8, 103),
),
    'thread_snapshot_v2'
)

KNOWN_TYPES_COLLECTION[0x909] = KCSubTypeElement('pth_name', KCSUBTYPE_TYPE.KC_ST_CHAR, KCSubTypeElement.GetSizeForArray(64, 1), 0, 1)


def _get_uuid_json_data(elementValues, elementName):
    return '"<%s>"' % ''.join("%02x" % i for i in elementValues)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO64')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO64'), (
    KCSubTypeElement('loadAddress', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 8, 1, _get_uuid_json_data)
),
    'dyld_load_info'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO')] = KCTypeDescription(GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO'), (
    KCSubTypeElement('loadAddress', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0),
    KCSubTypeElement('imageUUID', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 4, 1, _get_uuid_json_data)
),
    'dyld_load_info'
)

KNOWN_TYPES_COLLECTION[0x908] = KCTypeDescription.FromKCTypeDescription(KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_LIBRARY_LOADINFO64')], 0x908, 'shared_cache_dyld_info')

KNOWN_TYPES_COLLECTION[0x33] = KCSubTypeElement('mach_absolute_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)
KNOWN_TYPES_COLLECTION[0x907] = KCSubTypeElement.FromBasicCtype('donating_pids', KCSUBTYPE_TYPE.KC_ST_INT32)

KNOWN_TYPES_COLLECTION[GetTypeForName('KCDATA_TYPE_USECS_SINCE_EPOCH')] = KCSubTypeElement('usecs_since_epoch', KCSUBTYPE_TYPE.KC_ST_UINT64, 8, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT32),
    KCSubTypeElement.FromBasicCtype('sp', KCSUBTYPE_TYPE.KC_ST_UINT32, 4)
),
    'kernel_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME'),
    'user_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64')] = KCTypeDescription(GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64'), (
    KCSubTypeElement.FromBasicCtype('lr', KCSUBTYPE_TYPE.KC_ST_UINT64),
    KCSubTypeElement.FromBasicCtype('sp', KCSUBTYPE_TYPE.KC_ST_UINT64, 8)
),
    'kernel_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME64')] = KCTypeDescription.FromKCTypeDescription(
    KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_STACKFRAME64')],
    GetTypeForName('STACKSHOT_KCTYPE_USER_STACKFRAME64'),
    'user_stack_frames'
)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_OSVERSION')] = KCSubTypeElement('osversion', KCSUBTYPE_TYPE.KC_ST_CHAR,
                          KCSubTypeElement.GetSizeForArray(256, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_BOOTARGS')] = KCSubTypeElement('bootargs', KCSUBTYPE_TYPE.KC_ST_CHAR,
                           KCSubTypeElement.GetSizeForArray(256, 1), 0, 1)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_KERN_PAGE_SIZE')] = KCSubTypeElement('kernel_page_size', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)

KNOWN_TYPES_COLLECTION[GetTypeForName('STACKSHOT_KCTYPE_JETSAM_LEVEL')] = KCSubTypeElement('jetsam_level', KCSUBTYPE_TYPE.KC_ST_UINT32, 4, 0, 0, KCSubTypeElement._get_naked_element_value)


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

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_PROC_STATUS')] = KCSubTypeElement('p_status', KCSUBTYPE_TYPE.KC_ST_UINT8, 1, 0, 0)

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_BSDINFOWITHUNIQID')] = KCTypeDescription(GetTypeForName('TASK_CRASHINFO_BSDINFOWITHUNIQID'),
    (   KCSubTypeElement('p_uuid', KCSUBTYPE_TYPE.KC_ST_UINT8, KCSubTypeElement.GetSizeForArray(16, 1), 0, 1),
        KCSubTypeElement.FromBasicCtype('p_uniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 16),
        KCSubTypeElement.FromBasicCtype('p_puniqueid', KCSUBTYPE_TYPE.KC_ST_UINT64, 24)
    ),
    'proc_uniqidentifierinfo')

KNOWN_TYPES_COLLECTION[GetTypeForName('TASK_CRASHINFO_EXCEPTION_CODES')] = KCSubTypeElement('TASK_CRASHINFO_EXCEPTION_CODES', KCSUBTYPE_TYPE.KC_ST_INT64,
    KCSubTypeElement.GetSizeForArray(2,8), 0, 1)

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
            KCSubTypeElement.FromBasicCtype('ri_cpu_time_qos_user_interactive', KCSUBTYPE_TYPE.KC_ST_UINT64, 208),
            KCSubTypeElement.FromBasicCtype('ri_billed_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 216),
            KCSubTypeElement.FromBasicCtype('ri_serviced_system_time', KCSUBTYPE_TYPE.KC_ST_UINT64, 224)
    ),
    'rusage_info_v3')

def GetSecondsFromMATime(mat, tb):
    return (float(mat) * tb['numerator']) / tb['denominator']

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
    if (s & TH_IDLE):
        retval.append("TH_IDLE")
    return retval

def SaveStackshotReport(j, outfile_name, dsc_uuid, dsc_libs_arr):
    import time
    from operator import itemgetter, attrgetter
    ss = j.get('KCDATA_BUFFER_BEGIN_STACKSHOT')
    if not ss:
        print "No KCDATA_BUFFER_BEGIN_STACKSHOT object found. Skipping writing report."
        return
    timestamp = ss.get('usecs_since_epoch', int(time.time()))
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S %z",time.gmtime(timestamp))
    os_version = ss.get('osversion', 'Unknown')
    timebase = ss.get('timebase_info', {"denominator": 1, "numerator": 1})
    dsc_common = [ss.get('shared_cache_dyld_info')['imageUUID'].strip('<>'),
                  ss.get('shared_cache_dyld_info')['loadAddress'],
                  "C"
                 ]

    dsc_libs = []
    if dsc_common[0].replace('-', '').lower() == dsc_uuid:
        print "SUCCESS: Found Matching dyld shared cache uuid. Loading library load addresses from layout provided."
        _load_addr = dsc_common[1]
        #print _load_addr
        #print dsc_libs_arr
        for i in dsc_libs_arr:
            _uuid = i[2].lower().replace('-','').strip()
            _addr = int(i[0], 16) + _load_addr
            dsc_libs.append([_uuid, _addr, "P"])
            #print "adding ", [_uuid, _addr, "C"]

    AllImageCatalog = []
    obj = {}
    obj["kernel"] = os_version
    obj["date"] = timestamp
    obj["reason"] = "kernel panic stackshot"
    obj["incident"] = "ABCDEFGH-1234-56IJ-789K-0LMNOPQRSTUV"
    obj["crashReporterKey"] = "12ab34cd45aabbccdd6712ab34cd45aabbccdd67"
    obj["bootArgs"] = ss.get('bootargs','')
    obj["frontmostPids"] = [0]
    obj["exception"] = "0xDEADF157"
    obj["processByPid"] = {}
    processByPid = obj["processByPid"]
    ssplist = ss.get('STACKSHOT_KCCONTAINER_TASK', {})
    kern_load_info = []
    if "0" in ssplist:
        kl_infos = ssplist["0"].get("dyld_load_info", [])
        for dlinfo in kl_infos:
            kern_load_info.append([dlinfo['imageUUID'].strip('<>'), dlinfo['loadAddress'], "K"])
    for pid,piddata in ssplist.iteritems():
        processByPid[str(pid)] = {}
        tsnap = processByPid[str(pid)]
        pr_lib_dsc = dsc_common
        if 'shared_cache_dyld_info' in tsnap:
            pr_lib_dsc = [tsnap.get('shared_cache_dyld_info')['imageUUID'].strip('<>'),
                          tsnap.get('shared_cache_dyld_info')['loadAddress'],
                          "C"
                         ]

        pr_libs = []
        if len(dsc_libs) == 0:
            pr_libs.append(pr_lib_dsc)
        _lib_type = "P"
        if int(pid) == 0:
            _lib_type = "K"
            pr_libs = []
        else:
            for dlinfo in piddata.get('dyld_load_info',[]):
                pr_libs.append([dlinfo['imageUUID'].strip('<>'), dlinfo['loadAddress'], _lib_type])

        pr_libs.extend(kern_load_info)
        pr_libs.extend(dsc_libs)

        pr_libs.sort(key=itemgetter(1))

        tasksnap = piddata['task_snapshot_v2']
        tsnap["pid"] = tasksnap["pid"]
        tsnap["residentMemoryBytes"] = tasksnap["task_size"]
        tsnap["timesDidThrottle"] = tasksnap["did_throttle"]
        tsnap["systemTimeTask"] = GetSecondsFromMATime(tasksnap["system_time_in_terminated_threads"], timebase)
        tsnap["pageIns"] = tasksnap["pageins"]
        tsnap["pageFaults"] = tasksnap["faults"]
        tsnap["userTimeTask"] = GetSecondsFromMATime(tasksnap["user_time_in_terminated_threads"], timebase)
        tsnap["procname"] = tasksnap["p_comm"]
        tsnap["copyOnWriteFaults"] = tasksnap["cow_faults"]
        tsnap["timesThrottled"] = tasksnap["was_throttled"]
        tsnap["threadById"] = {}
        threadByID = tsnap["threadById"]
        thlist = piddata.get('STACKSHOT_KCCONTAINER_THREAD', {})
        for tid,thdata in thlist.iteritems():
            threadByID[str(tid)] = {}
            thsnap = threadByID[str(tid)]
            threadsnap = thdata["thread_snapshot_v2"]
            thsnap["userTime"] = GetSecondsFromMATime(threadsnap["user_time"], timebase)
            thsnap["id"] = threadsnap["thread_id"]
            thsnap["basePriority"] = threadsnap["base_priority"]
            thsnap["systemTime"] = threadsnap["sys_time"]
            thsnap["schedPriority"] = threadsnap["sched_priority"]
            thsnap["state"] = GetStateDescription(threadsnap['state'])
            thsnap["qosEffective"] = threadsnap["ts_eqos"]
            thsnap["qosRequested"] = threadsnap["ts_rqos"]

            if threadsnap['continuation']:
                thsnap["continuation"] = GetSymbolInfoForFrame(AllImageCatalog, pr_libs, threadsnap['continuation'])
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
            if threadsnap['wait_event']:
                thsnap["waitEvent"] = GetSymbolInfoForFrame(AllImageCatalog, pr_libs, threadsnap['wait_event'])

    obj['binaryImages'] = AllImageCatalog
    fh = open(outfile_name, "w")
    fh.write('{"bug_type":"288", "timestamp":"'+ timestamp +'", "os_version":"'+ os_version +'"}\n')
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

def ProcessDyldSharedCacheFile(shared_cache_file_path, sdk_str=""):
    """ returns (uuid, text_info) output from shared_cache_util.
                In case of error None is returned and err message is printed to stdout.
    """
    if not os.path.exists(shared_cache_file_path):
        print "File path: %s does not exists" % shared_cache_file_path
        return None
    if sdk_str:
        sdk_str = ' -sdk "%s" ' % sdk_str
    (c, so) = RunCommand("xcrun {} -find dyld_shared_cache_util".format(sdk_str))
    if c:
        print "Failed to find path to dyld_shared_cache_util. Exit code: %d , message: %s" % (c,so)
        return None
    dyld_shared_cache_util = so.strip()
    (c, so) = RunCommand("{} -info {}".format(dyld_shared_cache_util, shared_cache_file_path))
    if c:
        print "Failed to get uuid info from %s" % shared_cache_file_path
        print so
        return None

    uuid = so.splitlines()[0].split(": ")[-1].strip().replace("-","").lower()
    
    (c, so) = RunCommand("{} -text_info {}".format(dyld_shared_cache_util, shared_cache_file_path))
    if c:
        print "Failed to get text_info from %s" % shared_cache_file_path
        print so
        return None
    
    print "Found %s uuid: %s" % (shared_cache_file_path, uuid)
    text_info = so

    return (uuid, so)

parser = argparse.ArgumentParser(description="Decode a kcdata binary file.")
parser.add_argument("-l", "--listtypes", action="store_true", required=False, default=False,
                    help="List all known types",
                    dest="list_known_types")

parser.add_argument("-s", "--stackshot", required=False, default=False,
                    help="Generate a stackshot report file",
                    dest="stackshot_file")

parser.add_argument("-U", "--uuid", required=False, default="", help="UUID of dyld shared cache to be analysed and filled in libs of stackshot report", dest="uuid")
parser.add_argument("-L", "--layout", required=False, type=argparse.FileType("r"), help="Path to layout file for DyldSharedCache. You can generate one by doing \n\tbash$xcrun -sdk <sdk> dyld_shared_cache_util -text_info </path/to/dyld_shared_cache> ", dest="layout")
parser.add_argument("-S", "--sdk", required=False, default="", help="sdk property passed to xcrun command to find the required tools. Default is empty string.", dest="sdk")
parser.add_argument("-D", "--dyld_shared_cache", required=False, default="", help="Path to dyld_shared_cache built by B&I", dest="dsc")
parser.add_argument("kcdata_file", type=argparse.FileType('r'), help="Path to a kcdata binary file.")



if __name__ == '__main__':
    args = parser.parse_args()

    if args.list_known_types:
        for (n, t) in KNOWN_TYPES_COLLECTION.items():
            print "%d : %s " % (n, str(t))
        sys.exit(1)

    file_name = args.kcdata_file.name
    master_objs = []
    master_container = None
    current_container = None
    for i in kcdata_item_iterator(file_name):
        #print "processed " + str(i)
        o = KCObject.FromKCItem(i)
        if o.IsContainerType():
            o = KCContainerObject(i.i_type, i.i_data, i.i_flags)

        if current_container is None:
            master_objs.append(o)
            current_container = o
            master_container = o
        else:
            current_container.AddObject(o)

        if o.IsContainerType():
            master_objs.append(current_container)
            current_container = o

        if o.IsContainerEnd():
            current_container = master_objs.pop()
    str_data = "{" + master_container.GetJsonRepr() + "}"
    try:
        json_obj = json.loads(str_data)
        dsc_uuid = None
        dsc_libs_arr = []
        libs_re = re.compile("^\s*(0x[a-fA-F0-9]+)\s->\s(0x[a-fA-F0-9]+)\s+<([a-fA-F0-9\-]+)>\s+.*$", re.MULTILINE)
        if args.uuid and args.layout:
            dsc_uuid = args.uuid.strip().replace("-",'').lower()
            dsc_libs_arr = libs_re.findall(args.layout.read())

        if args.dsc:
            _ret = ProcessDyldSharedCacheFile(args.dsc, args.sdk)
            if _ret:
                dsc_uuid = _ret[0]
                dsc_libs_arr = libs_re.findall(_ret[1])

        if args.stackshot_file:
            SaveStackshotReport(json_obj, args.stackshot_file, dsc_uuid, dsc_libs_arr)
        else:
            print json.dumps(json_obj, sort_keys=True, indent=4, separators=(',', ': '))

    except Exception, e:
        raise
        print e
        print "--------------------------------------------"*3
        print str_data
