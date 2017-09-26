import sys
import macholib
from macholib import MachO as macho
from collections import namedtuple
import re

# some fixups in macholib that are required for kext support
macholib.mach_o.MH_KEXT_BUNDLE = 0xB

macholib.mach_o.MH_FILETYPE_NAMES[macholib.mach_o.MH_KEXT_BUNDLE] = "kext bundle"
macholib.mach_o.MH_FILETYPE_SHORTNAMES[macholib.mach_o.MH_KEXT_BUNDLE] = "kext"

_old_MachOHeader_load = macho.MachOHeader.load
def new_load(s, fh):
    try:
        _old_MachOHeader_load(s, fh)
    except ValueError as e:
        if str(e.message).find('total_size > low_offset') >= 0:
            pass
        else:
            raise
    except Exception as e:
        raise
macho.MachOHeader.load = new_load

class MemFile(object):
    def __init__(self, memory, size):
        self._start = 0
        self._readp = 0
        self._end = size
        self._mem = memory

    def tell(self):
        return self._readp

    def check_bounds(self, seek_position, operation):
        if not (self._start <= seek_position <= self._end):
            raise IOError("%s to offset %d failed bounds check [%d, %d]" % (
                operation, seek_position, self._start, self._end))

    def seek(self, offset, whence=0):
        seekto = offset
        if whence == 0:
            seekto += self._start
        elif whence == 1:
            seekto += self.tell()
        elif whence == 2:
            seekto += self._end
        else:
            raise IOError("Invalid whence argument to seek: %r" % (whence,))
        self.check_bounds(seekto, 'seek')
        self._readp = seekto

    def write(self, bytes):
        raise NotImplementedError('write is not supported')

    def read(self, size=sys.maxsize):
        if size < 0:
            raise ValueError("Invalid size {} while reading from {}".format(size, self._fileobj))
        here = self.tell()
        self.check_bounds(here, 'read')
        bytes = min(size, self._end - here)
        retval = self._mem[self._readp:self._readp + bytes]
        self._readp += bytes
        return retval

MachOSegment = namedtuple('MachOSegment', 'name vmaddr vmsize fileoff filesize')

class MemMacho(macho.MachO):

    def __init__(self, memdata, size=None):
        if size is None:
            super(MemMacho,self).__init__(memdata)
            return
        #
        # supports the ObjectGraph protocol
        self.graphident = 'mem:%d//'.format(size)
        self.filename = 'mem:%d//'.format(size)

        # initialized by load
        self.fat = None
        self.headers = []
        fp = MemFile(memdata, size)
        self.load(fp)


    def get_segments_with_name(self, filter_re):
        """ param: filter_re is a compiled re which will be matched against segment name.
                    Use: '' to match anything and everything
            returns: [ MachOSegment, MachOSegment, ... ]
        """
        if type(filter_re) is str:
            filter_re = re.compile(filter_re)
        retval = []
        for h in self.headers:
            for cmd in h.commands:
                # cmds is [(load_command, segment, [sections..])]
                (lc, segment, sections) = cmd
                if isinstance(segment, SEGMENT_TYPES):
                    segname = segment.segname[:segment.segname.find('\x00')]
                    if filter_re.match(segname):
                        retval.append(MachOSegment(segname, segment.vmaddr, segment.vmsize, segment.fileoff, segment.filesize))
        return retval

    def get_sections_with_name(self, filter_re):
        """ param: filter_re is a compiled re which will be matched against <segment_name>.<section_name>
                    Use: '' to match anything and everything
            returns: [ MachOSegment, MachOSegment, ... ]
                     where each MachOSegment.name is <segment_name>.<section_name>
        """
        if type(filter_re) is str:
            filter_re = re.compile(filter_re)
        retval = []
        for h in self.headers:
            for cmd in h.commands:
                # cmds is [(load_command, segment, [sections..])]
                (lc, segment, sections) = cmd
                if isinstance(segment, SEGMENT_TYPES):
                    segname = segment.segname[:segment.segname.find('\x00')]
                    for section in sections:
                        section_name = section.sectname[:section.sectname.find('\x00')]
                        full_section_name= "{}.{}".format(segname, section_name)
                        if filter_re.match(full_section_name):
                            retval.append(MachOSegment(full_section_name, section.addr, section.size, section.offset, section.size))
        return retval


    def get_uuid(self):
        retval = ''
        for h in self.headers:
            for cmd in h.commands:
                # cmds is [(load_command, segment, [sections..])]
                (lc, segment, sections) = cmd
                if isinstance(segment, macholib.mach_o.uuid_command):
                    retval = GetUUIDSummary(segment.uuid)
        return retval

def get_text_segment(segments):
    retval = None
    for s in segments:
        if s.name == '__TEXT_EXEC':
            return s
    for s in segments:
        if s.name == '__TEXT':
            return s
    return retval

def get_segment_with_addr(segments, addr):
    """ param: segments [MachOSegment, ...]
        return: None or MachOSegment where addr is in vmaddr...(vmaddr+vmsize)
    """
    for s in segments:
        if addr >= s.vmaddr and addr < (s.vmaddr + s.vmsize):
            return s
    return None

def GetUUIDSummary(arr):
    data = []
    for i in range(16):
        data.append(ord(arr[i]))
    return "{a[0]:02X}{a[1]:02X}{a[2]:02X}{a[3]:02X}-{a[4]:02X}{a[5]:02X}-{a[6]:02X}{a[7]:02X}-{a[8]:02X}{a[9]:02X}-{a[10]:02X}{a[11]:02X}{a[12]:02X}{a[13]:02X}{a[14]:02X}{a[15]:02X}".format(a=data)

SEGMENT_TYPES = (macholib.mach_o.segment_command_64, macholib.mach_o.segment_command)

def get_load_command_human_name(cmd):
    """ return string name of LC_LOAD_DYLIB => "load_dylib"
        "<unknown>" if not found
    """
    retval = "<unknown>"
    if cmd in macho.LC_REGISTRY:
        retval = macho.LC_REGISTRY[cmd].__name__
        retval = retval.replace("_command","")
    return retval

class VisualMachoMap(object):
    KB_1 = 1024
    KB_16 = 16 * 1024
    MB_1 = 1 * 1024 * 1024
    GB_1 = 1 * 1024 * 1024 * 1024

    def __init__(self, name, width=40):
        self.name = name
        self.width = 40
        self.default_side_padding = 2

    def get_header_line(self):
        return '+' + '-' * (self.width - 2) + '+'

    def get_space_line(self):
        return '|' + ' ' * (self.width - 2) + '|'

    def get_dashed_line(self):
        return '|' + '-' * (self.width - 2) + '|'

    def get_dotted_line(self):
        return '|' + '.' * (self.width - 2) + '|'

    def center_text_in_line(self, line, text):
        even_length = bool(len(text) % 2 == 0)
        if len(text) > len(line) - 2:
            raise ValueError("text is larger than line of text")

        lbreak_pos = len(line)/2 - len(text)/2
        if not even_length:
            lbreak_pos -= 1
        out = line[:lbreak_pos] + text
        return out + line[len(out):]

    def get_separator_lines(self):
        return ['/' + ' ' * (self.width - 2) + '/', '/' + ' ' * (self.width - 2) + '/']

    def printMachoMap(self, mobj):
        MapBlock = namedtuple('MapBlock', 'name vmaddr vmsize fileoff filesize extra_info is_segment')
        outstr = self.name + '\n'
        other_cmds = ''
        blocks = []
        for hdr in mobj.headers:
            cmd_index = 0
            for cmd in hdr.commands:
                # cmds is [(load_command, segment, [sections..])]
                (lc, segment, sections) = cmd
                lc_cmd_str = get_load_command_human_name(lc.cmd)
                lc_str_rep = "\n\t LC: {:s} size:{:d} nsects:{:d}".format(lc_cmd_str, lc.cmdsize, len(sections))
                # print lc_str_rep
                if isinstance(segment, SEGMENT_TYPES):
                    segname = segment.segname[:segment.segname.find('\x00')]
                    # print "\tsegment: {:s} vmaddr: {:x} vmsize:{:d} fileoff: {:x} filesize: {:d}".format(
                    #             segname, segment.vmaddr, segment.vmsize, segment.fileoff, segment.filesize)
                    blocks.append(MapBlock(segname, segment.vmaddr, segment.vmsize, segment.fileoff, segment.filesize,
                                            ' LC:{} : {} init:{:#0X} max:{:#0X}'.format(lc_cmd_str, segname, segment.initprot, segment.maxprot),
                                            True))
                    for section in sections:
                        section_name = section.sectname[:section.sectname.find('\x00')]
                        blocks.append(MapBlock(section_name, section.addr, section.size, section.offset,
                                                section.size, 'al:{} flags:{:#0X}'.format(section.align, section.flags), False))
                        #print "\t\tsection:{:s} addr:{:x} off:{:x} size:{:d}".format(section_name, section.addr, section.offset, section.size)
                elif isinstance(segment, macholib.mach_o.uuid_command):
                    other_cmds += "\n\t uuid: {:s}".format(GetUUIDSummary(segment.uuid))
                elif isinstance(segment, macholib.mach_o.rpath_command):
                    other_cmds += "\n\t rpath: {:s}".format(segment.path)
                elif isinstance(segment, macholib.mach_o.dylib_command):
                    other_cmds += "\n\t dylib: {:s} ({:s})".format(str(sections[:sections.find('\x00')]), str(segment.current_version))
                else:
                    other_cmds += lc_str_rep
                cmd_index += 1

        # fixup the self.width param
        for _b in blocks:
            if self.default_side_padding + len(_b.name) + 2 > self.width:
                self.width = self.default_side_padding + len(_b.name) + 2
        if self.width % 2 != 0:
            self.width += 1

        sorted_blocks = sorted(blocks, key=lambda b: b.vmaddr)
        mstr = [self.get_header_line()]
        prev_block = MapBlock('', 0, 0, 0, 0, '', False)
        for b in sorted_blocks:
            # TODO add separator blocks if vmaddr is large from prev_block
            if b.is_segment:
                s = self.get_dashed_line()
            else:
                s = self.get_dotted_line()
            s = self.center_text_in_line(s, b.name)
            line = "{:s} {: <#020X} ({: <10d}) floff:{: <#08x}  {}".format(s, b.vmaddr, b.vmsize, b.fileoff, b.extra_info)
            if (b.vmaddr - prev_block.vmaddr) > VisualMachoMap.KB_16:
                mstr.append(self.get_space_line())
                mstr.append(self.get_space_line())

            mstr.append(line)

            if b.vmsize > VisualMachoMap.MB_1:
                mstr.append(self.get_space_line())
                mstr.extend(self.get_separator_lines())
                mstr.append(self.get_space_line())
            #mstr.append(self.get_space_line())
            prev_block = b
        mstr.append(self.get_space_line())
        if prev_block.vmsize > VisualMachoMap.KB_16:
            mstr.append(self.get_space_line())
        mstr.append(self.get_header_line())
        print outstr
        print "\n".join(mstr)
        print "\n\n=============== Other Load Commands ==============="
        print other_cmds


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print "Usage: {} /path/to/macho_binary".format(sys.argv[0])
        sys.exit(1)
    with open(sys.argv[-1], 'rb') as fp:
        data = fp.read()
    mobject = MemMacho(data, len(data))

    p = VisualMachoMap(sys.argv[-1])
    p.printMachoMap(mobject)
    sys.exit(0)

