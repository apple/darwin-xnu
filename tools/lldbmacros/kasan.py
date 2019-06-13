from xnu import *
from utils import *
from core.configuration import *

shift = None

shadow_strings = {
    0x00: 'VALID',
    0x01: 'PARTIAL1',
    0x02: 'PARTIAL2',
    0x03: 'PARTIAL3',
    0x04: 'PARTIAL4',
    0x05: 'PARTIAL5',
    0x06: 'PARTIAL6',
    0x07: 'PARTIAL7',
    0xac: 'ARRAY_COOKIE',
    0xf0: 'STACK_RZ',
    0xf1: 'STACK_LEFT_RZ',
    0xf2: 'STACK_MID_RZ',
    0xf3: 'STACK_RIGHT_RZ',
    0xf5: 'STACK_FREED',
    0xf8: 'STACK_OOSCOPE',
    0xf9: 'GLOBAL_RZ',
    0xe9: 'HEAP_RZ',
    0xfa: 'HEAP_LEFT_RZ',
    0xfb: 'HEAP_RIGHT_RZ',
    0xfd: 'HEAP_FREED'
}

def is_kasan_build():
    try:
        enable = kern.globals.kasan_enabled
        return True
    except ValueError, e:
        return False

def shadow_for_address(addr, shift):
    return ((addr >> 3) + shift)

def address_for_shadow(addr, shift):
    return ((addr - shift) << 3)

def get_shadow_byte(shadow_addr):
    return unsigned(kern.GetValueFromAddress(shadow_addr, 'uint8_t *')[0])

def print_legend():
    for (k,v) in shadow_strings.iteritems():
        print " {:02x}: {}".format(k,v)

def print_shadow_context(addr, context):
    addr = shadow_for_address(addr, shift)
    base = (addr & ~0xf) - 16 * context
    shadow = kern.GetValueFromAddress(unsigned(base), "uint8_t *")

    print " "*17 + "  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f"
    for x in range(0, 2*context+1):
        vals = ""
        l = " "
        for y in xrange(x*16, (x+1)*16):
            r = " "
            if base+y == addr:
                l = "["
                r = "]"
            elif base+y+1 == addr:
                r = ""
            sh = shadow[y]
            vals += "{}{:02x}{}".format(l, sh, r)
            l = ""
        print("{:x}:{}".format(base + 16*x, vals))

kasan_guard_size = 16
def print_alloc_free_entry(addr, orig_ptr):
    h = kern.GetValueFromAddress(addr, 'struct freelist_entry *')
    asz = unsigned(h.size)
    usz = unsigned(h.user_size)
    pgsz = unsigned(kern.globals.page_size)

    if h.zone:
        zone = h.zone
        if str(zone.zone_name).startswith("fakestack"):
            alloc_type = "fakestack"
            leftrz = 16
        else:
            alloc_type = "zone"
            leftrz = unsigned(zone.kasan_redzone)
    else:
        alloc_type = "kalloc"
        if asz - usz >= 2*pgsz:
            leftrz = pgsz
        else:
            leftrz = kasan_guard_size

    rightrz = asz - usz - leftrz

    print "Freed {} object".format(alloc_type)
    print "Valid range: 0x{:x} -- 0x{:x} ({} bytes)".format(addr + leftrz, addr + leftrz + usz - 1, usz)
    print "Total range: 0x{:x} -- 0x{:x} ({} bytes)".format(addr, addr + asz - 1, asz)
    print "Offset:      {} bytes".format(orig_ptr - addr - leftrz)
    print "Redzone:     {} / {} bytes".format(leftrz, rightrz)
    if h.zone:
        print "Zone:        0x{:x} <{:s}>".format(unsigned(zone), zone.zone_name)

    btframes = unsigned(h.frames)
    if btframes > 0:
        print "",
        print "Free site backtrace ({} frames):".format(btframes)
        for i in xrange(0, btframes):
            fr = unsigned(kern.globals.vm_kernel_slid_base) + unsigned(h.backtrace[i])
            print " #{:}: {}".format(btframes-i-1, GetSourceInformationForAddress(fr))

    print "",
    print_hexdump(addr, asz, 1)

alloc_header_sz = 16

def magic_for_addr(addr, xor):
    magic = addr & 0xffff
    magic ^= (addr >> 16) & 0xffff
    magic ^= (addr >> 32) & 0xffff
    magic ^= (addr >> 48) & 0xffff
    magic ^= xor
    return magic

def print_alloc_info(_addr):
    addr = (_addr & ~0x7)

    _shp = shadow_for_address(_addr, shift)
    _shbyte = get_shadow_byte(_shp)
    _shstr = shadow_byte_to_string(_shbyte)

    # If we're in a left redzone, scan to the start of the real allocation, where
    # the header should live
    shbyte = _shbyte
    while shbyte == 0xfa:
        addr += 8
        shbyte = get_shadow_byte(shadow_for_address(addr, shift))

    # Search backwards for an allocation
    searchbytes = 0
    while searchbytes < 8*4096:

        shp = shadow_for_address(addr, shift)
        shbyte = get_shadow_byte(shp)
        shstr = shadow_byte_to_string(shbyte)

        headerp = addr - alloc_header_sz
        liveh = kern.GetValueFromAddress(headerp, 'struct kasan_alloc_header *')
        freeh = kern.GetValueFromAddress(addr, 'struct freelist_entry *')

        # heap allocations should only ever have these shadow values
        if shbyte not in (0,1,2,3,4,5,6,7, 0xfa, 0xfb, 0xfd, 0xf5):
            print "No allocation found at 0x{:x} (found shadow {:x})".format(_addr, shbyte)
            return

        if magic_for_addr(addr, 0x3a65) == unsigned(liveh.magic):
            usz = unsigned(liveh.user_size)
            asz = unsigned(liveh.alloc_size)
            leftrz = unsigned(liveh.left_rz)
            base = headerp + alloc_header_sz - leftrz

            if _addr >= base and _addr < base + asz:
                footer = kern.GetValueFromAddress(addr + usz, 'struct kasan_alloc_footer *')
                rightrz = asz - usz - leftrz
                offset = _addr - addr

                print "Live heap object"
                print "Valid range: 0x{:x} -- 0x{:x} ({} bytes)".format(addr, addr + usz - 1, usz)
                print "Total range: 0x{:x} -- 0x{:x} ({} bytes)".format(base, base + asz - 1, asz)
                print "Offset:      {} bytes (shadow: 0x{:02x} {}, remaining: {} bytes)".format(offset, _shbyte, _shstr, usz - offset)
                print "Redzone:     {} / {} bytes".format(leftrz, rightrz)

                btframes = unsigned(liveh.frames)
                print "",
                print "Alloc site backtrace ({} frames):".format(btframes)
                for i in xrange(0, btframes):
                    fr = unsigned(kern.globals.vm_kernel_slid_base) + unsigned(footer.backtrace[i])
                    print " #{:}: {}".format(btframes-i-1, GetSourceInformationForAddress(fr))

                print "",
                print_hexdump(base, asz, 1)
            return

        elif magic_for_addr(addr, 0xf233) == unsigned(freeh.magic):
            asz = unsigned(freeh.size)
            if _addr >= addr and _addr < addr + asz:
                print_alloc_free_entry(addr, _addr)
            return

        searchbytes += 8
        addr -= 8

    print "No allocation found at 0x{:x}".format(_addr)

def shadow_byte_to_string(sb):
    return shadow_strings.get(sb, '??')

def print_whatis(_addr, ctx):
    addr = _addr & ~0x7
    total_size = 0
    base = None
    leftrz = None
    rightrz = None
    extra = "Live"

    shaddr = shadow_for_address(addr, shift)
    try:
        shbyte = get_shadow_byte(shaddr)
    except:
        print "Unmapped shadow 0x{:x} for address 0x{:x}".format(shaddr, addr)
        return

    maxsearch = 8*4096

    if shbyte in [0xfa, 0xfb, 0xfd, 0xf5]:
        print_alloc_info(_addr)
        return

    if shbyte not in [0,1,2,3,4,5,6,7,0xf8]:
        print "Poisoned memory, shadow {:x} [{}]".format(shbyte, shadow_byte_to_string(shbyte))
        return

    if shbyte is 0xf8:
        extra = "Out-of-scope"

    # look for the base of the object
    while shbyte in [0,1,2,3,4,5,6,7,0xf8]:
        sz = 8 - shbyte
        if shbyte is 0xf8:
            sz = 8
        total_size += sz
        addr -= 8
        shbyte = get_shadow_byte(shadow_for_address(addr, shift))
        maxsearch -= 8
        if maxsearch <= 0:
            print "No object found"
            return
    base = addr + 8
    leftrz = shbyte

    # If we did not find a left/mid redzone, we aren't in an object
    if leftrz not in [0xf1, 0xf2, 0xfa, 0xf9]:
        print "No object found"
        return

    # now size the object
    addr = (_addr & ~0x7) + 8
    shbyte = get_shadow_byte(shadow_for_address(addr, shift))
    while shbyte in [0,1,2,3,4,5,6,7,0xf8]:
        sz = 8 - shbyte
        if shbyte is 0xf8:
            sz = 8
        total_size += sz
        addr += 8
        shbyte = get_shadow_byte(shadow_for_address(addr, shift))
        maxsearch -= 8
        if maxsearch <= 0:
            print "No object found"
            return
    rightrz = shbyte

    # work out the type of the object from its redzone
    objtype = "Unknown"
    if leftrz == 0xf1 or leftrz == 0xf2:
        objtype = "stack"
    elif leftrz == 0xf9 and rightrz == 0xf9:
        objtype = "global"
    elif leftrz == 0xfa and rightrz == 0xfb:
        print_alloc_info(_addr)
        return

    print "{} {} object".format(extra, objtype)
    print "Valid range: 0x{:x} -- 0x{:x} ({} bytes)".format(base, base+total_size-1, total_size)
    print "Offset:      {} bytes".format(_addr - base)
    print "",
    print_hexdump(base, total_size, 1)

def print_hexdump(base, size, ctx):
    if size < 16:
        size = 16
    base -= base % 16
    start = base - 16*ctx
    size += size % 16
    size = min(size + 16*2*ctx, 256)

    try:
        data_array = kern.GetValueFromAddress(start, "uint8_t *")
        print_hex_data(data_array[0:size], start, "Hexdump")
    except:
        pass

def kasan_subcommand(cmd, args, opts):
    addr = None
    if len(args) > 0:
        addr = long(args[0], 0)

    if cmd in ['a2s', 'toshadow', 'fromaddr', 'fromaddress']:
        print "0x{:016x}".format(shadow_for_address(addr, shift))
    elif cmd in ['s2a', 'toaddr', 'toaddress', 'fromshadow']:
        print "0x{:016x}".format(address_for_shadow(addr, shift))
    elif cmd == 'shadow':
        shadow = shadow_for_address(addr, shift)
        sb = get_shadow_byte(shadow)
        print("0x{:02x} @ 0x{:016x} [{}]\n\n".format(sb, shadow, shadow_byte_to_string(sb)))
        ctx = long(opts.get("-C", 5))
        print_shadow_context(addr, ctx)
    elif cmd == 'key' or cmd == 'legend':
        print_legend()
    elif cmd == 'info':
        pages_used = unsigned(kern.globals.shadow_pages_used)
        pages_total = unsigned(kern.globals.shadow_pages_total)
        nkexts = unsigned(kern.globals.kexts_loaded)
        print "Offset:       0x{:016x}".format(shift)
        print "Shadow used:  {} / {} ({:.1f}%)".format(pages_used, pages_total, 100.0*pages_used/pages_total)
        print "Kexts loaded: {}".format(nkexts)
    elif cmd == 'whatis':
        ctx = long(opts.get("-C", 1))
        print_whatis(addr, ctx)
    elif cmd == 'alloc' or cmd == 'heap':
        print_alloc_info(addr)
    else:
        print "Unknown subcommand: `{}'".format(cmd)

@lldb_command('kasan', 'C:')
def Kasan(cmd_args=None, cmd_options={}):
    """kasan <cmd> [opts..]

    Commands:

      info               basic KASan information
      shadow <addr>      print shadow around 'addr'
      heap <addr>        show info about heap object at 'addr'
      whatis <addr>      print whatever KASan knows about address
      toshadow <addr>    convert address to shadow pointer
      toaddr <shdw>      convert shadow pointer to address
      legend             print a shadow byte table

    -C <num> : num lines of context to show"""

    if not is_kasan_build():
        print "KASan not enabled in build"
        return

    if len(cmd_args) == 0:
        print Kasan.__doc__
        return

    global shift
    shift = unsigned(kern.globals.__asan_shadow_memory_dynamic_address)

    # Since the VM is not aware of the KASan shadow mapping, accesses to it will
    # fail. Setting kdp_read_io=1 avoids this check.
    if GetConnectionProtocol() == "kdp" and unsigned(kern.globals.kdp_read_io) == 0:
        print "Setting kdp_read_io=1 to allow KASan shadow reads"
        if sizeof(kern.globals.kdp_read_io) == 4:
            WriteInt32ToMemoryAddress(1, addressof(kern.globals.kdp_read_io))
        elif sizeof(kern.globals.kdp_read_io) == 8:
            WriteInt64ToMemoryAddress(1, addressof(kern.globals.kdp_read_io))
        readio = unsigned(kern.globals.kdp_read_io)
        assert readio == 1

    return kasan_subcommand(cmd_args[0], cmd_args[1:], cmd_options)

