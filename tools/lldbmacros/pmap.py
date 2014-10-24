from xnu import *
import xnudefines
from kdp import *
from utils import *

def ReadPhysInt(phys_addr, bitsize = 64, cpuval = None):
    """ Read a physical memory data based on address.
        params:
            phys_addr : int - Physical address to read
            bitsize   : int - defines how many bytes to read. defaults to 64 bit
            cpuval    : None (optional)
        returns:
            int - int value read from memory. in case of failure 0xBAD10AD is returned.
    """
    if "kdp" == GetConnectionProtocol():
        return KDPReadPhysMEM(phys_addr, bitsize)

    #NO KDP. Attempt to use physical memory
    paddr_in_kva = kern.PhysToKernelVirt(long(phys_addr))
    if paddr_in_kva :
        if bitsize == 64 :
            return kern.GetValueFromAddress(paddr_in_kva, 'uint64_t *').GetSBValue().Dereference().GetValueAsUnsigned()
        if bitsize == 32 :
            return kern.GetValueFromAddress(paddr_in_kva, 'uint32_t *').GetSBValue().Dereference().GetValueAsUnsigned()
        if bitsize == 16 :
            return kern.GetValueFromAddress(paddr_in_kva, 'uint16_t *').GetSBValue().Dereference().GetValueAsUnsigned()
        if bitsize == 8 :
            return kern.GetValueFromAddress(paddr_in_kva, 'uint8_t *').GetSBValue().Dereference().GetValueAsUnsigned()
    return 0xBAD10AD

@lldb_command('readphys')
def ReadPhys(cmd_args = None):
    """ Reads the specified untranslated address
        The argument is interpreted as a physical address, and the 64-bit word
        addressed is displayed.
        usage: readphys <nbits> <address>
        nbits: 8,16,32,64
        address: 1234 or 0x1234
    """
    if cmd_args == None or len(cmd_args) < 2:
        print "Insufficient arguments.", ReadPhys.__doc__
        return False
    else:
        nbits = ArgumentStringToInt(cmd_args[0])
        phys_addr = ArgumentStringToInt(cmd_args[1])
        print "{0: <#x}".format(ReadPhysInt(phys_addr, nbits))
    return True

lldb_alias('readphys8', 'readphys 8 ')
lldb_alias('readphys16', 'readphys 16 ')
lldb_alias('readphys32', 'readphys 32 ')
lldb_alias('readphys64', 'readphys 64 ')

def KDPReadPhysMEM(address, bits):
    """ Setup the state for READPHYSMEM64 commands for reading data via kdp
        params:
            address : int - address where to read the data from
            bits : int - number of bits in the intval (8/16/32/64)
        returns:
            int: read value from memory.
            0xBAD10AD: if failed to read data.
    """
    retval = 0xBAD10AD
    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Nothing to do here."
        return retval

    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        return retval

    kdp_pkt_size = GetType('kdp_readphysmem64_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        return retval

    data_addr = int(addressof(kern.globals.manual_pkt))
    pkt = kern.GetValueFromAddress(data_addr, 'kdp_readphysmem64_req_t *')

    header_value =GetKDPPacketHeaderInt(request=GetEnumValue('kdp_req_t::KDP_READPHYSMEM64'), length=kdp_pkt_size)

    if ( WriteInt64ToMemoryAddress((header_value), int(addressof(pkt.hdr))) and
         WriteInt64ToMemoryAddress(address, int(addressof(pkt.address))) and
         WriteInt32ToMemoryAddress((bits/8), int(addressof(pkt.nbytes))) and
         WriteInt16ToMemoryAddress(xnudefines.lcpu_self, int(addressof(pkt.lcpu)))
         ):

        if WriteInt32ToMemoryAddress(1, input_address):
            # now read data from the kdp packet
            data_address = unsigned(addressof(kern.GetValueFromAddress(int(addressof(kern.globals.manual_pkt.data)), 'kdp_readphysmem64_reply_t *').data))
            if bits == 64 :
                retval =  kern.GetValueFromAddress(data_address, 'uint64_t *').GetSBValue().Dereference().GetValueAsUnsigned()
            if bits == 32 :
                retval =  kern.GetValueFromAddress(data_address, 'uint32_t *').GetSBValue().Dereference().GetValueAsUnsigned()
            if bits == 16 :
                retval =  kern.GetValueFromAddress(data_address, 'uint16_t *').GetSBValue().Dereference().GetValueAsUnsigned()
            if bits == 8 :
                retval =  kern.GetValueFromAddress(data_address, 'uint8_t *').GetSBValue().Dereference().GetValueAsUnsigned()
    return retval


def KDPWritePhysMEM(address, intval, bits):
    """ Setup the state for WRITEPHYSMEM64 commands for saving data in kdp
        params:
            address : int - address where to save the data
            intval : int - integer value to be stored in memory
            bits : int - number of bits in the intval (8/16/32/64)
        returns:
            boolean: True if the write succeeded.
    """
    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Nothing to do here."
        return False
    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        return False

    kdp_pkt_size = GetType('kdp_writephysmem64_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        return False

    data_addr = int(addressof(kern.globals.manual_pkt))
    pkt = kern.GetValueFromAddress(data_addr, 'kdp_writephysmem64_req_t *')

    header_value =GetKDPPacketHeaderInt(request=GetEnumValue('kdp_req_t::KDP_WRITEPHYSMEM64'), length=kdp_pkt_size)

    if ( WriteInt64ToMemoryAddress((header_value), int(addressof(pkt.hdr))) and
         WriteInt64ToMemoryAddress(address, int(addressof(pkt.address))) and
         WriteInt32ToMemoryAddress((bits/8), int(addressof(pkt.nbytes))) and
         WriteInt16ToMemoryAddress(xnudefines.lcpu_self, int(addressof(pkt.lcpu)))
         ):

        if bits == 8:
            if not WriteInt8ToMemoryAddress(intval, int(addressof(pkt.data))):
                return False
        if bits == 16:
            if not WriteInt16ToMemoryAddress(intval, int(addressof(pkt.data))):
                return False
        if bits == 32:
            if not WriteInt32ToMemoryAddress(intval, int(addressof(pkt.data))):
                return False
        if bits == 64:
            if not WriteInt64ToMemoryAddress(intval, int(addressof(pkt.data))):
                return False
        if WriteInt32ToMemoryAddress(1, input_address):
            return True
    return False


def WritePhysInt(phys_addr, int_val, bitsize = 64):
    """ Write and integer value in a physical memory data based on address.
        params:
            phys_addr : int - Physical address to read
            int_val   : int - int value to write in memory
            bitsize   : int - defines how many bytes to read. defaults to 64 bit
        returns:
            bool - True if write was successful.
    """
    if "kdp" == GetConnectionProtocol():
        if not KDPWritePhysMEM(phys_addr, int_val, bitsize):
            print "Failed to write via KDP."
            return False
        return True
    #We are not connected via KDP. So do manual math and savings.
    print "Failed: Write to physical memory is not supported for %s connection." % GetConnectionProtocol()
    return False

@lldb_command('writephys')
def WritePhys(cmd_args=None):
    """ writes to the specified untranslated address
        The argument is interpreted as a physical address, and the 64-bit word
        addressed is displayed.
        usage: writephys <nbits> <address> <value>
        nbits: 8,16,32,64
        address: 1234 or 0x1234
        value: int value to be written
        ex. (lldb)writephys 16 0x12345abcd 0x25
    """
    if cmd_args == None or len(cmd_args) < 3:
        print "Invalid arguments.", WritePhys.__doc__
    else:
        nbits = ArgumentStringToInt(cmd_args[0])
        phys_addr = ArgumentStringToInt(cmd_args[1])
        int_value = ArgumentStringToInt(cmd_args[2])
        print WritePhysInt(phys_addr, int_value, nbits)


lldb_alias('writephys8', 'writephys 8 ')
lldb_alias('writephys16', 'writephys 16 ')
lldb_alias('writephys32', 'writephys 32 ')
lldb_alias('writephys64', 'writephys 64 ')


def _PT_Step(paddr, index, verbose_level = vSCRIPT):
    """
     Step to lower-level page table and print attributes
       paddr: current page table entry physical address
       index: current page table entry index (0..511)
       verbose_level:    vHUMAN: print nothing
                         vSCRIPT: print basic information
                         vDETAIL: print basic information and hex table dump
     returns: (pt_paddr, pt_valid, pt_large)
       pt_paddr: next level page table entry physical address
                      or null if invalid
       pt_valid: 1 if $kgm_pt_paddr is valid, 0 if the walk
                      should be aborted
       pt_large: 1 if kgm_pt_paddr is a page frame address
                      of a large page and not another page table entry
    """
    entry_addr = paddr + (8 * index)
    entry = ReadPhysInt(entry_addr, 64, xnudefines.lcpu_self )
    out_string = ''
    if verbose_level >= vDETAIL:
        for pte_loop in range(0, 512):
            paddr_tmp = paddr + (8 * pte_loop)
            out_string += "{0: <#020x}:\t {1: <#020x}\n".format(paddr_tmp, ReadPhysInt(paddr_tmp, 64, xnudefines.lcpu_self))
    paddr_mask = ~((0xfff<<52) | 0xfff)
    paddr_large_mask =  ~((0xfff<<52) | 0x1fffff)
    pt_valid = False
    pt_large = False
    pt_paddr = 0
    if verbose_level < vSCRIPT:
        if entry & 0x1 :
            pt_valid = True
            pt_large = False
            pt_paddr = entry & paddr_mask
            if entry & (0x1 <<7):
                pt_large = True
                pt_paddr = entry & paddr_large_mask
    else:
        out_string+= "{0: <#020x}:\n\t{1:#020x}\n\t".format(entry_addr, entry)
        if entry & 0x1:
            out_string += " valid"
            pt_paddr = entry & paddr_mask
            pt_valid = True
        else:
            out_string += " invalid"
            pt_paddr = 0
            pt_valid = False
            #Stop decoding other bits
            entry = 0
        if entry & (0x1 << 1):
            out_string += " writable"
        else:
            out_string += " read-only"

        if entry & (0x1 << 2):
            out_string += " user"
        else:
            out_string += " supervisor"

        if entry & (0x1 << 3):
            out_string += " PWT"

        if entry & (0x1 << 4):
            out_string += " PCD"

        if entry & (0x1 << 5):
            out_string += " accessed"

        if entry & (0x1 << 6):
            out_string += " dirty"

        if entry & (0x1 << 7):
            out_string += " large"
            pt_large = True
        else:
            pt_large = False

        if entry & (0x1 << 8):
            out_string += " global"

        if entry & (0x3 << 9):
            out_string += " avail:{0:x}".format((entry >> 9) & 0x3)

        if entry & (0x1 << 63):
            out_string += " noexec"
    print out_string
    return (pt_paddr, pt_valid, pt_large)




def _PmapL4Walk(pmap_addr_val,vaddr, verbose_level = vSCRIPT):
    """ Walk the l4 pmap entry.
        params: pmap_addr_val - core.value representing kernel data of type pmap_addr_t
        vaddr : int - virtual address to walk
    """
    is_cpu64_bit = int(kern.globals.cpu_64bit)
    pt_paddr = unsigned(pmap_addr_val)
    pt_valid = (unsigned(pmap_addr_val) != 0)
    pt_large = 0
    pframe_offset = 0
    if pt_valid and is_cpu64_bit:
        # Lookup bits 47:39 of linear address in PML4T
        pt_index = (vaddr >> 39) & 0x1ff
        pframe_offset = vaddr & 0x7fffffffff
        if verbose_level > vHUMAN :
            print "pml4 (index {0:d}):".format(pt_index)
        (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
    if pt_valid:
        # Lookup bits 38:30 of the linear address in PDPT
        pt_index = (vaddr >> 30) & 0x1ff
        pframe_offset = vaddr & 0x3fffffff
        if verbose_level > vHUMAN:
            print "pdpt (index {0:d}):".format(pt_index)
        (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
    if pt_valid and not pt_large:
        #Lookup bits 29:21 of the linear address in PDPT
        pt_index = (vaddr >> 21) & 0x1ff
        pframe_offset = vaddr & 0x1fffff
        if verbose_level > vHUMAN:
            print "pdt (index {0:d}):".format(pt_index)
        (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
    if pt_valid and not pt_large:
        #Lookup bits 20:21 of linear address in PT
        pt_index = (vaddr >> 12) & 0x1ff
        pframe_offset = vaddr & 0xfff
        if verbose_level > vHUMAN:
            print "pt (index {0:d}):".format(pt_index)
        (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
    paddr = 0
    paddr_isvalid = False
    if pt_valid:
        paddr = pt_paddr + pframe_offset
        paddr_isvalid = True

    if verbose_level > vHUMAN:
        if paddr_isvalid:
            pvalue = ReadPhysInt(paddr, 32, xnudefines.lcpu_self)
            print "phys {0: <#020x}: {1: <#020x}".format(paddr, pvalue)
        else:
            print "no translation"

    return paddr

def _PmapWalkARMLevel1Section(tte, vaddr, verbose_level = vSCRIPT):
    paddr = 0
    out_string = ""
    #Supersection or just section?
    if (tte & 0x40000) == 0x40000:
        paddr = ( (tte & 0xFF000000) | (vaddr & 0x00FFFFFF) )
    else:
        paddr = ( (tte & 0xFFF00000) | (vaddr & 0x000FFFFF) )

    if verbose_level >= vSCRIPT:
        out_string += "{0: <#020x}\n\t{1: <#020x}\n\t".format(addressof(tte), tte)
        #bit [1:0] evaluated in PmapWalkARM
        # B bit 2
        b_bit = (tte & 0x4) >> 2
        # C bit 3
        c_bit = (tte & 0x8) >> 3
        #XN bit 4
        if (tte & 0x10) :
            out_string += "no-execute"
        else:
            out_string += "execute"
        #Domain bit [8:5] if not supersection
        if (tte & 0x40000) == 0x0:
            out_string += " domain ({:d})".format(((tte & 0x1e0) >> 5) )
        #IMP bit 9
        out_string += " imp({:d})".format( ((tte & 0x200) >> 9) )
        # AP bit 15 and [11:10] merged to a single 3 bit value
        access = ( (tte & 0xc00) >> 10 ) | ((tte & 0x8000) >> 13)
        out_string += xnudefines.arm_level2_access_strings[access]

        #TEX bit [14:12]
        tex_bits = ((tte & 0x7000) >> 12)
        #Print TEX, C , B all together
        out_string += " TEX:C:B({:d}{:d}{:d}:{:d}:{:d})".format(
                                                                    1 if (tex_bits & 0x4) else 0,
                                                                    1 if (tex_bits & 0x2) else 0,
                                                                    1 if (tex_bits & 0x1) else 0,
                                                                    c_bit,
                                                                    b_bit
                                                                    )
        # S bit 16
        if tte & 0x10000:
            out_string += " shareable"
        else:
            out_string += " not-shareable"
        # nG bit 17
        if tte & 0x20000 :
            out_string += " not-global"
        else:
            out_string += " global"
        # Supersection bit 18
        if tte & 0x40000:
            out_string += " supersection"
        else:
            out_string += " section"
        #NS bit 19
        if tte & 0x80000 :
            out_string += " no-secure"
        else:
            out_string += " secure"

    print out_string
    return paddr



def _PmapWalkARMLevel2(tte, vaddr, verbose_level = vSCRIPT):
    """ Pmap walk the level 2 tte.
        params:
          tte - value object
          vaddr - int
        returns: str - description of the tte + additional informaiton based on verbose_level
    """
    pte_base = kern.PhysToKernelVirt(tte & 0xFFFFFC00)
    pte_index = (vaddr >> 12) & 0xFF
    pte_base_val = kern.GetValueFromAddress(pte_base, 'pt_entry_t *')
    pte = pte_base_val[pte_index]
    out_string = ''
    if verbose_level >= vSCRIPT:
        out_string += "{0: <#020x}\n\t{1: <#020x}\n\t".format(addressof(tte), tte)
        # bit [1:0] evaluated in PmapWalkARM
        # NS bit 3
        if tte & 0x8:
            out_string += ' no-secure'
        else:
            out_string += ' secure'
        #Domain bit [8:5]
        out_string += " domain({:d})".format(((tte & 0x1e0) >> 5))
        # IMP bit 9
        out_string += " imp({:d})".format( ((tte & 0x200) >> 9))
        out_string += "\n"
    if verbose_level >= vSCRIPT:
        out_string += "second-level table (index {:d}):\n".format(pte_index)
    if verbose_level >= vDETAIL:
        for i in range(256):
            tmp = pte_base_val[i]
            out_string += "{0: <#020x}:\t{1: <#020x}\n".format(addressof(tmp), unsigned(tmp))

    paddr = 0
    if pte & 0x2:
        paddr = (unsigned(pte) & 0xFFFFF000) | (vaddr & 0xFFF)

    if verbose_level >= vSCRIPT:
        out_string += " {0: <#020x}\n\t{1: <#020x}\n\t".format(addressof(pte), unsigned(pte))
        if (pte & 0x3) == 0x0:
            out_string += " invalid"
        else:
            if (pte & 0x3) == 0x1:
                out_string += " large"
                # XN bit 15
                if pte & 0x8000 == 0x8000:
                    out_string+= " no-execute"
                else:
                    out_string += " execute"
            else:
                out_string += " small"
                # XN bit 0
                if (pte & 0x1) == 0x01:
                    out_string += " no-execute"
                else:
                    out_string += " execute"
            # B bit 2
            b_bit = (pte & 0x4) >> 2
            c_bit = (pte & 0x8) >> 3
            # AP bit 9 and [5:4], merged to a single 3-bit value
            access = (pte & 0x30) >> 4 | (pte & 0x200) >> 7
            out_string += xnudefines.arm_level2_access_strings[access]

            #TEX bit [14:12] for large, [8:6] for small
            tex_bits = ((pte & 0x1c0) >> 6)
            if (pte & 0x3) == 0x1:
                tex_bits = ((pte & 0x7000) >> 12)

            # Print TEX, C , B alltogether
            out_string += " TEX:C:B({:d}{:d}{:d}:{:d}:{:d})".format(
                                                                    1 if (tex_bits & 0x4) else 0,
                                                                    1 if (tex_bits & 0x2) else 0,
                                                                    1 if (tex_bits & 0x1) else 0,
                                                                    c_bit,
                                                                    b_bit
                                                                    )
            # S bit 10
            if pte & 0x400 :
                out_string += " shareable"
            else:
                out_string += " not-shareable"

            # nG bit 11
            if pte & 0x800:
                out_string += " not-global"
            else:
                out_string += " global"
    print out_string
    return paddr
    #end of level 2 walking of arm


def PmapWalkARM(pmap, vaddr, verbose_level = vHUMAN):
    """ Pmap walking for ARM kernel.
        params:
          pmapval: core.value - representing pmap_t in kernel
          vaddr:  int     - integer representing virtual address to walk
    """
    paddr = 0
    # shift by TTESHIFT (20) to get tte index
    tte_index = ((vaddr - unsigned(pmap.min)) >> 20 )
    tte = pmap.tte[tte_index]
    if verbose_level >= vSCRIPT:
        print "First-level table (index {:d}):".format(tte_index)
    if verbose_level >= vDETAIL:
        for i in range(0, 4096):
            ptr = unsigned(addressof(pmap.tte[i]))
            val = unsigned(pmap.tte[i])
            print "{0: <#020x}:\t {1: <#020x}".format(ptr, val)
    if (tte & 0x3) == 0x1:
        paddr = _PmapWalkARMLevel2(tte, vaddr, verbose_level)
    elif (tte & 0x3) == 0x2 :
        paddr = _PmapWalkARMLevel1Section(tte, vaddr, verbose_level)
    else:
        paddr = 0
        if verbose_level >= vSCRIPT:
            print "Invalid First-Level Translation Table Entry: {0: #020x}".format(tte)

    if verbose_level >= vHUMAN:
        if paddr:
            print "Translation of {:#x} is {:#x}.".format(vaddr, paddr)
        else:
            print "(no translation)"

    return paddr

def PmapWalkX86_64(pmapval, vaddr):
    """
        params: pmapval - core.value representing pmap_t in kernel
        vaddr:  int     - int representing virtual address to walk
    """
    return _PmapL4Walk(pmapval.pm_cr3, vaddr, config['verbosity'])

def assert_64bit(val):
    assert(val < 2**64)

ARM64_TTE_SIZE = 8
ARM64_VMADDR_BITS = 48

def PmapBlockOffsetMaskARM64(level):
    assert level >= 1 and level <= 3
    page_size = kern.globals.page_size
    ttentries = (page_size / ARM64_TTE_SIZE)
    return page_size * (ttentries ** (3 - level)) - 1

def PmapBlockBaseMaskARM64(level):
    assert level >= 1 and level <= 3
    page_size = kern.globals.page_size
    return ((1 << ARM64_VMADDR_BITS) - 1) & ~PmapBlockOffsetMaskARM64(level)

def PmapIndexMaskARM64(level):
    assert level >= 1 and level <= 3
    page_size = kern.globals.page_size
    ttentries = (page_size / ARM64_TTE_SIZE)
    return page_size * (ttentries ** (3 - level) * (ttentries - 1))

def PmapIndexDivideARM64(level):
    assert level >= 1 and level <= 3
    page_size = kern.globals.page_size
    ttentries = (page_size / ARM64_TTE_SIZE)
    return page_size * (ttentries ** (3 - level))

def PmapTTnIndexARM64(vaddr, level):
    assert(type(vaddr) in (long, int))
    assert_64bit(vaddr)

    return (vaddr & PmapIndexMaskARM64(level)) // PmapIndexDivideARM64(level)

def PmapDecodeTTEARM64(tte, level):
    assert(type(tte) == long)
    assert(type(level) == int)
    assert_64bit(tte)

    if tte & 0x1 == 0x1:
        if (tte & 0x2 == 0x2) and (level != 0x3):
            print "Type       = Table pointer."
            print "Table addr = {:#x}.".format(tte & 0xfffffffff000)
            print "PXN        = {:#x}.".format((tte >> 59) & 0x1)
            print "XN         = {:#x}.".format((tte >> 60) & 0x1)
            print "AP         = {:#x}.".format((tte >> 61) & 0x3)
            print "NS         = {:#x}".format(tte >> 63)
        else:
            print "Type       = Block."
            print "AttrIdx    = {:#x}.".format((tte >> 2) & 0x7)
            print "NS         = {:#x}.".format((tte >> 5) & 0x1)
            print "AP         = {:#x}.".format((tte >> 6) & 0x3)
            print "SH         = {:#x}.".format((tte >> 8) & 0x3)
            print "AF         = {:#x}.".format((tte >> 10) & 0x1)
            print "nG         = {:#x}.".format((tte >> 11) & 0x1)
            print "HINT       = {:#x}.".format((tte >> 52) & 0x1)
            print "PXN        = {:#x}.".format((tte >> 53) & 0x1)
            print "XN         = {:#x}.".format((tte >> 54) & 0x1)
            print "SW Use     = {:#x}.".format((tte >> 55) & 0xf)
    else:
        print "Invalid."

    return

def PmapWalkARM64(pmap, vaddr, verbose_level = vHUMAN):
    assert(type(pmap) == core.cvalue.value)
    assert(type(vaddr) in (long, int))
    page_size = kern.globals.page_size
    page_offset_mask = (page_size - 1)
    page_base_mask = ((1 << ARM64_VMADDR_BITS) - 1) & (~page_offset_mask)

    assert_64bit(vaddr)
    paddr = -1

    tt1_index = PmapTTnIndexARM64(vaddr, 1)
    tt2_index = PmapTTnIndexARM64(vaddr, 2)
    tt3_index = PmapTTnIndexARM64(vaddr, 3)

    # L1
    tte = long(unsigned(pmap.tte[tt1_index]))
    assert(type(tte) == long)
    assert_64bit(tte)

    if verbose_level >= vSCRIPT:
        print "L1 entry: {:#x}".format(tte)
    if verbose_level >= vDETAIL:
        PmapDecodeTTEARM64(tte, 1)

    if tte & 0x1 == 0x1:
        # Check for L1 block entry
        if tte & 0x2 == 0x0:
            # Handle L1 block entry
            paddr = tte & PmapBlockBaseMaskARM64(1)
            paddr = paddr | (vaddr & PmapBlockOffsetMaskARM64(1))
            print "phys: {:#x}".format(paddr)
        else:
            # Handle L1 table entry
            l2_phys = (tte & page_base_mask) + (ARM64_TTE_SIZE * tt2_index)
            assert(type(l2_phys) == long)

            l2_virt = kern.PhysToKernelVirt(l2_phys)
            assert(type(l2_virt) == long)

            if verbose_level >= vDETAIL:
                print "L2 physical address: {:#x}. L2 virtual address: {:#x}".format(l2_phys, l2_virt)

            # L2
            ttep = kern.GetValueFromAddress(l2_virt, "tt_entry_t*")
            tte = long(unsigned(dereference(ttep)))
            assert(type(tte) == long)

            if verbose_level >= vSCRIPT:
                print "L2 entry: {:#0x}".format(tte)
            if verbose_level >= vDETAIL:
                PmapDecodeTTEARM64(tte, 2)

            if tte & 0x1 == 0x1:
                # Check for L2 block entry
                if tte & 0x2 == 0x0:
                    # Handle L2 block entry
                    paddr = tte & PmapBlockBaseMaskARM64(2)
                    paddr = paddr | (vaddr & PmapBlockOffsetMaskARM64(2))
                else:
                    # Handle L2 table entry
                    l3_phys = (tte & page_base_mask) + (ARM64_TTE_SIZE * tt3_index)
                    assert(type(l3_phys) == long)

                    l3_virt = kern.PhysToKernelVirt(l3_phys)
                    assert(type(l3_virt) == long)

                    if verbose_level >= vDETAIL:
                        print "L3 physical address: {:#x}. L3 virtual address: {:#x}".format(l3_phys, l3_virt)

                    # L3
                    ttep = kern.GetValueFromAddress(l3_virt, "tt_entry_t*")
                    tte = long(unsigned(dereference(ttep)))
                    assert(type(tte) == long)

                    if verbose_level >= vSCRIPT:
                        print "L3 entry: {:#0x}".format(tte)
                    if verbose_level >= vDETAIL:
                        PmapDecodeTTEARM64(tte, 3)

                    if tte & 0x3 == 0x3:
                        paddr = tte & page_base_mask
                        paddr = paddr | (vaddr & page_offset_mask)
                    elif verbose_level >= vHUMAN:
                        print "L3 entry invalid: {:#x}\n".format(tte)
            elif verbose_level >= vHUMAN: # tte & 0x1 == 0x1
                print "L2 entry invalid: {:#x}\n".format(tte)
    elif verbose_level >= vHUMAN:
        print "L1 entry invalid: {:#x}\n".format(tte)

    if verbose_level >= vHUMAN:
        if paddr:
            print "Translation of {:#x} is {:#x}.".format(vaddr, paddr)
        else:
            print "(no translation)"

    return paddr

def PmapWalk(pmap, vaddr, verbose_level = vHUMAN):
    if kern.arch == 'x86_64':
        return PmapWalkX86_64(pmap, vaddr)
    elif kern.arch == 'arm':
        return PmapWalkARM(pmap, vaddr, verbose_level)
    elif kern.arch == 'arm64':
        return PmapWalkARM64(pmap, vaddr, verbose_level)
    else:
        raise NotImplementedError("PmapWalk does not support {0}".format(kern.arch))

@lldb_command('pmap_walk')
def PmapWalkHelper(cmd_args=None):
    """ Perform a page-table walk in <pmap> for <virtual_address>.
        Syntax: (lldb) pmap_walk <pmap> <virtual_address> [-v]
            Multiple -v's can be specified for increased verbosity
    """
    if cmd_args == None or len(cmd_args) < 2:
        raise ArgumentError("Too few arguments to pmap_walk.")

    pmap = kern.GetValueAsType(cmd_args[0], 'pmap_t')
    addr = unsigned(kern.GetValueFromAddress(cmd_args[1], 'void *'))
    PmapWalk(pmap, addr, config['verbosity'])
    return
