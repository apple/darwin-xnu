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

    kdp_pkt_size = GetType('kdp_writephysmem64_req_t').GetByteSize() + (bits / 8)
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
            if entry & (0x1 << 62):
                out_string += " compressed"
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

def _PT_StepEPT(paddr, index, verbose_level = vSCRIPT):
    """
     Step to lower-level page table and print attributes for EPT pmap
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
        if entry & 0x7 :
            pt_valid = True
            pt_large = False
            pt_paddr = entry & paddr_mask
            if entry & (0x1 <<7):
                pt_large = True
                pt_paddr = entry & paddr_large_mask
    else:
        out_string+= "{0: <#020x}:\n\t{1:#020x}\n\t".format(entry_addr, entry)
        if entry & 0x7:
            out_string += "valid"
            pt_paddr = entry & paddr_mask
            pt_valid = True
        else:
            out_string += "invalid"
            pt_paddr = 0
            pt_valid = False
            if entry & (0x1 << 62):
                out_string += " compressed"
            #Stop decoding other bits
            entry = 0
        if entry & 0x1:
            out_string += " readable"
        else:
            out_string += " no read"
        if entry & (0x1 << 1):
            out_string += " writable"
        else:
            out_string += " no write"

        if entry & (0x1 << 2):
            out_string += " executable"
        else:
            out_string += " no exec"

        ctype = entry & 0x38
        if ctype == 0x30:
            out_string += " cache-WB"
        elif ctype == 0x28:
            out_string += " cache-WP"
        elif ctype == 0x20:
            out_string += " cache-WT"
        elif ctype == 0x8:
            out_string += " cache-WC"
        else:
            out_string += " cache-NC"

        if (entry & 0x40) == 0x40:
            out_string += " Ignore-PTA"

        if (entry & 0x100) == 0x100:
            out_string += " accessed"

        if (entry & 0x200) == 0x200:
            out_string += " dirty"

        if entry & (0x1 << 7):
            out_string += " large"
            pt_large = True
        else:
            pt_large = False
    print out_string
    return (pt_paddr, pt_valid, pt_large)

def _PmapL4Walk(pmap_addr_val,vaddr, ept_pmap, verbose_level = vSCRIPT):
    """ Walk the l4 pmap entry.
        params: pmap_addr_val - core.value representing kernel data of type pmap_addr_t
        vaddr : int - virtual address to walk
    """
    pt_paddr = unsigned(pmap_addr_val)
    pt_valid = (unsigned(pmap_addr_val) != 0)
    pt_large = 0
    pframe_offset = 0
    if pt_valid:
        # Lookup bits 47:39 of linear address in PML4T
        pt_index = (vaddr >> 39) & 0x1ff
        pframe_offset = vaddr & 0x7fffffffff
        if verbose_level > vHUMAN :
            print "pml4 (index {0:d}):".format(pt_index)
        if not(ept_pmap):
            (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
        else:
            (pt_paddr, pt_valid, pt_large) = _PT_StepEPT(pt_paddr, pt_index, verbose_level)
    if pt_valid:
        # Lookup bits 38:30 of the linear address in PDPT
        pt_index = (vaddr >> 30) & 0x1ff
        pframe_offset = vaddr & 0x3fffffff
        if verbose_level > vHUMAN:
            print "pdpt (index {0:d}):".format(pt_index)
        if not(ept_pmap):
            (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
        else:
            (pt_paddr, pt_valid, pt_large) = _PT_StepEPT(pt_paddr, pt_index, verbose_level)
    if pt_valid and not pt_large:
        #Lookup bits 29:21 of the linear address in PDPT
        pt_index = (vaddr >> 21) & 0x1ff
        pframe_offset = vaddr & 0x1fffff
        if verbose_level > vHUMAN:
            print "pdt (index {0:d}):".format(pt_index)
        if not(ept_pmap):
            (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
        else:
            (pt_paddr, pt_valid, pt_large) = _PT_StepEPT(pt_paddr, pt_index, verbose_level)
    if pt_valid and not pt_large:
        #Lookup bits 20:21 of linear address in PT
        pt_index = (vaddr >> 12) & 0x1ff
        pframe_offset = vaddr & 0xfff
        if verbose_level > vHUMAN:
            print "pt (index {0:d}):".format(pt_index)
        if not(ept_pmap):
            (pt_paddr, pt_valid, pt_large) = _PT_Step(pt_paddr, pt_index, verbose_level)
        else:
            (pt_paddr, pt_valid, pt_large) = _PT_StepEPT(pt_paddr, pt_index, verbose_level)
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

def PmapDecodeTTEARM(tte, level, verbose_level):
    """ Display the bits of an ARM translation table or page table entry
        in human-readable form.
        tte: integer value of the TTE/PTE
        level: translation table level.  Valid values are 1 or 2.
        verbose_level: verbosity. vHUMAN, vSCRIPT, vDETAIL
    """
    out_string = ""
    if level == 1 and (tte & 0x3) == 0x2:
        if verbose_level < vSCRIPT:
            return

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

    elif level == 1 and (tte & 0x3) == 0x1:

        if verbose_level >= vSCRIPT:
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

    elif level == 2:
        pte = tte
        if verbose_level >= vSCRIPT:
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


def _PmapWalkARMLevel1Section(tte, vaddr, verbose_level = vSCRIPT):
    paddr = 0
    #Supersection or just section?
    if (tte & 0x40000) == 0x40000:
        paddr = ( (tte & 0xFF000000) | (vaddr & 0x00FFFFFF) )
    else:
        paddr = ( (tte & 0xFFF00000) | (vaddr & 0x000FFFFF) )

    if verbose_level >= vSCRIPT:
        print "{0: <#020x}\n\t{1: <#020x}\n\t".format(addressof(tte), tte),

    PmapDecodeTTEARM(tte, 1, verbose_level)

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

    paddr = 0
    if pte & 0x2:
        paddr = (unsigned(pte) & 0xFFFFF000) | (vaddr & 0xFFF)

    if verbose_level >= vSCRIPT:
        print "{0: <#020x}\n\t{1: <#020x}\n\t".format(addressof(tte), tte),

    PmapDecodeTTEARM(tte, 1, verbose_level)
    if verbose_level >= vSCRIPT:
        print "second-level table (index {:d}):".format(pte_index)
    if verbose_level >= vDETAIL:
        for i in range(256):
            tmp = pte_base_val[i]
            print "{0: <#020x}:\t{1: <#020x}".format(addressof(tmp), unsigned(tmp))

    if verbose_level >= vSCRIPT:
        print " {0: <#020x}\n\t{1: <#020x}\n\t".format(addressof(pte), unsigned(pte)),

    PmapDecodeTTEARM(pte, 2, verbose_level)

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
    # Assume all L1 indexing starts at VA 0...for our purposes it does,
    # as that's where all user pmaps start, and the kernel pmap contains
    # 4 L1 pages (the lower 2 of which are unused after bootstrap)
    tte_index = vaddr >> 20
    tte = pmap.tte[tte_index]
    if verbose_level >= vSCRIPT:
        print "First-level table (index {:d}):".format(tte_index)
    if verbose_level >= vDETAIL:
        for i in range(0, pmap.tte_index_max):
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

def PmapWalkX86_64(pmapval, vaddr, verbose_level = vSCRIPT):
    """
        params: pmapval - core.value representing pmap_t in kernel
        vaddr:  int     - int representing virtual address to walk
    """
    if pmapval.pm_cr3 != 0:
        if verbose_level > vHUMAN:
            print "Using normal Intel PMAP from pm_cr3\n"
        return _PmapL4Walk(pmapval.pm_cr3, vaddr, 0, config['verbosity'])
    else:
        if verbose_level > vHUMAN:
            print "Using EPT pmap from pm_eptp\n"
        return _PmapL4Walk(pmapval.pm_eptp, vaddr, 1, config['verbosity'])

def assert_64bit(val):
    assert(val < 2**64)

ARM64_TTE_SIZE = 8
ARM64_TTE_SHIFT = 3
ARM64_VMADDR_BITS = 48

def PmapBlockOffsetMaskARM64(level):
    assert level >= 1 and level <= 3
    page_size = kern.globals.arm_hardware_page_size
    ttentries = (page_size / ARM64_TTE_SIZE)
    return page_size * (ttentries ** (3 - level)) - 1

def PmapBlockBaseMaskARM64(level):
    assert level >= 1 and level <= 3
    page_size = kern.globals.arm_hardware_page_size
    return ((1 << ARM64_VMADDR_BITS) - 1) & ~PmapBlockOffsetMaskARM64(level)

def PmapIndexMaskARM64(level):
    assert level >= 1 and level <= 3
    page_size = kern.globals.arm_hardware_page_size
    ttentries = (page_size / ARM64_TTE_SIZE)
    return page_size * (ttentries ** (3 - level) * (ttentries - 1))

def PmapIndexDivideARM64(level):
    assert level >= 1 and level <= 3
    page_size = kern.globals.arm_hardware_page_size
    ttentries = (page_size / ARM64_TTE_SIZE)
    return page_size * (ttentries ** (3 - level))

def PmapTTnIndexARM64(vaddr, level):
    assert(type(vaddr) in (long, int))
    assert_64bit(vaddr)

    return (vaddr & PmapIndexMaskARM64(level)) // PmapIndexDivideARM64(level)

def PmapDecodeTTEARM64(tte, level):
    """ Display the bits of an ARM64 translation table or page table entry
        in human-readable form.
        tte: integer value of the TTE/PTE
        level: translation table level.  Valid values are 1, 2, or 3.
    """
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
    page_size = kern.globals.arm_hardware_page_size
    page_offset_mask = (page_size - 1)
    page_base_mask = ((1 << ARM64_VMADDR_BITS) - 1) & (~page_offset_mask)

    assert_64bit(vaddr)
    paddr = -1

    tt0_index = 0
    tt1_index = PmapTTnIndexARM64(vaddr, 1)
    tt2_index = PmapTTnIndexARM64(vaddr, 2)
    tt3_index = PmapTTnIndexARM64(vaddr, 3)

    # The pmap starts at a page tabel level that is defined by register
    # values; the kernel exports the root level for LLDB
    level = kern.globals.arm64_root_pgtable_level
    assert(level <= 3)

    if level == 0:
        root_tt_index = tt0_index
    elif level == 1:
        root_tt_index = tt1_index
    elif level == 2:
        root_tt_index = tt2_index
    elif level == 3:
        root_tt_index = tt3_index

    # If the root of the page table is not a full page, we need to
    # truncate the index
    root_tt_index = root_tt_index % unsigned(kern.globals.arm64_root_pgtable_num_ttes)

    tte = long(unsigned(pmap.tte[root_tt_index]))
    assert(type(tte) == long)
    assert_64bit(tte)

    while (True):
        if (level == 0):
            # L0
            # This is unsupported at the moment, as no kernel configurations use L0
            assert(False)

        elif (level == 1):
            # L1
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
                    break
                else:
                    # Handle L1 table entry
                    l2_phys = (tte & page_base_mask) + (ARM64_TTE_SIZE * tt2_index)
                    assert(type(l2_phys) == long)

                    l2_virt = kern.PhysToKernelVirt(l2_phys)
                    assert(type(l2_virt) == long)

                    if verbose_level >= vDETAIL:
                        print "L2 physical address: {:#x}. L2 virtual address: {:#x}".format(l2_phys, l2_virt)

                    ttep = kern.GetValueFromAddress(l2_virt, "tt_entry_t*")
                    tte = long(unsigned(dereference(ttep)))
                    assert(type(tte) == long)
            elif verbose_level >= vHUMAN:
                print "L1 entry invalid: {:#x}\n".format(tte)

        elif (level == 2):
            # L2
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
                    break
                else:
                    # Handle L2 table entry
                    l3_phys = (tte & page_base_mask) + (ARM64_TTE_SIZE * tt3_index)
                    assert(type(l3_phys) == long)

                    l3_virt = kern.PhysToKernelVirt(l3_phys)
                    assert(type(l3_virt) == long)

                    if verbose_level >= vDETAIL:
                        print "L3 physical address: {:#x}. L3 virtual address: {:#x}".format(l3_phys, l3_virt)

                    ttep = kern.GetValueFromAddress(l3_virt, "tt_entry_t*")
                    tte = long(unsigned(dereference(ttep)))
                    assert(type(tte) == long)
            elif verbose_level >= vHUMAN: # tte & 0x1 == 0x1
                print "L2 entry invalid: {:#x}\n".format(tte)

        elif (level == 3):
            # L3
            if verbose_level >= vSCRIPT:
                print "L3 entry: {:#0x}".format(tte)
            if verbose_level >= vDETAIL:
                PmapDecodeTTEARM64(tte, 3)

            if tte & 0x3 == 0x3:
                paddr = tte & page_base_mask
                paddr = paddr | (vaddr & page_offset_mask)
            elif verbose_level >= vHUMAN:
                print "L3 entry invalid: {:#x}\n".format(tte)

            # This was the leaf page table page for this request; we're done
            break

        # We've parsed one level, so go to the next level
        assert(level <= 3)
        level = level + 1

    if verbose_level >= vHUMAN:
        if paddr:
            print "Translation of {:#x} is {:#x}.".format(vaddr, paddr)
        else:
            print "(no translation)"

    return paddr

def PmapWalk(pmap, vaddr, verbose_level = vHUMAN):
    if kern.arch == 'x86_64':
        return PmapWalkX86_64(pmap, vaddr, verbose_level)
    elif kern.arch == 'arm':
        return PmapWalkARM(pmap, vaddr, verbose_level)
    elif kern.arch.startswith('arm64'):
        return PmapWalkARM64(pmap, vaddr, verbose_level)
    else:
        raise NotImplementedError("PmapWalk does not support {0}".format(kern.arch))

@lldb_command('pmap_walk')
def PmapWalkHelper(cmd_args=None):
    """ Perform a page-table walk in <pmap> for <virtual_address>.
        Syntax: (lldb) pmap_walk <pmap> <virtual_address> [-v] [-e]
            Multiple -v's can be specified for increased verbosity
    """
    if cmd_args == None or len(cmd_args) < 2:
        raise ArgumentError("Too few arguments to pmap_walk.")

    pmap = kern.GetValueAsType(cmd_args[0], 'pmap_t')
    addr = unsigned(kern.GetValueFromAddress(cmd_args[1], 'void *'))
    PmapWalk(pmap, addr, config['verbosity'])
    return

@lldb_command('decode_tte')
def DecodeTTE(cmd_args=None):
    """ Decode the bits in the TTE/PTE value specified <tte_val> for translation level <level>
        Syntax: (lldb) decode_tte <tte_val> <level>
    """
    if cmd_args == None or len(cmd_args) < 2:
        raise ArgumentError("Too few arguments to decode_tte.")
    if kern.arch == 'arm':
        PmapDecodeTTEARM(kern.GetValueFromAddress(cmd_args[0], "unsigned long"), ArgumentStringToInt(cmd_args[1]), vSCRIPT)
    elif kern.arch.startswith('arm64'):
        PmapDecodeTTEARM64(long(kern.GetValueFromAddress(cmd_args[0], "unsigned long")), ArgumentStringToInt(cmd_args[1]))
    else:
        raise NotImplementedError("decode_tte does not support {0}".format(kern.arch))


PVH_HIGH_FLAGS_ARM64 = (1 << 62) | (1 << 61) | (1 << 60) | (1 << 59)
PVH_HIGH_FLAGS_ARM32 = (1 << 31)

def PVWalkARM(pa):
    """ Walk a physical-to-virtual reverse mapping list maintained by the arm pmap
        pa: physical address (NOT page number).  Does not need to be page-aligned 
    """
    vm_first_phys = unsigned(kern.globals.vm_first_phys)
    vm_last_phys = unsigned(kern.globals.vm_last_phys)
    if pa < vm_first_phys or pa >= vm_last_phys:
        raise ArgumentError("PA {:#x} is outside range of managed physical addresses: [{:#x}, {:#x})".format(pa, vm_first_phys, vm_last_phys))
    page_size = kern.globals.page_size
    pn = (pa - unsigned(kern.globals.vm_first_phys)) / page_size
    pvh = unsigned(kern.globals.pv_head_table[pn])
    pvh_type = pvh & 0x3
    print "PVH raw value: ({:#x})".format(pvh)
    if kern.arch.startswith('arm64'):
        iommu_flag = 0x4
        iommu_table_flag = 1 << 63
        pvh = pvh | PVH_HIGH_FLAGS_ARM64
    else:
        iommu_flag = 0
        iommu_table_flag = 0 
        pvh = pvh | PVH_HIGH_FLAGS_ARM32
    if pvh_type == 0:
        print "PVH type: NULL"
        return
    elif pvh_type == 3:
        print "PVH type: page-table descriptor ({:#x})".format(pvh & ~0x3)
        return
    elif pvh_type == 2:
        ptep = pvh & ~0x3
        pte_str = ''
        print "PVH type: single PTE"
        if ptep & iommu_flag:
            ptep = ptep & ~iommu_flag
            if ptep & iommu_table_flag:
                pte_str = ' (IOMMU table), entry'
            else:
                pte_str = ' (IOMMU state), descriptor'
                ptep = ptep | iommu_table_flag
        print "PTE {:#x}{:s}: {:#x}".format(ptep, pte_str, dereference(kern.GetValueFromAddress(ptep, 'pt_entry_t *')))
    elif pvh_type == 1:
        pvep = pvh & ~0x3
        print "PVH type: PTE list"
        while pvep != 0:
            pve = kern.GetValueFromAddress(pvep, "pv_entry_t *")
            if unsigned(pve.pve_next) & 0x1:
                pve_str = ' (alt acct) '
            else:
                pve_str = ''
            current_pvep = pvep
            pvep = unsigned(pve.pve_next) & ~0x1
            ptep = unsigned(pve.pve_ptep) & ~0x3
            if ptep & iommu_flag:
                ptep = ptep & ~iommu_flag
                if ptep & iommu_table_flag:
                    pve_str = ' (IOMMU table), entry'
                else:
                    pve_str = ' (IOMMU state), descriptor'
                    ptep = ptep | iommu_table_flag
            print "PVE {:#x}, PTE {:#x}{:s}: {:#x}".format(current_pvep, ptep, pve_str, dereference(kern.GetValueFromAddress(ptep, 'pt_entry_t *')))

@lldb_command('pv_walk')
def PVWalk(cmd_args=None):
    """ Show mappings for <physical_address> tracked in the PV list.
        Syntax: (lldb) pv_walk <physical_address>
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Too few arguments to pv_walk.")
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("pv_walk does not support {0}".format(kern.arch))
    PVWalkARM(kern.GetValueFromAddress(cmd_args[0], 'unsigned long'))

@lldb_command('kvtophys')
def KVToPhys(cmd_args=None):
    """ Translate a kernel virtual address to the corresponding physical address.
        Assumes the virtual address falls within the kernel static region.
        Syntax: (lldb) kvtophys <kernel virtual address>
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Too few arguments to kvtophys.")
    if kern.arch.startswith('arm'):
        print "{:#x}".format(KVToPhysARM(long(unsigned(kern.GetValueFromAddress(cmd_args[0], 'unsigned long')))))
    elif kern.arch == 'x86_64':
        print "{:#x}".format(long(unsigned(kern.GetValueFromAddress(cmd_args[0], 'unsigned long'))) - unsigned(kern.globals.physmap_base))

@lldb_command('phystokv')
def PhysToKV(cmd_args=None):
    """ Translate a physical address to the corresponding static kernel virtual address.
        Assumes the physical address corresponds to managed DRAM.
        Syntax: (lldb) phystokv <physical address>
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Too few arguments to phystokv.")
    print "{:#x}".format(kern.PhysToKernelVirt(long(unsigned(kern.GetValueFromAddress(cmd_args[0], 'unsigned long')))))

def KVToPhysARM(addr):
    if kern.arch.startswith('arm64'):
        ptov_table = kern.globals.ptov_table
        for i in range(0, kern.globals.ptov_index):
            if (addr >= long(unsigned(ptov_table[i].va))) and (addr < (long(unsigned(ptov_table[i].va)) + long(unsigned(ptov_table[i].len)))):
                return (addr - long(unsigned(ptov_table[i].va)) + long(unsigned(ptov_table[i].pa)))
    return (addr - unsigned(kern.globals.gVirtBase) + unsigned(kern.globals.gPhysBase))

def ShowPTEARM(pte):
    """ Display vital information about an ARM page table entry
        pte: kernel virtual address of the PTE.  Should be L3 PTE.  May also work with L2 TTEs for certain devices.
    """
    page_size = kern.globals.arm_hardware_page_size
    pn = (KVToPhysARM(pte) - unsigned(kern.globals.vm_first_phys)) / page_size
    pvh = unsigned(kern.globals.pv_head_table[pn])
    if kern.arch.startswith('arm64'):
        pvh = pvh | PVH_HIGH_FLAGS_ARM64
    else:
        pvh = pvh | PVH_HIGH_FLAGS_ARM32
    pvh_type = pvh & 0x3
    if pvh_type != 0x3:
        raise ValueError("PV head {:#x} does not correspond to a page-table descriptor".format(pvh))
    ptd = kern.GetValueFromAddress(pvh & ~0x3, 'pt_desc_t *')
    print "descriptor: {:#x}".format(ptd)
    print "pmap: {:#x}".format(ptd.pmap)
    pt_index = (pte % kern.globals.page_size) / page_size
    pte_pgoff = pte % page_size
    if kern.arch.startswith('arm64'):
        pte_pgoff = pte_pgoff / 8
        nttes = page_size / 8
    else:
        pte_pgoff = pte_pgoff / 4
        nttes = page_size / 4
    if ptd.pt_cnt[pt_index].refcnt == 0x4000:
        level = 2
        granule = nttes * page_size
    else:
        level = 3
        granule = page_size
    print "maps VA: {:#x}".format(long(unsigned(ptd.pt_map[pt_index].va)) + (pte_pgoff * granule))
    pteval = long(unsigned(dereference(kern.GetValueFromAddress(unsigned(pte), 'pt_entry_t *'))))
    print "value: {:#x}".format(pteval)
    if kern.arch.startswith('arm64'):
        print "level: {:d}".format(level)
        PmapDecodeTTEARM64(pteval, level)
    elif kern.arch == 'arm':
        PmapDecodeTTEARM(pteval, 2, vSCRIPT)

@lldb_command('showpte')
def ShowPTE(cmd_args=None):
    """ Display vital information about the page table entry at VA <pte>
        Syntax: (lldb) showpte <pte_va>
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Too few arguments to showpte.")
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("showpte does not support {0}".format(kern.arch))
    ShowPTEARM(kern.GetValueFromAddress(cmd_args[0], 'unsigned long'))

def FindMappingAtLevelARM(pmap, tt, nttes, level, action):
    """ Perform the specified action for all valid mappings in an ARM translation table
        pmap: owner of the translation table
        tt: translation table or page table
        nttes: number of entries in tt
        level: translation table level, 1 or 2
        action: callback for each valid TTE
    """
    for i in range(nttes):
        try:
            tte = tt[i]
            if level == 1:
                if tte & 0x3 == 0x1:
                    type = 'table'
                    granule = 1024
                    paddr = tte & 0xFFFFFC00
                elif tte & 0x3 == 0x2:
                    type = 'block'
                    if (tte & 0x40000) == 0x40000:
                        granule = 1 << 24
                        paddr = tte & 0xFF000000
                    else:
                        granule = 1 << 20
                        paddr = tte & 0xFFF00000
                else:
                    continue
            elif (tte & 0x3) == 0x1:
                type = 'entry'
                granule = 1 << 16
                paddr = tte & 0xFFFF0000
            elif (tte & 0x3) != 0:
                type = 'entry' 
                granule = 1 << 12
                paddr = tte & 0xFFFFF000
            else:
                continue
            action(pmap, level, type, addressof(tt[i]), paddr, granule)
            if level == 1 and (tte & 0x3) == 0x1:
                tt_next = kern.GetValueFromAddress(kern.PhysToKernelVirt(paddr), 'tt_entry_t *')
                FindMappingAtLevelARM(pmap, tt_next, granule / 4, level + 1, action)
        except Exception as exc:
            print "Unable to access tte {:#x}".format(unsigned(addressof(tt[i])))

def FindMappingAtLevelARM64(pmap, tt, nttes, level, action):
    """ Perform the specified action for all valid mappings in an ARM64 translation table
        pmap: owner of the translation table
        tt: translation table or page table
        nttes: number of entries in tt
        level: translation table level, 1 2 or 3
        action: callback for each valid TTE
    """
    page_size = kern.globals.arm_hardware_page_size
    page_offset_mask = (page_size - 1)
    page_base_mask = ((1 << ARM64_VMADDR_BITS) - 1) & (~page_offset_mask)
    for i in range(nttes):
        try:
            tte = tt[i]
            if tte & 0x1 == 0x1:
                if tte & 0x2 == 0x2:
                    if level < 3:
                        type = 'table'
                    else:
                        type = 'entry'
                    granule = page_size
                    paddr = tte & page_base_mask
                elif level < 3:
                    type = 'block'
                    granule = PmapBlockOffsetMaskARM64(level) + 1
                    paddr = tte & PmapBlockBaseMaskARM64(level)
                else:
                    continue
                action(pmap, level, type, addressof(tt[i]), paddr, granule)
                if level < 3 and (tte & 0x2 == 0x2):
                    tt_next = kern.GetValueFromAddress(kern.PhysToKernelVirt(paddr), 'tt_entry_t *')
                    FindMappingAtLevelARM64(pmap, tt_next, granule / ARM64_TTE_SIZE, level + 1, action)
        except Exception as exc:
            print "Unable to access tte {:#x}".format(unsigned(addressof(tt[i]))) 

def ScanPageTables(action, targetPmap=None):
    """ Perform the specified action for all valid mappings in all page tables,
        optionally restricted to a single pmap.
        pmap: pmap whose page table should be scanned.  If None, all pmaps on system will be scanned.
    """
    print "Scanning all available translation tables.  This may take a long time..."
    def ScanPmap(pmap, action):
        if kern.arch.startswith('arm64'):
            granule = kern.globals.arm64_root_pgtable_num_ttes * 8
        elif kern.arch == 'arm':
            granule = pmap.tte_index_max * 4
        action(pmap, 1, 'root', pmap.tte, unsigned(pmap.ttep), granule)
        if kern.arch.startswith('arm64'):
            FindMappingAtLevelARM64(pmap, pmap.tte, kern.globals.arm64_root_pgtable_num_ttes, kern.globals.arm64_root_pgtable_level, action)
        elif kern.arch == 'arm':
            FindMappingAtLevelARM(pmap, pmap.tte, pmap.tte_index_max, 1, action)

    if targetPmap is not None:
        ScanPmap(kern.GetValueFromAddress(targetPmap, 'pmap_t'), action)
    else:
        for pmap in IterateQueue(kern.globals.map_pmap_list, 'pmap_t', 'pmaps'):
            ScanPmap(pmap, action)        

@lldb_command('showallmappings')
def ShowAllMappings(cmd_args=None):
    """ Find and display all available mappings on the system for
        <physical_address>.  Optionally only searches the pmap
        specified by [<pmap>]
        Syntax: (lldb) showallmappings <physical_address> [<pmap>]
        WARNING: this macro can take a long time (up to 30min.) to complete!
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Too few arguments to showallmappings.")
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("showallmappings does not support {0}".format(kern.arch))
    pa = kern.GetValueFromAddress(cmd_args[0], 'unsigned long')
    targetPmap = None
    if len(cmd_args) > 1:
        targetPmap = cmd_args[1]
    def printMatchedMapping(pmap, level, type, tte, paddr, granule):
        if paddr <= pa < (paddr + granule):
            print "pmap: {:#x}: L{:d} {:s} at {:#x}: [{:#x}, {:#x})".format(pmap, level, type, unsigned(tte), paddr, paddr + granule)
    ScanPageTables(printMatchedMapping, targetPmap)

def checkPVList(pmap, level, type, tte, paddr, granule):
    """ Checks an ARM physical-to-virtual mapping list for consistency errors.
        pmap: owner of the translation table
        level: translation table level.  PV lists will only be checked for L2 (arm32) or L3 (arm64) tables.
        type: unused
        tte: KVA of PTE to check for presence in PV list.  If None, presence check will be skipped.
        paddr: physical address whose PV list should be checked.  Need not be page-aligned.
        granule: unused
    """
    vm_first_phys = unsigned(kern.globals.vm_first_phys)
    vm_last_phys = unsigned(kern.globals.vm_last_phys)
    page_size = kern.globals.page_size
    if kern.arch.startswith('arm64'):
        page_offset_mask = (page_size - 1)
        page_base_mask = ((1 << ARM64_VMADDR_BITS) - 1) & (~page_offset_mask)
        paddr = paddr & page_base_mask
        max_level = 3
        pvh_set_bits = PVH_HIGH_FLAGS_ARM64
    elif kern.arch == 'arm':
        page_base_mask = 0xFFFFF000
        paddr = paddr & page_base_mask
        max_level = 2
        pvh_set_bits = PVH_HIGH_FLAGS_ARM32
    if level < max_level or paddr < vm_first_phys or paddr >= vm_last_phys:
        return
    pn = (paddr - vm_first_phys) / page_size
    pvh = unsigned(kern.globals.pv_head_table[pn]) | pvh_set_bits
    pvh_type = pvh & 0x3
    if pmap is not None:
        pmap_str = "pmap: {:#x}: ".format(pmap)
    else:
        pmap_str = ''
    if tte is not None:
        tte_str = "pte {:#x} ({:#x}): ".format(unsigned(tte), paddr)
    else:
        tte_str = "paddr {:#x}: ".format(paddr) 
    if pvh_type == 0 or pvh_type == 3:
        print "{:s}{:s}unexpected PVH type {:d}".format(pmap_str, tte_str, pvh_type)
    elif pvh_type == 2:
        ptep = pvh & ~0x3
        if tte is not None and ptep != unsigned(tte):
            print "{:s}{:s}PVH mismatch ({:#x})".format(pmap_str, tte_str, ptep)
        try:
            pte = long(unsigned(dereference(kern.GetValueFromAddress(ptep, 'pt_entry_t *')))) & page_base_mask 
            if (pte != paddr):
                print "{:s}{:s}PVH {:#x} maps wrong page ({:#x}) ".format(pmap_str, tte_str, ptep, pte)
        except Exception as exc:
            print "{:s}{:s}Unable to read PVH {:#x}".format(pmap_str, tte_str, ptep)
    elif pvh_type == 1:
        pvep = pvh & ~0x3
        tte_match = False
        while pvep != 0:
            pve = kern.GetValueFromAddress(pvep, "pv_entry_t *")
            pvep = unsigned(pve.pve_next) & ~0x1
            ptep = unsigned(pve.pve_ptep) & ~0x3
            if tte is not None and ptep == unsigned(tte):
                tte_match = True
            try:
                pte = long(unsigned(dereference(kern.GetValueFromAddress(ptep, 'pt_entry_t *')))) & page_base_mask 
                if (pte != paddr):
                    print "{:s}{:s}PVE {:#x} maps wrong page ({:#x}) ".format(pmap_str, tte_str, ptep, pte)
            except Exception as exc:
                print "{:s}{:s}Unable to read PVE {:#x}".format(pmap_str, tte_str, ptep)
        if tte is not None and not tte_match:
            print "{:s}{:s}not found in PV list".format(pmap_str, tte_str, paddr)

@lldb_command('pv_check', 'P')
def PVCheck(cmd_args=None, cmd_options={}):
    """ Check the physical-to-virtual mapping for a given PTE or physical address
        Syntax: (lldb) pv_check <addr> [-p]
            -P        : Interpret <addr> as a physical address rather than a PTE
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Too few arguments to pv_check.")
    if kern.arch == 'arm':
        level = 2
    elif kern.arch.startswith('arm64'):
        level = 3
    else:
        raise NotImplementedError("showallmappings does not support {0}".format(kern.arch))
    if "-P" in cmd_options:
        pte = None
        pa = long(unsigned(kern.GetValueFromAddress(cmd_args[0], "unsigned long")))
    else:
        pte = kern.GetValueFromAddress(cmd_args[0], 'pt_entry_t *')
        pa = long(unsigned(dereference(pte)))
    checkPVList(None, level, None, pte, pa, None)

@lldb_command('check_pmaps')
def CheckPmapIntegrity(cmd_args=None):
    """ Performs a system-wide integrity check of all PTEs and associated PV lists.
        Optionally only checks the pmap specified by [<pmap>]
        Syntax: (lldb) check_pmaps [<pmap>]
        WARNING: this macro can take a HUGE amount of time (several hours) if you do not
        specify [pmap] to limit it to a single pmap.  It will also give false positives
        for kernel_pmap, as we do not create PV entries for static kernel mappings on ARM.
        Use of this macro without the [<pmap>] argument is heavily discouraged.
    """
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("showallmappings does not support {0}".format(kern.arch))
    targetPmap = None
    if len(cmd_args) > 0:
        targetPmap = cmd_args[0]
    ScanPageTables(checkPVList, targetPmap)

@lldb_command('pmapsforledger')
def PmapsForLedger(cmd_args=None):
    """ Find and display all pmaps currently using <ledger>.
        Syntax: (lldb) pmapsforledger <ledger>
    """
    if cmd_args == None or len(cmd_args) < 1:
        raise ArgumentError("Too few arguments to pmapsforledger.")
    if not kern.arch.startswith('arm'):
        raise NotImplementedError("pmapsforledger does not support {0}".format(kern.arch))
    ledger = kern.GetValueFromAddress(cmd_args[0], 'ledger_t')
    for pmap in IterateQueue(kern.globals.map_pmap_list, 'pmap_t', 'pmaps'):
        if pmap.ledger == ledger:
            print "pmap: {:#x}".format(pmap)
