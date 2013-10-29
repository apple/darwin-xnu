from xnu import *
from misc import DoReadMsr64, DoWriteMsr64

######################################
# Globals
######################################
lapic_base_addr = 0xfee00000
ioapic_base_addr = 0xfec00000
ioapic_index_off = 0x0
ioapic_data_off = 0x10


######################################
# LAPIC Helper functions
######################################
def IsArchX86_64():
    """ Determines if target machine is x86_64  
        Returns:
            True if running on x86_64, False otherwise
    """
    return kern.arch == "x86_64"
        

@static_var('x2apic_enabled', -1)
def IsX2ApicEnabled():
    """ Reads the APIC configuration MSR to determine if APIC is operating
        in x2APIC mode. The MSR is read the first time this function is
        called, and the answer is remembered for all subsequent calls.
        Returns:
            True if APIC is x2APIC mode
            False if not
    """
    apic_cfg_msr = 0x1b
    apic_cfg_msr_x2en_mask = 0xc00
    if IsX2ApicEnabled.x2apic_enabled < 0:
        if (int(DoReadMsr64(apic_cfg_msr, xnudefines.lcpu_self)) & apic_cfg_msr_x2en_mask == 
            apic_cfg_msr_x2en_mask):
            IsX2ApicEnabled.x2apic_enabled = 1
        else:
            IsX2ApicEnabled.x2apic_enabled = 0
    return IsX2ApicEnabled.x2apic_enabled == 1

def DoLapicRead32(offset, cpu):
    """ Read the specified 32-bit LAPIC register
        Params:
            offset: int - index of LAPIC register to read
            cpu: int - cpu ID
        Returns:
            The 32-bit LAPIC register value
    """
    if IsX2ApicEnabled():
        return DoReadMsr64(offset >> 4, cpu)
    else:
        return ReadPhysInt(lapic_base_addr + offset, 32, cpu)

def DoLapicWrite32(offset, val, cpu):
    """ Write the specified 32-bit LAPIC register
        Params:
            offset: int - index of LAPIC register to write
            val: int - write value
            cpu: int - cpu ID
        Returns:
            True if success, False if error
    """
    if IsX2ApicEnabled():
        return DoWriteMsr64(offset >> 4, cpu, val)
    else:
        return WritePhysInt(lapic_base_addr + offset, val, 32)

######################################
# LAPIC Register Print functions
######################################
def GetLapicVersionFields(reg_val):
    """ Helper function for DoLapicDump that prints the fields of the
        version register. 
        Params:
            reg_val: int - the value of the version register to print
        Returns:   
            string showing the fields
    """
    lvt_num = (reg_val >> 16) + 1
    version = reg_val & 0xff
    return "[VERSION={:d} MaxLVT={:d}]".format(lvt_num, version)
    
def GetLapicSpuriousVectorFields(reg_val):
    """ Helper function for DoLapicDump that prints the fields of the
        spurious vector register.
        Params:
            reg_val: int - the value of the spurious vector registre to print
        Returns:   
            string showing the fields
    """
    vector = reg_val & 0xff
    enabled = (reg_val & 0x100) >> 8
    return "[VEC={:3d} ENABLED={:d}]".format(vector, enabled)
  
def GetLapicIcrHiFields(reg_val):
    """ Helper function for DoLapicDump that prints the fields of the 
        upper 32-bits of the Interrupt Control Register (ICR).
        Params:
            reg_val: int - the value of the ICR to show
        Returns:   
            string showing the fields
    """
    dest = reg_val >> 24
    return "[DEST={:d}]".format(dest)

def GetLapicTimerDivideFields(reg_val):
    """ Helper function for DoLapicDump that prints the fields of the
        timer divide register.
        Params:
            reg_val: int - the value of the timer divide register
        Returns:   
            string showing the fields
    """
    divide_val = ((reg_val & 0x8) >> 1) | (reg_val & 0x3)
    if divide_val == 0x7:
        divide_by = 1
    else:
        divide_by = 2 << divide_val
    return "[Divide by {:d}]".format(divide_by)

def GetApicFields(reg_val):
    """ Helper function for DoLapicDump and DoIoapicDump that prints the
        fields of the APIC register.
        Params:
            reg_val: int - the value of the APIC register to print
        Returns:   
            string showing the fields
    """
    vector = reg_val & 0xff
    tsc_deadline = reg_val & 0x40000
    periodic = reg_val & 0x20000
    masked = reg_val & 0x10000
    trigger = reg_val & 0x8000
    polarity = reg_val & 0x2000
    pending = reg_val & 0x1000

    ret_str = "[VEC={:3d} MASK={:3s} TRIG={:5s} POL={:4s} PEND={:3s}".format( 
        vector,
        "no" if masked == 0 else "yes",
        "edge" if trigger == 0 else "level",
        "low" if polarity == 0 else "high",
        "no" if pending == 0 else "yes")
    if not periodic == 0:
        ret_str += " PERIODIC"
    if not tsc_deadline == 0:
        ret_str += " TSC_DEADLINE"
    ret_str += "]"
    return ret_str

def DoLapicDump():
    """ Prints all LAPIC registers
    """
    print "LAPIC operating mode: {:s}".format(
        "x2APIC" if IsX2ApicEnabled() else "xAPIC")
    # LAPIC register offset, register name, field formatting function
    lapic_dump_table = [
        (0x020, "ID", None),
        (0x030, "VERSION", GetLapicVersionFields),
        (0x080, "TASK PRIORITY", None),
        (0x0A0, "PROCESSOR PRIORITY", None),
        (0x0D0, "LOGICAL DEST", None),
        (0x0E0, "DEST FORMAT", None),
        (0x0F0, "SPURIOUS VECTOR", GetLapicSpuriousVectorFields),
        (0x100, "ISR[031:000]", None),
        (0x110, "ISR[063:032]", None),
        (0x120, "ISR[095:064]", None),
        (0x130, "ISR[127:096]", None),
        (0x140, "ISR[159:128]", None),
        (0x150, "ISR[191:160]", None),
        (0x160, "ISR[223:192]", None),
        (0x170, "ISR[225:224]", None),
        (0x180, "TMR[031:000]", None),
        (0x190, "TMR[063:032]", None),
        (0x1A0, "TMR[095:064]", None),
        (0x1B0, "TMR[127:096]", None),
        (0x1C0, "TMR[159:128]", None),
        (0x1D0, "TMR[191:160]", None),
        (0x1E0, "TMR[223:192]", None),
        (0x1F0, "TMR[225:224]", None),
        (0x200, "IRR[031:000]", None),
        (0x210, "IRR[063:032]", None),
        (0x220, "IRR[095:064]", None),
        (0x230, "IRR[127:096]", None),
        (0x240, "IRR[159:128]", None),
        (0x250, "IRR[191:160]", None),
        (0x260, "IRR[223:192]", None),
        (0x270, "IRR[225:224]", None),
        (0x280, "ERROR STATUS", None),
        (0x300, "Interrupt Command LO", GetApicFields),
        (0x310, "Interrupt Command HI", GetLapicIcrHiFields),
        (0x320, "LVT Timer", GetApicFields),
        (0x350, "LVT LINT0", GetApicFields),
        (0x360, "LVT LINT1", GetApicFields),
        (0x370, "LVT Error", GetApicFields),
        (0x340, "LVT PerfMon", GetApicFields),
        (0x330, "LVT Thermal", GetApicFields),
        (0x3e0, "Timer Divide", GetLapicTimerDivideFields),
        (0x380, "Timer Init Count", None),
        (0x390, "Timer Cur Count", None)]
    for reg in lapic_dump_table:
        reg_val = DoLapicRead32(reg[0], xnudefines.lcpu_self)
        if reg[2] == None:
            print "LAPIC[{:#05x}] {:21s}: {:#010x}".format(reg[0], reg[1], reg_val)
        else:
            print "LAPIC[{:#05x}] {:21s}: {:#010x} {:s}".format(reg[0], reg[1],
                reg_val, reg[2](reg_val))

######################################
# IOAPIC Helper functions
######################################
def DoIoApicRead(offset):
    """ Read the specified IOAPIC register
        Params:
            offset: int - index of IOAPIC register to read
        Returns:
            int 32-bit read value
    """
    WritePhysInt(ioapic_base_addr + ioapic_index_off, offset, 8)
    return ReadPhysInt(ioapic_base_addr + ioapic_data_off, 32)

def DoIoApicWrite(offset, val):
    """ Write the specified IOAPIC register
        Params:
            offset: int - index of IOAPIC register to write
        Returns:
            True if success, False if error
    """
    WritePhysInt(ioapic_base_addr + ioapic_index_off, offset, 8)
    return WritePhysInt(ioapic_base_addr + ioapic_data_off, val, 32)

def DoIoApicDump():
    """ Prints all IOAPIC registers
    """
    # Show IOAPIC ID register
    ioapic_id = DoIoApicRead(0)
    print "IOAPIC[0x00] {:9s}: {:#010x}".format("ID", ioapic_id)
    # Show IOAPIC Version register
    ioapic_ver = DoIoApicRead(1)
    maxredir = ((ioapic_ver >> 16) & 0xff) + 1
    print "IOAPIC[0x01] {:9s}: {:#010x}".format("VERSION", ioapic_ver) +\
        "       [MAXREDIR={:02d} PRQ={:d} VERSION={:#04x}]".format(
            maxredir,
            ioapic_ver >> 15 & 0x1,
            ioapic_ver & 0xff)
    # Show IOAPIC redirect regsiters
    for redir in range(maxredir):
        redir_val_lo = DoIoApicRead(0x10 + redir * 2)
        redir_val_hi = DoIoApicRead(0x10 + (redir * 2) + 1)
        print "IOAPIC[{:#04x}] IOREDIR{:02d}: {:#08x}{:08x} {:s}".format(
            0x10 + (redir * 2),
            redir, 
            redir_val_hi,
            redir_val_lo,
            GetApicFields(redir_val_lo))

######################################
# LLDB commands
######################################
@lldb_command('lapic_read32')
def LapicRead32(cmd_args=None):
    """ Read the LAPIC register at the specified offset. The CPU can
        be optionally specified
        Syntax: lapic_read32 <offset> [lcpu]
    """
    if cmd_args == None or len(cmd_args) < 1:
        print LapicRead32.__doc__
        return
    if not IsArchX86_64():
        print "lapic_read32 not supported on this architecture."
        return
    
    lcpu = xnudefines.lcpu_self
    if len(cmd_args) > 1:
        lcpu = ArgumentStringToInt(cmd_args[1])

    offset = ArgumentStringToInt(cmd_args[0])
    read_val = DoLapicRead32(offset, lcpu)
    print "LAPIC[{:#05x}]: {:#010x}".format(offset, read_val)

@lldb_command('lapic_write32')
def LapicWrite32(cmd_args=None):
    """ Write the LAPIC register at the specified offset. The CPU can
        be optionally specified. Prints an error message if there was a
        failure. Prints nothing upon success.
        Syntax: lapic_write32 <offset> <val> [lcpu]
    """
    if cmd_args == None or len(cmd_args) < 2:
        print LapicWrite32.__doc__
        return
    if not IsArchX86_64():
        print "lapic_write32 not supported on this architecture."
        return
    offset = ArgumentStringToInt(cmd_args[0])
    write_val = ArgumentStringToInt(cmd_args[1])
    lcpu = xnudefines.lcpu_self
    if len(cmd_args) > 2:
        lcpu = ArgumentStringToInt(cmd_args[2])
    if not DoLapicWrite32(offset, write_val, lcpu):
        print "lapic_write32 FAILED"

@lldb_command('lapic_dump')
def LapicDump(cmd_args=None):
    """ Prints all LAPIC entries
    """
    if not IsArchX86_64():
        print "lapic_dump not supported on this architecture."
        return
    DoLapicDump()

@lldb_command('ioapic_read32')
def IoApicRead32(cmd_args=None):
    """ Read the IOAPIC register at the specified offset.
        Syntax: ioapic_read32 <offset>
    """
    if cmd_args == None or len(cmd_args) < 1:
        print IoApicRead32.__doc__
        return
    if not IsArchX86_64():
        print "ioapic_read32 not supported on this architecture."
        return

    offset = ArgumentStringToInt(cmd_args[0])
    read_val = DoIoApicRead(offset)
    print "IOAPIC[{:#04x}]: {:#010x}".format(offset, read_val)

@lldb_command('ioapic_write32')
def IoApicWrite32(cmd_args=None):
    """ Write the IOAPIC register at the specified offset.
        Syntax: ioapic_write32 <offset> <val>
    """
    if cmd_args == None or len(cmd_args) < 2:
        print IoApicWrite32.__doc__
        return
    if not IsArchX86_64():
        print "ioapic_write32 not supported on this architecture."
        return

    offset = ArgumentStringToInt(cmd_args[0])
    write_val = ArgumentStringToInt(cmd_args[1])
    if not DoIoApicWrite(offset, write_val):
        print "ioapic_write32 FAILED"
    return

@lldb_command('ioapic_dump')
def IoApicDump(cmd_args=None):
    """ Prints all IOAPIC entries
    """
    if not IsArchX86_64():
        print "ioapic_dump not supported on this architecture."
        return
    DoIoApicDump()

