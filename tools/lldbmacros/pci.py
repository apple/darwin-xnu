from xnu import *

######################################
# Helper functions
######################################
def GetMemMappedPciCfgAddrFromRegistry():
    """ Retrieve the base address of the memory mapped PCI config space. It is
        found in registry entry AppleACPIPlatformExpert, property acpi-mmcfg-seg0.
        Returns:
            int base address of memory mapped PCI config space
    """
    kgm_pci_cfg_base_default = 0xe0000000
    acpi_pe_obj = FindRegistryObjectRecurse(kern.globals.gRegistryRoot,
        "AppleACPIPlatformExpert")
    if acpi_pe_obj is None:
        print "Could not find AppleACPIPlatformExpert in registry, \
        using default base address for memory mapped PCI config space"
        return kgm_pci_cfg_base_default
    entry = kern.GetValueFromAddress(int(acpi_pe_obj), 'IOService *')
    acpi_mmcfg_seg_prop = LookupKeyInPropTable(entry.fPropertyTable, "acpi-mmcfg-seg0")
    if acpi_mmcfg_seg_prop is None:
        print "Could not find acpi-mmcfg-seg0 property, \
        using default base address for memory mapped PCI config space"
        return kgm_pci_cfg_base_default
    else:
        return int(GetNumber(acpi_mmcfg_seg_prop))

@static_var('kgm_pci_cfg_base', -1)
def GetMemMappedPciCfgAddrBase():
    """ Returns the base address of the memory mapped PCI config space. The address
        is retrieved once from the registry, and is remembered for all subsequent 
        calls to this function
        Returns:
            int base address of memory mapped PCI config space
    """
    if GetMemMappedPciCfgAddrBase.kgm_pci_cfg_base == -1:
        # Retrieve the base address from the registry if it hasn't been
        # initialized yet
        GetMemMappedPciCfgAddrBase.kgm_pci_cfg_base = GetMemMappedPciCfgAddrFromRegistry()
    return GetMemMappedPciCfgAddrBase.kgm_pci_cfg_base

def MakeMemMappedPciCfgAddr(bus, dev, func, offs):
    """ Construct the memory address for the PCI config register specified by the
        bus, device, function, and offset
        Params:
            bus, dev, func, offs: int - bus, device, function, and offset that specifies
            the PCI config space register
        Returns:
            int - the physical memory address that maps to the PCI config space register
    """
    return GetMemMappedPciCfgAddrBase() | (bus << 20) | (dev << 15) | (func << 12) | offs

def DoPciCfgRead(bits, bus, dev, func, offs):
    """ Helper function that performs PCI config space read
        Params:
            bits: int - bit width of access: 8, 16, or 32 bits
            bus, dev, func, offs: int - PCI config bus, device, function and offset
        Returns:
            int - the value read from PCI config space
    """
    phys_addr = MakeMemMappedPciCfgAddr(bus, dev, func, offs)
    return ReadPhysInt(phys_addr, bits)

def DoPciCfgWrite(bits, bus, dev, func, offs, val):
    """ Helper function that performs PCI config space write
        Params:
            bits: int - bit width of access: 8, 16, or 32 bits
            bus, dev, func, offs: int - PCI config bus, device, function and offset
        Returns:
            boolean - True upon success, False otherwise
    """
    phys_addr = MakeMemMappedPciCfgAddr(bus, dev, func, offs)
    return WritePhysInt(phys_addr, val, bits)

def ShowPciCfgBytes(bus, dev, func, offset):
    """ Prints 16 bytes of PCI config space starting at specified offset
        Params:
            bus, dev, func, offset: int - bus, dev, function, and offset of the
            PCI config space register
    """
    # Print mem-mapped address at beginning of each 16-byte line
    phys_addr = MakeMemMappedPciCfgAddr(bus, dev, func, offset)
    read_vals = [DoPciCfgRead(32, bus, dev, func, offset + byte) 
                    for byte in range(0, 16, 4)]
    # It would be nicer to have a shorter format that we could loop
    # over, but each call to print results in a newline which 
    # would prevent us from printing all 16 bytes on one line.
    bytes_fmt = "{:08x}:" + "{:02x} " * 16
    print bytes_fmt.format(
        phys_addr,
        read_vals[0] & 0xff, (read_vals[0] >> 8) & 0xff,
        (read_vals[0] >> 16) & 0xff, (read_vals[0] >> 24) & 0xff,
        read_vals[1] & 0xff, (read_vals[1] >> 8) & 0xff,
        (read_vals[1] >> 16) & 0xff, (read_vals[1] >> 24) & 0xff,
        read_vals[2] & 0xff, (read_vals[2] >> 8) & 0xff,
        (read_vals[2] >> 16) & 0xff, (read_vals[2] >> 24) & 0xff,
        read_vals[3] & 0xff, (read_vals[3] >> 8) & 0xff,
        (read_vals[3] >> 16) & 0xff, (read_vals[3] >> 24) & 0xff)

def DoPciCfgDump(bus, dev, func):
    """ Dumps PCI config space of the PCI device specified by bus, dev, function
        Params:
            bus, dev, func: int - bus, dev, function of PCI config space to dump
    """
    # Check for a valid PCI device
    vendor_id = DoPciCfgRead(16, bus, dev, func, 0)
    if (vendor_id == 0xbad10ad) or not (vendor_id > 0 and vendor_id < 0xffff):
        return
    # Show the standard PCI config space
    print "address: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
    print "--------------------------------------------------------"
    for offset in range(0, 256, 16):
        ShowPciCfgBytes(bus, dev, func, offset)
    # Check for PCIE extended capability config space
    if DoPciCfgRead(8, bus, dev, func, 256) < 0xff:
        print " \n"
        for offset in range(256, 4096, 16):
            ShowPciCfgBytes(bus, dev, func, offset)

def DoPciCfgScan(max_bus, dump):
    """ Do a PCI config scan starting at bus 0 up to specified max bus
        Params:
            max_bus: int - maximum bus to scan
            dump: bool - if True, dump the config space of each scanned device
                         if False, print basic information of each scanned device
    """
    max_dev  = 32
    max_func = 8
    bdfs = ({'bus':bus, 'dev':dev, 'func':func}
            for bus in range(max_bus)
            for dev in range(max_dev)
            for func in range(max_func))
    fmt_string = "{:03x}:" * 3 + " " + \
        "{:02x}" * 2 + "   " + \
        "{:02x}" * 2 + "    {:02x} | " + \
        "{:02x}" * 3
    for bdf in bdfs:
        bus = bdf['bus']
        dev = bdf['dev']
        func = bdf['func']
        vend_dev_id = DoPciCfgRead(32, bus, dev, func, 0)
        if not (vend_dev_id > 0 and vend_dev_id < 0xffffffff):
            continue
        if dump == False:
            class_rev_id = DoPciCfgRead(32, bus, dev, func, 8)
            print fmt_string.format(
                bus, dev, func,
                (vend_dev_id >> 8) & 0xff, vend_dev_id & 0xff,
                (vend_dev_id >> 24) & 0xff, (vend_dev_id >> 16) & 0xff,
                class_rev_id & 0xff, (class_rev_id >> 24) & 0xff,
                (class_rev_id >> 16) & 0xff, (class_rev_id >> 8) & 0xff)
        else:
            print "{:03x}:{:03x}:{:03x}".format(bus, dev, func)
            DoPciCfgDump(bus, dev, func)

######################################
# LLDB commands
######################################
@lldb_command('pci_cfg_read')
def PciCfgRead(cmd_args=None):
    """ Read PCI config space at the specified bus, device, function, and offset
        Syntax: pci_cfg_read <bits> <bus> <device> <function> <offset>
            bits: 8, 16, 32
    """
    if cmd_args == None or len(cmd_args) < 5:
        print PciCfgRead.__doc__
        return
    
    bits = ArgumentStringToInt(cmd_args[0])
    bus  = ArgumentStringToInt(cmd_args[1])
    dev  = ArgumentStringToInt(cmd_args[2])
    func = ArgumentStringToInt(cmd_args[3])
    offs = ArgumentStringToInt(cmd_args[4])

    read_val = DoPciCfgRead(bits, bus, dev, func, offs)
    if read_val == 0xbad10ad:
        print "ERROR: Failed to read PCI config space"
        return

    format_for_bits = {8:"{:#04x}", 16:"{:#06x}", 32:"{:#010x}"}
    phys_addr = MakeMemMappedPciCfgAddr(bus, dev, func, offs)
    fmt_string = "{:08x}: " + format_for_bits[bits]
    print fmt_string.format(phys_addr, read_val)

lldb_alias('pci_cfg_read8', 'pci_cfg_read 8')
lldb_alias('pci_cfg_read16', 'pci_cfg_read 16')
lldb_alias('pci_cfg_read32', 'pci_cfg_read 32')

@lldb_command('pci_cfg_write')
def PciCfgWrite(cmd_args=None):
    """ Write PCI config space at the specified bus, device, function, and offset
        Syntax: pci_cfg_write <bits> <bus> <device> <function> <offset> <write val>
            bits: 8, 16, 32

        Prints an error message if there was a problem
        Prints nothing upon success.
    """
    if cmd_args == None or len(cmd_args) < 6:
        print PciCfgWrite.__doc__
        return

    bits = ArgumentStringToInt(cmd_args[0])
    bus  = ArgumentStringToInt(cmd_args[1])
    dev  = ArgumentStringToInt(cmd_args[2])
    func = ArgumentStringToInt(cmd_args[3])
    offs = ArgumentStringToInt(cmd_args[4])
    write_val = ArgumentStringToInt(cmd_args[5])

    if DoPciCfgWrite(bits, bus, dev, func, offs, write_val) == False:
        print "ERROR: Failed to write PCI config space"

lldb_alias('pci_cfg_write8', 'pci_cfg_write 8')
lldb_alias('pci_cfg_write16', 'pci_cfg_write 16')
lldb_alias('pci_cfg_write32', 'pci_cfg_write 32')

@lldb_command('pci_cfg_dump')
def PciCfgDump(cmd_args=None):
    """ Dump PCI config space for specified bus, device, and function
        If an invalid/inaccessible PCI device is specified, nothing will
        be printed out.
        Syntax: pci_cfg_dump <bus> <dev> <fuction>
    """
    if cmd_args == None or len(cmd_args) < 3:
        print PciCfgDump.__doc__
        return

    bus  = ArgumentStringToInt(cmd_args[0])
    dev  = ArgumentStringToInt(cmd_args[1])
    func = ArgumentStringToInt(cmd_args[2])

    DoPciCfgDump(bus, dev, func)

@lldb_command('pci_cfg_scan')
def PciCfgScan(cmd_args=None):
    """ Scan for pci devices. The maximum bus number to be scanned defaults to 8,
        but can be specified as an argument
        Syntax: pci_cfg_scan [max bus number]
    """
    if cmd_args == None or len(cmd_args) == 0:
        max_bus = 8
    elif len(cmd_args) == 1:
        max_bus = ArgumentStringToInt(cmd_args[0])
    else:
        print PciCfgScan.__doc__
        return

    print "bus:dev:fcn: vendor device rev | class"
    print "--------------------------------------"
    DoPciCfgScan(max_bus, False)

@lldb_command('pci_cfg_dump_all')
def PciCfgDumpAll(cmd_args=None):
    """ Dump config space for all scanned PCI devices. The maximum bus number to
        be scanned defaults to 8, but can be specified as an argument
        Syntax: pci_cfg_dump_all [max bus number]
    """
    if cmd_args == None or len(cmd_args) == 0:
        max_bus = 8
    elif len(cmd_args) == 1:
        max_bus = ArgumentStringToInt(cmd_args[0])
    else:
        print PciCfgDumpAll.__doc__
        return
    
    DoPciCfgScan(max_bus, True)
