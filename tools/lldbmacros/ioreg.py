from xnu import *
from utils import *
from kdp import *
from core import caching
import sys
from collections import deque

######################################
# Globals
######################################
plane = None

#####################################
# Utility functions.
#####################################
def CastIOKitClass(obj, target_type):
    """ Type cast an object to another IOKIT CPP class.
        params:
            obj - core.value  object representing some C construct in lldb
            target_type - str : ex 'OSString *'
                        - lldb.SBType :
    """
    v = Cast(obj, target_type)
    v.GetSBValue().SetPreferDynamicValue(lldb.eNoDynamicValues)
    return v

######################################
# Type Summaries
######################################
@lldb_type_summary(['OSObject *'])
@header("")
def GetObjectSummary(obj):
    """ Show info about an OSObject - its vtable ptr and retain count, & more info for simple container classes.
    """
    if obj is None:
        return

    vt = dereference(Cast(obj, 'uintptr_t *')) - 2 * sizeof('uintptr_t')
    vt = kern.StripKernelPAC(vt)
    vtype = kern.SymbolicateFromAddress(vt)
    if len(vtype):
        vtype_str = " <" + vtype[0].GetName() + ">"
    else:
        vtype_str = ""
    if hasattr(obj, 'retainCount'):
        retCount = (obj.retainCount & 0xffff)
        cntnrRetCount = (obj.retainCount >> 16)
        out_string = "`object 0x{0: <16x}, vt 0x{1: <16x}{2:s}, retain count {3:d}, container retain {4:d}` ".format(obj, vt, vtype_str, retCount, cntnrRetCount)
    else:
        out_string = "`object 0x{0: <16x}, vt 0x{1: <16x}{2:s}` ".format(obj, vt, vtype_str)

    ztvAddr = kern.GetLoadAddressForSymbol('_ZTV8OSString')
    if vt == ztvAddr:
        out_string += GetString(obj)
        return out_string
    
    ztvAddr = kern.GetLoadAddressForSymbol('_ZTV8OSSymbol')
    if vt == ztvAddr:
        out_string += GetString(obj)
        return out_string
    
    ztvAddr = kern.GetLoadAddressForSymbol('_ZTV8OSNumber')
    if vt == ztvAddr:
        out_string += GetNumber(obj)
        return out_string
    
    ztvAddr = kern.GetLoadAddressForSymbol('_ZTV9OSBoolean')
    if vt == ztvAddr:
        out_string += GetBoolean(obj)
        return out_string
    
    ztvAddr = kern.GetLoadAddressForSymbol('_ZTV7OSArray')
    if vt == ztvAddr:
        out_string += "(" + GetArray(CastIOKitClass(obj, 'OSArray *')) + ")"
        return out_string
    
    ztvAddr = kern.GetLoadAddressForSymbol('_ZTV5OSSet')
    if vt == ztvAddr:
        out_string += GetSet(CastIOKitClass(obj, 'OSSet *'))
        return out_string
    
    ztvAddr = kern.GetLoadAddressForSymbol('_ZTV12OSDictionary')
    if vt == ztvAddr:
        out_string += GetDictionary(CastIOKitClass(obj, 'OSDictionary *'))
        return out_string
    
    return out_string


def GetObjectTypeStr(obj):
    """ Return the type of an OSObject's container class
    """
    if obj is None:
        return None

    vt = dereference(Cast(obj, 'uintptr_t *')) - 2 * sizeof('uintptr_t')
    vt = kern.StripKernelPAC(vt)
    vtype = kern.SymbolicateFromAddress(vt)
    if len(vtype):
        return vtype[0].GetName()

    # See if the value is in a kext with no symbols
    for kval in IterateLinkedList(kern.globals.kmod, 'next'):
        if vt >= unsigned(kval.address) and vt <= (unsigned(kval.address) + unsigned(kval.size)):
            return "kmod:{:s}+{:#0x}".format(kval.name, vt - unsigned(kval.address))
    return None


@lldb_type_summary(['IORegistryEntry *'])
@header("")
def GetRegistryEntrySummary(entry):
    """ returns a string containing summary information about an IORegistry
        object including it's registry id , vtable ptr and retain count
    """
    name = None
    out_string = ""
    registryTable = entry.fRegistryTable
    propertyTable = entry.fPropertyTable
    
    name = LookupKeyInOSDict(registryTable, kern.globals.gIOServicePlane.nameKey)
    if name is None:
        name = LookupKeyInOSDict(registryTable, kern.globals.gIONameKey)
    if name is None:
        name = LookupKeyInOSDict(propertyTable, kern.globals.gIOClassKey)
    
    if name is not None:
        out_string += "+-o {0:s}  ".format(GetString(CastIOKitClass(name, 'OSString *')))
    elif CastIOKitClass(entry, 'IOService *').pwrMgt and CastIOKitClass(entry, 'IOService *').pwrMgt.Name:
        out_string += "+-o {0:s}  ".format(CastIOKitClass(entry, 'IOService *').pwrMgt.Name)
    else:
        out_string += "+-o ??  "
    
    # I'm using uintptr_t for now to work around <rdar://problem/12749733> FindFirstType & Co. should allow you to make pointer types directly
    vtableAddr = dereference(Cast(entry, 'uintptr_t *')) - 2 * sizeof('uintptr_t *')
    vtableAddr = kern.StripKernelPAC(vtableAddr)
    vtype = kern.SymbolicateFromAddress(vtableAddr)
    if vtype is None or len(vtype) < 1:
        out_string += "<object 0x{0: <16x}, id 0x{1:x}, vtable 0x{2: <16x}".format(entry, CastIOKitClass(entry, 'IORegistryEntry *').reserved.fRegistryEntryID, vtableAddr)
    else:
        out_string += "<object 0x{0: <16x}, id 0x{1:x}, vtable 0x{2: <16x} <{3:s}>".format(entry, CastIOKitClass(entry, 'IORegistryEntry *').reserved.fRegistryEntryID,
                                                                                           vtableAddr, vtype[0].GetName())
    
    ztvAddr = kern.GetLoadAddressForSymbol('_ZTV15IORegistryEntry')
    if vtableAddr != ztvAddr:
        out_string += ", "
        state = CastIOKitClass(entry, 'IOService *').__state[0]
        # kIOServiceRegisteredState
        if 0 == state & 2:
            out_string += "!"
        out_string += "registered, "
        # kIOServiceMatchedState
        if 0 == state & 4:
            out_string += "!"
        out_string += "matched, "
        #kIOServiceInactiveState
        if 0 != state & 1:
            out_string += "in"
        busyCount = (CastIOKitClass(entry, 'IOService *').__state[1] & 0xff)
        retCount = (CastIOKitClass(entry, 'IOService *').retainCount & 0xffff)
        out_string += "active, busy {0}, retain count {1}>".format(busyCount, retCount)
    return out_string

######################################
# Commands
######################################
@lldb_command('showallclasses')
def ShowAllClasses(cmd_args=None):
    """ Show the instance counts and ivar size of all OSObject subclasses.
        See ioclasscount man page for details
    """
    idx = 0
    count = unsigned(kern.globals.sAllClassesDict.count)
    
    while idx < count:
        meta = CastIOKitClass(kern.globals.sAllClassesDict.dictionary[idx].value, 'OSMetaClass *')
        idx += 1
        print GetMetaClass(meta)

@lldb_command('showobject')
def ShowObject(cmd_args=None):
    """ Show info about an OSObject - its vtable ptr and retain count, & more info for simple container classes.
    """
    if not cmd_args:
        print "Please specify the address of the OSObject whose info you want to view. Type help showobject for help"
        return
    
    obj = kern.GetValueFromAddress(cmd_args[0], 'OSObject *')
    print GetObjectSummary(obj)

#Macro: dumpobject
@lldb_command('dumpobject')
def DumpObject(cmd_args=None):
    """ Dumps object information if it is a valid object confirmed by showobject
        Usage: dumpobject <address of object to be dumped> [class/struct type of object]
    """
    if not cmd_args:
        print "No arguments passed"
        print DumpObject.__doc__
        return False

    if len(cmd_args) == 1:
        try:
            object_info = lldb_run_command("showobject {:s}".format(cmd_args[0]))
        except:
            print "Error!! showobject failed due to invalid value"
            print DumpObject.__doc__
            return False

        srch = re.search(r'<vtable for ([A-Za-z].*)>', object_info)
        if not srch:
            print "Error!! Couldn't find object in registry, input type manually as 2nd argument"
            print DumpObject.__doc__
            return False

        object_type = srch.group(1)
    else:
        type_lookup = lldb_run_command("image lookup -t {:s}".format(cmd_args[1]))
        if type_lookup.find(cmd_args[1])!= -1:
            object_type = cmd_args[1]
        else:
            print "Error!! Input type {:s} isn't available in image lookup".format(cmd_args[1])
            return False

    print "******** Object Dump for value \'{:s}\' with type \"{:s}\" ********".format(cmd_args[0], object_type)
    print lldb_run_command("p/x *({:s}*){:s}".format(object_type, cmd_args[0]))

#EndMacro: dumpobject

@lldb_command('setregistryplane')
def SetRegistryPlane(cmd_args=None):
    """ Set the plane to be used for the IOKit registry macros
        syntax: (lldb) setregistryplane 0  - will display all known planes
        syntax: (lldb) setregistryplane 0xaddr      - will set the registry plane to 0xaddr
        syntax: (lldb) setregistryplane gIODTPlane  - will set the registry plane to gIODTPlane
    """
    if not cmd_args:
        print "Please specify the name of the plane you want to use with the IOKit registry macros."
        print SetRegistryPlane.__doc__
    
    if cmd_args[0] == "0":
        print GetObjectSummary(kern.globals.gIORegistryPlanes)
    else:
        global plane
        plane = kern.GetValueFromAddress(cmd_args[0], 'IORegistryPlane *')
    return

@lldb_command('showregistryentry')
def ShowRegistryEntry(cmd_args=None):
    """ Show info about a registry entry; its properties and descendants in the current plane
        syntax: (lldb) showregistryentry 0xaddr
        syntax: (lldb) showregistryentry gIOPMRootDomain
    """
    if not cmd_args:
        print "Please specify the address of the registry entry whose info you want to view."
        print ShowRegistryEntry.__doc__
        return
    
    entry = kern.GetValueFromAddress(cmd_args[0], 'IORegistryEntry *')
    ShowRegistryEntryRecurse(entry, "", True)

@lldb_command('showregistry')
def ShowRegistry(cmd_args=None):
    """ Show info about all registry entries in the current plane
        If prior to invoking this command no registry plane is specified
        using 'setregistryplane', the command defaults to the IOService plane
    """
    ShowRegistryEntryRecurse(kern.globals.gRegistryRoot, "", False)

@lldb_command('showregistryprops')
def ShowRegistryProps(cmd_args=None):
    """ Show info about all registry entries in the current plane, and their properties
        If prior to invoking this command no registry plane is specified
        using 'setregistryplane', the command defaults to the IOService plane
    """
    ShowRegistryEntryRecurse(kern.globals.gRegistryRoot, "", True)

@lldb_command('findregistryentry')
def FindRegistryEntry(cmd_args=None):
    """ Search for registry entry that matches the given string
        If prior to invoking this command no registry plane is specified
        using 'setregistryplane', the command defaults to searching entries from the IOService plane
        syntax: (lldb) findregistryentries AppleACPICPU - will find the first registry entry that matches AppleACPICPU
    """
    if not cmd_args:
        print "Please specify the name of the registry entry you want to find"
        print FindRegistryEntry.__doc__
        return
    
    FindRegistryEntryRecurse(kern.globals.gRegistryRoot, cmd_args[0], True)

@lldb_command('findregistryentries')
def FindRegistryEntries(cmd_args=None):
    """ Search for all registry entries that match the given string
        If prior to invoking this command no registry plane is specified
        using 'setregistryplane', the command defaults to searching entries from the IOService plane
        syntax: (lldb) findregistryentries AppleACPICPU - will find all registry entries that match AppleACPICPU
    """
    if not cmd_args:
        print "Please specify the name of the registry entry/entries you want to find"
        print FindRegistryEntries.__doc__
        return
    
    FindRegistryEntryRecurse(kern.globals.gRegistryRoot, cmd_args[0], False)

@lldb_command('findregistryprop')
def FindRegistryProp(cmd_args=None):
    """ Given a registry entry, print out the contents for the property that matches
        a specific string
        syntax: (lldb) findregistryprop 0xaddr IOSleepSupported
        syntax: (lldb) findregistryprop gIOPMRootDomain IOSleepSupported
        syntax: (lldb) findregistryprop gIOPMRootDomain "Supported Features"
    """
    if not cmd_args or len(cmd_args) < 2:
        print "Please specify the address of a IORegistry entry and the property you're looking for"
        print FindRegistryProp.__doc__
        return
    
    entry = kern.GetValueFromAddress(cmd_args[0], 'IOService *')
    propertyTable = entry.fPropertyTable
    print GetObjectSummary(LookupKeyInPropTable(propertyTable, cmd_args[1]))

@lldb_command('readioport8')
def ReadIOPort8(cmd_args=None):
    """ Read value stored in the specified IO port. The CPU can be optionally
        specified as well.
        Prints 0xBAD10AD in case of a bad read
        Syntax: (lldb) readioport8 <port> [lcpu (kernel's numbering convention)]
    """
    if not cmd_args:
        print "Please specify a port to read out of"
        print ReadIOPort8.__doc__
        return
    
    portAddr = ArgumentStringToInt(cmd_args[0])
    if len(cmd_args) >= 2:
        lcpu = ArgumentStringToInt(cmd_args[1])
    else:
        lcpu = xnudefines.lcpu_self
            
    ReadIOPortInt(portAddr, 1, lcpu)

@lldb_command('readioport16')
def ReadIOPort16(cmd_args=None):
    """ Read value stored in the specified IO port. The CPU can be optionally
        specified as well.
        Prints 0xBAD10AD in case of a bad read
        Syntax: (lldb) readioport16 <port> [lcpu (kernel's numbering convention)]
    """
    if not cmd_args:
        print "Please specify a port to read out of"
        print ReadIOPort16.__doc__
        return
    
    portAddr = ArgumentStringToInt(cmd_args[0])
    if len(cmd_args) >= 2:
        lcpu = ArgumentStringToInt(cmd_args[1])
    else:
        lcpu = xnudefines.lcpu_self
    
    ReadIOPortInt(portAddr, 2, lcpu)

@lldb_command('readioport32')
def ReadIOPort32(cmd_args=None):
    """ Read value stored in the specified IO port. The CPU can be optionally
        specified as well.
        Prints 0xBAD10AD in case of a bad read
        Syntax: (lldb) readioport32 <port> [lcpu (kernel's numbering convention)]
    """
    if not cmd_args:
        print "Please specify a port to read out of"
        print ReadIOPort32.__doc__
        return
    
    portAddr = ArgumentStringToInt(cmd_args[0])
    if len(cmd_args) >= 2:
        lcpu = ArgumentStringToInt(cmd_args[1])
    else:
        lcpu = xnudefines.lcpu_self
    
    ReadIOPortInt(portAddr, 4, lcpu)

@lldb_command('writeioport8')
def WriteIOPort8(cmd_args=None):
    """ Write the value to the specified IO port. The size of the value is
        determined by the name of the command. The CPU used can be optionally
        specified as well.
        Syntax: (lldb) writeioport8 <port> <value> [lcpu (kernel's numbering convention)]
    """
    if not cmd_args or len(cmd_args) < 2:
        print "Please specify a port to write to, followed by the value you want to write"
        print WriteIOPort8.__doc__
        return
    
    portAddr = ArgumentStringToInt(cmd_args[0])
    value = ArgumentStringToInt(cmd_args[1])
    
    if len(cmd_args) >= 3:
        lcpu = ArgumentStringToInt(cmd_args[2])
    else:
        lcpu = xnudefines.lcpu_self
    
    WriteIOPortInt(portAddr, 1, value, lcpu)

@lldb_command('writeioport16')
def WriteIOPort16(cmd_args=None):
    """ Write the value to the specified IO port. The size of the value is
        determined by the name of the command. The CPU used can be optionally
        specified as well.
        Syntax: (lldb) writeioport16 <port> <value> [lcpu (kernel's numbering convention)]
    """
    if not cmd_args or len(cmd_args) < 2:
        print "Please specify a port to write to, followed by the value you want to write"
        print WriteIOPort16.__doc__
        return
    
    portAddr = ArgumentStringToInt(cmd_args[0])
    value = ArgumentStringToInt(cmd_args[1])
    
    if len(cmd_args) >= 3:
        lcpu = ArgumentStringToInt(cmd_args[2])
    else:
        lcpu = xnudefines.lcpu_self
    
    WriteIOPortInt(portAddr, 2, value, lcpu)

@lldb_command('writeioport32')
def WriteIOPort32(cmd_args=None):
    """ Write the value to the specified IO port. The size of the value is
        determined by the name of the command. The CPU used can be optionally
        specified as well.
        Syntax: (lldb) writeioport32 <port> <value> [lcpu (kernel's numbering convention)]
    """
    if not cmd_args or len(cmd_args) < 2:
        print "Please specify a port to write to, followed by the value you want to write"
        print WriteIOPort32.__doc__
        return
    
    portAddr = ArgumentStringToInt(cmd_args[0])
    value = ArgumentStringToInt(cmd_args[1])
    
    if len(cmd_args) >= 3:
        lcpu = ArgumentStringToInt(cmd_args[2])
    else:
        lcpu = xnudefines.lcpu_self
    
    WriteIOPortInt(portAddr, 4, value, lcpu)

@lldb_command('showioservicepm')
def ShowIOServicePM(cmd_args=None):
    """ Routine to dump the IOServicePM object
        Syntax: (lldb) showioservicepm <IOServicePM pointer>
    """
    if not cmd_args:
        print "Please enter the pointer to the IOServicePM object you'd like to introspect"
        print ShowIOServicePM.__doc__
        return
    
    iopmpriv = kern.GetValueFromAddress(cmd_args[0], 'IOServicePM *')
    out_string = "MachineState {0: <6d} (".format(iopmpriv.MachineState)
    
    # Power state map
    pstate_map = {
            0:  'kIOPM_Finished',
            1:  'kIOPM_OurChangeTellClientsPowerDown',
            2:  'kIOPM_OurChangeTellClientsPowerDown',
            3:  'kIOPM_OurChangeNotifyInterestedDriversWillChange',
            4:  'kIOPM_OurChangeSetPowerState',
            5:  'kIOPM_OurChangeWaitForPowerSettle',
            6:  'kIOPM_OurChangeNotifyInterestedDriversDidChange',
            7:  'kIOPM_OurChangeTellCapabilityDidChange',
            8:  'kIOPM_OurChangeFinish',
            9:  'Unused_MachineState_9',
            10: 'kIOPM_ParentChangeTellPriorityClientsPowerDown',
            11: 'kIOPM_ParentChangeNotifyInterestedDriversWillChange',
            12: 'kIOPM_ParentChangeSetPowerState',
            13: 'kIOPM_ParentChangeWaitForPowerSettle',
            14: 'kIOPM_ParentChangeNotifyInterestedDriversDidChange',
            15: 'kIOPM_ParentChangeTellCapabilityDidChange',
            16: 'kIOPM_ParentChangeAcknowledgePowerChange',
            17: 'kIOPM_NotifyChildrenStart',
            18: 'kIOPM_NotifyChildrenOrdered',
            19: 'kIOPM_NotifyChildrenDelayed',
            20: 'kIOPM_SyncTellClientsPowerDown',
            21: 'kIOPM_SyncTellPriorityClientsPowerDown',
            22: 'kIOPM_SyncNotifyWillChange',
            23: 'kIOPM_SyncNotifyDidChange',
            24: 'kIOPM_SyncTellCapabilityDidChange',
            25: 'kIOPM_SyncFinish',
            26: 'kIOPM_TellCapabilityChangeDone',
            27: 'kIOPM_DriverThreadCallDone'
        }
    powerstate = unsigned(iopmpriv.MachineState)
    if powerstate in pstate_map:
        out_string += "{0:s}".format(pstate_map[powerstate])
    else:
        out_string += "Unknown_MachineState"
    out_string += "), "
    
    if iopmpriv.MachineState != 20:
        out_string += "DriverTimer = {0: <6d}, SettleTime = {1: < 6d}, HeadNoteFlags = {2: #12x}, HeadNotePendingAcks = {3: #012x}, ".format(
                unsigned(iopmpriv.DriverTimer),
                unsigned(iopmpriv.SettleTimeUS),
                unsigned(iopmpriv.HeadNoteChangeFlags),
                unsigned(iopmpriv.HeadNotePendingAcks))
    
    if iopmpriv.DeviceOverrideEnabled != 0:
        out_string += "DeviceOverrides, "
    
    out_string += "DeviceDesire = {0: <6d}, DesiredPowerState = {1: <6d}, PreviousRequest = {2: <6d}\n".format(
            unsigned(iopmpriv.DeviceDesire),
            unsigned(iopmpriv.DesiredPowerState),
            unsigned(iopmpriv.PreviousRequestPowerFlags))
    
    print out_string


@lldb_command("showinterruptvectors")
def ShowInterruptVectorInfo(cmd_args=None):
    """
    Shows interrupt vectors.
    """

    # Constants
    kInterruptTriggerModeMask  = 0x01
    kInterruptTriggerModeEdge  = 0x00
    kInterruptTriggerModeLevel = kInterruptTriggerModeMask
    kInterruptPolarityMask     = 0x02
    kInterruptPolarityHigh     = 0x00
    kInterruptPolarityLow      = kInterruptPolarityMask
    kInterruptShareableMask    = 0x04
    kInterruptNotShareable     = 0x00
    kInterruptIsShareable      = kInterruptShareableMask
    kIOInterruptTypePCIMessaged = 0x00010000

    # Get all interrupt controllers
    interrupt_controllers = list(SearchInterruptControllerDrivers())

    print("Interrupt controllers: ")
    for ic in interrupt_controllers:
        print("  {}".format(ic))
    print("")

    # Iterate over all entries in the registry
    for entry in GetMatchingEntries(lambda _: True):
        # Get the name of the entry
        entry_name = GetRegistryEntryName(entry)

        # Get the location of the entry
        entry_location = GetRegistryEntryLocationInPlane(entry, kern.globals.gIOServicePlane)
        if entry_location is None:
            entry_location = ""
        else:
            entry_location = "@" + entry_location

        # Get the interrupt properties
        (msi_mode, vectorDataList, vectorContList) = GetRegistryEntryInterruptProperties(entry)
        should_print = False
        out_str = ""
        for (vector_data, vector_cont) in zip(vectorDataList, vectorContList):
            # vector_cont is the name of the interrupt controller. Find the matching controller from
            # the list of controllers obtained earlier
            matching_ics = filter(lambda ic: ic.name == vector_cont, interrupt_controllers)

            if len(matching_ics) > 0:
                should_print = True
                # Take the first match
                matchingIC = matching_ics[0]

                # Use the vector_data to determine the vector and any flags
                data_ptr = vector_data.data
                data_length = vector_data.length

                # Dereference vector_data as a uint32_t * and add the base vector number
                gsi = unsigned(dereference(Cast(data_ptr, 'uint32_t *')))
                gsi += matchingIC.base_vector_number

                # If data_length is >= 8 then vector_data contains interrupt flags
                if data_length >= 8:
                    # Add sizeof(uint32_t) to data_ptr to get the flags pointer
                    flags_ptr = kern.GetValueFromAddress(unsigned(data_ptr) + sizeof("uint32_t"))
                    flags = unsigned(dereference(Cast(flags_ptr, 'uint32_t *')))
                    out_str += "  +----- [Interrupt Controller {ic}] vector {gsi}, {trigger_level}, {active}, {shareable}{messaged}\n" \
                            .format(ic=matchingIC.name, gsi=hex(gsi), 
                                    trigger_level="level trigger" if flags & kInterruptTriggerModeLevel else "edge trigger",
                                    active="active low" if flags & kInterruptPolarityLow else "active high",
                                    shareable="shareable" if flags & kInterruptIsShareable else "exclusive",
                                    messaged=", messaged" if flags & kIOInterruptTypePCIMessaged else "")
                else:
                    out_str += "  +----- [Interrupt Controller {ic}] vector {gsi}\n".format(ic=matchingIC.name, gsi=hex(gsi))
        if should_print:
            print("[ {entry_name}{entry_location} ]{msi_mode}\n{out_str}" \
                .format(entry_name=entry_name,
                        entry_location=entry_location,
                        msi_mode=" - MSIs enabled" if msi_mode else "",
                        out_str=out_str))

@lldb_command("showiokitclasshierarchy")
def ShowIOKitClassHierarchy(cmd_args=None):
    """
    Show class hierarchy for a IOKit class
    """
    if not cmd_args:
        print("Usage: showiokitclasshierarchy <IOKit class name>")
        return

    class_name = cmd_args[0]
    metaclasses = GetMetaClasses()
    if class_name not in metaclasses:
        print("Class {} does not exist".format(class_name))
        return
    metaclass = metaclasses[class_name]

    # loop over superclasses
    hierarchy = []
    current_metaclass = metaclass
    while current_metaclass is not None:
        hierarchy.insert(0, current_metaclass)
        current_metaclass = current_metaclass.superclass()

    for (index, mc) in enumerate(hierarchy):
        indent = ("    " * index) + "+---"
        print("{}[ {} ] {}".format(indent, str(mc.className()), str(mc.data())))




######################################
#  Helper routines
######################################
def ShowRegistryEntryRecurse(entry, prefix, printProps):
    """ prints registry entry summary and recurses through all its children.
    """
    # Setup
    global plane
    out_string = ""
    plen = (len(prefix)//2)
    registryTable = entry.fRegistryTable
    propertyTable = entry.fPropertyTable
    
    # Print entry details
    print "{0:s}{1:s}".format(prefix, GetRegistryEntrySummary(entry))
    # Printing large property tables make it look like lldb is 'stuck'
    if printProps:
        print GetRegDictionary(propertyTable, prefix + "  | ")
    
    # Recurse
    if plane is None:
        childKey = kern.globals.gIOServicePlane.keys[1]
    else:
        childKey = plane.keys[1]
    childArray = LookupKeyInOSDict(registryTable, childKey)
    if childArray is not None:
        idx = 0
        ca = CastIOKitClass(childArray, 'OSArray *')
        count = unsigned(ca.count)
        while idx < count:
            if plen != 0 and plen != 1 and (plen & (plen - 1)) == 0:
                ShowRegistryEntryRecurse(CastIOKitClass(ca.array[idx], 'IORegistryEntry *'), prefix + "| ", printProps)
            else:
                ShowRegistryEntryRecurse(CastIOKitClass(ca.array[idx], 'IORegistryEntry *'), prefix + "  ", printProps)
            idx += 1

def FindRegistryEntryRecurse(entry, search_name, stopAfterFirst):
    """ Checks if given registry entry's name matches the search_name we're looking for
        If yes, it prints the entry's summary and then recurses through its children
        If no, it does nothing and recurses through its children
    """
    # Setup
    global plane
    registryTable = entry.fRegistryTable
    propertyTable = entry.fPropertyTable
    
    # Compare
    name = None
    name = LookupKeyInOSDict(registryTable, kern.globals.gIOServicePlane.nameKey)
    if name is None:
        name = LookupKeyInOSDict(registryTable, kern.globals.gIONameKey)
    if name is None:
        name = LookupKeyInOSDict(propertyTable, kern.globals.gIOClassKey)
    
    if name is not None:
        if str(CastIOKitClass(name, 'OSString *').string) == search_name:
            print GetRegistryEntrySummary(entry)
            if stopAfterFirst is True:
                return True
    elif CastIOKitClass(entry, 'IOService *').pwrMgt and CastIOKitClass(entry, 'IOService *').pwrMgt.Name:
        name = CastIOKitClass(entry, 'IOService *').pwrMgt.Name
        if str(name) == search_name:
            print GetRegistryEntrySummary(entry)
            if stopAfterFirst is True:
                return True
    
    # Recurse
    if plane is None:
        childKey = kern.globals.gIOServicePlane.keys[1]
    else:
        childKey = plane.keys[1]
    childArray = LookupKeyInOSDict(registryTable, childKey)
    if childArray is not None:
        idx = 0
        ca = CastIOKitClass(childArray, 'OSArray *')
        count = unsigned(ca.count)
        while idx < count:
            if FindRegistryEntryRecurse(CastIOKitClass(ca.array[idx], 'IORegistryEntry *'), search_name, stopAfterFirst) is True:
                return True
            idx += 1
    return False

def FindRegistryObjectRecurse(entry, search_name):
    """ Checks if given registry entry's name matches the search_name we're looking for
        If yes, return the entry
        If no, it does nothing and recurses through its children
        Implicitly stops after finding the first entry
    """
    # Setup
    global plane
    registryTable = entry.fRegistryTable
    propertyTable = entry.fPropertyTable

    # Compare
    name = None
    name = LookupKeyInOSDict(registryTable, kern.globals.gIOServicePlane.nameKey)
    if name is None:
        name = LookupKeyInOSDict(registryTable, kern.globals.gIONameKey)
    if name is None:
        name = LookupKeyInOSDict(propertyTable, kern.globals.gIOClassKey)
    
    if name is not None:
        if str(CastIOKitClass(name, 'OSString *').string) == search_name:
            return entry
    elif CastIOKitClass(entry, 'IOService *').pwrMgt and CastIOKitClass(entry, 'IOService *').pwrMgt.Name:
        name = CastIOKitClass(entry, 'IOService *').pwrMgt.Name
        if str(name) == search_name:
            return entry
    
    # Recurse
    if plane is None:
        childKey = kern.globals.gIOServicePlane.keys[1]
    else:
        childKey = plane.keys[1]
    childArray = LookupKeyInOSDict(registryTable, childKey)
    if childArray is not None:
        ca = CastIOKitClass(childArray, 'OSArray *')
        for idx in range(ca.count):
            registry_object = FindRegistryObjectRecurse(CastIOKitClass(ca.array[idx], 'IORegistryEntry *'), search_name)
            if not registry_object or int(registry_object) == int(0):
                continue
            else:
                return registry_object
    return None


class IOKitMetaClass(object):
    """
    A class that represents a IOKit metaclass. This is used to represent the
    IOKit inheritance hierarchy.
    """

    def __init__(self, meta):
        """
        Initialize a IOKitMetaClass object.

        Args:
            meta (core.cvalue.value): A LLDB value representing a
                OSMetaClass *.
        """
        self._meta = meta
        self._superclass = None

    def data(self):
        return self._meta

    def setSuperclass(self, superclass):
        """
        Set the superclass for this metaclass.

        Args:
            superclass (core.cvalue.value): A LLDB value representing a
                OSMetaClass *.
        """
        self._superclass = superclass

    def superclass(self):
        """
        Get the superclass for this metaclass (set by the setSuperclass method).

        Returns:
            core.cvalue.value: A LLDB value representing a OSMetaClass *.
        """
        return self._superclass

    def className(self):
        """
        Get the name of the class this metaclass represents.

        Returns:
            str: The class name
        """
        return self._meta.className.string

    def inheritsFrom(self, other):
        """
        Check if the class represented by this metaclass inherits from a class
        represented by another metaclass.

        Args:
            other (IOKitMetaClass): The other metaclass

        Returns:
            bool: Returns True if this class inherits from the other class and
                False otherwise.
        """
        current = self
        while current is not None:
            if current == other:
                return True
            else:
                current = current.superclass()


def GetRegistryEntryClassName(entry):
    """
    Get the class name of a registry entry.

    Args:
        entry (core.cvalue.value): A LLDB value representing a
            IORegistryEntry *.

    Returns:
        str: The class name of the entry or None if a class name could not be
            found.
    """
    # Check using IOClass key
    result = LookupKeyInOSDict(entry.fPropertyTable, kern.globals.gIOClassKey)
    if result is not None:
        return GetString(result).replace("\"", "")
    else:
        # Use the vtable of the entry to determine the concrete type
        vt = dereference(Cast(entry, 'uintptr_t *')) - 2 * sizeof('uintptr_t')
        vt = kern.StripKernelPAC(vt)
        vtype = kern.SymbolicateFromAddress(vt)
        if len(vtype) > 0:
            vtableName = vtype[0].GetName()
            return vtableName[11:] # strip off "vtable for "
        else:
            return None


def GetRegistryEntryName(entry):
    """
    Get the name of a registry entry.

    Args:
        entry (core.cvalue.value): A LLDB value representing a
            IORegistryEntry *.

    Returns:
        str: The name of the entry or None if a name could not be found.
    """
    name = None

    # First check the IOService plane nameKey
    result = LookupKeyInOSDict(entry.fRegistryTable, kern.globals.gIOServicePlane.nameKey)
    if result is not None:
        name = GetString(result)

    # Check the global IOName key
    if name is None:
        result = LookupKeyInOSDict(entry.fRegistryTable, kern.globals.gIONameKey)
        if result is not None:
            name = GetString(result)

    # Check the IOClass key
    if name is None:
        result = LookupKeyInOSDict(entry.fPropertyTable, kern.globals.gIOClassKey)
        if result is not None:
            name = GetString(result)

    # Remove extra quotes        
    if name is not None:
        return name.replace("\"", "")
    else:
        return GetRegistryEntryClassName(entry)


def GetRegistryEntryLocationInPlane(entry, plane):
    """
    Get the registry entry location in a IOKit plane.

    Args:
        entry (core.cvalue.value): A LLDB value representing a
            IORegistryEntry *.
        plane: An IOKit plane such as kern.globals.gIOServicePlane.

    Returns:
        str: The location of the entry or None if a location could not be
            found.
    """
    # Check the plane's pathLocationKey
    sym = LookupKeyInOSDict(entry.fRegistryTable, plane.pathLocationKey)

    # Check the global IOLocation key
    if sym is None:
        sym = LookupKeyInOSDict(entry.fRegistryTable, kern.globals.gIOLocationKey)
    if sym is not None:
        return GetString(sym).replace("\"", "")
    else:
        return None


def GetMetaClasses():
    """
    Enumerate all IOKit metaclasses. Uses dynamic caching.

    Returns:
        Dict[str, IOKitMetaClass]: A dictionary mapping each metaclass name to
            a IOKitMetaClass object representing the metaclass.
    """
    METACLASS_CACHE_KEY = "iokit_metaclasses"
    cached_data = caching.GetDynamicCacheData(METACLASS_CACHE_KEY)

    # If we have cached data, return immediately
    if cached_data is not None:
        return cached_data

    # This method takes a while, so it prints a progress indicator
    print("Enumerating IOKit metaclasses: ")
    
    # Iterate over all classes present in sAllClassesDict
    idx = 0
    count = unsigned(kern.globals.sAllClassesDict.count)
    metaclasses_by_address = {}
    while idx < count:
        # Print progress after every 10 items
        if idx % 10 == 0:
            print("  {} metaclass structures parsed...".format(idx))
        
        # Address of metaclass
        address = kern.globals.sAllClassesDict.dictionary[idx].value

        # Create IOKitMetaClass and store in dict
        metaclasses_by_address[int(address)] = IOKitMetaClass(CastIOKitClass(kern.globals.sAllClassesDict.dictionary[idx].value, 'OSMetaClass *'))
        idx += 1
    
    print("  Enumerated {} metaclasses.".format(count))

    # At this point, each metaclass is independent of each other. We don't have superclass links set up yet.

    for (address, metaclass) in metaclasses_by_address.items():
        # Get the address of the superclass using the superClassLink in IOMetaClass
        superclass_address = int(metaclass.data().superClassLink)

        # Skip null superclass
        if superclass_address == 0:
            continue

        # Find the superclass object in the dict
        if superclass_address in metaclasses_by_address:
            metaclass.setSuperclass(metaclasses_by_address[superclass_address])
        else:
            print("warning: could not find superclass for {}".format(str(metaclass.data())))
    
    # This method returns a dictionary mapping each class name to the associated metaclass object
    metaclasses_by_name = {}
    for (_, metaclass) in metaclasses_by_address.items():
        metaclasses_by_name[str(metaclass.className())] = metaclass

    # Save the result in the cache
    caching.SaveDynamicCacheData(METACLASS_CACHE_KEY, metaclasses_by_name)

    return metaclasses_by_name


def GetMatchingEntries(matcher):
    """
    Iterate over the IOKit registry and find entries that match specific
        criteria.

    Args:
        matcher (function): A matching function that returns True for a match
            and False otherwise.

    Yields:
        core.cvalue.value: LLDB values that represent IORegistryEntry * for
            each registry entry found.
    """

    # Perform a BFS over the IOKit registry tree
    bfs_queue = deque()
    bfs_queue.append(kern.globals.gRegistryRoot)
    while len(bfs_queue) > 0:
        # Dequeue an entry
        entry = bfs_queue.popleft()

        # Check if entry matches
        if matcher(entry):
            yield entry

        # Find children of this entry and enqueue them
        child_array = LookupKeyInOSDict(entry.fRegistryTable, kern.globals.gIOServicePlane.keys[1])
        if child_array is not None:
            idx = 0
            ca = CastIOKitClass(child_array, 'OSArray *')
            count = unsigned(ca.count)
            while idx < count:
                bfs_queue.append(CastIOKitClass(ca.array[idx], 'IORegistryEntry *'))
                idx += 1


def FindMatchingServices(matching_name):
    """
    Finds registry entries that match the given string. Works similarly to:

    io_iterator_t iter;
    IOServiceGetMatchingServices(..., IOServiceMatching(matching_name), &iter);
    while (( io_object_t next = IOIteratorNext(iter))) { ... }

    Args:
        matching_name (str): The class name to search for.

    Yields:
        core.cvalue.value: LLDB values that represent IORegistryEntry * for
            each registry entry found.
    """

    # Check if the argument is valid
    metaclasses = GetMetaClasses()
    if matching_name not in metaclasses:
        return
    matching_metaclass = metaclasses[matching_name]

    # An entry matches if it inherits from matching_metaclass
    def matcher(entry):
        # Get the class name of the entry and the associated metaclass
        entry_name = GetRegistryEntryClassName(entry)
        if entry_name in metaclasses:
            entry_metaclass = metaclasses[entry_name]
            return entry_metaclass.inheritsFrom(matching_metaclass)
        else:
            return False
    
    # Search for entries
    for entry in GetMatchingEntries(matcher):
        yield entry


def GetRegistryEntryParent(entry, iokit_plane=None):
    """
    Gets the parent entry of a registry entry.

    Args:
        entry (core.cvalue.value): A LLDB value representing a
            IORegistryEntry *.
        iokit_plane (core.cvalue.value, optional): A LLDB value representing a
            IORegistryPlane *. By default, this method uses the IOService
            plane.

    Returns:
        core.cvalue.value: A LLDB value representing a IORegistryEntry* that
            is the parent entry of the entry argument in the specified plane.
            Returns None if no entry could be found.
    """
    kParentSetIndex = 0
    parent_key = None
    if iokit_plane is None:
        parent_key = kern.globals.gIOServicePlane.keys[kParentSetIndex]
    else:
        parent_key = plane.keys[kParentSetIndex]
    parent_array = LookupKeyInOSDict(entry.fRegistryTable, parent_key)
    parent_entry = None
    if parent_array is not None:
        idx = 0
        ca = CastIOKitClass(parent_array, 'OSArray *')
        count = unsigned(ca.count)
        if count > 0:
            parent_entry = CastIOKitClass(ca.array[0], 'IORegistryEntry *')
    return parent_entry


def GetRegistryEntryInterruptProperties(entry):
    """
    Get the interrupt properties of a registry entry.

    Args:
        entry (core.cvalue.value): A LLDB value representing a IORegistryEntry *.

    Returns:
        (bool, List[core.cvalue.value], List[str]): A tuple with the following
            fields:
                - First field (bool): Whether this entry has a non-null
                    IOPCIMSIMode.
                - Second field (List[core.cvalue.value]): A list of LLDB values
                    representing OSData *. The OSData* pointer points to
                    interrupt vector data.
                - Third field (List[str]): A list of strings representing the
                    interrupt controller names from the
                    IOInterruptControllers property.
    """
    INTERRUPT_SPECIFIERS_PROPERTY = "IOInterruptSpecifiers"
    INTERRUPT_CONTROLLERS_PROPERTY = "IOInterruptControllers"
    MSI_MODE_PROPERTY = "IOPCIMSIMode"

    # Check IOInterruptSpecifiers
    interrupt_specifiers = LookupKeyInPropTable(entry.fPropertyTable, INTERRUPT_SPECIFIERS_PROPERTY)
    if interrupt_specifiers is not None:
        interrupt_specifiers = CastIOKitClass(interrupt_specifiers, 'OSArray *')
    
    # Check IOInterruptControllers
    interrupt_controllers = LookupKeyInPropTable(entry.fPropertyTable, INTERRUPT_CONTROLLERS_PROPERTY)
    if interrupt_controllers is not None:
        interrupt_controllers = CastIOKitClass(interrupt_controllers, 'OSArray *')

    # Check MSI mode
    msi_mode = LookupKeyInPropTable(entry.fPropertyTable, MSI_MODE_PROPERTY)

    result_vector_data = []
    result_vector_cont = []
    if interrupt_specifiers is not None and interrupt_controllers is not None:
        interrupt_specifiers_array_count = unsigned(interrupt_specifiers.count)
        interrupt_controllers_array_count = unsigned(interrupt_controllers.count)
        # The array lengths should be the same
        if interrupt_specifiers_array_count == interrupt_controllers_array_count and interrupt_specifiers_array_count > 0:
            idx = 0
            while idx < interrupt_specifiers_array_count:
                # IOInterruptSpecifiers is an array of OSData *
                vector_data = CastIOKitClass(interrupt_specifiers.array[idx], "OSData *")

                # IOInterruptControllers is an array of OSString *
                vector_cont = GetString(interrupt_controllers.array[idx])

                result_vector_data.append(vector_data)
                result_vector_cont.append(vector_cont)
                idx += 1
    
    return (msi_mode is not None, result_vector_data, result_vector_cont)


class InterruptControllerDevice(object):
    """Represents a IOInterruptController"""

    def __init__(self, device, driver, base_vector_number, name):
        """
        Initialize a InterruptControllerDevice.

        Args:
            device (core.cvalue.value): The device object.
            driver (core.cvalue.value): The driver object.
            base_vector_number (int): The base interrupt vector.
            name (str): The name of this interrupt controller.

        Note:
            Use the factory method makeInterruptControllerDevice to validate
            properties.
        """
        self.device = device
        self.driver = driver
        self.name = name
        self.base_vector_number = base_vector_number


    def __str__(self):
        """
        String representation of this InterruptControllerDevice.
        """
        return " Name {}, base vector = {}, device = {}, driver = {}".format(
            self.name, hex(self.base_vector_number), str(self.device), str(self.driver))

    @staticmethod
    def makeInterruptControllerDevice(device, driver):
        """
        Factory method to create a InterruptControllerDevice.

        Args:
            device (core.cvalue.value): The device object.
            driver (core.cvalue.value): The driver object.

        Returns:
            InterruptControllerDevice: Returns an instance of
                InterruptControllerDevice or None if the arguments do not have
                the required properties.
        """
        BASE_VECTOR_PROPERTY = "Base Vector Number"
        INTERRUPT_CONTROLLER_NAME_PROPERTY = "InterruptControllerName"
        base_vector = LookupKeyInPropTable(device.fPropertyTable, BASE_VECTOR_PROPERTY)
        if base_vector is None:
            base_vector = LookupKeyInPropTable(driver.fPropertyTable, BASE_VECTOR_PROPERTY)
        device_name = LookupKeyInPropTable(device.fPropertyTable, INTERRUPT_CONTROLLER_NAME_PROPERTY)
        if device_name is None:
            device_name = LookupKeyInPropTable(driver.fPropertyTable, INTERRUPT_CONTROLLER_NAME_PROPERTY)

        if device_name is not None:
            # Some interrupt controllers do not have a base vector number. Assume it is 0.
            base_vector_number = 0
            if base_vector is not None:
                base_vector_number = unsigned(GetNumber(base_vector))
            device_name = GetString(device_name)
            # Construct object and return
            return InterruptControllerDevice(device, driver, base_vector_number, device_name)
        else:
            # error case
            return None


def SearchInterruptControllerDrivers():
    """
    Search the IOKit registry for entries that match IOInterruptController.

    Yields:
        core.cvalue.value: A LLDB value representing a IORegistryEntry * that
        inherits from IOInterruptController.
    """
    for entry in FindMatchingServices("IOInterruptController"):
        # Get parent
        parent = GetRegistryEntryParent(entry)

        # Make the interrupt controller object
        ic = InterruptControllerDevice.makeInterruptControllerDevice(parent, entry)

        # Yield object
        if ic is not None:
            yield ic


def LookupKeyInOSDict(osdict, key):
    """ Returns the value corresponding to a given key in a OSDictionary
        Returns None if the key was not found
    """
    if not osdict:
        return
    count = unsigned(osdict.count)
    result = None
    idx = 0
    while idx < count and result is None:
        if key == osdict.dictionary[idx].key:
            result = osdict.dictionary[idx].value
        idx += 1
    return result

def LookupKeyInPropTable(propertyTable, key_str):
    """ Returns the value corresponding to a given key from a registry entry's property table
        Returns None if the key was not found
        The property that is being searched for is specified as a string in key_str
    """
    if not propertyTable:
        return
    count = unsigned(propertyTable.count)
    result = None
    idx = 0
    while idx < count and result is None:
        if key_str == str(propertyTable.dictionary[idx].key.string):
            result = propertyTable.dictionary[idx].value
        idx += 1
    return result

def GetRegDictionary(osdict, prefix):
    """ Returns a specially formatted string summary of the given OSDictionary
        This is done in order to pretty-print registry property tables in showregistry
        and other macros
    """
    out_string = prefix + "{\n"
    idx = 0
    count = unsigned(osdict.count)
    
    while idx < count:
        out_string += prefix + "  " + GetObjectSummary(osdict.dictionary[idx].key) + " = " + GetObjectSummary(osdict.dictionary[idx].value) + "\n"
        idx += 1
    out_string += prefix + "}\n"
    return out_string

def GetString(string):
    """ Returns the python string representation of a given OSString
    """
    out_string = "\"{0:s}\"".format(CastIOKitClass(string, 'OSString *').string)
    return out_string

def GetNumber(num):
    out_string = "{0:d}".format(CastIOKitClass(num, 'OSNumber *').value)
    return out_string

def GetBoolean(b):
    """ Shows info about a given OSBoolean
    """
    out_string = ""
    if b == kern.globals.gOSBooleanFalse:
        out_string += "No"
    else:
        out_string += "Yes"
    return out_string

def GetMetaClass(mc):
    """ Shows info about a given OSSymbol
    """
    out_string = "{0: <5d}x {1: >5d} bytes {2:s}\n".format(mc.instanceCount, mc.classSize, mc.className.string)
    return out_string

def GetArray(arr):
    """ Returns a string containing info about a given OSArray
    """
    out_string = ""
    idx = 0
    count = unsigned(arr.count)
    
    while idx < count:
        obj = arr.array[idx]
        idx += 1
        out_string += GetObjectSummary(obj)
        if idx < unsigned(arr.count):
            out_string += ","
    return out_string

def GetDictionary(d):
    """ Returns a string containing info about a given OSDictionary
    """
    out_string = "{"
    idx = 0
    count = unsigned(d.count)

    while idx < count:
        obj = d.dictionary[idx].key
        out_string += GetObjectSummary(obj) + "="
        obj = d.dictionary[idx].value
        idx += 1
        out_string += GetObjectSummary(obj)
        if idx < count:
            out_string += ","
    out_string += "}"
    return out_string

def GetSet(se):
    """ Returns a string containing info about a given OSSet
    """
    out_string += "[" + GetArray(se.members) + "]"
    return out_string

def ReadIOPortInt(addr, numbytes, lcpu):
    """ Prints results after reading a given ioport
    """
    result = 0xBAD10AD
    
    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Nothing to do here."
        return
    
    # Set up the manual KDP packet
    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        print "0x{0: <4x}: 0x{1: <1x}".format(addr, result)
        return
    
    kdp_pkt_size = GetType('kdp_readioport_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        print "0x{0: <4x}: 0x{1: <1x}".format(addr, result)
        return
    
    kgm_pkt = kern.GetValueFromAddress(data_address, 'kdp_readioport_req_t *')
    
    header_value = GetKDPPacketHeaderInt(request=GetEnumValue('kdp_req_t::KDP_READIOPORT'), length = kdp_pkt_size)
    
    if( WriteInt64ToMemoryAddress((header_value), int(addressof(kgm_pkt.hdr))) and
        WriteInt16ToMemoryAddress(addr, int(addressof(kgm_pkt.address))) and
        WriteInt32ToMemoryAddress(numbytes, int(addressof(kgm_pkt.nbytes))) and
        WriteInt16ToMemoryAddress(lcpu, int(addressof(kgm_pkt.lcpu))) and
        WriteInt32ToMemoryAddress(1, input_address)
        ):
        
        result_pkt = Cast(addressof(kern.globals.manual_pkt.data), 'kdp_readioport_reply_t *')
        
        if(result_pkt.error == 0):
            if numbytes == 1:
                result = dereference(Cast(addressof(result_pkt.data), 'uint8_t *'))
            elif numbytes == 2:
                result = dereference(Cast(addressof(result_pkt.data), 'uint16_t *'))
            elif numbytes == 4:
                result = dereference(Cast(addressof(result_pkt.data), 'uint32_t *'))

    print "{0: <#6x}: {1:#0{2}x}".format(addr, result, (numbytes*2)+2)

def WriteIOPortInt(addr, numbytes, value, lcpu):
    """ Writes 'value' into ioport specified by 'addr'. Prints errors if it encounters any
    """
    if "kdp" != GetConnectionProtocol():
        print "Target is not connected over kdp. Nothing to do here."
        return
    
    # Set up the manual KDP packet
    input_address = unsigned(addressof(kern.globals.manual_pkt.input))
    len_address = unsigned(addressof(kern.globals.manual_pkt.len))
    data_address = unsigned(addressof(kern.globals.manual_pkt.data))
    if not WriteInt32ToMemoryAddress(0, input_address):
        print "error writing {0: #x} to port {1: <#6x}: failed to write 0 to input_address".format(value, addr)
        return
    
    kdp_pkt_size = GetType('kdp_writeioport_req_t').GetByteSize()
    if not WriteInt32ToMemoryAddress(kdp_pkt_size, len_address):
        print "error writing {0: #x} to port {1: <#6x}: failed to write kdp_pkt_size".format(value, addr)
        return
    
    kgm_pkt = kern.GetValueFromAddress(data_address, 'kdp_writeioport_req_t *')
    
    header_value = GetKDPPacketHeaderInt(request=GetEnumValue('kdp_req_t::KDP_WRITEIOPORT'), length = kdp_pkt_size)
    
    if( WriteInt64ToMemoryAddress((header_value), int(addressof(kgm_pkt.hdr))) and
        WriteInt16ToMemoryAddress(addr, int(addressof(kgm_pkt.address))) and
        WriteInt32ToMemoryAddress(numbytes, int(addressof(kgm_pkt.nbytes))) and
        WriteInt16ToMemoryAddress(lcpu, int(addressof(kgm_pkt.lcpu)))
        ):
        if numbytes == 1:
            if not WriteInt8ToMemoryAddress(value, int(addressof(kgm_pkt.data))):
                print "error writing {0: #x} to port {1: <#6x}: failed to write 8 bit data".format(value, addr)
                return
        elif numbytes == 2:
            if not WriteInt16ToMemoryAddress(value, int(addressof(kgm_pkt.data))):
                print "error writing {0: #x} to port {1: <#6x}: failed to write 16 bit data".format(value, addr)
                return
        elif numbytes == 4:
            if not WriteInt32ToMemoryAddress(value, int(addressof(kgm_pkt.data))):
                print "error writing {0: #x} to port {1: <#6x}: failed to write 32 bit data".format(value, addr)
                return
        if not WriteInt32ToMemoryAddress(1, input_address):
            print "error writing {0: #x} to port {1: <#6x}: failed to write to input_address".format(value, addr)
            return

        result_pkt = Cast(addressof(kern.globals.manual_pkt.data), 'kdp_writeioport_reply_t *')
        
        # Done with the write
        if(result_pkt.error == 0):
            print "Writing {0: #x} to port {1: <#6x} was successful".format(value, addr)
    else:
        print "error writing {0: #x} to port {1: <#6x}".format(value, addr)

@lldb_command('showinterruptcounts')
def showinterruptcounts(cmd_args=None):
    """ Shows event source based interrupt counts by nub name and interrupt index.
        Does not cover interrupts that are not event source based.  Will report 0
        if interrupt accounting is disabled.
    """

    header_format = "{0: <20s} {1: >5s} {2: >20s}"
    content_format = "{0: <20s} {1: >5d} {2: >20d}"

    print header_format.format("Name", "Index", "Count")
    
    for i in kern.interrupt_stats:
        owner = CastIOKitClass(i.owner, 'IOInterruptEventSource *')
        nub = CastIOKitClass(owner.provider, 'IORegistryEntry *') 
        name = None

        # To uniquely identify an interrupt, we need the nub name and the index.  The index
        # is stored with the stats object, but we need to retrieve the name.

        registryTable = nub.fRegistryTable
        propertyTable = nub.fPropertyTable
    
        name = LookupKeyInOSDict(registryTable, kern.globals.gIOServicePlane.nameKey)
        if name is None:
            name = LookupKeyInOSDict(registryTable, kern.globals.gIONameKey)
        if name is None:
            name = LookupKeyInOSDict(propertyTable, kern.globals.gIOClassKey)

        if name is None:
            nub_name = "Unknown"
        else:
            nub_name = GetString(CastIOKitClass(name, 'OSString *'))

        # We now have everything we need; spew the requested data.

        interrupt_index = i.interruptIndex
        first_level_count = i.interruptStatistics[0]

        print content_format.format(nub_name, interrupt_index, first_level_count)
    
    return True

@lldb_command('showinterruptstats')
def showinterruptstats(cmd_args=None):
    """ Shows event source based interrupt statistics by nub name and interrupt index.
        Does not cover interrupts that are not event source based.  Will report 0
        if interrupt accounting is disabled, or if specific statistics are disabled.
        Time is reported in ticks of mach_absolute_time.  Statistics are:
        
        Interrupt Count: Number of times the interrupt context handler was run
        Interrupt Time: Total time spent in the interrupt context handler (if any)
        Workloop Count: Number of times the kernel context handler was run
        Workloop CPU Time: Total CPU time spent running the kernel context handler
        Workloop Time: Total time spent running the kernel context handler
    """

    header_format = "{0: <20s} {1: >5s} {2: >20s} {3: >20s} {4: >20s} {5: >20s} {6: >20s} {7: >20s} {8: >20s} {9: >20s}"
    content_format = "{0: <20s} {1: >5d} {2: >20d} {3: >20d} {4: >20d} {5: >20d} {6: >20d} {7: >20d} {8: >20d} {9: >#20x}"

    print header_format.format("Name", "Index", "Interrupt Count", "Interrupt Time", "Avg Interrupt Time", "Workloop Count", "Workloop CPU Time", "Workloop Time", "Avg Workloop Time", "Owner")
    
    for i in kern.interrupt_stats:
        owner = CastIOKitClass(i.owner, 'IOInterruptEventSource *')
        nub = CastIOKitClass(owner.provider, 'IORegistryEntry *') 
        name = None

        # To uniquely identify an interrupt, we need the nub name and the index.  The index
        # is stored with the stats object, but we need to retrieve the name.

        registryTable = nub.fRegistryTable
        propertyTable = nub.fPropertyTable
    
        name = LookupKeyInOSDict(registryTable, kern.globals.gIOServicePlane.nameKey)
        if name is None:
            name = LookupKeyInOSDict(registryTable, kern.globals.gIONameKey)
        if name is None:
            name = LookupKeyInOSDict(propertyTable, kern.globals.gIOClassKey)

        if name is None:
            nub_name = "Unknown"
        else:
            nub_name = GetString(CastIOKitClass(name, 'OSString *'))

        # We now have everything we need; spew the requested data.

        interrupt_index = i.interruptIndex
        first_level_count = i.interruptStatistics[0]
        second_level_count = i.interruptStatistics[1]
        first_level_time = i.interruptStatistics[2]
        second_level_cpu_time = i.interruptStatistics[3]
        second_level_system_time = i.interruptStatistics[4]

        avg_first_level_time = 0
        if first_level_count != 0:
            avg_first_level_time = first_level_time / first_level_count

        avg_second_level_time = 0
        if second_level_count != 0:
            avg_second_level_time = second_level_system_time / second_level_count

        print content_format.format(nub_name, interrupt_index, first_level_count, first_level_time, avg_first_level_time,
            second_level_count, second_level_cpu_time, second_level_system_time, avg_second_level_time, owner)
    
    return True

