from xnu import *
from utils import *
import sys

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
    vtype = kern.SymbolicateFromAddress(vt)
    if hasattr(obj, 'retainCount'):
        retCount = (obj.retainCount & 0xffff)
        cntnrRetCount = (retCount >> 16)
        out_string = "`object 0x{0: <16x}, vt 0x{1: <16x} <{2:s}>, retain count {3:d}, container retain {4:d}` ".format(obj, vt, vtype[0].GetName(), retCount, cntnrRetCount)
    else:
        if len(vtype):
            out_string = "`object 0x{0: <16x}, vt 0x{1: <16x} <{2:s}>` ".format(obj, vt, vtype[0].GetName())
        else:
            out_string = "`object 0x{0: <16x}, vt 0x{1: <16x}` ".format(obj, vt)
    
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

    header_format = "{0: <20s} {1: >5s} {2: >20s} {3: >20s} {4: >20s} {5: >20s} {6: >20s}"
    content_format = "{0: <20s} {1: >5d} {2: >20d} {3: >20d} {4: >20d} {5: >20d} {6: >20d}"

    print header_format.format("Name", "Index", "Interrupt Count", "Interrupt Time", "Workloop Count", "Workloop CPU Time", "Workloop Time")
    
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

        print content_format.format(nub_name, interrupt_index, first_level_count, first_level_time, second_level_count, second_level_cpu_time, second_level_system_time)
    
    return True

