#!/usr/bin/python
#

#source of register info is from http://opensource.apple.com/source/gdb/gdb-962/src/gdb/arm-tdep.c
import lldb
import struct
osplugin_target_obj = None

class PluginValue(lldb.SBValue):
    def GetChildMemberWithName(val, name):
        val_type = val.GetType()
        if val_type.IsPointerType() == True:
            val_type = val_type.GetPointeeType()
        for i in range(val_type.GetNumberOfFields()):
            if name == val_type.GetFieldAtIndex(i).GetName():
                return PluginValue(val.GetChildAtIndex(i))
        return None

class Armv8_RegisterSet(object):
    """ register info set for armv8 64 bit architecture"""
    register_info = { 'sets' : ['GPR'],
                  'registers': [
    {'name': 'x0'  , 'bitsize':64, 'offset':  0, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 0, 'dwarf': 0, 'alt-name':'arg1', 'generic':'arg1'},
    {'name': 'x1'  , 'bitsize':64, 'offset':  8, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 1, 'dwarf': 1, 'alt-name':'arg2', 'generic':'arg2'},
    {'name': 'x2'  , 'bitsize':64, 'offset': 16, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 2, 'dwarf': 2, 'alt-name':'arg3', 'generic':'arg3'},
    {'name': 'x3'  , 'bitsize':64, 'offset': 24, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 3, 'dwarf': 3, 'alt-name':'arg4', 'generic':'arg4'},
    {'name': 'x4'  , 'bitsize':64, 'offset': 32, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 4, 'dwarf': 4, 'alt-name':'arg5', 'generic':'arg5'},
    {'name': 'x5'  , 'bitsize':64, 'offset': 40, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 5, 'dwarf': 5, 'alt-name':'arg6', 'generic':'arg6'},
    {'name': 'x6'  , 'bitsize':64, 'offset': 48, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 6, 'dwarf': 6, 'alt-name':'arg7', 'generic':'arg7'},
    {'name': 'x7'  , 'bitsize':64, 'offset': 56, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 7, 'dwarf': 7, 'alt-name':'arg8', 'generic':'arg8'},
    {'name': 'x8'  , 'bitsize':64, 'offset': 64, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 8, 'dwarf': 8},
    {'name': 'x9'  , 'bitsize':64, 'offset': 72, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 9, 'dwarf': 9},
    {'name': 'x10' , 'bitsize':64, 'offset': 80, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':10, 'dwarf':10},
    {'name': 'x11' , 'bitsize':64, 'offset': 88, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':11, 'dwarf':11},
    {'name': 'x12' , 'bitsize':64, 'offset': 96, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':12, 'dwarf':12},
    {'name': 'x13' , 'bitsize':64, 'offset':104, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':13, 'dwarf':13},
    {'name': 'x14' , 'bitsize':64, 'offset':112, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':14, 'dwarf':14},
    {'name': 'x15' , 'bitsize':64, 'offset':120, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':15, 'dwarf':15},
    {'name': 'x16' , 'bitsize':64, 'offset':128, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':16, 'dwarf':16},
    {'name': 'x17' , 'bitsize':64, 'offset':136, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':17, 'dwarf':17},
    {'name': 'x18' , 'bitsize':64, 'offset':144, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':18, 'dwarf':18},
    {'name': 'x19' , 'bitsize':64, 'offset':152, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':19, 'dwarf':19},
    {'name': 'x20' , 'bitsize':64, 'offset':160, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':20, 'dwarf':20},
    {'name': 'x21' , 'bitsize':64, 'offset':168, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':21, 'dwarf':21},
    {'name': 'x22' , 'bitsize':64, 'offset':176, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':22, 'dwarf':22},
    {'name': 'x23' , 'bitsize':64, 'offset':184, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':23, 'dwarf':23},
    {'name': 'x24' , 'bitsize':64, 'offset':192, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':24, 'dwarf':24},
    {'name': 'x25' , 'bitsize':64, 'offset':200, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':25, 'dwarf':25},
    {'name': 'x26' , 'bitsize':64, 'offset':208, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':26, 'dwarf':26},
    {'name': 'x27' , 'bitsize':64, 'offset':216, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':27, 'dwarf':27},
    {'name': 'x28' , 'bitsize':64, 'offset':224, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':28, 'dwarf':28},
    {'name': 'fp'  , 'bitsize':64, 'offset':232, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':29, 'dwarf':29, 'alt-name': 'fp', 'generic':'fp'},
    {'name': 'lr'  , 'bitsize':64, 'offset':240, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':30, 'dwarf':30, 'alt-name': 'lr', 'generic':'lr'},
    {'name': 'sp'  , 'bitsize':64, 'offset':248, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':31, 'dwarf':31, 'alt-name': 'sp', 'generic':'sp'},
    {'name': 'pc'  , 'bitsize':64, 'offset':256, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':32, 'dwarf':32, 'alt-name': 'pc', 'generic':'pc'},
    {'name': 'far' , 'bitsize':64, 'offset':264, 'encoding':'uint', 'format':'hex', 'set':0},
    {'name': 'cpsr', 'bitsize':32, 'offset':272, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':33, 'dwarf':33, 'generic':'flags'},
    {'name': 'esr' , 'bitsize':32, 'offset':276, 'encoding':'uint', 'format':'hex', 'set':0},
    ]
    }

    def __init__(self):
        self.switch_context_address = osplugin_target_obj.FindSymbols('Switch_context')[0].GetSymbol().GetStartAddress().GetLoadAddress(osplugin_target_obj)
        self.ResetRegisterValues()
    def ResetRegisterValues(self):
        self.x0 = 0
        self.x1 = 0
        self.x2 = 0
        self.x3 = 0
        self.x4 = 0
        self.x5 = 0
        self.x6 = 0
        self.x7 = 0
        self.x8 = 0
        self.x9 = 0
        self.x10 = 0
        self.x11 = 0
        self.x12 = 0
        self.x13 = 0
        self.x14 = 0
        self.x15 = 0
        self.x16 = 0
        self.x17 = 0
        self.x18 = 0
        self.x19 = 0
        self.x20 = 0
        self.x21 = 0
        self.x22 = 0
        self.x23 = 0
        self.x24 = 0
        self.x25 = 0
        self.x26 = 0
        self.x27 = 0
        self.x28 = 0
        self.fp = 0
        self.lr = 0
        self.sp = 0
        self.pc = 0
        self.far = 0
        self.cpsr = 0
        self.esr = 0

    def __str__(self):
        return """ pc = """

    def GetPackedRegisterState(self):
        return struct.pack('34QII', self.x0, self.x1, self.x2, self.x3, self.x4, self.x5,
            self.x6, self.x7, self.x8, self.x9, self.x10, self.x11, self.x12, self.x13,
            self.x14, self.x15, self.x16, self.x17, self.x18, self.x19, self.x20, self.x21,
            self.x22, self.x23, self.x24, self.x25, self.x26, self.x27, self.x28, self.fp,
            self.lr, self.sp, self.pc, self.far, self.cpsr, self.esr)

    def ReadRegisterDataFromKDPSavedState(self, kdp_state, kernel_version):
        """ Setup register values from KDP saved information.
        """
        saved_state = kernel_version.CreateValueFromExpression(None, '(struct arm_saved_state64 *) ' + str(kdp_state.GetValueAsUnsigned()))
        saved_state = saved_state.Dereference()
        saved_state = PluginValue(saved_state)
        self.ResetRegisterValues()
        self.x0 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(0).GetValueAsUnsigned()
        self.x1 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(1).GetValueAsUnsigned()
        self.x2 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(2).GetValueAsUnsigned()
        self.x3 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(3).GetValueAsUnsigned()
        self.x4 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(4).GetValueAsUnsigned()
        self.x5 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(5).GetValueAsUnsigned()
        self.x6 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(6).GetValueAsUnsigned()
        self.x7 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(7).GetValueAsUnsigned()
        self.x8 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(8).GetValueAsUnsigned()
        self.x9 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(9).GetValueAsUnsigned()
        self.x10 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(10).GetValueAsUnsigned()
        self.x11 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(11).GetValueAsUnsigned()
        self.x12 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(12).GetValueAsUnsigned()
        self.x13 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(13).GetValueAsUnsigned()
        self.x14 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(14).GetValueAsUnsigned()
        self.x15 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(15).GetValueAsUnsigned()
        self.x16 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(16).GetValueAsUnsigned()
        self.x17 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(17).GetValueAsUnsigned()
        self.x18 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(18).GetValueAsUnsigned()
        self.x19 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(19).GetValueAsUnsigned()
        self.x20 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(20).GetValueAsUnsigned()
        self.x21 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(21).GetValueAsUnsigned()
        self.x22 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(22).GetValueAsUnsigned()
        self.x23 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(23).GetValueAsUnsigned()
        self.x24 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(24).GetValueAsUnsigned()
        self.x25 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(25).GetValueAsUnsigned()
        self.x26 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(26).GetValueAsUnsigned()
        self.x27 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(27).GetValueAsUnsigned()
        self.x28 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(28).GetValueAsUnsigned()
        self.fp = saved_state.GetChildMemberWithName('fp').GetValueAsUnsigned()
        self.lr = saved_state.GetChildMemberWithName('lr').GetValueAsUnsigned()
        self.sp = saved_state.GetChildMemberWithName('sp').GetValueAsUnsigned()
        self.pc = saved_state.GetChildMemberWithName('pc').GetValueAsUnsigned()
        self.far = saved_state.GetChildMemberWithName('far').GetValueAsUnsigned()
        self.cpsr = saved_state.GetChildMemberWithName('cpsr').GetValueAsUnsigned()
        self.esr = saved_state.GetChildMemberWithName('esr').GetValueAsUnsigned()
        return self

    def ReadRegisterDataFromKernelStack(self, kstack_saved_state_addr, kernel_version):
        saved_state = kernel_version.CreateValueFromExpression(None, '(arm_kernel_saved_state_t *) '+ str(kstack_saved_state_addr))
        saved_state = saved_state.Dereference()
        saved_state = PluginValue(saved_state)
        self.ResetRegisterValues()
        self.x16 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(0).GetValueAsUnsigned()
        self.x17 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(1).GetValueAsUnsigned()
        self.x19 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(2).GetValueAsUnsigned()
        self.x20 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(3).GetValueAsUnsigned()
        self.x21 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(4).GetValueAsUnsigned()
        self.x22 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(5).GetValueAsUnsigned()
        self.x23 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(6).GetValueAsUnsigned()
        self.x24 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(7).GetValueAsUnsigned()
        self.x25 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(8).GetValueAsUnsigned()
        self.x26 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(9).GetValueAsUnsigned()
        self.x27 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(10).GetValueAsUnsigned()
        self.x28 = saved_state.GetChildMemberWithName('x').GetChildAtIndex(11).GetValueAsUnsigned()
        self.fp = saved_state.GetChildMemberWithName('fp').GetValueAsUnsigned()
        self.lr = saved_state.GetChildMemberWithName('lr').GetValueAsUnsigned()
        self.sp = saved_state.GetChildMemberWithName('sp').GetValueAsUnsigned()
        # pc for a blocked thread is treated to be the next instruction it would run after thread switch.
        self.pc = self.switch_context_address
        self.cpsr = saved_state.GetChildMemberWithName('cpsr').GetValueAsUnsigned()
        return self

    def ReadRegisterDataFromContinuation(self, continuation_ptr):
        self.ResetRegisterValues()
        self.pc = continuation_ptr
        return self

    @classmethod
    def GetRegisterInfo(cls, regnum):
        if regnum < 0 or regnum > len(cls.register_info['registers']):
            return ''
            
        reginfo = cls.register_info['registers'][regnum]
        retval = ''
        for i in reginfo.keys():
            v_str = str(reginfo[i])
            if i == 'set':
                v_str = 'General Purpose Registers'
            retval += "%s:%s;" % (str(i), v_str)
        return retval



class Armv7_RegisterSet(object):
    """ register info set for armv7 32 bit architecture """
    register_info = { 'sets' : ['GPR'],
                  'registers': [
        { 'name':'r0'   , 'bitsize' : 32, 'offset' :  0, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 0, 'dwarf' : 0},
        { 'name':'r1'   , 'bitsize' : 32, 'offset' :  4, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 1, 'dwarf' : 1},
        { 'name':'r2'   , 'bitsize' : 32, 'offset' :  8, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 2, 'dwarf' : 2},
        { 'name':'r3'   , 'bitsize' : 32, 'offset' : 12, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 3, 'dwarf' : 3},
        { 'name':'r4'   , 'bitsize' : 32, 'offset' : 16, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 4, 'dwarf' : 4},
        { 'name':'r5'   , 'bitsize' : 32, 'offset' : 20, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 5, 'dwarf' : 5},
        { 'name':'r6'   , 'bitsize' : 32, 'offset' : 24, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 6, 'dwarf' : 6},
        { 'name':'r7'   , 'bitsize' : 32, 'offset' : 28, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 7, 'dwarf' : 7},
        { 'name':'r8'   , 'bitsize' : 32, 'offset' : 32, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 8, 'dwarf' : 8},
        { 'name':'r9'   , 'bitsize' : 32, 'offset' : 36, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc': 9, 'dwarf' : 9},
        { 'name':'r10'  , 'bitsize' : 32, 'offset' : 40, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':10, 'dwarf' :10},
        { 'name':'r11'  , 'bitsize' : 32, 'offset' : 44, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':11, 'dwarf' :11, 'alt-name': 'fp', 'generic': 'fp'},
        { 'name':'r12'  , 'bitsize' : 32, 'offset' : 48, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':12, 'dwarf' :12},
        { 'name':'sp'   , 'bitsize' : 32, 'offset' : 52, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':13, 'dwarf' :13, 'generic': 'sp'},
        { 'name':'lr'   , 'bitsize' : 32, 'offset' : 56, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':14, 'dwarf' :14, 'generic': 'lr'},
        { 'name':'pc'   , 'bitsize' : 32, 'offset' : 60, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':15, 'dwarf' :15, 'generic': 'pc'},
        { 'name':'cpsr' , 'bitsize' : 32, 'offset' : 64, 'encoding':'uint', 'format':'hex', 'set':0, 'gcc':16, 'dwarf' :16, 'generic':'flags'},
        { 'name':'fsr'  , 'bitsize' : 32, 'offset' : 68, 'encoding':'uint', 'format':'hex', 'set':0},
        { 'name':'far'  , 'bitsize' : 32, 'offset' : 72, 'encoding':'uint', 'format':'hex', 'set':0}
        ]
        }

    def __init__(self):
        self.switch_context_address = osplugin_target_obj.FindSymbols('load_reg')[0].GetSymbol().GetStartAddress().GetLoadAddress(osplugin_target_obj) + 8
        self.ResetRegisterValues()
    
    @classmethod
    def GetRegisterInfo(cls, regnum):
        if regnum < 0 or regnum > len(cls.register_info['registers']):
            return ''
            
        reginfo = cls.register_info['registers'][regnum]
        retval = ''
        for i in reginfo.keys():
            v_str = str(reginfo[i])
            if i == 'set':
                v_str = 'General Purpose Registers'
            retval += "%s:%s;" % (str(i), v_str)
        return retval

    def ResetRegisterValues(self):
        self.r0 = 0
        self.r1 = 0
        self.r2 = 0
        self.r3 = 0
        self.r4 = 0
        self.r5 = 0
        self.r6 = 0
        self.r7 = 0
        self.r8 = 0
        self.r9 = 0
        self.r10 = 0
        self.r11 = 0
        self.r12 = 0
        self.sp = 0
        self.lr = 0
        self.pc = 0
        self.cpsr = 0
        self.fsr = 0
        self.far = 0

    def __str__(self):
        return """
            r0 = {o.r0: <#010x}
            r1 = {o.r1: <#010x}
            r2 = {o.r2: <#010x}
            r3 = {o.r3: <#010x}
            r4 = {o.r4: <#010x}
            r5 = {o.r5: <#010x}
            r6 = {o.r6: <#010x}
            r7 = {o.r7: <#010x}
            r8 = {o.r8: <#010x}
            r9 = {o.r9: <#010x}
            r10 = {o.r10: <#010x}
            r11 = {o.r11: <#010x}
            r12 = {o.r12: <#010x}
            sp = {o.sp: <#010x}
            lr = {o.lr: <#010x}
            pc = {o.pc: <#010x}
            cpsr = {o.cpsr: <#010x}
            fsr = {o.fsr : <#010x}
            far = {o.far : <#010x}
            """.format(o=self)

    def GetPackedRegisterState(self):
        return struct.pack('19I', self.r0, self.r1, self.r2, self.r3,
            self.r4, self.r5, self.r6, self.r7,
            self.r8, self.r9, self.r10, self.r11,
            self.r12, self.sp, self.lr, self.pc,
            self.cpsr, self.fsr, self.far)

    def ReadRegisterDataFromKDPSavedState(self, kdp_state, kernel_version):
        saved_state = kernel_version.CreateValueFromExpression(None, '(struct arm_saved_state *) ' + str(kdp_state.GetValueAsUnsigned()))
        saved_state = saved_state.Dereference()
        saved_state = PluginValue(saved_state)
        self.ResetRegisterValues()
        self.r0 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(0).GetValueAsUnsigned()
        self.r1 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(1).GetValueAsUnsigned()
        self.r2 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(2).GetValueAsUnsigned()
        self.r3 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(3).GetValueAsUnsigned()
        self.r4 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(4).GetValueAsUnsigned()
        self.r5 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(5).GetValueAsUnsigned()
        self.r6 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(6).GetValueAsUnsigned()
        self.r7 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(7).GetValueAsUnsigned()
        self.r8 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(8).GetValueAsUnsigned()
        self.r9 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(9).GetValueAsUnsigned()
        self.r10 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(10).GetValueAsUnsigned()
        self.r11 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(11).GetValueAsUnsigned()
        self.r12 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(12).GetValueAsUnsigned()
        self.sp = saved_state.GetChildMemberWithName('sp').GetValueAsUnsigned()
        self.lr = saved_state.GetChildMemberWithName('lr').GetValueAsUnsigned()
        self.pc = saved_state.GetChildMemberWithName('pc').GetValueAsUnsigned()
        self.cpsr = saved_state.GetChildMemberWithName('cpsr').GetValueAsUnsigned()
        self.fsr = saved_state.GetChildMemberWithName('fsr').GetValueAsUnsigned()
        self.far = saved_state.GetChildMemberWithName('far').GetValueAsUnsigned()
        return self

    def ReadRegisterDataFromKernelStack(self, kstack_saved_state_addr, kernel_version):
        saved_state = kernel_version.CreateValueFromExpression(None, '(struct arm_saved_state *) '+ str(kstack_saved_state_addr))
        saved_state = saved_state.Dereference()
        saved_state = PluginValue(saved_state)
        self.ResetRegisterValues()
        self.r0 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(0).GetValueAsUnsigned()
        self.r1 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(1).GetValueAsUnsigned()
        self.r2 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(2).GetValueAsUnsigned()
        self.r3 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(3).GetValueAsUnsigned()
        self.r4 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(4).GetValueAsUnsigned()
        self.r5 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(5).GetValueAsUnsigned()
        self.r6 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(6).GetValueAsUnsigned()
        self.r7 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(7).GetValueAsUnsigned()
        self.r8 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(8).GetValueAsUnsigned()
        self.r9 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(9).GetValueAsUnsigned()
        self.r10 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(10).GetValueAsUnsigned()
        self.r11 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(11).GetValueAsUnsigned()
        self.r12 = saved_state.GetChildMemberWithName('r').GetChildAtIndex(12).GetValueAsUnsigned()
        self.sp = saved_state.GetChildMemberWithName('sp').GetValueAsUnsigned()
        self.lr = saved_state.GetChildMemberWithName('lr').GetValueAsUnsigned()
        # pc for a blocked thread is treated to be the next instruction it would run after thread switch.
        self.pc = self.switch_context_address
        self.cpsr = saved_state.GetChildMemberWithName('cpsr').GetValueAsUnsigned()
        self.fsr = saved_state.GetChildMemberWithName('fsr').GetValueAsUnsigned()
        self.far = saved_state.GetChildMemberWithName('far').GetValueAsUnsigned()
        return self

    def ReadRegisterDataFromContinuation(self, continuation_ptr):
        self.ResetRegisterValues()
        self.pc = continuation_ptr
        return self


class I386_RegisterSet(object):
    """ register info set for i386 architecture
    """
    register_info = { 'sets' : ['GPR'],
                  'registers': [
        { 'name': 'eax'   , 'bitsize': 32, 'offset' : 0, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 0, 'dwarf': 0},
        { 'name': 'ebx'   , 'bitsize': 32, 'offset' : 4, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 3, 'dwarf': 3},
        { 'name': 'ecx'   , 'bitsize': 32, 'offset' : 8, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 1, 'dwarf': 1},
        { 'name': 'edx'   , 'bitsize': 32, 'offset' :12, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 2, 'dwarf': 2},
        { 'name': 'edi'   , 'bitsize': 32, 'offset' :16, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 7, 'dwarf': 7},
        { 'name': 'esi'   , 'bitsize': 32, 'offset' :20, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 6, 'dwarf': 6},
        { 'name': 'ebp'   , 'bitsize': 32, 'offset' :24, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 4, 'dwarf': 5, 'generic': 'fp', 'alt-name': 'fp'},
        { 'name': 'esp'   , 'bitsize': 32, 'offset' :28, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 5, 'dwarf': 4, 'generic': 'sp', 'alt-name': 'sp'},
        { 'name': 'ss'    , 'bitsize': 32, 'offset' :32, 'encoding': 'uint' , 'format':'hex' , 'set': 0},
        { 'name': 'eflags', 'bitsize': 32, 'offset' :36, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' : 9, 'dwarf': 9, 'generic': 'flags'},
        { 'name': 'eip'   , 'bitsize': 32, 'offset' :40, 'encoding': 'uint' , 'format':'hex' , 'set': 0, 'gcc' :8, 'dwarf':8, 'generic': 'pc', 'alt-name': 'pc'},
        { 'name': 'cs'    , 'bitsize': 32, 'offset' :44, 'encoding': 'uint' , 'format':'hex' , 'set': 0},
        { 'name': 'ds'    , 'bitsize': 32, 'offset' :48, 'encoding': 'uint' , 'format':'hex' , 'set': 0},
        { 'name': 'es'    , 'bitsize': 32, 'offset' :52, 'encoding': 'uint' , 'format':'hex' , 'set': 0},
        { 'name': 'fs'    , 'bitsize': 32, 'offset' :56, 'encoding': 'uint' , 'format':'hex' , 'set': 0},
        { 'name': 'gs'    , 'bitsize': 32, 'offset' :60, 'encoding': 'uint' , 'format':'hex' , 'set': 0},
        ]
        }

    def __init__(self):
        self.ResetRegisterValues()
    
    @classmethod
    def GetRegisterInfo(cls, regnum):
        if regnum < 0 or regnum > len(cls.register_info['registers']):
            return ''
            
        reginfo = cls.register_info['registers'][regnum]
        retval = ''
        for i in reginfo.keys():
            v_str = str(reginfo[i])
            if i == 'set':
                v_str = 'General Purpose Registers'
            retval += "%s:%s;" % (str(i), v_str)
        return retval

    def ResetRegisterValues(self):
        """ set all registers to zero """
        self.eax = 0
        self.ebx = 0
        self.ecx = 0
        self.edx = 0
        self.edi = 0
        self.esi = 0
        self.ebp = 0
        self.esp = 0
        self.ss  = 0
        self.eflags = 0
        self.eip = 0
        self.cs = 0
        self.ds = 0
        self.es = 0
        self.fs = 0
        self.gs = 0

    def __str__(self):
        return """
            eax = {o.eax: #010x}
            ebx = {o.ebx: #010x}
            ecx = {o.ecx: #010x}
            edx = {o.edx: #010x}
            edi = {o.edi: #010x}
            esi = {o.esi: #010x}
            ebp = {o.ebp: #010x}
            esp = {o.esp: #010x}
            ss  = {o.ss: #010x}
         eflags = {o.eflags: #010x}
            eip = {o.eip: #010x}
            cs  = {o.cs: #010x}
            ds  = {o.ds: #010x}
            es  = {o.es: #010x}
            fs  = {o.fs: #010x}
            gs  = {o.gs: #010x}
            """.format(o=self)

    def GetPackedRegisterState(self):
        """ get a struct.pack register data """
        return struct.pack('16I', self.eax, self.ebx, self.ecx,
            self.edx, self.edi, self.esi,
            self.ebp, self.esp, self.ss,
            self.eflags, self.eip, self.cs,
            self.ds, self.es, self.fs, self.gs
            )

    def ReadRegisterDataFromKDPSavedState(self, kdp_state, kernel_version):
        """ to be implemented"""
        return None

    def ReadRegisterDataFromKernelStack(self, kstack_saved_state_addr, kernel_version):
        """ to be implemented """
        return None

    def ReadRegisterDataFromContinuation(self, continuation_ptr):
        self.ResetRegisterValues()
        self.eip = continuation_ptr
        return self


class X86_64RegisterSet(object):
    """ register info set for x86_64 architecture """
    register_info = { 'sets' : ['GPR'],
                  'registers': [
        { 'name':'rax'       , 'bitsize' :  64, 'offset' :   0, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 0, 'dwarf' : 0},
        { 'name':'rbx'       , 'bitsize' :  64, 'offset' :   8, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 3, 'dwarf' : 3},
        { 'name':'rcx'       , 'bitsize' :  64, 'offset' :  16, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 2, 'dwarf' : 2, 'generic':'arg4', 'alt-name':'arg4', },
        { 'name':'rdx'       , 'bitsize' :  64, 'offset' :  24, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 1, 'dwarf' : 1, 'generic':'arg3', 'alt-name':'arg3', },
        { 'name':'rdi'       , 'bitsize' :  64, 'offset' :  32, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 5, 'dwarf' : 5, 'generic':'arg1', 'alt-name':'arg1', },
        { 'name':'rsi'       , 'bitsize' :  64, 'offset' :  40, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 4, 'dwarf' : 4, 'generic':'arg2', 'alt-name':'arg2', },
        { 'name':'rbp'       , 'bitsize' :  64, 'offset' :  48, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 6, 'dwarf' : 6, 'generic':'fp'  , 'alt-name':'fp', },
        { 'name':'rsp'       , 'bitsize' :  64, 'offset' :  56, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 7, 'dwarf' : 7, 'generic':'sp'  , 'alt-name':'sp', },
        { 'name':'r8'        , 'bitsize' :  64, 'offset' :  64, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 8, 'dwarf' : 8, 'generic':'arg5', 'alt-name':'arg5', },
        { 'name':'r9'        , 'bitsize' :  64, 'offset' :  72, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 9, 'dwarf' : 9, 'generic':'arg6', 'alt-name':'arg6', },
        { 'name':'r10'       , 'bitsize' :  64, 'offset' :  80, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 10, 'dwarf' : 10},
        { 'name':'r11'       , 'bitsize' :  64, 'offset' :  88, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 11, 'dwarf' : 11},
        { 'name':'r12'       , 'bitsize' :  64, 'offset' :  96, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 12, 'dwarf' : 12},
        { 'name':'r13'       , 'bitsize' :  64, 'offset' : 104, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 13, 'dwarf' : 13},
        { 'name':'r14'       , 'bitsize' :  64, 'offset' : 112, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 14, 'dwarf' : 14},
        { 'name':'r15'       , 'bitsize' :  64, 'offset' : 120, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 15, 'dwarf' : 15},
        { 'name':'rip'       , 'bitsize' :  64, 'offset' : 128, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'gcc' : 16, 'dwarf' : 16, 'generic':'pc', 'alt-name':'pc' },
        { 'name':'rflags'    , 'bitsize' :  64, 'offset' : 136, 'encoding':'uint'  , 'format':'hex'         , 'set': 0, 'generic':'flags', 'alt-name':'flags' },
        { 'name':'cs'        , 'bitsize' :  64, 'offset' : 144, 'encoding':'uint'  , 'format':'hex'         , 'set': 0                          },
        { 'name':'fs'        , 'bitsize' :  64, 'offset' : 152, 'encoding':'uint'  , 'format':'hex'         , 'set': 0                          },
        { 'name':'gs'        , 'bitsize' :  64, 'offset' : 160, 'encoding':'uint'  , 'format':'hex'         , 'set': 0                          },
        ]
        }
    def __init__(self):
        self.ResetRegisterValues()

    @classmethod
    def GetRegisterInfo(cls, regnum):
        if regnum < 0 or regnum > len(cls.register_info['registers']):
            return ''

        reginfo = cls.register_info['registers'][regnum]
        retval = ''
        for i in reginfo.keys():
            v_str = str(reginfo[i])
            if i == 'set':
                v_str = 'General Purpose Registers'
            retval += "%s:%s;" % (str(i), v_str)
        return retval


    def ResetRegisterValues(self):
        """ set all the registers to zero. """
        self.rax = 0
        self.rbx = 0
        self.rcx = 0
        self.rdx = 0
        self.rdi = 0
        self.rsi = 0
        self.rbp = 0
        self.rsp = 0
        self.r8  = 0
        self.r9  = 0
        self.r10 = 0
        self.r11 = 0
        self.r12 = 0
        self.r13 = 0
        self.r14 = 0
        self.r15 = 0
        self.rip = 0
        self.rflags = 0
        self.cs  = 0
        self.fs  = 0
        self.gs  = 0

    def __str__(self):
        return """
            rax = {o.rax: <#018x}
            rbx = {o.rbx: <#018x}
            rcx = {o.rcx: <#018x}
            rdx = {o.rdx: <#018x}
            rdi = {o.rdi: <#018x}
            rsi = {o.rsi: <#018x}
            rbp = {o.rbp: <#018x}
            rsp = {o.rsp: <#018x}
            r8  = {o.r8: <#018x}
            r9  = {o.r9: <#018x}
            r10 = {o.r10: <#018x}
            r11 = {o.r11: <#018x}
            r12 = {o.r12: <#018x}
            r13 = {o.r13: <#018x}
            r14 = {o.r14: <#018x}
            r15 = {o.r15: <#018x}
            rip = {o.rip: <#018x}
            rflags =  {o.rflags: <#018x}
            cs = {o.cs: <#018x}
            fs = {o.fs: <#018x}
            gs = {o.gs: <#018x}
            """.format(o=self)

    def GetPackedRegisterState(self):
        """ get a struct.pack register data for passing to C constructs """
        return struct.pack('21Q', self.rax, self.rbx, self.rcx, self.rdx, self.rdi,
            self.rsi, self.rbp, self.rsp, self.r8,  self.r9,
            self.r10, self.r11, self.r12, self.r13, self.r14,
            self.r15, self.rip, self.rflags, self.cs, self.fs, self.gs)

    def ReadRegisterDataFromKDPSavedState(self, kdp_state, kernel_version):
        saved_state = kernel_version.CreateValueFromExpression(None,  '(struct x86_saved_state64 *) '+ str(kdp_state.GetValueAsUnsigned()))
        saved_state = saved_state.Dereference()
        saved_state = PluginValue(saved_state)
        self.ResetRegisterValues()
        self.rdi = saved_state.GetChildMemberWithName('rdi').GetValueAsUnsigned()
        self.rsi = saved_state.GetChildMemberWithName('rsi').GetValueAsUnsigned()
        self.rdx = saved_state.GetChildMemberWithName('rdx').GetValueAsUnsigned()
        self.r10 = saved_state.GetChildMemberWithName('r10').GetValueAsUnsigned()
        self.r8 = saved_state.GetChildMemberWithName('r8').GetValueAsUnsigned()
        self.r9 = saved_state.GetChildMemberWithName('r9').GetValueAsUnsigned()
        self.r15 = saved_state.GetChildMemberWithName('r15').GetValueAsUnsigned()
        self.r14 = saved_state.GetChildMemberWithName('r14').GetValueAsUnsigned()
        self.r13 = saved_state.GetChildMemberWithName('r13').GetValueAsUnsigned()
        self.r12 = saved_state.GetChildMemberWithName('r12').GetValueAsUnsigned()
        self.r11 = saved_state.GetChildMemberWithName('r11').GetValueAsUnsigned()
        self.rbp = saved_state.GetChildMemberWithName('rbp').GetValueAsUnsigned()
        self.rbx = saved_state.GetChildMemberWithName('rbx').GetValueAsUnsigned()
        self.rcx = saved_state.GetChildMemberWithName('rcx').GetValueAsUnsigned()
        self.rax = saved_state.GetChildMemberWithName('rax').GetValueAsUnsigned()
        self.rip = saved_state.GetChildMemberWithName('isf').GetChildMemberWithName('rip').GetValueAsUnsigned()
        self.rflags = saved_state.GetChildMemberWithName('isf').GetChildMemberWithName('rflags').GetValueAsUnsigned()
        self.rsp = saved_state.GetChildMemberWithName('isf').GetChildMemberWithName('rsp').GetValueAsUnsigned()
        return self

    def ReadRegisterDataFromKernelStack(self, kstack_saved_state_addr, kernel_version):
        saved_state = kernel_version.CreateValueFromExpression(None, '(struct x86_kernel_state *) '+ str(kstack_saved_state_addr))
        saved_state = saved_state.Dereference()
        saved_state = PluginValue(saved_state)
        self.ResetRegisterValues()
        self.rbx = saved_state.GetChildMemberWithName('k_rbx').GetValueAsUnsigned()
        self.rsp = saved_state.GetChildMemberWithName('k_rsp').GetValueAsUnsigned()
        self.rbp = saved_state.GetChildMemberWithName('k_rbp').GetValueAsUnsigned()
        self.r12 = saved_state.GetChildMemberWithName('k_r12').GetValueAsUnsigned()
        self.r13 = saved_state.GetChildMemberWithName('k_r13').GetValueAsUnsigned()
        self.r14 = saved_state.GetChildMemberWithName('k_r14').GetValueAsUnsigned()
        self.r15 = saved_state.GetChildMemberWithName('k_r15').GetValueAsUnsigned()
        self.rip = saved_state.GetChildMemberWithName('k_rip').GetValueAsUnsigned()
        return self

    def ReadRegisterDataFromContinuation(self, continuation_ptr):
        self.ResetRegisterValues()
        self.rip = continuation_ptr
        return self




def IterateQueue(queue_head, element_ptr_type, element_field_name):
    """ iterate over a queue in kernel of type queue_head_t. refer to osfmk/kern/queue.h
        params:
            queue_head         - lldb.SBValue : Value object for queue_head.
            element_type       - lldb.SBType : a pointer type of the element 'next' points to. Typically its structs like thread, task etc..
            element_field_name - str : name of the field in target struct.
        returns:
            A generator does not return. It is used for iterating.
            SBValue  : an object thats of type (element_type) queue_head->next. Always a pointer object
    """
    queue_head_addr = 0x0
    if queue_head.TypeIsPointerType():
        queue_head_addr = queue_head.GetValueAsUnsigned()
    else:
        queue_head_addr = queue_head.GetAddress().GetLoadAddress(osplugin_target_obj)
    cur_elt = queue_head.GetChildMemberWithName('next')
    while True:
        if not cur_elt.IsValid() or cur_elt.GetValueAsUnsigned() == 0 or cur_elt.GetValueAsUnsigned() == queue_head_addr:
            break
        elt = cur_elt.Cast(element_ptr_type)
        yield elt
        cur_elt = elt.GetChildMemberWithName(element_field_name).GetChildMemberWithName('next')

def GetUniqueSessionID(process_obj):
    """ Create a unique session identifier.
        params:
          process_obj: lldb.SBProcess object refering to connected process.
        returns:
          int - a unique number identified by processid and stopid.
    """
    session_key_str = ""
    if hasattr(process_obj, "GetUniqueID"):
        session_key_str += str(process_obj.GetUniqueID()) + ":"
    else:
        session_key_str += "0:"

    if hasattr(process_obj, "GetStopID"):
        session_key_str += str(process_obj.GetStopID())
    else:
        session_key_str +="1"

    return hash(session_key_str)


(archX86_64, archARMv7, archI386, archARMv8) = ("x86_64", "armv7", "i386", "arm64")

class OperatingSystemPlugIn(object):
    """Class that provides data for an instance of a LLDB 'OperatingSystemPython' plug-in class"""

    def __init__(self, process):
        '''Initialization needs a valid.SBProcess object'''
        self.process = None
        self.registers = None
        self.threads = None
        self.thread_cache = {}
        self.current_session_id = 0
        self.kdp_thread = None
        if type(process) is lldb.SBProcess and process.IsValid():
            global osplugin_target_obj
            self.process = process
            self._target = process.target
            osplugin_target_obj = self._target
            self.current_session_id = GetUniqueSessionID(self.process)
            self.version = self._target.FindGlobalVariables('version', 1).GetValueAtIndex(0)
            self.kernel_stack_size = self._target.FindGlobalVariables('kernel_stack_size', 1).GetValueAtIndex(0).GetValueAsUnsigned()
            self.kernel_context_size = 0
            self.connected_over_kdp = False
            # connected_to_debugserver signifies if we are connected to astris or other gdbserver instance
            # that has the correct thread state for on core threads. For kdp and coredumps we rely on in memory
            # state of threads.
            self.connected_to_debugserver = True
            plugin_string = self.process.GetPluginName().lower()
            if plugin_string.find("kdp") >=0:
                self.connected_over_kdp = True
                self.connected_to_debugserver = False
            #print "version", self.version, "kernel_stack_size", self.kernel_stack_size, "context_size", self.kernel_context_size
            self.threads = None # Will be an dictionary containing info for each thread
            triple = self.process.target.triple
            arch = triple.split('-')[0].lower()
            self.target_arch = ""
            self.kernel_context_size = 0
            if arch == archX86_64 :
                self.target_arch = archX86_64
                print "Target arch: x86_64"
                self.register_set = X86_64RegisterSet()
                self.kernel_context_size = self._target.FindFirstType('x86_kernel_state').GetByteSize()
                self.kernel_thread_state_size = self._target.FindFirstType('struct thread_kernel_state').GetByteSize()
            elif arch.startswith(archARMv7) :
                self.target_arch = arch
                print "Target arch: " + self.target_arch
                self.register_set = Armv7_RegisterSet()
            elif arch.startswith(archARMv8):
                self.target_arch = arch
                print "Target arch: " + self.target_arch
                self.register_set = Armv8_RegisterSet()
            #  connection     intel         arm
            #  kdp            Memory        Memory
            #  gdb            Server        Server
            #  coredump       Memory        Server
            if not self.connected_over_kdp :
                if plugin_string.find('core') >= 0 and self.target_arch == archX86_64:
                    self.connected_to_debugserver = False
            self.registers = self.register_set.register_info
            if self.connected_to_debugserver:
                print "Connected to live debugserver or arm core. Will associate on-core threads to registers reported by server."
            else:
                print "Instantiating threads completely from saved state in memory."

    def create_thread(self, tid, context):
        # tid == deadbeef means its a custom thread which kernel does not know of.
        if tid == 0xdeadbeef :
            # tid manipulation should be the same as in "switchtoregs" code in lldbmacros/process.py .
            tid = 0xdead0000 | (context & ~0xffff0000)
            tid = tid & 0xdeadffff
            thread_obj = { 'tid'   : tid,
                           'ptr'   : context,
                           'name'  : 'switchtoregs' + hex(context),
                           'queue' : 'None',
                           'state' : 'stopped',
                           'stop_reason' : 'none'
                         }
            self.thread_cache[tid] = thread_obj
            return thread_obj
        
        th_ptr = context
        th = self.version.CreateValueFromExpression(str(th_ptr),'(struct thread *)' + str(th_ptr))
        thread_id = th.GetChildMemberWithName('thread_id').GetValueAsUnsigned()
        if tid != thread_id:
            print "FATAL ERROR: Creating thread from memory 0x%x with tid in mem=%d when requested tid = %d " % (context, thread_id, tid)
            return None
        thread_obj = { 'tid'   : thread_id,
                       'ptr'   : th.GetValueAsUnsigned(),
                       'name'  : hex(th.GetValueAsUnsigned()).rstrip('L'),
                       'queue' : hex(th.GetChildMemberWithName('wait_queue').GetValueAsUnsigned()).rstrip('L'),
                       'state' : 'stopped',
                       'stop_reason' : 'none'
                     }
        if self.current_session_id != GetUniqueSessionID(self.process):
            self.thread_cache = {}
            self.current_session_id = GetUniqueSessionID(self.process)

        self.thread_cache[tid] = thread_obj
        return thread_obj


    def get_thread_info(self):
        self.kdp_thread = None
        self.kdp_state = None
        if self.connected_over_kdp :
            kdp = self._target.FindGlobalVariables('kdp',1).GetValueAtIndex(0)
            kdp_state = kdp.GetChildMemberWithName('saved_state')
            kdp_thread = kdp.GetChildMemberWithName('kdp_thread')
            if kdp_thread and kdp_thread.GetValueAsUnsigned() != 0:
                self.kdp_thread = kdp_thread
                self.kdp_state = kdp_state
                kdp_thid = kdp_thread.GetChildMemberWithName('thread_id').GetValueAsUnsigned()
                self.create_thread(kdp_thid, kdp_thread.GetValueAsUnsigned())
                self.thread_cache[kdp_thid]['core']=0
                retval = [self.thread_cache[kdp_thid]]
                return retval
            else:
                print "FATAL FAILURE: Unable to find kdp_thread state for this connection."
                return []

        num_threads = self._target.FindGlobalVariables('threads_count',1).GetValueAtIndex(0).GetValueAsUnsigned()
        #In case we are caught before threads are initialized. Fallback to threads known by astris/gdb server.
        if num_threads <=0 :
            return []

        self.current_session_id = GetUniqueSessionID(self.process)
        self.threads = []
        self.thread_cache = {}
        self.processors = []
        try:
            processor_list_val = PluginValue(self._target.FindGlobalVariables('processor_list',1).GetValueAtIndex(0))
            while processor_list_val.IsValid() and processor_list_val.GetValueAsUnsigned() !=0 :
                th = processor_list_val.GetChildMemberWithName('active_thread')
                th_id = th.GetChildMemberWithName('thread_id').GetValueAsUnsigned()
                cpu_id = processor_list_val.GetChildMemberWithName('cpu_id').GetValueAsUnsigned()
                self.processors.append({'active_thread': th.GetValueAsUnsigned(), 'cpu_id': cpu_id})
                self.create_thread(th_id, th.GetValueAsUnsigned())
                if self.connected_to_debugserver:
                    self.thread_cache[th_id]['core'] = cpu_id
                self.thread_cache[th_id]['queue'] = "cpu-%d" % int(cpu_id)
                nth = self.thread_cache[th_id]
                self.threads.append(nth)
                self.thread_cache[nth['tid']] = nth
                processor_list_val = processor_list_val.GetChildMemberWithName('processor_list')
        except KeyboardInterrupt, ke:
            print "OS Plugin Interrupted during thread loading process. \nWARNING:Thread registers and backtraces may not be accurate."
            return self.threads

        if hasattr(self.process, 'CreateOSPluginThread'):
            return self.threads

        # FIXME remove legacy code
        try:
            thread_q_head = self._target.FindGlobalVariables('threads', 1).GetValueAtIndex(0)
            thread_type = self._target.FindFirstType('thread')
            thread_ptr_type = thread_type.GetPointerType()
            for th in IterateQueue(thread_q_head, thread_ptr_type, 'threads'):
                th_id = th.GetChildMemberWithName('thread_id').GetValueAsUnsigned()
                self.create_thread(th_id, th.GetValueAsUnsigned())
                nth = self.thread_cache[th_id]
                for cputhread in self.processors:
                    if cputhread['active_thread'] == nth['ptr']:
                        nth['core'] = cputhread['cpu_id']
                self.threads.append( nth )
        except KeyboardInterrupt, ke:
            print "OS Plugin Interrupted during thread loading process. \nWARNING:Thread registers and backtraces may not be accurate."
            return self.threads
        # end legacy code
        return self.threads

    def get_register_info(self):
        if self.registers == None:
            print "Register Information not found "
        return self.register_set.register_info

    def get_register_data(self, tid):
        thobj = None
        try:
            regs = self.register_set
            if self.current_session_id != GetUniqueSessionID(self.process):
                self.thread_cache = {}
                self.current_session_id = GetUniqueSessionID(self.process)
            if tid in self.thread_cache.keys():
                
                #Check if the thread is a fake one. Then create and return registers directly
                if self.thread_cache[tid]['name'].find('switchtoregs') == 0:
                    savedstateobj = self.version.CreateValueFromExpression(None, '(uintptr_t *) ' + str(self.thread_cache[tid]['ptr']))
                    regs.ReadRegisterDataFromKDPSavedState(savedstateobj, self.version)
                    return regs.GetPackedRegisterState()

                thobj = self.version.CreateValueFromExpression(self.thread_cache[tid]['name'], '(struct thread *)' + str(self.thread_cache[tid]['ptr']))
            
            if thobj == None :
                print "FATAL ERROR: Could not find thread with id %d" % tid
                regs.ResetRegisterValues()
                return regs.GetPackedRegisterState()

            if self.kdp_thread and self.kdp_thread.GetValueAsUnsigned() == thobj.GetValueAsUnsigned():
                regs.ReadRegisterDataFromKDPSavedState(self.kdp_state, self.version)
                return regs.GetPackedRegisterState()
            if int(PluginValue(thobj).GetChildMemberWithName('kernel_stack').GetValueAsUnsigned()) != 0 :
                if self.target_arch == archX86_64 :
                    # we do have a stack so lets get register information
                    saved_state_addr = PluginValue(thobj).GetChildMemberWithName('kernel_stack').GetValueAsUnsigned() + self.kernel_stack_size - self.kernel_thread_state_size
                    regs.ReadRegisterDataFromKernelStack(saved_state_addr, self.version)
                    return regs.GetPackedRegisterState()
                elif self.target_arch.startswith(archARMv7) and int(PluginValue(thobj).GetChildMemberWithName('machine').GetChildMemberWithName('kstackptr').GetValueAsUnsigned()) != 0:
                    #we have stack on the machine.kstackptr.
                    saved_state_addr = PluginValue(thobj).GetChildMemberWithName('machine').GetChildMemberWithName('kstackptr').GetValueAsUnsigned()
                    regs.ReadRegisterDataFromKernelStack(saved_state_addr, self.version)
                    return regs.GetPackedRegisterState()
                elif self.target_arch.startswith(archARMv8) and int(PluginValue(thobj).GetChildMemberWithName('machine').GetChildMemberWithName('kstackptr').GetValueAsUnsigned()) != 0:
                    saved_state_addr = PluginValue(thobj).GetChildMemberWithName('machine').GetChildMemberWithName('kstackptr').GetValueAsUnsigned()
                    arm_ctx = PluginValue(self.version.CreateValueFromExpression(None, '(struct arm_kernel_context *) ' + str(saved_state_addr)))
                    arm_ss_addr = arm_ctx.GetChildMemberWithName('ss').GetLoadAddress()
                    regs.ReadRegisterDataFromKernelStack(arm_ss_addr, self.version)
                    return regs.GetPackedRegisterState()
            elif self.target_arch == archX86_64 or self.target_arch.startswith(archARMv7) or self.target_arch.startswith(archARMv8):
                regs.ReadRegisterDataFromContinuation( PluginValue(thobj).GetChildMemberWithName('continuation').GetValueAsAddress())
                return regs.GetPackedRegisterState()
            #incase we failed very miserably
        except KeyboardInterrupt, ke:
            print "OS Plugin Interrupted during thread register load. \nWARNING:Thread registers and backtraces may not be accurate. for tid = %d" % tid
        regs.ResetRegisterValues()
        print "FATAL ERROR: Failed to get register state for thread id 0x%x " % tid
        print thobj
        return regs.GetPackedRegisterState()
