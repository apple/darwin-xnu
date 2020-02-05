"""
Defines a class value which encapsulates the basic lldb Scripting Bridge APIs. This provides an easy
wrapper to extract information from C based constructs. 
 |------- core.value------------|
 | |--lldb Scripting Bridge--|  |
 | |    |--lldb core--|      |  |   
 | |-------------------------|  |
 |------------------------------|
Use the member function GetSBValue() to access the base Scripting Bridge value.
"""
import lldb
import re
from lazytarget import *

_cstring_rex = re.compile("((?:\s*|const\s+)\s*char(?:\s+\*|\s+[A-Za-z_0-9]*\s*\[|)\s*)",re.MULTILINE|re.DOTALL)

class value(object):
    '''A class designed to wrap lldb.SBValue() objects so the resulting object
    can be used as a variable would be in code. So if you have a Point structure
    variable in your code in the current frame named "pt", you can initialize an instance
    of this class with it:
    
    pt = lldb.value(lldb.frame.FindVariable("pt"))
    print pt
    print pt.x
    print pt.y

    pt = lldb.value(lldb.frame.FindVariable("rectangle_array"))
    print rectangle_array[12]
    print rectangle_array[5].origin.x'''
    def __init__(self, sbvalue):
        #_sbval19k84obscure747 is specifically chosen to be obscure. 
        #This avoids conflicts when attributes could mean any field value in code
        self._sbval19k84obscure747 = sbvalue
        self._sbval19k84obscure747_type = sbvalue.GetType()
        self._sbval19k84obscure747_is_ptr = sbvalue.GetType().IsPointerType()
        self.sbvalue = sbvalue

    def __nonzero__(self):
        return ( self._sbval19k84obscure747.__nonzero__() and self._GetValueAsUnsigned() != 0 )

    def __repr__(self):
        return self._sbval19k84obscure747.__str__()
    
    def __cmp__(self, other):
        if type(other) is int or type(other) is long:
            me = int(self)
            if type(me) is long:
                other = long(other)
            return me.__cmp__(other)
        if type(other) is value:
            return int(self).__cmp__(int(other))
        raise TypeError("Cannot compare value with type {}".format(type(other)))
    
    def __str__(self):
        global _cstring_rex
        type_name = self._sbval19k84obscure747_type.GetName()
        if len(_cstring_rex.findall(type_name)) > 0 :
            return self._GetValueAsString()
        summary = self._sbval19k84obscure747.GetSummary()
        if summary:
            return summary.strip('"')
        return self._sbval19k84obscure747.__str__()

    def __getitem__(self, key):
        # Allow array access if this value has children...
        if type(key) is slice:
            _start = int(key.start)
            _end = int(key.stop)
            _step = 1
            if key.step != None:
                _step = int(key.step)
            retval = []
            while _start < _end:
                retval.append(self[_start])
                _start += _step
            return retval
        if type(key) in (int, long):
            return value(self._sbval19k84obscure747.GetValueForExpressionPath("[%i]" % key))
        if type(key) is value:
            return value(self._sbval19k84obscure747.GetValueForExpressionPath("[%i]" % int(key)))
        raise TypeError("Cannot fetch Array item for this type")

    def __getattr__(self, name):
        child_sbvalue = self._sbval19k84obscure747.GetChildMemberWithName (name)
        if child_sbvalue:
            return value(child_sbvalue)
        raise AttributeError("No field by name: "+name )

    def __add__(self, other):
        return int(self) + int(other)
    
    def __radd__(self, other):
        return int(self) + int(other)
        
    def __sub__(self, other):
        return int(self) - int(other)
    
    def __rsub__(self, other):
        return int(other) - int(self)
        
    def __mul__(self, other):
        return int(self) * int(other)
    
    def __rmul__(self, other):
        return int(self) * int(other)
    
    def __floordiv__(self, other):
        return int(self) // int(other)
        
    def __mod__(self, other):
        return int(self) % int(other)
    
    def __rmod__(self, other):
        return int(other) % int(self)
        
    def __divmod__(self, other):
        return int(self) % int(other)
    
    def __rdivmod__(self, other):
        return int(other) % int(self)
        
    def __pow__(self, other):
        return int(self) ** int(other)
        
    def __lshift__(self, other):
        return int(self) << int(other)
        
    def __rshift__(self, other):
        return int(self) >> int(other)
        
    def __and__(self, other):
        return int(self) & int(other)
    
    def __rand(self, other):
        return int(self) & int(other)
        
    def __xor__(self, other):
        return int(self) ^ int(other)
        
    def __or__(self, other):
        return int(self) | int(other)
        
    def __div__(self, other):
        return int(self) / int(other)
    
    def __rdiv__(self, other):
        return int(other)/int(self)
        
    def __truediv__(self, other):
        return int(self) / int(other)
        
    def __iadd__(self, other):
        result = self.__add__(other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __isub__(self, other):
        result = self.__sub__(other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __imul__(self, other):
        result = self.__mul__(other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __idiv__(self, other):
        result = self.__div__(other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __itruediv__(self, other):
        result = self.__truediv__(other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __ifloordiv__(self, other):
        result =  self.__floordiv__(self, other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __imod__(self, other):
        result =  self.__and__(self, other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __ipow__(self, other):
        result = self.__pow__(self, other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __ipow__(self, other, modulo):
        result = self.__pow__(self, other, modulo)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __ilshift__(self, other):
        result = self.__lshift__(other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __irshift__(self, other):
        result =  self.__rshift__(other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __iand__(self, other):
        result =  self.__and__(self, other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __ixor__(self, other):
        result =  self.__xor__(self, other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __ior__(self, other):
        result =  self.__ior__(self, other)
        self._sbval19k84obscure747.SetValueFromCString (str(result))
        return result
        
    def __neg__(self):
        return -int(self)
        
    def __pos__(self):
        return +int(self)
        
    def __abs__(self):
        return abs(int(self))
        
    def __invert__(self):
        return ~int(self)
        
    def __complex__(self):
        return complex (int(self))
        
    def __int__(self):
        if self._sbval19k84obscure747_is_ptr:
            return self._GetValueAsUnsigned()
        tname= self._sbval19k84obscure747_type.GetName()
        if tname.find('uint') >= 0 or tname.find('unsigned') >= 0:
            return self._GetValueAsUnsigned()
        retval = self._sbval19k84obscure747.GetValueAsSigned()
        # <rdar://problem/12481949> lldb python: GetValueAsSigned does not return the correct value
        if (retval & 0x80000000):
            retval = retval - 0x100000000
        return retval
        
    def __long__(self):
        return self._sbval19k84obscure747.GetValueAsSigned()
        
    def __float__(self):
        return float (self._sbval19k84obscure747.GetValueAsSigned())
        
    def __oct__(self):
        return '0%o' % self._GetValueAsUnsigned()
        
    def __hex__(self):
        return '0x%x' % self._GetValueAsUnsigned()

    def __eq__(self, other):
        self_err = lldb.SBError()
        other_err = lldb.SBError()
        self_val = self._sbval19k84obscure747.GetValueAsUnsigned(self_err)
        if self_err.fail:
                raise ValueError("unable to extract value of self")
        if type(other) is value:
            other_val = other._sbval19k84obscure747.GetValueAsUnsigned(other_err)
            if other_err.fail:
                raise ValueError("unable to extract value of other")
            return self_val == other_val
        if type(other) is int:
            return int(self) == other
        raise TypeError("Equality operation is not defined for this type.")
                                                                    
    def __neq__(self, other):
        return not self.__eq__(other)
    
    def GetSBValue(self):
        return self._sbval19k84obscure747
    
    def __getstate__(self):
        err = lldb.SBError()
        if self._sbval19k84obscure747_is_ptr:
            addr = self._sbval19k84obscure747.GetValueAsUnsigned()
            size = self._sbval19k84obscure747_type.GetPointeeType().GetByteSize()
        else:
            addr = self._sbval19k84obscure747.AddressOf().GetValueAsUnsigned()
            size = self._sbval19k84obscure747_type.GetByteSize()
        
        content = LazyTarget.GetProcess().ReadMemory(addr, size, err)
        if err.fail:
            content = ''
        return content

    def _GetValueAsSigned(self):
        if self._sbval19k84obscure747_is_ptr:
            print "ERROR: You cannot get 'int' from pointer type %s, please use unsigned(obj) for such purposes." % str(self._sbval19k84obscure747_type)
            raise ValueError("Cannot get signed int for pointer data.")
        serr = lldb.SBError()
        retval = self._sbval19k84obscure747.GetValueAsSigned(serr)
        if serr.success:
            return retval
        raise ValueError("Failed to read signed data. "+ str(self._sbval19k84obscure747) +"(type =" + str(self._sbval19k84obscure747_type) + ") Error description: " + serr.GetCString())

    def _GetValueAsCast(self, dest_type):
        if type(dest_type) is not lldb.SBType:
            raise ValueError("Invalid type for dest_type: {}".format(type(dest_type)))
        addr = self._GetValueAsUnsigned()
        sbval = self._sbval19k84obscure747.target.CreateValueFromExpression("newname", "(void *)"+str(addr))
        val = value(sbval.Cast(dest_type))
        return val

    def _GetValueAsUnsigned(self):
        serr = lldb.SBError()
        if self._sbval19k84obscure747_is_ptr:
            retval = self._sbval19k84obscure747.GetValueAsAddress()
        else:
            retval = self._sbval19k84obscure747.GetValueAsUnsigned(serr)
        if serr.success:
            return retval
        raise ValueError("Failed to read unsigned data. "+ str(self._sbval19k84obscure747) +"(type =" + str(self._sbval19k84obscure747_type) + ") Error description: " + serr.GetCString())
    
    def _GetValueAsString(self, offset = 0, maxlen = 1024):
        serr = lldb.SBError()
        sbdata = None
        if self._sbval19k84obscure747_is_ptr:
            sbdata = self._sbval19k84obscure747.GetPointeeData(offset, maxlen)
        else:
            sbdata = self._sbval19k84obscure747.GetData()
        
        retval = ''
        bytesize = sbdata.GetByteSize()
        if bytesize == 0 :
            #raise ValueError('Unable to read value as string')
            return ''
        for i in range(0, bytesize) :
            serr.Clear()
            ch = chr(sbdata.GetUnsignedInt8(serr, i))
            if serr.fail :
                raise ValueError("Unable to read string data: " + serr.GetCString())
            if ch == '\0':
                break
            retval += ch
        return retval 
    
    def __format__(self, format_spec):
        ret_format = "{0:"+format_spec+"}"
        # typechar is last char. see http://www.python.org/dev/peps/pep-3101/
        type_spec=format_spec.strip().lower()[-1]
        if type_spec == 'x':
            return ret_format.format(self._GetValueAsUnsigned())
        if type_spec == 'd':
            return ret_format.format(int(self))
        if type_spec == 's':
            return ret_format.format(str(self))
        if type_spec == 'o':
            return ret_format.format(int(oct(self)))
        if type_spec == 'c':
            return ret_format.format(int(self))
        
        return "unknown format " + format_spec + str(self)
        
        
def unsigned(val):
    """ Helper function to get unsigned value from core.value
        params: val - value (see value class above) representation of an integer type
        returns: int which is unsigned. 
        raises : ValueError if the type cannot be represented as unsigned int.
    """
    if type(val) is value:
        return val._GetValueAsUnsigned()
    return int(val)

def sizeof(t):
    """ Find the byte size of a type. 
        params: t - str : ex 'time_spec' returns equivalent of sizeof(time_spec) in C
                t - value: ex a value object. returns size of the object
        returns: int - byte size length 
    """
    if type(t) is value :
        return t.GetSBValue().GetByteSize()
    if type(t) is str:
        return gettype(t).GetByteSize()
    raise ValueError("Cannot get sizeof. Invalid argument")
    
        
def dereference(val):
    """ Get a dereferenced obj for a pointer type obj
        params: val - value object representing a pointer type C construct in lldb
        returns: value - value
        ex. val = dereference(ptr_obj) #python
        is same as
            obj_ptr = (int *)0x1234  #C
            val = *obj_ptr           #C
    """
    if type(val) is value and val._sbval19k84obscure747_is_ptr:
        return value(val.GetSBValue().Dereference())
    raise TypeError('Cannot dereference this type.')
        
def addressof(val):
    """ Get address of a core.value object. 
        params: val - value object representing a C construct in lldb
        returns: value - value object referring to 'type(val) *' type
        ex. addr = addressof(hello_obj)  #python 
        is same as
           uintptr_t addr = (uintptr_t)&hello_obj  #C
    """
    if type(val) is value:
        return value(val.GetSBValue().AddressOf())
    raise TypeError("Cannot do addressof for non-value type objects")

def cast(obj, target_type):
    """ Type cast an object to another C type.
        params:
            obj - core.value  object representing some C construct in lldb
            target_type - str : ex 'char *'
                        - lldb.SBType :
    """
    dest_type = target_type
    if type(target_type) is str:
        dest_type = gettype(target_type)
    elif type(target_type) is value:
        dest_type = target_type.GetSBValue().GetType()

    if type(obj) is value:
        return obj._GetValueAsCast(dest_type)
    elif type(obj) is int:
        print "ERROR: You cannot cast an 'int' to %s, please use kern.GetValueFromAddress() for such purposes." % str(target_type) 
    raise TypeError("object of type %s cannot be casted to %s" % (str(type(obj)), str(target_type)))

def containerof(obj, target_type, field_name):
    """ Type cast an object to another C type from a pointer to a field.
        params:
            obj - core.value  object representing some C construct in lldb
            target_type - str : ex 'struct thread'
                        - lldb.SBType :
            field_name - the field name within the target_type obj is a pointer to
    """
    addr = int(obj) - getfieldoffset(target_type, field_name)
    obj = value(obj.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
    return cast(obj, target_type + " *")


_value_types_cache={}

def gettype(target_type):
    """ Returns lldb.SBType of the given target_type
        params:
            target_type - str, ex. 'char', 'uint32_t' etc
        returns:
            lldb.SBType - SBType corresponding to the given target_type
        raises:
            NameError  - Incase the type is not identified
    """
    global _value_types_cache
    target_type = str(target_type).strip()
    if target_type in _value_types_cache:
        return _value_types_cache[target_type]

    target_type = target_type.strip()

    requested_type_is_struct = False
    m = re.match(r'\s*struct\s*(.*)$', target_type)
    if m:
        requested_type_is_struct = True
        target_type = m.group(1)

    tmp_type = None
    requested_type_is_pointer = False
    if target_type.endswith('*') :
        requested_type_is_pointer = True

    # tmp_type = LazyTarget.GetTarget().FindFirstType(target_type.rstrip('*').strip())
    search_type = target_type.rstrip('*').strip()
    type_arr = [t for t in LazyTarget.GetTarget().FindTypes(search_type)]

    if requested_type_is_struct:
        type_arr = [t for t in type_arr if t.type == lldb.eTypeClassStruct]

    # After the sort, the struct type with more fields will be at index [0].
    # This hueristic helps selecting struct type with more fields compared to ones with "opaque" members
    type_arr.sort(reverse=True, key=lambda x: x.GetNumberOfFields())
    if len(type_arr) > 0:
        tmp_type = type_arr[0]
    else:
        raise NameError('Unable to find type '+target_type)

    if not tmp_type.IsValid():
        raise NameError('Unable to Cast to type '+target_type)

    if requested_type_is_pointer:
        tmp_type = tmp_type.GetPointerType()
    _value_types_cache[target_type] = tmp_type

    return _value_types_cache[target_type]


def getfieldoffset(struct_type, field_name):
    """ Returns the byte offset of a field inside a given struct
        Understands anonymous unions and field names in sub-structs
        params:
            struct_type - str or lldb.SBType, ex. 'struct ipc_port *' or port.gettype()
            field_name  - str, name of the field inside the struct ex. 'ip_messages'
        returns:
            int - byte offset of the field_name inside the struct_type
        raises:
            TypeError  - - In case the struct_type has no field with the name field_name
    """

    if type(struct_type) == str:
        struct_type = gettype(struct_type)

    if '.' in field_name :
        # Handle recursive fields in sub-structs
        components = field_name.split('.', 1)
        for field in struct_type.get_fields_array():
            if str(field.GetName()) == components[0]:
                return getfieldoffset(struct_type, components[0]) + getfieldoffset(field.GetType(), components[1])
        raise TypeError('Field name "%s" not found in type "%s"' % (components[0], str(struct_type)))

    offset = 0
    for field in struct_type.get_fields_array():
        if str(field.GetName()) == field_name:
            return field.GetOffsetInBytes()

        # Hack for anonymous unions - the compiler does this, so cvalue should too
        if field.GetName() is None and field.GetType().GetTypeClass() == lldb.eTypeClassUnion :
            for union_field in field.GetType().get_fields_array():
                if str(union_field.GetName()) == field_name:
                    return union_field.GetOffsetInBytes() + field.GetOffsetInBytes()
    raise TypeError('Field name "%s" not found in type "%s"' % (field_name, str(struct_type)))

def islong(x):
    """ Returns True if a string represents a long integer, False otherwise
    """
    try:
        long(x,16)
    except ValueError:
        try:
            long(x)
        except ValueError:
            return False
    return True

def readmemory(val):
    """ Returns a string of hex data that is referenced by the value.
        params: val - a value object. 
        return: str - string of hex bytes. 
        raises: TypeError if val is not a valid type
    """
    if not type(val) is value:
        raise TypeError('%s is not of type value' % str(type(val)))
    return val.__getstate__()
