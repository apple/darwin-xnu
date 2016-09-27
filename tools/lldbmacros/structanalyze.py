import lldb
from xnu import *

def _showStructPacking(symbol, prefix, begin_offset=0, typedef=None):
  """
     recursively parse the field members of structure. 
     params : symbol (lldb.SBType) reference to symbol in binary
              prefix (string)      string to be prefixed for each line of output. Useful for recursive struct parsing.
     returns: string containing lines of output.
  """
  ctype = "unknown type"
  if symbol.GetTypeClass() == lldb.eTypeClassUnion :
    ctype = "union"
  if symbol.GetTypeClass() == lldb.eTypeClassStruct :
    ctype = "struct"

  if typedef:
    outstr =  "[%4d] (%s) (%s) %s { " % (symbol.GetByteSize(), typedef, ctype, symbol.GetName()) + "\n"
  else :
    outstr =  "[%4d] (%s) %s { " % (symbol.GetByteSize(), ctype, symbol.GetName()) + "\n"
  numFields = symbol.GetNumberOfFields()
  _has_memory_hole = False
  _compact_size = 0    # asuming the struct is perfectly packed
  _compact_offset = begin_offset
  _previous_bit_offset = 0 
  for i in range(numFields):
    member = symbol.GetFieldAtIndex(i)
    m_offset = member.GetOffsetInBytes() + begin_offset
    m_offset_bits = member.GetOffsetInBits()
    m_type = member.GetType()
    m_name = member.GetName()
    m_size = m_type.GetByteSize()
    warningstr = ""
    debugstr = "" # + str((m_size, m_offset , m_offset_bits, _previous_bit_offset, _compact_offset, begin_offset))
    if _compact_offset != m_offset and (m_offset_bits -  _previous_bit_offset) > m_size*8 :
      _has_memory_hole = True
      warningstr = "   *** Possible memory hole ***" 
      _compact_offset = m_offset
    _compact_offset += m_size

    _type_class = m_type.GetTypeClass()
    _canonical_type = m_type.GetCanonicalType()
    _canonical_type_class = m_type.GetCanonicalType().GetTypeClass()

    if _type_class == lldb.eTypeClassTypedef and (_canonical_type_class == lldb.eTypeClassStruct or _canonical_type_class == lldb.eTypeClassUnion) :
      outstr += prefix + ("*%4d," % m_offset) + _showStructPacking(_canonical_type, prefix+"    ", m_offset, str(m_type)) + warningstr + debugstr + "\n"
    elif _type_class == lldb.eTypeClassStruct or _type_class == lldb.eTypeClassUnion :
      outstr += prefix + ("*%4d," % m_offset) + _showStructPacking(m_type, prefix+"    ", m_offset) + warningstr + debugstr + "\n"
    else:
      outstr += prefix + ("+%4d,[%4d] (%s) %s" % (m_offset, m_size, m_type.GetName(), m_name)) + warningstr + debugstr + "\n"
    if i > 0 :
      _previous_bit_offset = m_offset_bits
  outstr += prefix + "}"
  if _has_memory_hole == True :
    outstr += "   *** Warning: Struct layout leaves memory hole *** "
  return outstr

@lldb_command('showstructpacking')
def showStructInfo(cmd_args=None):
  """Show how a structure is packed in the binary. The format is 
     +<offset>, [<size_of_member>] (<type>) <name> 
     For example:
      (lldb) script lldbmacros.showStructInfo("pollfd")
      [  8] (struct) pollfd { 
      +  0,[  4] (int) fd
      +  4,[  2] (short) events
      +  6,[  2] (short) revents
      }
    syntax: showstructpacking task
  """
  if not cmd_args:
    raise ArgumentError("Please provide a type name.")
  
  sym = gettype(cmd_args[0])
  if sym == None:
    print "No such struct found"
  if sym.GetTypeClass() == lldb.eTypeClassTypedef:
      sym = sym.GetCanonicalType()
  if sym.GetTypeClass() != lldb.eTypeClassStruct:
    print "%s is not a structure" % cmd_args[0]
  else:
    print _showStructPacking(sym,"", 0)

# EndMacro: showstructinto
