import lldb
from xnu import *

_UnionStructClass = [ lldb.eTypeClassStruct, lldb.eTypeClassClass, lldb.eTypeClassUnion ]

def _showStructPacking(O, symbol, begin_offset=0, symsize=0, typedef=None, outerSize=0, memberName=None):
    """
       recursively parse the field members of structure.
       params : O the output formatter (standard.py)
                symbol (lldb.SBType) reference to symbol in binary
       returns: string containing lines of output.
    """
    ctype = "unknown type"
    is_union = False
    is_class = False
    union_size = None
    sym_size = symbol.GetByteSize()

    if symbol.GetTypeClass() == lldb.eTypeClassUnion:
        ctype = "union"
        is_union = True
        union_size = sym_size
    if symbol.GetTypeClass() == lldb.eTypeClassStruct:
        ctype = "struct"
    if symbol.GetTypeClass() == lldb.eTypeClassClass:
        ctype = "class"
        is_class = True

    if not outerSize or outerSize == sym_size:
        outstr = O.format("{:04d},[{:4d}]", begin_offset, sym_size)
    elif outerSize < sym_size: # happens with c++ inheritance
        outstr = O.format("{:04d},[{:4d}]", begin_offset, outerSize)
    else:
        outstr = O.format("{:04d},[{:4d}]{VT.DarkRed}{{{:+d}}}{VT.Default}",
                begin_offset, sym_size, outerSize - sym_size)

    if typedef:
        outstr += O.format(" {0}", typedef)
    if symbol.IsAnonymousType():
        outstr += O.format(" ({VT.DarkMagenta}anonymous {0}{VT.Default})", ctype)
    else:
        outstr += O.format(" ({VT.DarkMagenta}{0} {1}{VT.Default})", ctype, symbol.GetName())
    if memberName:
        outstr += O.format(" {0} {{", memberName)
    else:
        outstr += ") {"

    print outstr

    with O.indent():
        _previous_size = 0
        _packed_bit_offset = 0
        _nfields = symbol.GetNumberOfFields()

        if is_class:
            _next_offset_in_bits = 0
            _nclasses = symbol.GetNumberOfDirectBaseClasses()

            for i in range(_nclasses):
                member = symbol.GetDirectBaseClassAtIndex(i)
                if i < _nclasses - 1:
                    m_size_bits = symbol.GetDirectBaseClassAtIndex(i + 1).GetOffsetInBits()
                elif _nfields:
                    m_size_bits = symbol.GetFieldAtIndex(0).GetOffsetInBits()
                else:
                    m_size_bits = symbol.GetByteSize() * 8

                m_offset = member.GetOffsetInBytes() + begin_offset
                m_type = member.GetType()
                m_name = member.GetName()
                m_size = m_size_bits / 8

                _previous_size = m_size
                _packed_bit_offset = member.GetOffsetInBits() + m_size_bits

                _showStructPacking(O, m_type, m_offset, str(m_type), outerSize=m_size, memberName=m_name)

        for i in range(_nfields):
            member = symbol.GetFieldAtIndex(i)
            m_offset = member.GetOffsetInBytes() + begin_offset
            m_offset_bits = member.GetOffsetInBits()

            m_type = member.GetType()
            m_name = member.GetName()
            m_size = m_type.GetByteSize()

            if member.IsBitfield():
                m_is_bitfield = True
                m_size_bits = member.GetBitfieldSizeInBits()
            else:
                m_is_bitfield = False
                m_size_bits = m_size * 8

            if not is_union and _packed_bit_offset < m_offset_bits:
                m_previous_offset = begin_offset + _packed_bit_offset / 8
                m_hole_bits = m_offset_bits - _packed_bit_offset
                if _packed_bit_offset % 8 == 0:
                    print O.format("{:04d},[{:4d}] ({VT.DarkRed}*** padding ***{VT.Default})",
                            m_previous_offset, m_hole_bits / 8)
                else:
                    print O.format("{:04d},[{:4d}] ({VT.Brown}*** padding : {:d} ***{VT.Default})",
                            m_previous_offset, _previous_size, m_hole_bits)

            _previous_size = m_size
            _packed_bit_offset = m_offset_bits + m_size_bits

            _type_class = m_type.GetTypeClass()
            _canonical_type = m_type.GetCanonicalType()
            _canonical_type_class = m_type.GetCanonicalType().GetTypeClass()

            if _type_class == lldb.eTypeClassTypedef and _canonical_type_class in _UnionStructClass:
                _showStructPacking(O, _canonical_type, m_offset, str(m_type), outerSize=union_size, memberName=m_name)
            elif _type_class in _UnionStructClass:
                _showStructPacking(O, m_type, m_offset, outerSize=union_size, memberName=m_name)
            else:
                outstr = O.format("{:04d},[{:4d}]", m_offset, m_size)
                if is_union and union_size != m_size_bits / 8:
                    outstr += O.format("{VT.DarkRed}{{{:+d}}}{VT.Default}",
                            union_size - m_size_bits / 8)
                if m_is_bitfield:
                    outstr += O.format(" ({VT.DarkGreen}{:s} : {:d}{VT.Default}) {:s}",
                            m_type.GetName(), m_size_bits, m_name)
                else:
                    outstr += O.format(" ({VT.DarkGreen}{:s}{VT.Default}) {:s}",
                            m_type.GetName(), m_name)
                print outstr

        referenceSize = min(outerSize, sym_size) or sym_size
        if not is_union and _packed_bit_offset < referenceSize * 8:
            m_previous_offset = begin_offset + _packed_bit_offset / 8
            m_hole_bits = referenceSize * 8 - _packed_bit_offset
            offset = _packed_bit_offset / 8 + begin_offset
            if _packed_bit_offset % 8 == 0:
                print O.format("{:04d},[{:4d}] ({VT.DarkRed}*** padding ***{VT.Default})",
                        m_previous_offset, m_hole_bits / 8)
            else:
                print O.format("{:04d},[{:4d}] ({VT.Brown}padding : {:d}{VT.Default})\n",
                        m_previous_offset, _previous_size, m_hole_bits)

    print "}"

@lldb_command('showstructpacking', fancy=True)
def showStructInfo(cmd_args=None, cmd_options={}, O=None):
    """Show how a structure is packed in the binary. The format is
       <offset>, [<size_of_member>] (<type>) <name>

       For example:
          (lldb) showstructpacking pollfd
             0,[   8] struct pollfd {
                 0,[   4] (int) fd
                 4,[   2] (short) events
                 6,[   2] (short) revents
          }

      syntax: showstructpacking task
    """
    if not cmd_args:
        raise ArgumentError("Please provide a type name.")

    ty_name = cmd_args[0]
    try:
        sym = gettype(ty_name)
    except NameError:
        return O.error("Cannot find type named {0}", ty_name)

    if sym.GetTypeClass() == lldb.eTypeClassTypedef:
        sym = sym.GetCanonicalType()

    if sym.GetTypeClass() not in _UnionStructClass:
        return O.error("{0} is not a structure/union/class type", ty_name)

    _showStructPacking(O, sym, 0)

# EndMacro: showstructinto
