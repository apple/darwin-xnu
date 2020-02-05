""" Please make sure you read the README file COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""

""" Note for adding new register support:
    
    1. Add target register to "supported registers" in the docstring of DecodeSysreg
    2. Populate _SYSREG_TO_DECODE_FUNC_MAP with your implementation, optionally using
       _SYSREG_TO_DOCNAME_MAP
    3. Populate _SUPPORTED_SYSREGS list with target register
    
"""

from xnu import *
import os
import sys
import xml.etree.ElementTree as ET

GREEN = '\033[0;32m'
RED   = '\033[0;31m'
NC    = '\033[0m'

_SUPPORTED_SYSREGS = ['ESR_EL1']

_SYSREG_DOC_PATH = os.path.dirname(os.path.abspath(__file__)) + '/sysregdoc/'

_SYSREG_TO_DOCNAME_MAP = {
    'ESR_EL1': 'AArch64-esr_el1.xml'
}

## Actual definition at the bottom of the file
_SYSREG_TO_DECODE_FUNC_MAP = None

# Macro: decode_sysreg
@lldb_command('decode_sysreg')
def DecodeSysreg(cmd_args=None):
    """ Print out human-understandable explanation of a system register value
        usage: decode_sysreg <sysreg> <value>
        example: decode_sysreg esr_el1 0x96000021

        supported registers:
        ESR_EL1
    """

    ## For now, require exactly 2 arguments
    if not cmd_args or len(cmd_args) != 2:
        raise ArgumentError("Missing arguments.")

    reg_name = cmd_args[0].upper()
    reg_value = int(cmd_args[1], 0)

    if reg_name not in _SUPPORTED_SYSREGS:
        raise ArgumentError("{} is not supported".format(reg_name))

    _SYSREG_TO_DECODE_FUNC_MAP[reg_name](reg_value)
# EndMacro: decode_sysreg


lldb_alias('decode_esr', 'decode_sysreg esr_el1')


def PrintEsrEl1Explanation(regval):
    """ Print out a detailed explanation of regval regarded as the value of
        ESR_EL1, by parsing ARM machine readable specification
    """
    xmlfilename = _SYSREG_DOC_PATH + _SYSREG_TO_DOCNAME_MAP['ESR_EL1']
    tree = ET.parse(xmlfilename)
    root = tree.getroot()

    ec = (regval >> 26) & ((1 << 6) - 1)
    ecstring = '0b{:06b}'.format(ec)

    print _Colorify(VT.Green, 'EC == ' + ecstring)

    ecxpath = './registers/register/reg_fieldsets/fields/field[@id="EC_31_26"]/field_values/field_value_instance[field_value="{}"]/field_value_description//para'.format(ecstring)
    ec_desc_paras = root.findall(ecxpath)

    if ec_desc_paras is None or len(ec_desc_paras) == 0:
        print 'EC not defined.'
        print '\r\n'

    for para in ec_desc_paras:
        sys.stdout.write(para.text)
        for child in para:
            sys.stdout.write(_GetParaChildrenStr(child))
            sys.stdout.write(child.tail)
        print '\r\n'
        print '\r\n'

    iss = regval & ((1 << 25) - 1);
    issstring = '0x{:07x}'.format(iss)
    print _Colorify(VT.Green, 'ISS == ' + issstring)
    print '\r\n'

    iss_condition_xpath = './registers/register/reg_fieldsets/fields/field[@id="EC_31_26"]/field_values/field_value_instance[field_value="{}"]/field_value_links_to'.format(ecstring)
    iss_condition = root.find(iss_condition_xpath)
    iss_condition_str = iss_condition.attrib['linked_field_condition']

    iss_fields_xpath = './registers/register/reg_fieldsets/fields/field[@id="ISS_24_0"]/partial_fieldset/fields[fields_instance="{}"]//field'.format(iss_condition_str)
    iss_fields = root.findall(iss_fields_xpath)
    
    for field in iss_fields:
        _PrintEsrIssField(field, regval)


def _GetParaChildrenStr(elem):
    """ Convert child tags of <para> element into text for printing
    """

    if elem.tag == 'binarynumber':
        return elem.text
    if elem.tag == 'arm-defined-word':
        return elem.text
    elif elem.tag == 'xref':
        return elem.attrib['browsertext'].encode('utf-8')
    elif elem.tag == 'register_link':
        return elem.text
    else:
        return _Colorify(VT.Red, '*unsupported text*')


def _PrintEsrIssField(elem, regval):
    """ Print detailed explanation of the ISS field of ESR
    """

    field_name_str = elem.find('field_name').text
    field_msb = int(elem.find('field_msb').text)
    field_lsb = int(elem.find('field_lsb').text)
    fd_before_paras = elem.findall('./field_description[@order="before"]//para')
    fd_after_paras = elem.findall('./field_description[@order="after"]//para')

    field_bits = field_msb - field_lsb + 1
    field_value = (regval >> field_lsb) & ((1 << field_bits) - 1)
    field_value_string = ('0b{:0' + '{}'.format(field_bits) + 'b}').format(field_value)

    print _Colorify(VT.Green, _GetIndentedString(2, field_name_str) + ' == ' + field_value_string)

    fv_desc_paras = elem.findall('./field_values/field_value_instance[field_value="{}"]/field_value_description//para'.format(field_value_string))

    if fv_desc_paras and len(fv_desc_paras):
        for para in fv_desc_paras:
            sys.stdout.write(_GetIndentedString(2, ''))
            sys.stdout.write(para.text)
            for child in para:
                sys.stdout.write(_GetParaChildrenStr(child))
                sys.stdout.write((child.tail))
        print '\r\n'
        print '\r\n'
    else:
        print _Colorify(VT.Red, _GetIndentedString(2, '(No matching value, dumping out full description)')) 
        for para in fd_before_paras:
            sys.stdout.write(_GetIndentedString(2, ''))
            sys.stdout.write(para.text)
            for child in para:
                sys.stdout.write(_GetParaChildrenStr(child))
                sys.stdout.write(child.tail)
            print '\r\n'
            print '\r\n'

        ## Dump all possible values
        all_field_values = elem.findall('./field_values/field_value_instance//field_value')
        all_field_values_str = [fv.text for fv in all_field_values]
        if all_field_values_str != []:
            print _GetIndentedString(2, ', '.join(all_field_values_str))

        for para in fd_after_paras:
            sys.stdout.write(_GetIndentedString(2, ''))
            sys.stdout.write(para.text)
            for child in para:
                sys.stdout.write(_GetParaChildrenStr(child))
                sys.stdout.write(child.tail)
            print '\r\n'
            print '\r\n'


def _GetIndentedString(indentation, msg):
    """ Return `msg` indented by `indentation` number of spaces
    """
    return ' ' * indentation + msg


def _Colorify(color, msg):
    """ Return `msg` enclosed by color codes
    """
    return color + msg + VT.Reset


_SYSREG_TO_DECODE_FUNC_MAP = {
    'ESR_EL1': PrintEsrEl1Explanation
}
