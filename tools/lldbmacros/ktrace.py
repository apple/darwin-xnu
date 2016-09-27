from xnu import *
from utils import *

# From the defines in bsd/sys/kdebug.h:

KdebugClassNames = {
    1: "MACH",
    2: "NETWORK",
    3: "FSYSTEM",
    4: "BSD",
    5: "IOKIT",
    6: "DRIVERS",
    7: "TRACE",
    8: "DLIL",
    9: "WORKQUEUE",
    10: "CORESTORAGE",
    11: "CG",
    20: "MISC",
    30: "SECURITY",
    31: "DYLD",
    32: "QT",
    33: "APPS",
    34: "LAUNCHD",
    36: "PPT",
    37: "PERF",
    38: "IMPORTANCE",
    39: "PERFCTRL",
    40: "BANK",
    41: "XPC",
    42: "ATM",
    43: "ARIADNE",
    44: "DAEMON",
    45: "ENERGYTRACE",
    49: "IMG",
    50: "CLPC",
    128: "ANS",
    129: "SIO",
    130: "SEP",
    131: "ISP",
    132: "OSCAR",
    133: "EMBEDDEDGFX"
}

def GetKdebugClassName(class_num):
    return (KdebugClassNames[class_num] + ' ({})'.format(class_num) if class_num in KdebugClassNames else 'unknown ({})'.format(class_num))

@lldb_type_summary(['typefilter_t'])
@header('{0: <20s}'.format("class") + ' '.join(map('{:02x}'.format, xrange(0, 255, 8))))
def GetKdebugTypefilter(typefilter):
    """ Summarizes the provided typefilter.
    """
    classes = 256
    subclasses_per_class = 256

    # 8 bits at a time
    subclasses_per_element = 64
    cur_typefilter = cast(typefilter, 'uint64_t *')
    subclasses_fmts = ' '.join(['{:02x}'] * 8)

    elements_per_class = subclasses_per_class / subclasses_per_element

    out_str = ''
    for i in xrange(0, classes):
        print_class = False
        subclasses = [0] * elements_per_class

        # check subclass ranges for set bits, remember those subclasses
        for j in xrange(0, elements_per_class):
            element = unsigned(cur_typefilter[i * elements_per_class + j])
            if element != 0:
                print_class = True
            if print_class:
                subclasses[j] = element

        # if any of the bits were set in a class, print the entire class
        if print_class:
            out_str += '{:<20s}'.format(GetKdebugClassName(i))
            for element in subclasses:
                # split up the 64-bit values into byte-sized pieces
                bytes = [unsigned((element >> i) & 0xff) for i in (0, 8, 16, 24, 32, 40, 48, 56)]
                out_str += subclasses_fmts.format(*bytes)
                out_str += ' '

            out_str += '\n'

    return out_str

@lldb_command('showkdebugtypefilter')
def ShowKdebugTypefilter(cmd_args=None):
    """ Show the current kdebug typefilter (or the typefilter at an address)

        usage: showkdebugtypefilter [<address>]
    """

    if cmd_args:
        print GetKdebugTypefilter.header
        print '-' * len(GetKdebugTypefilter.header)

        typefilter = kern.GetValueFromAddress(cmd_args[0], 'typefilter_t')
        if unsigned(typefilter) == 0:
            raise ArgumentError('argument provided is NULL')

        print GetKdebugTypefilter()
        return

    typefilter = kern.globals.kdbg_typefilter
    if unsigned(typefilter) == 0:
        raise ArgumentError('no argument provided and active typefilter is not set')

    print GetKdebugTypefilter.header
    print '-' * len(GetKdebugTypefilter.header)
    print GetKdebugTypefilter(typefilter)
