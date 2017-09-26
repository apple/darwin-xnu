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

        ## if any of the bits were set in a class, print the entire class
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
        typefilter = kern.GetValueFromAddress(cmd_args[0], 'typefilter_t')
        if unsigned(typefilter) == 0:
            raise ArgumentError('argument provided is NULL')

        print GetKdebugTypefilter.header
        print '-' * len(GetKdebugTypefilter.header)

        print GetKdebugTypefilter(typefilter)
        return

    typefilter = kern.globals.kdbg_typefilter
    if unsigned(typefilter) == 0:
        raise ArgumentError('no argument provided and active typefilter is not set')

    print GetKdebugTypefilter.header
    print '-' * len(GetKdebugTypefilter.header)
    print GetKdebugTypefilter(typefilter)

def GetKdebugStatus():
    """ Get a string summary of the kdebug subsystem.
    """
    out = ''

    kdebug_flags = kern.globals.kd_ctrl_page.kdebug_flags
    out += 'kdebug flags: {}\n'.format(xnudefines.GetStateString(xnudefines.kdebug_flags_strings, kdebug_flags))
    events = kern.globals.nkdbufs
    buf_mb = events * (64 if kern.arch == 'x86_64' or kern.arch.startswith('arm64') else 32) / 1000000
    out += 'events allocated: {:<d} ({:<d} MB)\n'.format(events, buf_mb)
    out += 'enabled: {}\n'.format('yes' if kern.globals.kdebug_enable != 0 else 'no')
    if kdebug_flags & xnudefines.kdebug_typefilter_check:
        out += 'typefilter:\n'
        out += GetKdebugTypefilter.header + '\n'
        out += '-' * len(GetKdebugTypefilter.header) + '\n'
        typefilter = kern.globals.kdbg_typefilter
        if unsigned(typefilter) != 0:
            out += GetKdebugTypefilter(typefilter)

    return out

@lldb_command('showkdebug')
def ShowKdebug(cmd_args=None):
    """ Show the current kdebug state.

        usage: showkdebug
    """

    print GetKdebugStatus()

@lldb_type_summary(['kperf_timer'])
@header('{:<10s} {:<7s} {:<20s}'.format('period-ns', 'action', 'pending'))
def GetKperfTimerSummary(timer):
    """ Get a string summary of a kperf timer.

        params:
            timer: the kperf_timer object to get a summary of
    """
    return '{:<10d} {:<7d} {:<20x}\n'.format(
        kern.GetNanotimeFromAbstime(timer.period), timer.actionid, timer.pending_cpus)

@lldb_type_summary(['action'])
@header('{:<10s} {:<20s} {:<20s}'.format('pid-filter', 'user-data', 'samplers'))
def GetKperfActionSummary(action):
    """ Get a string summary of a kperf action.

        params:
            action: the action object to get a summary of
    """
    samplers = xnudefines.GetStateString(xnudefines.kperf_samplers_strings, action.sample)
    return '{:<10s} {:<20x} {:<20s}\n'.format(
        '-' if action.pid_filter < 0 else str(action.pid_filter), action.userdata, samplers)

def GetKperfStatus():
    """ Get a string summary of the kperf subsystem.
    """
    out = ''

    kperf_status = kern.globals.sampling_status
    out += 'sampling: '
    if kperf_status == 0:
        out += 'off\n'
    elif kperf_status == 1:
        out += 'on\n'
    elif kperf_status == 2:
        out += 'shutting down\n'
    else:
        out += 'unknown\n'

    pet = 0# kern.globals.pet_running
    pet_timer_id = kern.globals.pet_timer_id
    if pet != 0:
        pet_idle_rate = kern.globals.pet_idle_rate
        out += 'legacy PET is active (timer = {:<d}, idle rate = {:<d})\n'.format(pet_timer_id, pet_idle_rate)
    else:
        out += 'legacy PET is off\n'

    lw_pet = kern.globals.kperf_lightweight_pet_active
    if lw_pet != 0:
        lw_pet_gen = kern.globals.kperf_pet_gen
        out += 'lightweight PET is active (timer = {:<d}, generation count = {:<d})\n'.format(pet_timer_id, lw_pet_gen)
    else:
        out += 'lightweight PET is off\n'

    actions = kern.globals.actionc
    actions_arr = kern.globals.actionv

    out += 'actions:\n'
    out += '{:<5s} '.format('id') + GetKperfActionSummary.header + '\n'
    for i in xrange(0, actions):
        out += '{:<5d} '.format(i) + GetKperfActionSummary(actions_arr[i])

    timers = kern.globals.kperf_timerc
    timers_arr = kern.globals.kperf_timerv

    out += 'timers:\n'
    out += '{:<5s} '.format('id') + GetKperfTimerSummary.header + '\n'
    for i in xrange(0, timers):
        out += '{:<5d} '.format(i) + GetKperfTimerSummary(timers_arr[i])

    return out

def GetKtraceStatus():
    """ Get a string summary of the ktrace subsystem.
    """
    out = ''

    state = kern.globals.ktrace_state
    if state == GetEnumValue('ktrace_state::KTRACE_STATE_OFF'):
        out += 'ktrace is off\n'
    else:
        out += 'ktrace is active ('
        if state == GetEnumValue('ktrace_state::KTRACE_STATE_FG'):
            out += 'foreground)'
        else:
            out += 'background)'
        out += '\n'
        owner = kern.globals.ktrace_last_owner_execname
        out += 'owned by: {0: <s}\n'.format(owner)
        active_mask = kern.globals.ktrace_active_mask
        out += 'active systems: {:<#x}\n'.format(active_mask)

    return out

@lldb_command('showktrace')
def ShowKtrace(cmd_args=None):
    """ Show the current ktrace state, including subsystems.

        usage: showktrace
    """

    print GetKtraceStatus()
    print ' '
    print 'kdebug:'
    print GetKdebugStatus()
    print ' '
    print 'kperf:'
    print GetKperfStatus()
