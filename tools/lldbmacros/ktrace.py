from xnu import *
from utils import *
from core.lazytarget import *
from misc import *
from collections import namedtuple

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
@header('{:<10s} {:<7s} {:<20s} {:<20s}'.format('period-ns', 'action', 'deadline', 'fire-time'))
def GetKperfTimerSummary(timer):
    """ Get a string summary of a kperf timer.

        params:
            timer: the kptimer object to get a summary of
    """
    try:
        fire_time = timer.kt_fire_time
    except:
        fire_time = 0
    return '{:<10d} {:<7d} {:<20d} {:<20d}\n'.format(
        kern.GetNanotimeFromAbstime(timer.kt_period_abs), timer.kt_actionid,
        timer.kt_cur_deadline, fire_time)

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

    kperf_status = int(kern.globals.kperf_status)
    out += 'sampling: '
    if kperf_status == GetEnumValue('kperf_sampling::KPERF_SAMPLING_OFF'):
        out += 'off\n'
    elif kperf_status == GetEnumValue('kperf_sampling::KPERF_SAMPLING_SHUTDOWN'):
        out += 'shutting down\n'
    elif kperf_status == GetEnumValue('kperf_sampling::KPERF_SAMPLING_ON'):
        out += 'on\n'
    else:
        out += 'unknown\n'

    pet = kern.globals.kptimer.g_pet_active
    pet_timer_id = kern.globals.kptimer.g_pet_active
    if pet != 0:
        pet_idle_rate = kern.globals.pet_idle_rate
        out += 'legacy PET is active (timer = {:<d}, idle rate = {:<d})\n'.format(pet_timer_id, pet_idle_rate)
    else:
        out += 'legacy PET is off\n'

    lw_pet = kern.globals.kppet.g_lightweight
    if lw_pet != 0:
        lw_pet_gen = kern.globals.kppet_gencount
        out += 'lightweight PET is active (timer = {:<d}, generation count = {:<d})\n'.format(pet_timer_id, lw_pet_gen)
    else:
        out += 'lightweight PET is off\n'

    actions = kern.globals.actionc
    actions_arr = kern.globals.actionv

    out += 'actions:\n'
    out += '{:<5s} '.format('id') + GetKperfActionSummary.header + '\n'
    for i in xrange(0, actions):
        out += '{:<5d} '.format(i) + GetKperfActionSummary(actions_arr[i])

    timers = kern.globals.kptimer.g_ntimers
    timers_arr = kern.globals.kptimer.g_timers

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


class KDCPU(object):
    def __init__(self, store, curidx):
        self.store = store
        self.curidx = curidx
        self.oldest_time = None


def IterateKdebugEvents():
    """
    Yield events from the in-memory kdebug trace buffers.
    """
    ctrl = kern.globals.kd_ctrl_page

    def get_kdstore(kdstorep):
        """
        See POINTER_FROM_KDSPTR.
        """
        buf = kern.globals.kd_bufs[kdstorep.buffer_index]
        return addressof(buf.kdsb_addr[kdstorep.offset])

    def get_kdbuf_timestamp(kdbuf):
        time_cpu = kdbuf.timestamp
        return unsigned(time_cpu)

    if (ctrl.kdebug_flags & xnudefines.KDBG_BFINIT) == 0:
        return

    barrier_min = ctrl.oldest_time

    if (ctrl.kdebug_flags & xnudefines.KDBG_WRAPPED) != 0:
        # TODO Yield a wrap event with the barrier_min timestamp.
        pass

    # Set up CPU state for merging events.
    ncpus = ctrl.kdebug_cpus
    cpus = []
    for cpu in range(ncpus):
        kdstoreinfo = kern.globals.kdbip[cpu]
        storep = kdstoreinfo.kd_list_head
        store = None
        curidx = 0
        if storep.raw != xnudefines.KDS_PTR_NULL:
            store = get_kdstore(storep)
            curidx = store.kds_readlast
        # XXX Doesn't have the same logic to avoid un-mergeable events
        #     (respecting barrier_min and bufindx) as the C code.

        cpus.append(KDCPU(store, curidx))

    while True:
        earliest_time = 0xffffffffffffffff
        min_cpu = None
        for cpu in cpus:
            if not cpu.store:
                continue

            # Check for overrunning the writer, which also indicates the CPU is
            # out of events.
            if cpu.oldest_time:
                timestamp = cpu.oldest_time
            else:
                timestamp = get_kdbuf_timestamp(
                        addressof(cpu.store.kds_records[cpu.curidx]))
                cpu.oldest_time = timestamp

            if timestamp < cpu.store.kds_timestamp:
                cpu.store = None
                continue

            if timestamp < earliest_time:
                earliest_time = timestamp
                min_cpu = cpu

        # Out of events.
        if not min_cpu:
            return

        yield min_cpu.store.kds_records[min_cpu.curidx]
        min_cpu.oldest_time = None

        min_cpu.curidx += 1
        if min_cpu.curidx == xnudefines.EVENTS_PER_STORAGE_UNIT:
            next = min_cpu.store.kds_next
            if next.raw == xnudefines.KDS_PTR_NULL:
                min_cpu.store = None
                min_cpu.curidx = None
            else:
                min_cpu.store = get_kdstore(next)
                min_cpu.curidx = min_cpu.store.kds_readlast

        # This CPU is out of events.
        if min_cpu.curidx == min_cpu.store.kds_bufindx:
            min_cpu.store = None
            continue


def GetKdebugEvent(event):
    """
    Return a string representing a kdebug trace event.
    """
    return '{:16} {:8} {:8x} {:16} {:16} {:16} {:16} {:4} {:8} {}'.format(
            unsigned(event.timestamp), 0, unsigned(event.debugid),
            unsigned(event.arg1), unsigned(event.arg2),
            unsigned(event.arg3), unsigned(event.arg4), unsigned(event.cpuid),
            unsigned(event.arg5), "")


@lldb_command('showkdebugtrace')
def ShowKdebugTrace(cmd_args=None):
    """
    List the events present in the kdebug trace buffers.

    (lldb) showkdebugtrace

    Caveats:
        * Events from IOPs may be missing or cut-off -- they weren't informed
          of this kind of buffer collection.
    """
    for event in IterateKdebugEvents():
        print(GetKdebugEvent(event))


@lldb_command('savekdebugtrace', 'N:')
def SaveKdebugTrace(cmd_args=None, cmd_options={}):
    """
    Save any valid ktrace events to a file.

    (lldb) savekdebugtrace [-N <n-events>] <file-to-write>

    Caveats:
        * 32-bit kernels are unsupported.
        * The trace file will be missing machine and config chunks, which might
          prevent tools from analyzing it.
    """

    if kern.arch not in ['x86_64', 'x86_64h', 'arm64', 'arm64e']:
        print('32-bit kernels are unsupported')
        return

    if len(cmd_args) != 1:
        raise ArgumentError('path to trace file is required')

    nevents = unsigned(kern.globals.nkdbufs)
    if nevents == 0:
        print('kdebug buffers are not set up')
        return

    limit_nevents = nevents
    if '-N' in cmd_options:
        limit_nevents = unsigned(cmd_options['-N'])
        if limit_nevents > nevents:
            limit_nevents = nevents
    verbose = config['verbosity'] > vHUMAN

    file_offset = 0
    with open(cmd_args[0], 'w+b') as f:
        FILE_MAGIC = 0x55aa0300
        EVENTS_TAG = 0x00001e00
        SSHOT_TAG = 0x8002
        CHUNKHDR_PACK = 'IHHQ'
        FILEHDR_PACK = CHUNKHDR_PACK + 'IIQQIIII'
        FILEHDR_SIZE = 40
        FUTURE_SIZE = 8

        numer, denom = GetTimebaseInfo()

        # XXX The kernel doesn't have a solid concept of the wall time.
        wall_abstime = 0
        wall_secs = 0
        wall_usecs = 0

        # XXX 32-bit is NYI
        k64 = True
        event_size = unsigned(64)

        file_hdr = struct.pack(
                FILEHDR_PACK, FILE_MAGIC, 0, 0, FILEHDR_SIZE,
                numer, denom, wall_abstime, wall_secs, wall_usecs, 0, 0,
                0x1 if k64 else 0)
        f.write(file_hdr)
        file_offset += 16 + FILEHDR_SIZE # chunk header plus file header

        skip_nevents = nevents - limit_nevents if limit_nevents else 0
        if skip_nevents > 0:
            print('omitting {} events from the beginning'.format(skip_nevents))

        events_hdr = struct.pack(
                CHUNKHDR_PACK, EVENTS_TAG, 0, 0, 0) # size will be filled in later
        f.write(events_hdr)
        file_offset += 16 # header size
        event_size_offset = file_offset - FUTURE_SIZE
        # Future events timestamp -- doesn't need to be set for merged events.
        f.write(struct.pack('Q', 0))
        file_offset += FUTURE_SIZE

        if verbose:
            print('events start at offset {}'.format(file_offset))

        process = LazyTarget().GetProcess()
        error = lldb.SBError()

        written_nevents = 0
        seen_nevents = 0
        for event in IterateKdebugEvents():
            seen_nevents += 1
            if skip_nevents >= seen_nevents:
                if seen_nevents % 1000 == 0:
                    sys.stderr.write('skipped {}/{} ({:4.2f}%) events'.format(
                            seen_nevents, skip_nevents,
                            float(seen_nevents) / skip_nevents * 100.0))
                    sys.stderr.write('\r')

                continue

            event = process.ReadMemory(
                    unsigned(addressof(event)), event_size, error)
            file_offset += event_size
            f.write(event)
            written_nevents += 1
            # Periodically update the CLI with progress.
            if written_nevents % 1000 == 0:
                sys.stderr.write('wrote {}/{} ({:4.2f}%) events'.format(
                        written_nevents, limit_nevents,
                        float(written_nevents) / nevents * 100.0))
                sys.stderr.write('\r')
        sys.stderr.write('\n')
        print('wrote {} events'.format(written_nevents))
        if verbose:
            print('events end at offset {}'.format(file_offset))

        # Normally, the chunk would need to be padded to 8, but events are
        # already aligned.

        kcdata = kern.globals.kc_panic_data
        kcdata_addr = unsigned(kcdata.kcd_addr_begin)
        kcdata_length = unsigned(kcdata.kcd_length)
        if kcdata_addr != 0 and kcdata_length != 0:
            print('writing stackshot')
            f.write(struct.pack(CHUNKHDR_PACK, SSHOT_TAG, 1, 0, kcdata_length))
            file_offset += 16
            if verbose:
                print('stackshot is {} bytes long'.format(kcdata_length))
                print('stackshot starts at offset {}'.format(file_offset))
            ssdata = process.ReadMemory(kcdata_addr, kcdata_length, error)
            f.write(ssdata)
            file_offset += kcdata_length
            if verbose:
                print('stackshot ends at offset {}'.format(file_offset))
        else:
            print('stackshot is not available, trace file may not be usable!')

        # After the number of events is known, fix up the events chunk size.
        events_data_size = unsigned(written_nevents * event_size) + FUTURE_SIZE
        f.seek(event_size_offset)
        f.write(struct.pack('Q', events_data_size))

    return
