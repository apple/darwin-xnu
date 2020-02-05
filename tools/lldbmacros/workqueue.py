from xnu import *
from scheduler import GetRecentTimestamp
import xnudefines

def GetProcWorkqueue(proc):
    wq = proc.p_wqptr;
    if unsigned(wq):
        return Cast(wq, "struct workqueue *");
    return None

@header("{:<20s} {:<20s} {:<20s} {:<10s} {:<10s} {:<10s} {:<10s} {:<10s} {:<10s} {:<30s}".format(
    'task', 'proc', 'wq', 'sched', 'pending', 'idle', 'dying', 'creations', 'fulfilled', 'wq_flags'))
def GetWorkqueueSummary(proc, wq):
    wq_flags = []
    if wq.wq_flags & GetEnumValue("workq_state_flags_t::WQ_EXITING"):
        wq_flags.append("EXITING")
    if wq.wq_flags & GetEnumValue("workq_state_flags_t::WQ_PROC_SUSPENDED"):
        wq_flags.append("PROC_SUSPENDED")
    if wq.wq_flags & GetEnumValue("workq_state_flags_t::WQ_DEATH_CALL_SCHEDULED"):
        wq_flags.append("DEATH_CALL")

    scheduled = GetEnumValue("workq_state_flags_t::WQ_DELAYED_CALL_SCHEDULED")
    pended = GetEnumValue("workq_state_flags_t::WQ_DELAYED_CALL_PENDED")
    if wq.wq_flags & (scheduled | pended):
        s = "DELAYED_CALL["
        if wq.wq_flags & scheduled: s += 'S'
        if wq.wq_flags & pended: s += 'P'
        s += ']'
        wq_flags.append(s)

    scheduled = GetEnumValue("workq_state_flags_t::WQ_IMMEDIATE_CALL_SCHEDULED")
    pended = GetEnumValue("workq_state_flags_t::WQ_IMMEDIATE_CALL_PENDED")
    if wq.wq_flags & (scheduled | pended):
        s = "IMMEDIATE_CALL["
        if wq.wq_flags & scheduled: s += 'S'
        if wq.wq_flags & pended: s += 'P'
        s += ']'
        wq_flags.append(s)

    return "{p.task: <#020x} {p: <#020x} {wq: <#020x} {wq.wq_threads_scheduled: <10d} {wq.wq_reqcount: <10d} {wq.wq_thidlecount: <10d} {wq.wq_thdying_count: <10d} {wq.wq_creations: <10d} {wq.wq_fulfilled: <10d} {wq_flags: <30s}".format(p=proc, wq=wq, wq_flags=" ".join(wq_flags));

@header("{:<20s} {:<20s} {:>10s}  {:9s} {:<20s} {:<10s} {:<30s}".format(
    'thread', 'uthread', 'thport', 'kind', 'kqueue', 'idle (ms)', 'uu_workq_flags'))
def GetWQThreadSummary(th, uth):
    p = Cast(th.task.bsd_info, 'proc *')
    wq = p.p_wqptr

    uu_workq_flags = []
    if uth.uu_workq_flags & 0x01: uu_workq_flags.append("NEW")
    if uth.uu_workq_flags & 0x02:
        uu_workq_flags.append("RUNNING")
        if wq.wq_creator == uth:
            kind = "creator"
        else:
            kind = "workq"
        idle = ""
    else:
        ts = kern.GetNanotimeFromAbstime(GetRecentTimestamp() - uth.uu_save.uus_workq_park_data.idle_stamp) / 1e9
        kind = "idle"
        idle = "%#.03f" % (ts)
    if uth.uu_workq_flags & 0x04: uu_workq_flags.append("DYING")
    if uth.uu_workq_flags & 0x08: uu_workq_flags.append("OVERCOMMIT")
    if uth.uu_workq_flags & 0x10: uu_workq_flags.append("OUTSIDE_QOS")
    if uth.uu_workq_flags & 0x20: uu_workq_flags.append("IDLE_CLEANUP")
    if uth.uu_workq_flags & 0x40: uu_workq_flags.append("EARLY_BOUND")
    if uth.uu_workq_flags & 0x80: uu_workq_flags.append("CPU%")

    kqr = uth.uu_kqr_bound
    if not kqr:
        kq = 0
    elif kqr.tr_flags & 0x1: # kevent
        kq = p.p_fd.fd_wqkqueue
        kind = "kqwq[%s]" % (xnudefines.thread_qos_short_strings[int(kqr.tr_kq_qos_index)])
    elif kqr.tr_flags & 0x2: # workloop
        kq = ContainerOf(kqr, 'struct kqworkloop', 'kqwl_request')
        kind = "workloop"
    else:
        kq = 0
        kind = "???"

    return "{th: <#020x} {uth: <#020x} {thport: >#010x}  {kind: <9s} {kq: <#020x} {idle: <10s} {uu_workq_flags: <30s}".format(th=th, uth=uth, thport=uth.uu_workq_thport, kind=kind, kq=kq, idle=idle, uu_workq_flags=" ".join(uu_workq_flags))

@header("{:<20s} {:<20s} {:<20s} {:<10s} {:<4s} {:<6s} {:<6s} {:<6s} {:<30s}".format(
    'request', 'kqueue', 'thread', 'state', '#', 'qos', 'kq_qos', 'kq_ovr', 'tr_flags'))
def GetWorkqueueThreadRequestSummary(proc, req):
    kq = 0
    tr_flags = []

    if req.tr_flags & 0x01:
        tr_flags.append("KEVENT")
        kq = proc.p_fd.fd_wqkqueue
    if req.tr_flags & 0x02:
        tr_flags.append("WORKLOOP")
        kq = ContainerOf(req, 'struct kqworkloop', 'kqwl_request')
    if req.tr_flags & 0x04: tr_flags.append("OVERCOMMIT")
    if req.tr_flags & 0x08: tr_flags.append("PARAMS")
    if req.tr_flags & 0x10: tr_flags.append("OUTSIDE_QOS")

    state = {0: "IDLE", 1: "NEW", 2: "QUEUED", 3: "CANCELED", 4: "BINDING", 5: "BOUND" }[int(req.tr_state)]
    if req.tr_kq_wakeup: state += "*"

    thread = 0
    if int(req.tr_state) in [3, 4]:
        thread = req.tr_thread

    qos = int(req.tr_qos)
    if qos == 8:
        qos = "MG"
    elif qos == 7:
        qos = "SP"
    else:
        qos = xnudefines.thread_qos_short_strings[qos]

    kq_qos = xnudefines.thread_qos_short_strings[int(req.tr_kq_qos_index)]
    kq_ovr = xnudefines.thread_qos_short_strings[int(req.tr_kq_override_index)]
    req_addr = unsigned(addressof(req))

    return "{req_addr: <#020x} {kq: <#020x} {thread: <#020x} {state: <10s} {req.tr_count: <4d} {qos: <6s} {kq_qos: <6s} {kq_ovr: <6s} {tr_flags: <30s}".format(
            req_addr=req_addr, req=req, kq=kq, thread=thread, state=state, qos=qos, kq_qos=kq_qos, kq_ovr=kq_ovr, tr_flags=" ".join(tr_flags))

@lldb_command('showwqthread', fancy=True)
def ShowWQThread(cmd_args=None, cmd_options={}, O=None):
    """ Shows info about a workqueue thread

        usage: showworkqthread <thread_t>
    """

    if not cmd_args:
        return O.error('missing struct proc * argument')

    th = kern.GetValueFromAddress(cmd_args[0], "struct thread *")
    if not (th.thread_tag & 0x20):
        raise ArgumentError('not a workqueue thread')

    with O.table(GetWQThreadSummary.header):
        print GetWQThreadSummary(th, Cast(th.uthread, 'struct uthread *'))


@lldb_command('showprocworkqueue', fancy=True)
def ShowProcWorkqueue(cmd_args=None, cmd_options={}, O=None):
    """ Shows the process workqueue

        usage: showprocworkqueue <proc_t>
    """

    if not cmd_args:
        return O.error('missing struct proc * argument')

    proc = kern.GetValueFromAddress(cmd_args[0], "proc_t")
    wq = Cast(proc.p_wqptr, "struct workqueue *");
    if not wq:
        return O.error("{:#x} doesn't have a workqueue", proc)

    with O.table(GetWorkqueueSummary.header):
        print GetWorkqueueSummary(proc, wq)

        with O.table(GetWorkqueueThreadRequestSummary.header, indent=True):
            if wq.wq_reqcount:
                print ""
            if wq.wq_event_manager_threadreq:
                print GetWorkqueueThreadRequestSummary(proc, wq.wq_event_manager_threadreq)
            for req in IteratePriorityQueue(wq.wq_overcommit_queue, 'struct workq_threadreq_s', 'tr_entry'):
                print GetWorkqueueThreadRequestSummary(proc, req)
            for req in IteratePriorityQueue(wq.wq_constrained_queue, 'struct workq_threadreq_s', 'tr_entry'):
                print GetWorkqueueThreadRequestSummary(proc, req)
            for req in IteratePriorityQueue(wq.wq_special_queue, 'struct workq_threadreq_s', 'tr_entry'):
                print GetWorkqueueThreadRequestSummary(proc, req)

        with O.table(GetWQThreadSummary.header, indent=True):
            print ""
            for uth in IterateTAILQ_HEAD(wq.wq_thrunlist, "uu_workq_entry"):
                print GetWQThreadSummary(Cast(uth.uu_thread, 'struct thread *'), uth)
            for uth in IterateTAILQ_HEAD(wq.wq_thidlelist, "uu_workq_entry"):
                print GetWQThreadSummary(Cast(uth.uu_thread, 'struct thread *'), uth)
            for uth in IterateTAILQ_HEAD(wq.wq_thnewlist, "uu_workq_entry"):
                print GetWQThreadSummary(Cast(uth.uu_thread, 'struct thread *'), uth)

@lldb_command('showallworkqueues', fancy=True)
def ShowAllWorkqueues(cmd_args=None, cmd_options={}, O=None):
    """ Display a summary of all the workqueues in the system

        usage: showallworkqueues
    """

    with O.table(GetWorkqueueSummary.header):
        for t in kern.tasks:
            proc = Cast(t.bsd_info, 'proc *')
            wq = Cast(proc.p_wqptr, "struct workqueue *");
            if wq:
                print GetWorkqueueSummary(proc, wq)
