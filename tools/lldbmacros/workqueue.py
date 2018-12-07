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
    elif kqr.kqr_state & 0x1: # workloop
        kq = ContainerOf(kqr, 'struct kqworkloop', 'kqwl_request')
        kind = "workloop"
    else:
        kq = p.p_fd.fd_wqkqueue
        kind = "kqwq[%s]" % (xnudefines.thread_qos_short_strings[int(kqr.kqr_qos_index)])

    return "{th: <#020x} {uth: <#020x} {thport: >#010x}  {kind: <9s} {kq: <#020x} {idle: <10s} {uu_workq_flags: <30s}".format(th=th, uth=uth, thport=uth.uu_workq_thport, kind=kind, kq=kq, idle=idle, uu_workq_flags=" ".join(uu_workq_flags))

@header("{:<20s} {:<20s} {:<10s} {:<3s} {:<4s} {:<30s}".format(
    'request', 'kqueue', 'state', '#', 'qos', 'tr_flags'))
def GetWorkqueueThreadRequestSummary(proc, req):
    kq = 0
    tr_flags = []

    if req.tr_flags & 0x01:
        tr_flags.append("KEVENT")
        kq = proc.p_fd.fd_wqkqueue
    if req.tr_flags & 0x02:
        tr_flags.append("WORKLOOP")
        kq = ContainerOf(req, 'struct kqworkloop', 'kqwl_request.kqr_req')
    if req.tr_flags & 0x04: tr_flags.append("OVERCOMMIT")
    if req.tr_flags & 0x08: tr_flags.append("PARAMS")
    if req.tr_flags & 0x10: tr_flags.append("OUTSIDE_QOS")

    state = {0: "IDLE", 1: "NEW", 2: "QUEUED", 4: "BINDING" }[int(req.tr_state)]

    qos = int(req.tr_qos)
    if qos == 8:
        qos = "MG"
    elif qos == 7:
        qos = "SP"
    else:
        qos = xnudefines.thread_qos_short_strings[qos]

    return "{req: <#020x} {kq: <#020x} {state: <10s} {req.tr_count: <3d} {qos: <4s} {tr_flags: <30s}".format(req=req, kq=kq, state=state, qos=qos, tr_flags=" ".join(tr_flags))

@lldb_command('showwqthread')
def ShowWQThread(cmd_args=None):
    """ Shows info about a workqueue thread

        usage: showworkqthread <thread_t>
    """

    if not cmd_args:
        raise ArgumentError('missing struct proc * argument')

    th = kern.GetValueFromAddress(cmd_args[0], "struct thread *")
    if not (th.thread_tag & 0x20):
        raise ArgumentError('not a workqueue thread')

    print GetWQThreadSummary.header
    print GetWQThreadSummary(th, Cast(th.uthread, 'struct uthread *'))


@lldb_command('showprocworkqueue')
def ShowProcWorkqueue(cmd_args=None):
    """ Shows the process workqueue

        usage: showprocworkqueue <proc_t>
    """

    if not cmd_args:
        raise ArgumentError('missing struct proc * argument')

    proc = kern.GetValueFromAddress(cmd_args[0], "proc_t")
    wq = Cast(proc.p_wqptr, "struct workqueue *");
    if wq:
        print GetWorkqueueSummary.header
        print GetWorkqueueSummary(proc, wq)

        if wq.wq_reqcount:
            print "    "
            print "    " + GetWorkqueueThreadRequestSummary.header
            if wq.wq_event_manager_threadreq:
                print "    " + GetWorkqueueThreadRequestSummary(proc, wq.wq_event_manager_threadreq)
            for req in IteratePriorityQueueEntry(wq.wq_overcommit_queue, 'struct workq_threadreq_s', 'tr_entry'):
                print "    " + GetWorkqueueThreadRequestSummary(proc, req)
            for req in IteratePriorityQueueEntry(wq.wq_constrained_queue, 'struct workq_threadreq_s', 'tr_entry'):
                print "    " + GetWorkqueueThreadRequestSummary(proc, req)
            for req in IteratePriorityQueueEntry(wq.wq_special_queue, 'struct workq_threadreq_s', 'tr_entry'):
                print "    " + GetWorkqueueThreadRequestSummary(proc, req)

        print "    "
        print "    " + GetWQThreadSummary.header
        for uth in IterateTAILQ_HEAD(wq.wq_thrunlist, "uu_workq_entry"):
            print "    " + GetWQThreadSummary(Cast(uth.uu_thread, 'struct thread *'), uth)
        for uth in IterateTAILQ_HEAD(wq.wq_thidlelist, "uu_workq_entry"):
            print "    " + GetWQThreadSummary(Cast(uth.uu_thread, 'struct thread *'), uth)
        for uth in IterateTAILQ_HEAD(wq.wq_thnewlist, "uu_workq_entry"):
            print "    " + GetWQThreadSummary(Cast(uth.uu_thread, 'struct thread *'), uth)

@lldb_command('showallworkqueues')
def ShowAllWorkqueues(cmd_args=None):
    """ Display a summary of all the workqueues in the system

        usage: showallworkqueues
    """

    print GetWorkqueueSummary.header

    for t in kern.tasks:
        proc = Cast(t.bsd_info, 'proc *')
        wq = Cast(proc.p_wqptr, "struct workqueue *");
        if wq:
            print GetWorkqueueSummary(proc, wq)
