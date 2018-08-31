/*
 * Copyright (c) 2012-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
 
#define PTHREAD_INTERNAL 1

#include <stdatomic.h>
#include <kern/debug.h>
#include <kern/mach_param.h>
#include <kern/sched_prim.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/affinity.h>
#include <kern/zalloc.h>
#include <kern/policy_internal.h>

#include <machine/machine_routines.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <sys/param.h>
#include <sys/eventvar.h>
#include <sys/pthread_shims.h>
#include <sys/proc_info.h>
#include <sys/proc_internal.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <kern/kcdata.h>

/* version number of the in-kernel shims given to pthread.kext */
#define PTHREAD_SHIMS_VERSION 1

/* on arm, the callbacks function has two #ifdef arm ponters */
#if defined(__arm__)
#define PTHREAD_CALLBACK_MEMBER map_is_1gb
#else
#define PTHREAD_CALLBACK_MEMBER ml_get_max_cpus
#endif

/* compile time asserts to check the length of structures in pthread_shims.h */
static_assert((sizeof(struct pthread_functions_s) - offsetof(struct pthread_functions_s, psynch_rw_yieldwrlock) - sizeof(void*)) == (sizeof(void*) * 100));
static_assert((sizeof(struct pthread_callbacks_s) - offsetof(struct pthread_callbacks_s, PTHREAD_CALLBACK_MEMBER) - sizeof(void*)) == (sizeof(void*) * 100));

/* old pthread code had definitions for these as they don't exist in headers */
extern kern_return_t mach_port_deallocate(ipc_space_t, mach_port_name_t);
extern kern_return_t semaphore_signal_internal_trap(mach_port_name_t);

#define PTHREAD_STRUCT_ACCESSOR(get, set, rettype, structtype, member) \
	static rettype \
	get(structtype x) { \
		return (x)->member; \
	} \
	static void \
	set(structtype x, rettype y) { \
		(x)->member = y; \
	}

PTHREAD_STRUCT_ACCESSOR(proc_get_threadstart, proc_set_threadstart, user_addr_t, struct proc*, p_threadstart);
PTHREAD_STRUCT_ACCESSOR(proc_get_pthsize, proc_set_pthsize, int, struct proc*, p_pthsize);
PTHREAD_STRUCT_ACCESSOR(proc_get_wqthread, proc_set_wqthread, user_addr_t, struct proc*, p_wqthread);
PTHREAD_STRUCT_ACCESSOR(proc_get_stack_addr_hint, proc_set_stack_addr_hint, user_addr_t, struct proc *, p_stack_addr_hint);
PTHREAD_STRUCT_ACCESSOR(proc_get_dispatchqueue_offset, proc_set_dispatchqueue_offset, uint64_t, struct proc*, p_dispatchqueue_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_dispatchqueue_serialno_offset, proc_set_dispatchqueue_serialno_offset, uint64_t, struct proc*, p_dispatchqueue_serialno_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_pthread_tsd_offset, proc_set_pthread_tsd_offset, uint32_t, struct proc *, p_pth_tsd_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_mach_thread_self_tsd_offset, proc_set_mach_thread_self_tsd_offset, uint64_t, struct proc *, p_mach_thread_self_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_pthhash, proc_set_pthhash, void*, struct proc*, p_pthhash);
PTHREAD_STRUCT_ACCESSOR(proc_get_return_to_kernel_offset, proc_set_return_to_kernel_offset, uint64_t, struct proc*, p_return_to_kernel_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_user_stack, proc_set_user_stack, user_addr_t, struct proc*, user_stack);

PTHREAD_STRUCT_ACCESSOR(uthread_get_threadlist, uthread_set_threadlist, void*, struct uthread*, uu_threadlist);
PTHREAD_STRUCT_ACCESSOR(uthread_get_sigmask, uthread_set_sigmask, sigset_t, struct uthread*, uu_sigmask);
PTHREAD_STRUCT_ACCESSOR(uthread_get_returnval, uthread_set_returnval, int, struct uthread*, uu_rval[0]);

#define WQPTR_IS_INITING_VALUE ((void *)~(uintptr_t)0)

static void *
proc_get_wqptr(struct proc *p) {
	void *wqptr =  p->p_wqptr;
	return (wqptr == WQPTR_IS_INITING_VALUE) ? NULL : wqptr;
}
static void
proc_set_wqptr(struct proc *p, void *y) {
	proc_lock(p);

	assert(y == NULL || p->p_wqptr == WQPTR_IS_INITING_VALUE);

	p->p_wqptr = y;

	if (y != NULL){
		wakeup(&p->p_wqptr);
	}

	proc_unlock(p);
}
static boolean_t
proc_init_wqptr_or_wait(struct proc *p) {
	proc_lock(p);

	if (p->p_wqptr == NULL){
		p->p_wqptr = WQPTR_IS_INITING_VALUE;
		proc_unlock(p);

		return TRUE;
	} else if (p->p_wqptr == WQPTR_IS_INITING_VALUE){
		assert_wait(&p->p_wqptr, THREAD_UNINT);
		proc_unlock(p);
		thread_block(THREAD_CONTINUE_NULL);

		return FALSE;
	} else {
		proc_unlock(p);

		return FALSE;
	}
}

__attribute__((noreturn))
static void
pthread_returning_to_userspace(void)
{
	thread_exception_return();
}

__attribute__((noreturn))
static void
pthread_bootstrap_return(void)
{
	thread_bootstrap_return();
}

static uint32_t
get_task_threadmax(void) {
	return task_threadmax;
}

static task_t
proc_get_task(struct proc *p) {
	return p->task;
}

static uint64_t
proc_get_register(struct proc *p) {
	return (p->p_lflag & P_LREGISTER);
}

static void
proc_set_register(struct proc *p) {
	proc_setregister(p);
}

static void*
uthread_get_uukwe(struct uthread *t)
{
	return &t->uu_kevent.uu_kwe;
}

static int
uthread_is_cancelled(struct uthread *t)
{
	return (t->uu_flag & (UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL;
}

static vm_map_t
_current_map(void)
{
	return current_map();
}

static boolean_t
qos_main_thread_active(void)
{
	return TRUE;
}

#if defined(__arm__)
/* On iOS, the stack placement depends on the address space size */
static uint32_t
map_is_1gb(vm_map_t map)
{
	return ((!vm_map_is_64bit(map)) && (get_map_max(map) == ml_get_max_offset(FALSE, MACHINE_MAX_OFFSET_MIN)));
}
#endif

static int proc_usynch_get_requested_thread_qos(struct uthread *uth)
{
	thread_t	thread = uth ? uth->uu_thread : current_thread();
	int			requested_qos;

	requested_qos = proc_get_thread_policy(thread, TASK_POLICY_ATTRIBUTE, TASK_POLICY_QOS);

	/*
	 * For the purposes of userspace synchronization, it doesn't make sense to
	 * place an override of UNSPECIFIED on another thread, if the current thread
	 * doesn't have any QoS set. In these cases, upgrade to
	 * THREAD_QOS_USER_INTERACTIVE.
	 */
	if (requested_qos == THREAD_QOS_UNSPECIFIED) {
		requested_qos = THREAD_QOS_USER_INTERACTIVE;
	}

	return requested_qos;
}

static int
proc_usynch_thread_qos_add_override_for_resource_check_owner(thread_t thread,
		int override_qos, boolean_t first_override_for_resource,
		user_addr_t resource, int resource_type,
		user_addr_t user_lock_addr, mach_port_name_t user_lock_owner)
{
	return proc_thread_qos_add_override_check_owner(thread, override_qos,
			first_override_for_resource, resource, resource_type,
			user_lock_addr, user_lock_owner);
}

static boolean_t
proc_usynch_thread_qos_add_override_for_resource(task_t task, struct uthread *uth,
		uint64_t tid, int override_qos, boolean_t first_override_for_resource,
		user_addr_t resource, int resource_type)
{
	thread_t thread = uth ? uth->uu_thread : THREAD_NULL;

	return proc_thread_qos_add_override(task, thread, tid, override_qos,
			first_override_for_resource, resource, resource_type);
}

static boolean_t
proc_usynch_thread_qos_remove_override_for_resource(task_t task,
		struct uthread *uth, uint64_t tid, user_addr_t resource, int resource_type)
{
	thread_t thread = uth ? uth->uu_thread : THREAD_NULL;

	return proc_thread_qos_remove_override(task, thread, tid, resource, resource_type);
}

static boolean_t
proc_usynch_thread_qos_reset_override_for_resource(task_t task,
		struct uthread *uth, uint64_t tid, user_addr_t resource, int resource_type)
{
	thread_t thread = uth ? uth->uu_thread : THREAD_NULL;

	return proc_thread_qos_reset_override(task, thread, tid, resource, resource_type);
}

static boolean_t
proc_usynch_thread_qos_squash_override_for_resource(thread_t thread,
		user_addr_t resource, int resource_type)
{
	return proc_thread_qos_squash_override(thread, resource, resource_type);
}

/* kernel (core) to kext shims */

void
pthread_init(void)
{
	if (!pthread_functions) {
		panic("pthread kernel extension not loaded (function table is NULL).");
	}
	pthread_functions->pthread_init();
}

int
fill_procworkqueue(proc_t p, struct proc_workqueueinfo * pwqinfo)
{
	return pthread_functions->fill_procworkqueue(p, pwqinfo);
}

/*
 * Returns true if the workqueue flags are available, and will fill
 * in exceeded_total and exceeded_constrained.
 */
boolean_t
workqueue_get_pwq_exceeded(void *v, boolean_t *exceeded_total,
                           boolean_t *exceeded_constrained)
{
	proc_t p = v;
	struct proc_workqueueinfo pwqinfo;
	int err;

	assert(p != NULL);
	assert(exceeded_total != NULL);
	assert(exceeded_constrained != NULL);

	err = fill_procworkqueue(p, &pwqinfo);
	if (err) {
		return FALSE;
	}
	if (!(pwqinfo.pwq_state & WQ_FLAGS_AVAILABLE)) {
		return FALSE;
	}

	*exceeded_total = (pwqinfo.pwq_state & WQ_EXCEEDED_TOTAL_THREAD_LIMIT);
	*exceeded_constrained = (pwqinfo.pwq_state & WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT);

	return TRUE;
}

uint32_t
workqueue_get_pwq_state_kdp(void * v)
{
	static_assert((WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT << 17) == kTaskWqExceededConstrainedThreadLimit);
	static_assert((WQ_EXCEEDED_TOTAL_THREAD_LIMIT << 17) == kTaskWqExceededTotalThreadLimit);
	static_assert((WQ_FLAGS_AVAILABLE << 17) == kTaskWqFlagsAvailable);
	static_assert((WQ_FLAGS_AVAILABLE | WQ_EXCEEDED_TOTAL_THREAD_LIMIT | WQ_EXCEEDED_CONSTRAINED_THREAD_LIMIT) == 0x7);
	proc_t p = v;
	if (pthread_functions == NULL || pthread_functions->get_pwq_state_kdp == NULL)
		return 0;
	else
		return pthread_functions->get_pwq_state_kdp(p);
}

void
workqueue_exit(struct proc *p)
{
	pthread_functions->workqueue_exit(p);
}

void
workqueue_mark_exiting(struct proc *p)
{
	pthread_functions->workqueue_mark_exiting(p);
}

void
workqueue_thread_yielded(void)
{
	pthread_functions->workqueue_thread_yielded();
}

sched_call_t
workqueue_get_sched_callback(void)
{
	if (pthread_functions->workqueue_get_sched_callback) {
		return pthread_functions->workqueue_get_sched_callback();
	}
	return NULL;
}

void
pth_proc_hashinit(proc_t p)
{
	pthread_functions->pth_proc_hashinit(p);
}

void
pth_proc_hashdelete(proc_t p)
{
	pthread_functions->pth_proc_hashdelete(p);
}

/* syscall shims */
int
bsdthread_create(struct proc *p, struct bsdthread_create_args *uap, user_addr_t *retval)
{
	return pthread_functions->bsdthread_create(p, uap->func, uap->func_arg, uap->stack, uap->pthread, uap->flags, retval);
}

int
bsdthread_register(struct proc *p, struct bsdthread_register_args *uap, __unused int32_t *retval)
{
	if (pthread_functions->version >= 1) {
		return pthread_functions->bsdthread_register2(p, uap->threadstart, uap->wqthread,
													  uap->flags, uap->stack_addr_hint, 
													  uap->targetconc_ptr, uap->dispatchqueue_offset,
													  uap->tsd_offset, retval);		
	} else {
		return pthread_functions->bsdthread_register(p, uap->threadstart, uap->wqthread,
													 uap->flags, uap->stack_addr_hint,
													 uap->targetconc_ptr, uap->dispatchqueue_offset,
													 retval);
	}
}

int
bsdthread_terminate(struct proc *p, struct bsdthread_terminate_args *uap, int32_t *retval)
{
	return pthread_functions->bsdthread_terminate(p, uap->stackaddr, uap->freesize, uap->port, uap->sem, retval);
}

int
bsdthread_ctl(struct proc *p, struct bsdthread_ctl_args *uap, int *retval)
{
    return pthread_functions->bsdthread_ctl(p, uap->cmd, uap->arg1, uap->arg2, uap->arg3, retval);
}


int
thread_selfid(struct proc *p, __unused struct thread_selfid_args *uap, uint64_t *retval)
{
	return pthread_functions->thread_selfid(p, retval);
}

int
workq_kernreturn(struct proc *p, struct workq_kernreturn_args *uap, int32_t *retval)
{
	return pthread_functions->workq_kernreturn(p, uap->options, uap->item, uap->affinity, uap->prio, retval);
}

int
workq_open(struct proc *p, __unused struct workq_open_args  *uap, int32_t *retval)
{
	return pthread_functions->workq_open(p, retval);
}

/* pthread synchroniser syscalls */

int
psynch_mutexwait(proc_t p, struct psynch_mutexwait_args *uap, uint32_t *retval)
{
	return pthread_functions->psynch_mutexwait(p, uap->mutex, uap->mgen, uap->ugen, uap->tid, uap->flags, retval);
}

int
psynch_mutexdrop(proc_t p, struct psynch_mutexdrop_args *uap, uint32_t *retval)
{
	return pthread_functions->psynch_mutexdrop(p, uap->mutex, uap->mgen, uap->ugen, uap->tid, uap->flags, retval);
}

int
psynch_cvbroad(proc_t p, struct psynch_cvbroad_args *uap, uint32_t *retval)
{
	return pthread_functions->psynch_cvbroad(p, uap->cv, uap->cvlsgen, uap->cvudgen, uap->flags, uap->mutex, uap->mugen, uap->tid, retval);
}

int
psynch_cvsignal(proc_t p, struct psynch_cvsignal_args *uap, uint32_t *retval)
{
	return pthread_functions->psynch_cvsignal(p, uap->cv, uap->cvlsgen, uap->cvugen, uap->thread_port, uap->mutex, uap->mugen, uap->tid, uap->flags, retval);
}

int
psynch_cvwait(proc_t p, struct psynch_cvwait_args * uap, uint32_t * retval)
{
	return pthread_functions->psynch_cvwait(p, uap->cv, uap->cvlsgen, uap->cvugen, uap->mutex, uap->mugen, uap->flags, uap->sec, uap->nsec, retval);
}

int
psynch_cvclrprepost(proc_t p, struct psynch_cvclrprepost_args * uap, int *retval)
{
	return pthread_functions->psynch_cvclrprepost(p, uap->cv, uap->cvgen, uap->cvugen, uap->cvsgen, uap->prepocnt, uap->preposeq, uap->flags, retval);
}

int
psynch_rw_longrdlock(proc_t p, struct psynch_rw_longrdlock_args * uap,  uint32_t *retval)
{
	return pthread_functions->psynch_rw_longrdlock(p, uap->rwlock, uap->lgenval, uap->ugenval, uap->rw_wc, uap->flags, retval);
}

int
psynch_rw_rdlock(proc_t p, struct psynch_rw_rdlock_args * uap, uint32_t * retval)
{
	return pthread_functions->psynch_rw_rdlock(p, uap->rwlock, uap->lgenval, uap->ugenval, uap->rw_wc, uap->flags, retval);
}

int
psynch_rw_unlock(proc_t p, struct psynch_rw_unlock_args *uap, uint32_t *retval)
{
	return pthread_functions->psynch_rw_unlock(p, uap->rwlock, uap->lgenval, uap->ugenval, uap->rw_wc, uap->flags, retval);
}

int
psynch_rw_unlock2(__unused proc_t p, __unused struct psynch_rw_unlock2_args *uap, __unused uint32_t *retval)
{
	return ENOTSUP;
}

int
psynch_rw_wrlock(proc_t p, struct psynch_rw_wrlock_args *uap, uint32_t *retval)
{
	return pthread_functions->psynch_rw_wrlock(p, uap->rwlock, uap->lgenval, uap->ugenval, uap->rw_wc, uap->flags, retval);
}

int
psynch_rw_yieldwrlock(proc_t p, struct psynch_rw_yieldwrlock_args *uap, uint32_t *retval)
{
	return pthread_functions->psynch_rw_yieldwrlock(p, uap->rwlock, uap->lgenval, uap->ugenval, uap->rw_wc, uap->flags, retval);
}

int
psynch_rw_upgrade(__unused proc_t p, __unused struct psynch_rw_upgrade_args * uap, __unused uint32_t *retval)
{
	return 0;
}

int
psynch_rw_downgrade(__unused proc_t p, __unused struct psynch_rw_downgrade_args * uap, __unused int *retval)
{
	return 0;
}

int
thread_qos_from_pthread_priority(unsigned long priority, unsigned long *flags)
{
	return pthread_functions->thread_qos_from_pthread_priority(priority, flags);
}

unsigned long
pthread_priority_canonicalize(unsigned long priority, boolean_t propagation)
{
	return pthread_functions->pthread_priority_canonicalize2(priority, propagation);
}

boolean_t
workq_thread_has_been_unbound(thread_t th, int qos_class)
{
	if (pthread_functions->workq_thread_has_been_unbound) {
		return pthread_functions->workq_thread_has_been_unbound(th, qos_class);
	} else {
		panic("pthread kext does not support workq_thread_has_been_unbound");
		return false;
	}
}

void
kdp_pthread_find_owner(thread_t thread, struct stackshot_thread_waitinfo *waitinfo)
{
	if (pthread_functions->pthread_find_owner)
		pthread_functions->pthread_find_owner(thread, waitinfo);
}

void *
kdp_pthread_get_thread_kwq(thread_t thread)
{
	if (pthread_functions->pthread_get_thread_kwq)
		return pthread_functions->pthread_get_thread_kwq(thread);

	return NULL;
}

static void
thread_will_park_or_terminate(thread_t thread)
{
	if (thread_owned_workloops_count(thread)) {
		(void)kevent_exit_on_workloop_ownership_leak(thread);
	}
}

#if defined(__arm64__)
static unsigned __int128
atomic_fetch_add_128_relaxed(_Atomic unsigned __int128 *ptr, unsigned __int128 value)
{
	return atomic_fetch_add_explicit(ptr, value, memory_order_relaxed);
}

static unsigned __int128
atomic_load_128_relaxed(_Atomic unsigned __int128 *ptr)
{
	return atomic_load_explicit(ptr, memory_order_relaxed);
}
#endif

/*
 * The callbacks structure (defined in pthread_shims.h) contains a collection
 * of kernel functions that were not deemed sensible to expose as a KPI to all
 * kernel extensions. So the kext is given them in the form of a structure of
 * function pointers.
 */
static const struct pthread_callbacks_s pthread_callbacks = {
	.version = PTHREAD_SHIMS_VERSION,
	.config_thread_max = CONFIG_THREAD_MAX,
	.get_task_threadmax = get_task_threadmax,

	.proc_get_threadstart = proc_get_threadstart,
	.proc_set_threadstart = proc_set_threadstart,
	.proc_get_pthsize = proc_get_pthsize,
	.proc_set_pthsize = proc_set_pthsize,
	.proc_get_wqthread = proc_get_wqthread,
	.proc_set_wqthread = proc_set_wqthread,
	.proc_get_dispatchqueue_offset = proc_get_dispatchqueue_offset,
	.proc_set_dispatchqueue_offset = proc_set_dispatchqueue_offset,
	.proc_get_wqptr = proc_get_wqptr,
	.proc_set_wqptr = proc_set_wqptr,
	.proc_get_pthhash = proc_get_pthhash,
	.proc_set_pthhash = proc_set_pthhash,
	.proc_get_task = proc_get_task,
	.proc_lock = proc_lock,
	.proc_unlock = proc_unlock,
	.proc_get_register = proc_get_register,
	.proc_set_register = proc_set_register,

	/* kernel IPI interfaces */
	.ipc_port_copyout_send = ipc_port_copyout_send,
	.task_get_ipcspace = get_task_ipcspace,
	.vm_map_page_info = vm_map_page_info,
	.vm_map_switch = vm_map_switch,
	.thread_set_wq_state32 = thread_set_wq_state32,
#if !defined(__arm__)
	.thread_set_wq_state64 = thread_set_wq_state64,
#endif

	.uthread_get_threadlist = uthread_get_threadlist,
	.uthread_set_threadlist = uthread_set_threadlist,
	.uthread_get_sigmask = uthread_get_sigmask,
	.uthread_set_sigmask = uthread_set_sigmask,
	.uthread_get_uukwe = uthread_get_uukwe,
	.uthread_get_returnval = uthread_get_returnval,
	.uthread_set_returnval = uthread_set_returnval,
	.uthread_is_cancelled = uthread_is_cancelled,

	.thread_exception_return = pthread_returning_to_userspace,
	.thread_bootstrap_return = pthread_bootstrap_return,
	.unix_syscall_return = unix_syscall_return,

	.absolutetime_to_microtime = absolutetime_to_microtime,

	.thread_set_workq_pri = thread_set_workq_pri,
	.thread_set_workq_qos = thread_set_workq_qos,

	.get_bsdthread_info = (void*)get_bsdthread_info,
	.thread_sched_call = thread_sched_call,
	.thread_static_param = thread_static_param,
	.thread_create_workq = thread_create_workq,
	.thread_policy_set_internal = thread_policy_set_internal,
	.thread_policy_get = thread_policy_get,
	.thread_set_voucher_name = thread_set_voucher_name,

	.thread_affinity_set = thread_affinity_set,

	.zalloc = zalloc,
	.zfree = zfree,
	.zinit = zinit,

	.workloop_fulfill_threadreq = workloop_fulfill_threadreq,

	.__pthread_testcancel = __pthread_testcancel,

	.mach_port_deallocate = mach_port_deallocate,
	.semaphore_signal_internal_trap = semaphore_signal_internal_trap,
	.current_map = _current_map,
	.thread_create = thread_create,
	.thread_resume = thread_resume,

	.convert_thread_to_port = convert_thread_to_port,
	.ml_get_max_cpus = (void*)ml_get_max_cpus,

#if defined(__arm__)
	.map_is_1gb = map_is_1gb,
#endif
#if defined(__arm64__)
	.atomic_fetch_add_128_relaxed = atomic_fetch_add_128_relaxed,
	.atomic_load_128_relaxed = atomic_load_128_relaxed,
#endif

	.proc_get_dispatchqueue_serialno_offset = proc_get_dispatchqueue_serialno_offset,
	.proc_set_dispatchqueue_serialno_offset = proc_set_dispatchqueue_serialno_offset,

	.proc_get_stack_addr_hint = proc_get_stack_addr_hint,
	.proc_set_stack_addr_hint = proc_set_stack_addr_hint,
	.proc_get_pthread_tsd_offset = proc_get_pthread_tsd_offset,
	.proc_set_pthread_tsd_offset = proc_set_pthread_tsd_offset,
	.proc_get_mach_thread_self_tsd_offset = proc_get_mach_thread_self_tsd_offset,
	.proc_set_mach_thread_self_tsd_offset = proc_set_mach_thread_self_tsd_offset,

	.thread_set_tsd_base = thread_set_tsd_base,

	.proc_usynch_get_requested_thread_qos = proc_usynch_get_requested_thread_qos,

	.qos_main_thread_active = qos_main_thread_active,

	.proc_usynch_thread_qos_add_override_for_resource_check_owner = proc_usynch_thread_qos_add_override_for_resource_check_owner,
	.proc_usynch_thread_qos_add_override_for_resource = proc_usynch_thread_qos_add_override_for_resource,
	.proc_usynch_thread_qos_remove_override_for_resource = proc_usynch_thread_qos_remove_override_for_resource,
	.proc_usynch_thread_qos_reset_override_for_resource = proc_usynch_thread_qos_reset_override_for_resource,

	.proc_init_wqptr_or_wait = proc_init_wqptr_or_wait,

	.thread_set_tag = thread_set_tag,
	.thread_get_tag = thread_get_tag,

	.proc_usynch_thread_qos_squash_override_for_resource = proc_usynch_thread_qos_squash_override_for_resource,
	.task_get_default_manager_qos = task_get_default_manager_qos,
	.thread_create_workq_waiting = thread_create_workq_waiting,

	.proc_get_return_to_kernel_offset = proc_get_return_to_kernel_offset,
	.proc_set_return_to_kernel_offset = proc_set_return_to_kernel_offset,
	.thread_will_park_or_terminate = thread_will_park_or_terminate,

	.qos_max_parallelism = qos_max_parallelism,

	.proc_get_user_stack = proc_get_user_stack,
	.proc_set_user_stack = proc_set_user_stack,
};

pthread_callbacks_t pthread_kern = &pthread_callbacks;
pthread_functions_t pthread_functions = NULL;

/*
 * pthread_kext_register is called by pthread.kext upon load, it has to provide
 * us with a function pointer table of pthread internal calls. In return, this
 * file provides it with a table of function pointers it needs.
 */

void
pthread_kext_register(pthread_functions_t fns, pthread_callbacks_t *callbacks)
{
	if (pthread_functions != NULL) {
		panic("Re-initialisation of pthread kext callbacks.");
	}

	if (callbacks != NULL) {
		*callbacks = &pthread_callbacks;
	} else {
		panic("pthread_kext_register called without callbacks pointer.");
	}

	if (fns) {
		pthread_functions = fns;
	}
}
