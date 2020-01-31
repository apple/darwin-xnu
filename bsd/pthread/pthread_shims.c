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
#include <pthread/workqueue_internal.h>
#include <sys/cdefs.h>
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
#define PTHREAD_CALLBACK_MEMBER __unused_was_map_is_1gb
#else
#define PTHREAD_CALLBACK_MEMBER __unused_was_ml_get_max_cpus
#endif

/* compile time asserts to check the length of structures in pthread_shims.h */
static_assert((sizeof(struct pthread_functions_s) - offsetof(struct pthread_functions_s, psynch_rw_yieldwrlock) - sizeof(void*)) == (sizeof(void*) * 100));
static_assert((sizeof(struct pthread_callbacks_s) - offsetof(struct pthread_callbacks_s, PTHREAD_CALLBACK_MEMBER) - sizeof(void*)) == (sizeof(void*) * 100));

/* old pthread code had definitions for these as they don't exist in headers */
extern kern_return_t mach_port_deallocate(ipc_space_t, mach_port_name_t);
extern kern_return_t semaphore_signal_internal_trap(mach_port_name_t);
extern void thread_deallocate_safe(thread_t thread);

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
PTHREAD_STRUCT_ACCESSOR(proc_get_pthread_tsd_offset, proc_set_pthread_tsd_offset, uint32_t, struct proc *, p_pth_tsd_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_mach_thread_self_tsd_offset, proc_set_mach_thread_self_tsd_offset, uint64_t, struct proc *, p_mach_thread_self_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_pthhash, proc_set_pthhash, void*, struct proc*, p_pthhash);

#define WQPTR_IS_INITING_VALUE ((void *)~(uintptr_t)0)

static void
proc_set_dispatchqueue_offset(struct proc *p, uint64_t offset)
{
	p->p_dispatchqueue_offset = offset;
}

static void
proc_set_return_to_kernel_offset(struct proc *p, uint64_t offset)
{
	p->p_return_to_kernel_offset = offset;
}

static user_addr_t
proc_get_user_stack(struct proc *p)
{
	return p->user_stack;
}

static void
uthread_set_returnval(struct uthread *uth, int retval)
{
	uth->uu_rval[0] = retval;
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
get_task_threadmax(void)
{
	return task_threadmax;
}

static uint64_t
proc_get_register(struct proc *p)
{
	return p->p_lflag & P_LREGISTER;
}

static void
proc_set_register(struct proc *p)
{
	proc_setregister(p);
}

static void*
uthread_get_uukwe(struct uthread *t)
{
	return &t->uu_save.uus_kwe;
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

static int
proc_usynch_get_requested_thread_qos(struct uthread *uth)
{
	thread_t        thread = uth ? uth->uu_thread : current_thread();
	int                     requested_qos;

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

static boolean_t
proc_usynch_thread_qos_add_override_for_resource(task_t task, struct uthread *uth,
    uint64_t tid, int override_qos, boolean_t first_override_for_resource,
    user_addr_t resource, int resource_type)
{
	thread_t thread = uth ? uth->uu_thread : THREAD_NULL;

	return proc_thread_qos_add_override(task, thread, tid, override_qos,
	           first_override_for_resource, resource, resource_type) == 0;
}

static boolean_t
proc_usynch_thread_qos_remove_override_for_resource(task_t task,
    struct uthread *uth, uint64_t tid, user_addr_t resource, int resource_type)
{
	thread_t thread = uth ? uth->uu_thread : THREAD_NULL;

	return proc_thread_qos_remove_override(task, thread, tid, resource,
	           resource_type) == 0;
}


static wait_result_t
psynch_wait_prepare(uintptr_t kwq, struct turnstile **tstore,
    thread_t owner, block_hint_t block_hint, uint64_t deadline)
{
	struct turnstile *ts;
	wait_result_t wr;

	if (tstore) {
		ts = turnstile_prepare(kwq, tstore, TURNSTILE_NULL,
		    TURNSTILE_PTHREAD_MUTEX);

		turnstile_update_inheritor(ts, owner,
		    (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

		thread_set_pending_block_hint(current_thread(), block_hint);

		wr = waitq_assert_wait64_leeway(&ts->ts_waitq, (event64_t)kwq,
		    THREAD_ABORTSAFE, TIMEOUT_URGENCY_USER_NORMAL, deadline, 0);
	} else {
		thread_set_pending_block_hint(current_thread(), block_hint);

		wr = assert_wait_deadline_with_leeway((event_t)kwq, THREAD_ABORTSAFE,
		    TIMEOUT_URGENCY_USER_NORMAL, deadline, 0);
	}

	return wr;
}

static void
psynch_wait_update_complete(struct turnstile *ts)
{
	assert(ts);
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);
}

static void
psynch_wait_complete(uintptr_t kwq, struct turnstile **tstore)
{
	assert(tstore);
	turnstile_complete(kwq, tstore, NULL);
}

static void
psynch_wait_update_owner(uintptr_t kwq, thread_t owner,
    struct turnstile **tstore)
{
	struct turnstile *ts;

	ts = turnstile_prepare(kwq, tstore, TURNSTILE_NULL,
	    TURNSTILE_PTHREAD_MUTEX);

	turnstile_update_inheritor(ts, owner,
	    (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));
	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete(kwq, tstore, NULL);
}

static void
psynch_wait_cleanup(void)
{
	turnstile_cleanup();
}

static kern_return_t
psynch_wait_wakeup(uintptr_t kwq, struct ksyn_waitq_element *kwe,
    struct turnstile **tstore)
{
	struct uthread *uth;
	struct turnstile *ts;
	kern_return_t kr;

	uth = __container_of(kwe, struct uthread, uu_save.uus_kwe);
	assert(uth);

	if (tstore) {
		ts = turnstile_prepare(kwq, tstore, TURNSTILE_NULL,
		    TURNSTILE_PTHREAD_MUTEX);
		turnstile_update_inheritor(ts, uth->uu_thread,
		    (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));

		kr = waitq_wakeup64_thread(&ts->ts_waitq, (event64_t)kwq,
		    uth->uu_thread, THREAD_AWAKENED);

		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
		turnstile_complete(kwq, tstore, NULL);
	} else {
		kr = thread_wakeup_thread((event_t)kwq, uth->uu_thread);
	}

	return kr;
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
	kern_return_t kr;
	static_assert(offsetof(struct bsdthread_register_args, threadstart) + sizeof(user_addr_t) ==
	    offsetof(struct bsdthread_register_args, wqthread));
	kr = machine_thread_function_pointers_convert_from_user(current_thread(), &uap->threadstart, 2);
	assert(kr == KERN_SUCCESS);

	if (pthread_functions->version >= 1) {
		return pthread_functions->bsdthread_register2(p, uap->threadstart,
		           uap->wqthread, uap->flags, uap->stack_addr_hint,
		           uap->targetconc_ptr, uap->dispatchqueue_offset,
		           uap->tsd_offset, retval);
	} else {
		return pthread_functions->bsdthread_register(p, uap->threadstart,
		           uap->wqthread, uap->flags, uap->stack_addr_hint,
		           uap->targetconc_ptr, uap->dispatchqueue_offset,
		           retval);
	}
}

int
bsdthread_terminate(struct proc *p, struct bsdthread_terminate_args *uap, int32_t *retval)
{
	thread_t th = current_thread();
	if (thread_get_tag(th) & THREAD_TAG_WORKQUEUE) {
		workq_thread_terminate(p, get_bsdthread_info(th));
	}
	return pthread_functions->bsdthread_terminate(p, uap->stackaddr, uap->freesize, uap->port, uap->sem, retval);
}

int
thread_selfid(struct proc *p, __unused struct thread_selfid_args *uap, uint64_t *retval)
{
	return pthread_functions->thread_selfid(p, retval);
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
psynch_rw_longrdlock(proc_t p, struct psynch_rw_longrdlock_args * uap, uint32_t *retval)
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

void
kdp_pthread_find_owner(thread_t thread, struct stackshot_thread_waitinfo *waitinfo)
{
	if (pthread_functions->pthread_find_owner) {
		pthread_functions->pthread_find_owner(thread, waitinfo);
	}
}

void *
kdp_pthread_get_thread_kwq(thread_t thread)
{
	if (pthread_functions->pthread_get_thread_kwq) {
		return pthread_functions->pthread_get_thread_kwq(thread);
	}

	return NULL;
}

void
thread_will_park_or_terminate(thread_t thread)
{
	if (thread_owned_workloops_count(thread)) {
		(void)kevent_exit_on_workloop_ownership_leak(thread);
	}
}

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
	.proc_set_dispatchqueue_offset = proc_set_dispatchqueue_offset,
	.proc_get_pthhash = proc_get_pthhash,
	.proc_set_pthhash = proc_set_pthhash,
	.proc_get_register = proc_get_register,
	.proc_set_register = proc_set_register,

	/* kernel IPI interfaces */
	.ipc_port_copyout_send = ipc_port_copyout_send,
	.task_get_ipcspace = get_task_ipcspace,
	.vm_map_page_info = vm_map_page_info,
	.thread_set_wq_state32 = thread_set_wq_state32,
#if !defined(__arm__)
	.thread_set_wq_state64 = thread_set_wq_state64,
#endif

	.uthread_get_uukwe = uthread_get_uukwe,
	.uthread_set_returnval = uthread_set_returnval,
	.uthread_is_cancelled = uthread_is_cancelled,

	.thread_exception_return = pthread_returning_to_userspace,
	.thread_bootstrap_return = pthread_bootstrap_return,
	.unix_syscall_return = unix_syscall_return,

	.get_bsdthread_info = (void*)get_bsdthread_info,
	.thread_policy_set_internal = thread_policy_set_internal,
	.thread_policy_get = thread_policy_get,

	.__pthread_testcancel = __pthread_testcancel,

	.mach_port_deallocate = mach_port_deallocate,
	.semaphore_signal_internal_trap = semaphore_signal_internal_trap,
	.current_map = _current_map,
	.thread_create = thread_create,
	.thread_resume = thread_resume,

	.convert_thread_to_port = convert_thread_to_port,

	.proc_get_stack_addr_hint = proc_get_stack_addr_hint,
	.proc_set_stack_addr_hint = proc_set_stack_addr_hint,
	.proc_get_pthread_tsd_offset = proc_get_pthread_tsd_offset,
	.proc_set_pthread_tsd_offset = proc_set_pthread_tsd_offset,
	.proc_get_mach_thread_self_tsd_offset = proc_get_mach_thread_self_tsd_offset,
	.proc_set_mach_thread_self_tsd_offset = proc_set_mach_thread_self_tsd_offset,

	.thread_set_tsd_base = thread_set_tsd_base,

	.proc_usynch_get_requested_thread_qos = proc_usynch_get_requested_thread_qos,

	.qos_main_thread_active = qos_main_thread_active,
	.thread_set_voucher_name = thread_set_voucher_name,

	.proc_usynch_thread_qos_add_override_for_resource = proc_usynch_thread_qos_add_override_for_resource,
	.proc_usynch_thread_qos_remove_override_for_resource = proc_usynch_thread_qos_remove_override_for_resource,

	.thread_set_tag = thread_set_tag,
	.thread_get_tag = thread_get_tag,

	.proc_set_return_to_kernel_offset = proc_set_return_to_kernel_offset,
	.thread_will_park_or_terminate = thread_will_park_or_terminate,

	.proc_get_user_stack = proc_get_user_stack,
	.task_findtid = task_findtid,
	.thread_deallocate_safe = thread_deallocate_safe,

	.psynch_wait_prepare = psynch_wait_prepare,
	.psynch_wait_update_complete = psynch_wait_update_complete,
	.psynch_wait_complete = psynch_wait_complete,
	.psynch_wait_cleanup = psynch_wait_cleanup,
	.psynch_wait_wakeup = psynch_wait_wakeup,
	.psynch_wait_update_owner = psynch_wait_update_owner,
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
