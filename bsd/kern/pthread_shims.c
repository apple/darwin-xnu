/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#include <kern/debug.h>
#include <kern/mach_param.h>
#include <kern/sched_prim.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/affinity.h>
#include <kern/zalloc.h>
#include <machine/machine_routines.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <sys/param.h>
#include <sys/pthread_shims.h>
#include <sys/proc_internal.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <vm/vm_map.h>
#include <vm/vm_protos.h>

/* version number of the in-kernel shims given to pthread.kext */
#define PTHREAD_SHIMS_VERSION 1

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
PTHREAD_STRUCT_ACCESSOR(proc_get_targconc, proc_set_targconc, user_addr_t, struct proc*, p_targconc);
PTHREAD_STRUCT_ACCESSOR(proc_get_dispatchqueue_offset, proc_set_dispatchqueue_offset, uint64_t, struct proc*, p_dispatchqueue_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_dispatchqueue_serialno_offset, proc_set_dispatchqueue_serialno_offset, uint64_t, struct proc*, p_dispatchqueue_serialno_offset);
PTHREAD_STRUCT_ACCESSOR(proc_get_wqptr, proc_set_wqptr, void*, struct proc*, p_wqptr);
PTHREAD_STRUCT_ACCESSOR(proc_get_wqsize, proc_set_wqsize, int, struct proc*, p_wqsize);
PTHREAD_STRUCT_ACCESSOR(proc_get_pthhash, proc_set_pthhash, void*, struct proc*, p_pthhash);

PTHREAD_STRUCT_ACCESSOR(uthread_get_threadlist, uthread_set_threadlist, void*, struct uthread*, uu_threadlist);
PTHREAD_STRUCT_ACCESSOR(uthread_get_sigmask, uthread_set_sigmask, sigset_t, struct uthread*, uu_sigmask);
PTHREAD_STRUCT_ACCESSOR(uthread_get_returnval, uthread_set_returnval, int, struct uthread*, uu_rval[0]);

static void
pthread_returning_to_userspace(void)
{
	thread_exception_return();
}

static uint32_t
get_task_threadmax(void) {
	return task_threadmax;
}

static task_t
proc_get_task(struct proc *p) {
	return p->task;
}

static lck_spin_t*
proc_get_wqlockptr(struct proc *p) {
	return &(p->p_wqlock);
}

static boolean_t*
proc_get_wqinitingptr(struct proc *p) {
	return &(p->p_wqiniting);
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

void
workqueue_init_lock(proc_t p)
{
	pthread_functions->workqueue_init_lock(p);
}

void
workqueue_destroy_lock(proc_t p)
{
	pthread_functions->workqueue_destroy_lock(p);
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
	return pthread_functions->bsdthread_register(p, uap->threadstart, uap->wqthread, uap->pthsize, uap->dummy_value, 
			uap->targetconc_ptr, uap->dispatchqueue_offset, retval);
}

int
bsdthread_terminate(struct proc *p, struct bsdthread_terminate_args *uap, int32_t *retval)
{
	return pthread_functions->bsdthread_terminate(p, uap->stackaddr, uap->freesize, uap->port, uap->sem, retval);
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

/* unimplemented guard */

// static void
// unhooked_panic(void)
// {
// 	panic("pthread system call not hooked up");
// }
 
/*
 * The callbacks structure (defined in pthread_shims.h) contains a collection
 * of kernel functions that were not deemed sensible to expose as a KPI to all
 * kernel extensions. So the kext is given them in the form of a structure of
 * function pointers.
 */
static struct pthread_callbacks_s pthread_callbacks = {
	.version = PTHREAD_SHIMS_VERSION,
	.config_thread_max = CONFIG_THREAD_MAX,
	.get_task_threadmax = get_task_threadmax,

	.proc_get_threadstart = proc_get_threadstart,
	.proc_set_threadstart = proc_set_threadstart,
	.proc_get_pthsize = proc_get_pthsize,
	.proc_set_pthsize = proc_set_pthsize,
	.proc_get_wqthread = proc_get_wqthread,
	.proc_set_wqthread = proc_set_wqthread,
	.proc_get_targconc = proc_get_targconc,
	.proc_set_targconc = proc_set_targconc,
	.proc_get_dispatchqueue_offset = proc_get_dispatchqueue_offset,
	.proc_set_dispatchqueue_offset = proc_set_dispatchqueue_offset,
	.proc_get_wqptr = proc_get_wqptr,
	.proc_set_wqptr = proc_set_wqptr,
	.proc_get_wqsize = proc_get_wqsize,
	.proc_set_wqsize = proc_set_wqsize,
	.proc_get_wqlockptr = proc_get_wqlockptr,
	.proc_get_wqinitingptr = proc_get_wqinitingptr,
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
	.thread_set_wq_state64 = thread_set_wq_state64,

	.uthread_get_threadlist = uthread_get_threadlist,
	.uthread_set_threadlist = uthread_set_threadlist,
	.uthread_get_sigmask = uthread_get_sigmask,
	.uthread_set_sigmask = uthread_set_sigmask,
	.uthread_get_uukwe = uthread_get_uukwe,
	.uthread_get_returnval = uthread_get_returnval,
	.uthread_set_returnval = uthread_set_returnval,
	.uthread_is_cancelled = uthread_is_cancelled,
	
	.thread_exception_return = pthread_returning_to_userspace,
	.thread_bootstrap_return = thread_bootstrap_return,
	.unix_syscall_return = unix_syscall_return,

	.absolutetime_to_microtime = absolutetime_to_microtime,

	.proc_restore_workq_bgthreadpolicy = proc_restore_workq_bgthreadpolicy,
	.proc_apply_workq_bgthreadpolicy = proc_apply_workq_bgthreadpolicy,

	.get_bsdthread_info = (void*)get_bsdthread_info,
	.thread_sched_call = thread_sched_call,
	.thread_static_param = thread_static_param,
	.thread_create_workq = thread_create_workq,
	.thread_policy_set_internal = thread_policy_set_internal,

	.thread_affinity_set = thread_affinity_set,

	.zalloc = zalloc,
	.zfree = zfree,
	.zinit = zinit,

	.__pthread_testcancel = __pthread_testcancel,

	.mach_port_deallocate = mach_port_deallocate,
	.semaphore_signal_internal_trap = semaphore_signal_internal_trap,
	.current_map = _current_map,
	.thread_create = thread_create,
	.thread_resume = thread_resume,
	
	.convert_thread_to_port = convert_thread_to_port,
	.ml_get_max_cpus = (void*)ml_get_max_cpus,


	.proc_get_dispatchqueue_serialno_offset = proc_get_dispatchqueue_serialno_offset,
	.proc_set_dispatchqueue_serialno_offset = proc_set_dispatchqueue_serialno_offset,
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
