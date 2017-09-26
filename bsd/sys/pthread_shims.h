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

#ifdef KERNEL_PRIVATE

#ifndef _PTHREAD_SHIMS_H_
#define _PTHREAD_SHIMS_H_

#ifndef ASSEMBLER

#include <kern/clock.h>
#include <kern/kern_types.h>
#include <kern/kcdata.h>
#include <kern/locks.h>
#include <sys/user.h>
#include <sys/_types.h>
#include <sys/_types/_sigset_t.h>
#include <sys/kernel_types.h>

#ifndef PTHREAD_INTERNAL
struct uthread;
#define M_PROC 41
#endif

#if !defined(_SCHED_CALL_T_DEFINED)
#define _SCHED_CALL_T_DEFINED
typedef void (*sched_call_t)(int type, thread_t thread);
#endif

typedef struct workq_reqthreads_req_s {unsigned long priority; int count;} *workq_reqthreads_req_t;
typedef struct workq_threadreq_s { void *opaqueptr[2]; uint32_t opaqueint[2];} *workq_threadreq_t;
enum workq_threadreq_type {
	WORKQ_THREADREQ_KEVENT = 1,
	WORKQ_THREADREQ_WORKLOOP = 2,
	WORKQ_THREADREQ_WORKLOOP_NO_THREAD_CALL = 3,
	WORKQ_THREADREQ_REDRIVE = 4,
};
enum workq_threadreq_op {
	WORKQ_THREADREQ_CHANGE_PRI = 1,
	WORKQ_THREADREQ_CANCEL = 2,
	WORKQ_THREADREQ_CHANGE_PRI_NO_THREAD_CALL = 3,
};
#define WORKQ_THREADREQ_FLAG_NOEMERGENCY 0x1


/*
 * Increment each time new reserved slots are used. When the pthread
 * kext registers this table, it will include the version of the xnu
 * headers that it was built against.
 */
#define PTHREAD_FUNCTIONS_TABLE_VERSION 1

typedef const struct pthread_functions_s {
	int version;

	/* internal calls, kernel core -> kext */
	void (*pthread_init)(void);
	int (*fill_procworkqueue)(proc_t p, void* pwqinfo);

	void (*__unused1)(void);
	void (*__unused2)(void);

	void (*workqueue_exit)(struct proc *p);
	void (*workqueue_mark_exiting)(struct proc *p);
	void (*workqueue_thread_yielded)(void);
	void (*pth_proc_hashinit)(proc_t p);
	void (*pth_proc_hashdelete)(proc_t p);

	/* syscall stubs */
	int (*bsdthread_create)(struct proc *p, user_addr_t user_func, user_addr_t user_funcarg, user_addr_t user_stack, user_addr_t user_pthread, uint32_t flags, user_addr_t *retval);
	int (*bsdthread_register)(struct proc *p, user_addr_t threadstart, user_addr_t wqthread, int pthsize, user_addr_t dummy_value, user_addr_t targetconc_ptr, uint64_t dispatchqueue_offset, int32_t *retval);
	int (*bsdthread_terminate)(struct proc *p, user_addr_t stackaddr, size_t size, uint32_t kthport, uint32_t sem, int32_t *retval);
	int (*thread_selfid)(struct proc *p, uint64_t *retval);
	int (*workq_kernreturn)(struct proc *p, int options, user_addr_t item, int affinity, int prio, int32_t *retval);
	int (*workq_open)(struct proc *p, int32_t *retval);

	/* psynch syscalls */
	int (*psynch_mutexwait)(proc_t p, user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags, uint32_t *retval);
	int (*psynch_mutexdrop)(proc_t p, user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags, uint32_t *retval);
	int (*psynch_cvbroad)(proc_t p, user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen, uint32_t flags, user_addr_t mutex, uint64_t mugen, uint64_t tid, uint32_t *retval);
	int (*psynch_cvsignal)(proc_t p, user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, int thread_port, user_addr_t mutex, uint64_t mugen, uint64_t tid, uint32_t flags, uint32_t *retval);
	int (*psynch_cvwait)(proc_t p, user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, user_addr_t mutex,  uint64_t mugen, uint32_t flags, int64_t sec, uint32_t nsec, uint32_t * retval);
	int (*psynch_cvclrprepost)(proc_t p, user_addr_t cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags, int *retval);
	int (*psynch_rw_longrdlock)(proc_t p, user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t *retval);
	int (*psynch_rw_rdlock)(proc_t p, user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t *retval);
	int (*psynch_rw_unlock)(proc_t p, user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t *retval);
	int (*psynch_rw_wrlock)(proc_t p, user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t *retval);
	int (*psynch_rw_yieldwrlock)(proc_t p, user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t *retval);

	sched_call_t (*workqueue_get_sched_callback)(void);

	/* New register function with TSD offset */
	int (*bsdthread_register2)(struct proc *p, user_addr_t threadstart, user_addr_t wqthread, uint32_t flags, user_addr_t stack_addr_hint, user_addr_t targetconc_ptr, uint32_t dispatchqueue_offset, uint32_t tsd_offset, int32_t *retval);

	/* New pthreadctl system. */
	int (*bsdthread_ctl)(struct proc *p, user_addr_t cmd, user_addr_t arg1, user_addr_t arg2, user_addr_t arg3, int *retval);

    /* Request threads to deliver kevents */
    thread_t (*workq_reqthreads)(struct proc *p, int requests_count, workq_reqthreads_req_t requests);

    /* Resolve a pthread_priority_t to a QoS/relative pri */
    integer_t (*thread_qos_from_pthread_priority)(unsigned long pthread_priority, unsigned long *flags);

	/* try to get wq flags in debugger context */
	uint32_t (*get_pwq_state_kdp)(proc_t p);

	void (*__unused3)(void);
	unsigned long (*pthread_priority_canonicalize2)(unsigned long pthread_priority, boolean_t propagation);

	/* Returns true on success, false on mismatch */
	boolean_t (*workq_thread_has_been_unbound)(thread_t th, int qos_class);

	void (*pthread_find_owner)(thread_t thread, struct stackshot_thread_waitinfo *waitinfo);
	void *(*pthread_get_thread_kwq)(thread_t thread);

	/*
	 * Submits a threadreq to the workq system.
	 *
	 * If type is WORKQ_THREADREQ_KEVENT, the semantics are similar to a call
	 * to workq_reqthreads and the kevent bind function will be called to
	 * indicate the thread fulfilling the request.  The req argument is ignored.
	 *
	 * If type is WORKQ_THREADREQ_WORKLOOP, The req argument should point to
	 * allocated memory of at least the sizeof(workq_threadreq_t).  That memory
	 * is lent to the workq system until workloop_fulfill_threadreq is called
	 * and passed the pointer, at which point it may be freed.
	 *
	 * The properties of the request are passed in the (pthread) priority and flags arguments.
	 *
	 * Will return zero upon success or an error value on failure.  An error of
	 * ENOTSUP means the type argument was not understood.
	 */
	int (*workq_threadreq)(struct proc *p, workq_threadreq_t req,
		enum workq_threadreq_type, unsigned long priority, int flags);

	/*
	 * Modifies an already submitted thread request.
	 *
	 * If operation is WORKQ_THREADREQ_CHANGE_PRI, arg1 is the new priority and arg2 is unused.
	 *
	 * If operation is WORKQ_THREADREQ_CANCEL, arg1 and arg2 are unused.
	 *
	 * Will return zero upon success or an error value on failure.  An error of
	 * ENOTSUP means the operation argument was not understood.
	 */
	int (*workq_threadreq_modify)(struct proc *t, workq_threadreq_t req,
			enum workq_threadreq_op operation,
			unsigned long arg1, unsigned long arg2);

	/* padding for future */
	void * _pad[87];
} * pthread_functions_t;

typedef const struct pthread_callbacks_s {
	int version;

	/* config information */
	uint32_t config_thread_max;
	uint32_t (*get_task_threadmax)(void);

	/* proc.h accessors */
	uint64_t (*proc_get_register)(struct proc *t);
	void (*proc_set_register)(struct proc *t);

	user_addr_t (*proc_get_threadstart)(struct proc *t);
	void (*proc_set_threadstart)(struct proc *t, user_addr_t addr);
	user_addr_t (*proc_get_wqthread)(struct proc *t);
	void (*proc_set_wqthread)(struct proc *t, user_addr_t addr);
	int (*proc_get_pthsize)(struct proc *t);
	void (*proc_set_pthsize)(struct proc *t, int size);
#if defined(__arm64__)
	unsigned __int128 (*atomic_fetch_add_128_relaxed)(_Atomic unsigned __int128 *ptr,
			unsigned __int128 value);
	unsigned __int128 (*atomic_load_128_relaxed)(_Atomic unsigned __int128 *ptr);
#else
	void *unused_was_proc_get_targconc;
	void *unused_was_proc_set_targconc;
#endif
	uint64_t (*proc_get_dispatchqueue_offset)(struct proc *t);
	void (*proc_set_dispatchqueue_offset)(struct proc *t, uint64_t offset);
	void *unused_was_proc_get_wqlockptr;
	void *unused_was_proc_get_wqinitingptr;
	void* (*proc_get_wqptr)(struct proc *t);
	void (*proc_set_wqptr)(struct proc *t, void* ptr);
	void *unused_was_proc_get_wqsize;
	void *unused_was_proc_set_wqsize;
	void (*proc_lock)(struct proc *t);
	void (*proc_unlock)(struct proc *t);
	task_t (*proc_get_task)(struct proc *t);
	void* (*proc_get_pthhash)(struct proc *t);
	void (*proc_set_pthhash)(struct proc *t, void* ptr);

	/* bsd/sys/user.h */
	void* (*uthread_get_threadlist)(struct uthread *t);
	void (*uthread_set_threadlist)(struct uthread *t, void* threadlist);
	sigset_t (*uthread_get_sigmask)(struct uthread *t);
	void (*uthread_set_sigmask)(struct uthread *t, sigset_t s);
	void* (*uthread_get_uukwe)(struct uthread *t);
	int (*uthread_get_returnval)(struct uthread *t);
	void (*uthread_set_returnval)(struct uthread *t, int val);
	int (*uthread_is_cancelled)(struct uthread *t);

	/* vm_protos.h calls */
	ipc_space_t (*task_get_ipcspace)(task_t t);
	mach_port_name_t (*ipc_port_copyout_send)(ipc_port_t sright, ipc_space_t space);

	/* osfmk/vm/vm_map.h */
	kern_return_t (*vm_map_page_info)(vm_map_t map, vm_map_offset_t offset, vm_page_info_flavor_t flavor, vm_page_info_t info, mach_msg_type_number_t *count);
	vm_map_t (*vm_map_switch)(vm_map_t map);

	/* wq functions */
	kern_return_t (*thread_set_wq_state32)(thread_t thread, thread_state_t state);
#if !defined(__arm__)
	kern_return_t (*thread_set_wq_state64)(thread_t thread, thread_state_t state);
#endif

	/* sched_prim.h */
	void (*thread_exception_return)(void);
	void (*thread_bootstrap_return)(void);

	/* kern/clock.h */
	void (*absolutetime_to_microtime)(uint64_t abstime, clock_sec_t *secs, clock_usec_t *microsecs);

	kern_return_t (*thread_set_workq_pri)(thread_t thread, integer_t priority, integer_t policy);
	kern_return_t (*thread_set_workq_qos)(thread_t thread, int qos_tier, int relprio);

	/* osfmk/kern/thread.h */
	struct uthread* (*get_bsdthread_info)(thread_t th);
	void (*thread_sched_call)(thread_t t, sched_call_t call);
	void (*thread_static_param)(thread_t t, boolean_t state);
	kern_return_t (*thread_create_workq)(task_t t, thread_continue_t c, thread_t *new_t);
	kern_return_t (*thread_policy_set_internal)(thread_t t, thread_policy_flavor_t flavour, thread_policy_t info, mach_msg_type_number_t count);

	/* osfmk/kern/affinity.h */
	kern_return_t (*thread_affinity_set)(thread_t thread, uint32_t tag);

	/* bsd/sys/systm.h */
	void (*unix_syscall_return)(int error);

	/* osfmk/kern/zalloc.h */
	void* (*zalloc)(zone_t zone);
	void (*zfree)(zone_t zone, void* ptr);
	zone_t (*zinit)(vm_size_t, vm_size_t maxmem, vm_size_t alloc, const char *name);

	/* bsd/kerb/kern_sig.c */
	void (*__pthread_testcancel)(int);

	/* calls without portfolio */
	kern_return_t (*mach_port_deallocate)(ipc_space_t space, mach_port_name_t name);
	kern_return_t (*semaphore_signal_internal_trap)(mach_port_name_t sema_name);
	vm_map_t (*current_map)(void);

	/* osfmk/kern/thread.h */
	ipc_port_t (*convert_thread_to_port)(thread_t th);

	/* mach/task.h */
	kern_return_t (*thread_create)(task_t parent_task, thread_act_t *child_act);

	/* mach/thread_act.h */
	kern_return_t (*thread_resume)(thread_act_t target_act);

	/* osfmk/<arch>/machine_routines.h */
	int (*ml_get_max_cpus)(void);

	#if defined(__arm__)
	uint32_t (*map_is_1gb)(vm_map_t);
	#endif

	/* <rdar://problem/12809089> xnu: struct proc p_dispatchqueue_serialno_offset additions */
	uint64_t (*proc_get_dispatchqueue_serialno_offset)(struct proc *p);
	void (*proc_set_dispatchqueue_serialno_offset)(struct proc *p, uint64_t offset);

	int (*proc_usynch_thread_qos_add_override_for_resource_check_owner)(thread_t thread, int override_qos, boolean_t first_override_for_resource,
			user_addr_t resource, int resource_type, user_addr_t user_lock_addr, mach_port_name_t user_lock_owner);
	void *unused_was_proc_set_stack_addr_hint;

	uint32_t (*proc_get_pthread_tsd_offset)(struct proc *p);
	void (*proc_set_pthread_tsd_offset)(struct proc *p, uint32_t pthread_tsd_offset);

	kern_return_t (*thread_set_tsd_base)(thread_t thread, mach_vm_offset_t tsd_base);

	int	(*proc_usynch_get_requested_thread_qos)(struct uthread *);
	uint64_t (*proc_get_mach_thread_self_tsd_offset)(struct proc *p);
	void (*proc_set_mach_thread_self_tsd_offset)(struct proc *p, uint64_t mach_thread_self_tsd_offset);

	kern_return_t (*thread_policy_get)(thread_t t, thread_policy_flavor_t flavor, thread_policy_t info, mach_msg_type_number_t *count, boolean_t *get_default);
	boolean_t (*qos_main_thread_active)(void);

	kern_return_t (*thread_set_voucher_name)(mach_port_name_t voucher_name);

	boolean_t (*proc_usynch_thread_qos_add_override_for_resource)(task_t task, struct uthread *, uint64_t tid, int override_qos, boolean_t first_override_for_resource, user_addr_t resource, int resource_type);
	boolean_t (*proc_usynch_thread_qos_remove_override_for_resource)(task_t task, struct uthread *, uint64_t tid, user_addr_t resource, int resource_type);
	boolean_t (*proc_usynch_thread_qos_reset_override_for_resource)(task_t task, struct uthread *, uint64_t tid, user_addr_t resource, int resource_type);

	boolean_t (*proc_init_wqptr_or_wait)(proc_t proc);

	uint16_t (*thread_set_tag)(thread_t thread, uint16_t tag);
	uint16_t (*thread_get_tag)(thread_t thread);

	int (*proc_usynch_thread_qos_squash_override_for_resource)(thread_t thread, user_addr_t resource, int resource_type);
	int (*task_get_default_manager_qos)(task_t task);

	int (*thread_create_workq_waiting)(task_t task, thread_continue_t thread_return, event_t event, thread_t *new_thread);

	user_addr_t (*proc_get_stack_addr_hint)(struct proc *p);
	void (*proc_set_stack_addr_hint)(struct proc *p, user_addr_t stack_addr_hint);

	uint64_t (*proc_get_return_to_kernel_offset)(struct proc *t);
	void (*proc_set_return_to_kernel_offset)(struct proc *t, uint64_t offset);

	/* indicates call is being made synchronously with workq_threadreq call */
#	define WORKLOOP_FULFILL_THREADREQ_SYNC   0x1
#	define WORKLOOP_FULFILL_THREADREQ_CANCEL 0x2
	int (*workloop_fulfill_threadreq)(struct proc *p, workq_threadreq_t req, thread_t thread, int flags);
	void (*thread_will_park_or_terminate)(thread_t thread);

	/* For getting maximum parallelism for a given QoS */
	uint32_t (*qos_max_parallelism)(int qos, uint64_t options);

	/* proc_internal.h: struct proc user_stack accessor */
	user_addr_t (*proc_get_user_stack)(struct proc *p);
	void (*proc_set_user_stack)(struct proc *p, user_addr_t user_stack);

	/* padding for future */
	void* _pad[69];

} *pthread_callbacks_t;

void
pthread_kext_register(pthread_functions_t fns, pthread_callbacks_t *callbacks);

#ifdef BSD_KERNEL_PRIVATE
void workqueue_mark_exiting(struct proc *);
void workqueue_exit(struct proc *);
void workqueue_thread_yielded(void);
sched_call_t workqueue_get_sched_callback(void);
void pthread_init(void);

extern pthread_callbacks_t pthread_kern;
extern pthread_functions_t pthread_functions;
#endif

#endif /* ASSEMBLER */
#endif /* _PTHREAD_SHIMS_H_ */
#endif /* KERNEL_PRIVATE */
