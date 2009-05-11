/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995-2005 Apple Computer, Inc. All Rights Reserved */
/*
 *	pthread_synch.c
 */

#define  _PTHREAD_CONDATTR_T
#define  _PTHREAD_COND_T
#define _PTHREAD_MUTEXATTR_T
#define _PTHREAD_MUTEX_T
#define _PTHREAD_RWLOCKATTR_T
#define _PTHREAD_RWLOCK_T

#undef pthread_mutexattr_t
#undef pthread_mutex_t
#undef pthread_condattr_t
#undef pthread_cond_t
#undef pthread_rwlockattr_t
#undef pthread_rwlock_t

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/acct.h>
#include <sys/kernel.h>
#include <sys/wait.h>
#include <sys/signalvar.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/lock.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <sys/pthread_internal.h>
#include <sys/vm.h>
#include <sys/user.h>		/* for coredump */


#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <mach/task.h>
#include <kern/kern_types.h>
#include <kern/task.h>
#include <kern/clock.h>
#include <mach/kern_return.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/kalloc.h>
#include <kern/sched_prim.h>	/* for thread_exception_return */
#include <kern/processor.h>
#include <kern/affinity.h>
#include <mach/mach_vm.h>
#include <mach/mach_param.h>
#include <mach/thread_status.h>
#include <mach/thread_policy.h>
#include <mach/message.h>
#include <mach/port.h>
#include <vm/vm_protos.h>
#include <vm/vm_map.h>`	/* for current_map() */
#include <mach/thread_act.h> /* for thread_resume */
#include <machine/machine_routines.h>
#if defined(__i386__)
#include <i386/machine_routines.h>
#include <i386/eflags.h>
#include <i386/psl.h>   
#include <i386/seg.h>   
#endif

#include <libkern/OSAtomic.h>

#if 0
#undef KERNEL_DEBUG
#define KERNEL_DEBUG KERNEL_DEBUG_CONSTANT
#undef KERNEL_DEBUG1
#define KERNEL_DEBUG1 KERNEL_DEBUG_CONSTANT1
#endif


#if defined(__ppc__) || defined(__ppc64__)
#include <architecture/ppc/cframe.h>
#endif


lck_grp_attr_t   *pthread_lck_grp_attr;
lck_grp_t    *pthread_lck_grp;
lck_attr_t   *pthread_lck_attr;
lck_mtx_t * pthread_list_mlock;
extern void pthread_init(void);

extern kern_return_t thread_getstatus(register thread_t act, int flavor,
			thread_state_t tstate, mach_msg_type_number_t *count);
extern kern_return_t thread_setstatus(thread_t thread, int flavor,
			thread_state_t tstate, mach_msg_type_number_t count);
extern void thread_set_cthreadself(thread_t thread, uint64_t pself, int isLP64);
extern kern_return_t mach_port_deallocate(ipc_space_t, mach_port_name_t);
extern kern_return_t semaphore_signal_internal_trap(mach_port_name_t);

static int workqueue_additem(struct workqueue *wq, int prio, user_addr_t item);
static int workqueue_removeitem(struct workqueue *wq, int prio, user_addr_t item);
static void workqueue_run_nextitem(proc_t p, thread_t th);
static void wq_runitem(proc_t p, user_addr_t item, thread_t th, struct threadlist *tl,
		       int reuse_thread, int wake_thread, int return_directly);
static int setup_wqthread(proc_t p, thread_t th, user_addr_t item, int reuse_thread, struct threadlist *tl);
static int  workqueue_addnewthread(struct workqueue *wq);
static void workqueue_removethread(struct workqueue *wq);
static void workqueue_lock(proc_t);
static void workqueue_lock_spin(proc_t);
static void workqueue_unlock(proc_t);

#define C_32_STK_ALIGN          16
#define C_64_STK_ALIGN          16
#define C_64_REDZONE_LEN        128
#define TRUNC_DOWN32(a,c)       ((((uint32_t)a)-(c)) & ((uint32_t)(-(c))))
#define TRUNC_DOWN64(a,c)       ((((uint64_t)a)-(c)) & ((uint64_t)(-(c))))


/*
 * Flags filed passed to bsdthread_create and back in pthread_start 
31  <---------------------------------> 0
_________________________________________
| flags(8) | policy(8) | importance(16) |
-----------------------------------------
*/
void _pthread_start(pthread_t self, mach_port_t kport, void *(*fun)(void *), void * funarg, size_t stacksize, unsigned int flags);

#define PTHREAD_START_CUSTOM	0x01000000
#define PTHREAD_START_SETSCHED	0x02000000
#define PTHREAD_START_DETACHED	0x04000000
#define PTHREAD_START_POLICY_BITSHIFT 16
#define PTHREAD_START_POLICY_MASK 0xff
#define PTHREAD_START_IMPORTANCE_MASK 0xffff

#define SCHED_OTHER      POLICY_TIMESHARE
#define SCHED_FIFO       POLICY_FIFO
#define SCHED_RR         POLICY_RR

void
pthread_init(void)
{

	pthread_lck_grp_attr = lck_grp_attr_alloc_init();
	pthread_lck_grp = lck_grp_alloc_init("pthread", pthread_lck_grp_attr);

	/*
	 * allocate the lock attribute for pthread synchronizers
	 */
	pthread_lck_attr = lck_attr_alloc_init();

	pthread_list_mlock = lck_mtx_alloc_init(pthread_lck_grp, pthread_lck_attr);

}

void
pthread_list_lock(void)
{
	lck_mtx_lock(pthread_list_mlock);
}

void
pthread_list_unlock(void)
{
	lck_mtx_unlock(pthread_list_mlock);
}


int
__pthread_mutex_destroy(__unused struct proc *p, struct __pthread_mutex_destroy_args *uap, __unused register_t *retval)
{
	int res;
	int mutexid = uap->mutexid;
	pthread_mutex_t * mutex;
	lck_mtx_t * lmtx;
	lck_mtx_t * lmtx1;
	
	
	mutex = pthread_id_to_mutex(mutexid);
	if (mutex == 0)
		return(EINVAL);

	MTX_LOCK(mutex->lock);
	if (mutex->sig == _PTHREAD_KERN_MUTEX_SIG)
	{
		if (mutex->owner == (thread_t)NULL &&
		    mutex->refcount == 1)
		{
			mutex->sig = _PTHREAD_NO_SIG;
			lmtx = mutex->mutex;
			lmtx1 = mutex->lock;
			mutex->mutex = NULL;
			pthread_id_mutex_remove(mutexid);
			mutex->refcount --;
			MTX_UNLOCK(mutex->lock);
			lck_mtx_free(lmtx, pthread_lck_grp);
			lck_mtx_free(lmtx1, pthread_lck_grp);
			kfree((void *)mutex, sizeof(struct _pthread_mutex));
			return(0);
		}
		else
			res = EBUSY;
	}
	else
		res = EINVAL;
	MTX_UNLOCK(mutex->lock);
	pthread_mutex_release(mutex);
	return (res);
}

/*
 * Initialize a mutex variable, possibly with additional attributes.
 */
static void
pthread_mutex_init_internal(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
	mutex->prioceiling = attr->prioceiling;
	mutex->protocol = attr->protocol;
	mutex->type = attr->type;
	mutex->pshared = attr->pshared;
	mutex->refcount = 0;
	mutex->owner = (thread_t)NULL;
	mutex->owner_proc = current_proc();
	mutex->sig = _PTHREAD_KERN_MUTEX_SIG;
	mutex->lock = lck_mtx_alloc_init(pthread_lck_grp, pthread_lck_attr);
	mutex->mutex = lck_mtx_alloc_init(pthread_lck_grp, pthread_lck_attr);
}

/*
 * Initialize a mutex variable, possibly with additional attributes.
 * Public interface - so don't trust the lock - initialize it first.
 */
int
__pthread_mutex_init(__unused struct proc *p, struct __pthread_mutex_init_args *uap, __unused register_t *retval)
{
	user_addr_t umutex = uap->mutex;
	pthread_mutex_t * mutex;
	user_addr_t uattr = uap->attr;
	pthread_mutexattr_t attr;
	unsigned int addr = (unsigned int)((uintptr_t)uap->mutex);
	int pmutex_sig;
	int mutexid;
	int error = 0;
	
	if ((umutex == 0) || (uattr == 0))
		return(EINVAL);

	if ((error = copyin(uattr, &attr, sizeof(pthread_mutexattr_t))))
		return(error);

	if (attr.sig != _PTHREAD_MUTEX_ATTR_SIG)
			return (EINVAL);

	if ((error = copyin(umutex, &pmutex_sig, sizeof(int))))
		return(error);
	
	if (pmutex_sig == _PTHREAD_KERN_MUTEX_SIG)
		return(EBUSY);
	mutex = (pthread_mutex_t *)kalloc(sizeof(pthread_mutex_t));
		
	 pthread_mutex_init_internal(mutex, &attr);
	
	
	addr += 8;
	mutexid = pthread_id_mutex_add(mutex);
	if (mutexid) {
		if ((error = copyout(&mutexid, ((user_addr_t)((uintptr_t)(addr))), 4)))
			goto cleanup;
		return(0);
	}  else	
		error = ENOMEM;
cleanup:
	if(mutexid)			
		pthread_id_mutex_remove(mutexid);
	lck_mtx_free(mutex->lock, pthread_lck_grp);
	lck_mtx_free(mutex->mutex, pthread_lck_grp);
	kfree(mutex, sizeof(struct _pthread_mutex));
	return(error);
}

/*
 * Lock a mutex.
 * TODO: Priority inheritance stuff
 */
int
__pthread_mutex_lock(struct proc *p, struct __pthread_mutex_lock_args *uap, __unused register_t *retval)
{
	int mutexid = uap->mutexid;
	pthread_mutex_t  * mutex;
	int error;

	mutex = pthread_id_to_mutex(mutexid);
	if (mutex == 0)
		return(EINVAL);

	MTX_LOCK(mutex->lock);

	if (mutex->sig != _PTHREAD_KERN_MUTEX_SIG)
	{
		error = EINVAL;
		goto out;
	}

	if ((p != mutex->owner_proc) && (mutex->pshared != PTHREAD_PROCESS_SHARED)) {
		error = EINVAL;
		goto out;
	}

	MTX_UNLOCK(mutex->lock);
	
	lck_mtx_lock(mutex->mutex);

	MTX_LOCK(mutex->lock);
	mutex->owner = current_thread();
	error = 0;
out:
	MTX_UNLOCK(mutex->lock);
	pthread_mutex_release(mutex);
	return (error);
}

/*
 * Attempt to lock a mutex, but don't block if this isn't possible.
 */
int
__pthread_mutex_trylock(struct proc *p, struct __pthread_mutex_trylock_args *uap, __unused register_t *retval)
{
	int mutexid = uap->mutexid;
	pthread_mutex_t  * mutex;
	boolean_t state;
	int error;

	mutex = pthread_id_to_mutex(mutexid);
	if (mutex == 0)
		return(EINVAL);

	MTX_LOCK(mutex->lock);

	if (mutex->sig != _PTHREAD_KERN_MUTEX_SIG)
	{
		error = EINVAL;
		goto out;
	}

	if ((p != mutex->owner_proc) && (mutex->pshared != PTHREAD_PROCESS_SHARED)) {
		error = EINVAL;
		goto out;
	}

	MTX_UNLOCK(mutex->lock);
	
	state = lck_mtx_try_lock(mutex->mutex);
	if (state) {
		MTX_LOCK(mutex->lock);
		mutex->owner = current_thread();
		MTX_UNLOCK(mutex->lock);
		error = 0;
	} else
		error = EBUSY;

	pthread_mutex_release(mutex);
	return (error);
out:
	MTX_UNLOCK(mutex->lock);
	pthread_mutex_release(mutex);
	return (error);
}

/*
 * Unlock a mutex.
 * TODO: Priority inheritance stuff
 */
int
__pthread_mutex_unlock(struct proc *p, struct __pthread_mutex_unlock_args *uap, __unused register_t *retval)
{
	int mutexid = uap->mutexid;
	pthread_mutex_t  * mutex;
	int error;

	mutex = pthread_id_to_mutex(mutexid);
	if (mutex == 0)
		return(EINVAL);

	MTX_LOCK(mutex->lock);

	if (mutex->sig != _PTHREAD_KERN_MUTEX_SIG)
	{
		error = EINVAL;
		goto out;
	}

	if ((p != mutex->owner_proc) && (mutex->pshared != PTHREAD_PROCESS_SHARED)) {
		error = EINVAL;
		goto out;
	}

	MTX_UNLOCK(mutex->lock);
	
	lck_mtx_unlock(mutex->mutex);

	MTX_LOCK(mutex->lock);
	mutex->owner = NULL;
	error = 0;
out:
	MTX_UNLOCK(mutex->lock);
	pthread_mutex_release(mutex);
	return (error);
}


int       
__pthread_cond_init(__unused struct proc *p, struct __pthread_cond_init_args *uap, __unused register_t *retval)
{
	pthread_cond_t * cond;
	pthread_condattr_t attr;
	user_addr_t ucond = uap->cond;
	user_addr_t uattr = uap->attr;
	unsigned int addr = (unsigned int)((uintptr_t)uap->cond);
	int condid, error, cond_sig;
	semaphore_t sem;
	kern_return_t kret;
	int value = 0;

	if ((ucond == 0) || (uattr == 0))
		return(EINVAL);

	if ((error = copyin(uattr, &attr, sizeof(pthread_condattr_t))))
		return(error);

	if (attr.sig != _PTHREAD_COND_ATTR_SIG)
			return (EINVAL);

	if ((error = copyin(ucond, &cond_sig, sizeof(int))))
		return(error);
	
	if (cond_sig == _PTHREAD_KERN_COND_SIG)
		return(EBUSY);
	kret = semaphore_create(kernel_task, &sem, SYNC_POLICY_FIFO, value);
	if (kret != KERN_SUCCESS)
		return(ENOMEM);

	cond = (pthread_cond_t *)kalloc(sizeof(pthread_cond_t));
		
	cond->lock = lck_mtx_alloc_init(pthread_lck_grp, pthread_lck_attr);
	cond->pshared = attr.pshared;
	cond->sig = _PTHREAD_KERN_COND_SIG;
	cond->sigpending = 0;
	cond->waiters = 0;
	cond->refcount = 0;
	cond->mutex = (pthread_mutex_t *)0;
	cond->owner_proc = current_proc();
	cond->sem = sem;
	
	addr += 8;
	condid = pthread_id_cond_add(cond);
	if (condid) {
		if ((error = copyout(&condid, ((user_addr_t)((uintptr_t)(addr))), 4)))
			goto cleanup;
		return(0);
	}  else	
		error = ENOMEM;
cleanup:
	if(condid)			
		pthread_id_cond_remove(condid);
	semaphore_destroy(kernel_task, cond->sem);
	kfree(cond, sizeof(pthread_cond_t));
	return(error);
}


/*
 * Destroy a condition variable.
 */
int       
__pthread_cond_destroy(__unused struct proc *p, struct __pthread_cond_destroy_args  *uap, __unused register_t *retval)
{
	pthread_cond_t *cond;
	int condid = uap->condid;
	semaphore_t sem;
	lck_mtx_t * lmtx;
	int res;
	
	cond = pthread_id_to_cond(condid);
	if (cond == 0)
		return(EINVAL);

	COND_LOCK(cond->lock);
	if (cond->sig == _PTHREAD_KERN_COND_SIG)
	{
		if (cond->refcount == 1)
		{
			cond->sig = _PTHREAD_NO_SIG;
			sem = cond->sem;
			cond->sem = NULL;
			lmtx = cond->lock;
			pthread_id_cond_remove(condid);
			cond->refcount --;
			COND_UNLOCK(cond->lock);
			lck_mtx_free(lmtx, pthread_lck_grp);
			(void)semaphore_destroy(kernel_task, sem);
			kfree((void *)cond, sizeof(pthread_cond_t));
			return(0);
		}
		else
			res = EBUSY;
	}
	else
		res = EINVAL;
	COND_UNLOCK(cond->lock);
	pthread_cond_release(cond);
	return (res);
}


/*
 * Signal a condition variable, waking up all threads waiting for it.
 */
int       
__pthread_cond_broadcast(__unused struct proc *p, struct __pthread_cond_broadcast_args  *uap, __unused register_t *retval)
{
	int condid = uap->condid;
	pthread_cond_t  * cond;
	int error;
	kern_return_t kret;

	cond = pthread_id_to_cond(condid);
	if (cond == 0)
		return(EINVAL);

	COND_LOCK(cond->lock);

	if (cond->sig != _PTHREAD_KERN_COND_SIG)
	{
		error = EINVAL;
		goto out;
	}

	if ((p != cond->owner_proc) && (cond->pshared != PTHREAD_PROCESS_SHARED)) {
		error = EINVAL;
		goto out;
	}

	COND_UNLOCK(cond->lock);
	
	kret = semaphore_signal_all(cond->sem);
    switch (kret) {
    case KERN_INVALID_ADDRESS:
    case KERN_PROTECTION_FAILURE:
        error = EINVAL;
        break;
    case KERN_ABORTED:
    case KERN_OPERATION_TIMED_OUT:
        error = EINTR;
        break;
    case KERN_SUCCESS:
        error = 0;
        break;
    default:
        error = EINVAL;
        break;
    }

	COND_LOCK(cond->lock);
out:
	COND_UNLOCK(cond->lock);
	pthread_cond_release(cond);
	return (error);
}


/*
 * Signal a condition variable, waking only one thread.
 */
int
__pthread_cond_signal(__unused struct proc *p, struct __pthread_cond_signal_args  *uap, __unused register_t *retval)
{
	int condid = uap->condid;
	pthread_cond_t  * cond;
	int error;
	kern_return_t kret;

	cond = pthread_id_to_cond(condid);
	if (cond == 0)
		return(EINVAL);

	COND_LOCK(cond->lock);

	if (cond->sig != _PTHREAD_KERN_COND_SIG)
	{
		error = EINVAL;
		goto out;
	}

	if ((p != cond->owner_proc) && (cond->pshared != PTHREAD_PROCESS_SHARED)) {
		error = EINVAL;
		goto out;
	}

	COND_UNLOCK(cond->lock);
	
	kret = semaphore_signal(cond->sem);
    switch (kret) {
    case KERN_INVALID_ADDRESS:
    case KERN_PROTECTION_FAILURE:
        error = EINVAL;
        break;
    case KERN_ABORTED:
    case KERN_OPERATION_TIMED_OUT:
        error = EINTR;
        break;
    case KERN_SUCCESS:
        error = 0;
        break;
    default:
        error = EINVAL;
        break;
    }

	COND_LOCK(cond->lock);
out:
	COND_UNLOCK(cond->lock);
	pthread_cond_release(cond);
	return (error);
}


int       
__pthread_cond_wait(__unused struct proc *p, struct __pthread_cond_wait_args  *uap, __unused register_t *retval)
{
	int condid = uap->condid;
	pthread_cond_t  * cond;
	int mutexid = uap->mutexid;
	pthread_mutex_t  * mutex;
	int error;
	kern_return_t kret;

	cond = pthread_id_to_cond(condid);
	if (cond == 0)
		return(EINVAL);

	mutex = pthread_id_to_mutex(mutexid);
	if (mutex == 0) {
		pthread_cond_release(cond);
		return(EINVAL);
	}
	COND_LOCK(cond->lock);

	if (cond->sig != _PTHREAD_KERN_COND_SIG)
	{
		error = EINVAL;
		goto out;
	}

	if ((p != cond->owner_proc) && (cond->pshared != PTHREAD_PROCESS_SHARED)) {
		error = EINVAL;
		goto out;
	}

	COND_UNLOCK(cond->lock);
	
	kret = semaphore_wait(cond->sem);
    switch (kret) {
    case KERN_INVALID_ADDRESS:
    case KERN_PROTECTION_FAILURE:
        error = EACCES;
        break;
    case KERN_ABORTED:
    case KERN_OPERATION_TIMED_OUT:
        error = EINTR;
        break;
    case KERN_SUCCESS:
        error = 0;
        break;
    default:
        error = EINVAL;
        break;
    }

	COND_LOCK(cond->lock);
out:
	COND_UNLOCK(cond->lock);
	pthread_cond_release(cond);
	pthread_mutex_release(mutex);
	return (error);
}

int       
__pthread_cond_timedwait(__unused struct proc *p, struct __pthread_cond_timedwait_args  *uap, __unused register_t *retval)
{
	int condid = uap->condid;
	pthread_cond_t  * cond;
	int mutexid = uap->mutexid;
	pthread_mutex_t  * mutex;
	mach_timespec_t absts;
	int error;
	kern_return_t kret;

	absts.tv_sec = 0;
	absts.tv_nsec = 0;

	if (uap->abstime)
		if ((error = copyin(uap->abstime, &absts, sizeof(mach_timespec_t ))))
			return(error);
	cond = pthread_id_to_cond(condid);
	if (cond == 0)
		return(EINVAL);

	mutex = pthread_id_to_mutex(mutexid);
	if (mutex == 0) {
		pthread_cond_release(cond);
		return(EINVAL);
	}
	COND_LOCK(cond->lock);

	if (cond->sig != _PTHREAD_KERN_COND_SIG)
	{
		error = EINVAL;
		goto out;
	}

	if ((p != cond->owner_proc) && (cond->pshared != PTHREAD_PROCESS_SHARED)) {
		error = EINVAL;
		goto out;
	}

	COND_UNLOCK(cond->lock);
	
	kret = semaphore_timedwait(cond->sem, absts);
    switch (kret) {
    case KERN_INVALID_ADDRESS:
    case KERN_PROTECTION_FAILURE:
        error = EACCES;
        break;
    case KERN_ABORTED:
    case KERN_OPERATION_TIMED_OUT:
        error = EINTR;
        break;
    case KERN_SUCCESS:
        error = 0;
        break;
    default:
        error = EINVAL;
        break;
    }

	COND_LOCK(cond->lock);
out:
	COND_UNLOCK(cond->lock);
	pthread_cond_release(cond);
	pthread_mutex_release(mutex);
	return (error);
}

int
bsdthread_create(__unused struct proc *p, struct bsdthread_create_args  *uap, user_addr_t *retval)
{
	kern_return_t kret;
	void * sright;
	int error = 0;
	int allocated = 0;
	mach_vm_offset_t stackaddr;
        mach_vm_size_t th_allocsize = 0;
        mach_vm_size_t user_stacksize;
        mach_vm_size_t th_stacksize;
        mach_vm_offset_t th_stackaddr;
        mach_vm_offset_t th_stack;
        mach_vm_offset_t th_pthread;
        mach_port_t th_thport;
	thread_t th;
	user_addr_t user_func = uap->func;
	user_addr_t user_funcarg = uap->func_arg;
	user_addr_t user_stack = uap->stack;
	user_addr_t user_pthread = uap->pthread;
	unsigned int  flags = (unsigned int)uap->flags;
	vm_map_t vmap = current_map();
	task_t ctask = current_task();
	unsigned int policy, importance;
	
	int isLP64 = 0;


#if 0
	KERNEL_DEBUG_CONSTANT(0x9000080 | DBG_FUNC_START, flags, 0, 0, 0, 0);
#endif

	isLP64 = IS_64BIT_PROCESS(p);


#if defined(__ppc__)
	stackaddr = 0xF0000000;
#elif defined(__i386__)
	stackaddr = 0xB0000000;
#else
#error Need to define a stack address hint for this architecture
#endif
	kret = thread_create(ctask, &th);
	if (kret != KERN_SUCCESS)
		return(ENOMEM);
	thread_reference(th);

	sright = (void *) convert_thread_to_port(th);
	th_thport = (void *)ipc_port_copyout_send(sright, get_task_ipcspace(ctask));

	if ((flags & PTHREAD_START_CUSTOM) == 0) {
		th_stacksize = (mach_vm_size_t)user_stack;		/* if it is custom them it is stacksize */
		th_allocsize = th_stacksize + PTH_DEFAULT_GUARDSIZE + p->p_pthsize;

		kret = mach_vm_map(vmap, &stackaddr,
    				th_allocsize,
    				page_size-1,
    				VM_MAKE_TAG(VM_MEMORY_STACK)| VM_FLAGS_ANYWHERE , NULL,
    				0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL,
    				VM_INHERIT_DEFAULT);
    		if (kret != KERN_SUCCESS)
    			kret = mach_vm_allocate(vmap,
    					&stackaddr, th_allocsize,
    					VM_MAKE_TAG(VM_MEMORY_STACK)| VM_FLAGS_ANYWHERE);
    		if (kret != KERN_SUCCESS) {
			error = ENOMEM;
			goto out;
    		}
#if 0
		KERNEL_DEBUG_CONSTANT(0x9000080 |DBG_FUNC_NONE, th_allocsize, stackaddr, 0, 2, 0);
#endif
		th_stackaddr = stackaddr;
		allocated = 1;
     		/*
		 * The guard page is at the lowest address
     		 * The stack base is the highest address
		 */
		kret = mach_vm_protect(vmap,  stackaddr, PTH_DEFAULT_GUARDSIZE, FALSE, VM_PROT_NONE);

    		if (kret != KERN_SUCCESS) { 
			error = ENOMEM;
			goto out1;
    		}
		th_stack = (stackaddr + th_stacksize + PTH_DEFAULT_GUARDSIZE);
		th_pthread = (stackaddr + th_stacksize + PTH_DEFAULT_GUARDSIZE);
		user_stacksize = th_stacksize;
	} else {
		th_stack = user_stack;
		user_stacksize = user_stack;
		th_pthread = user_pthread;
#if 0
		KERNEL_DEBUG_CONSTANT(0x9000080 |DBG_FUNC_NONE, 0, 0, 0, 3, 0);
#endif
	}
	
#if defined(__ppc__)
	/*
	 * Set up PowerPC registers...
	 * internally they are always kept as 64 bit and
	 * since the register set is the same between 32 and 64bit modes
	 * we don't need 2 different methods for setting the state
	 */
	{
	        ppc_thread_state64_t state64;
		ppc_thread_state64_t *ts64 = &state64;

		ts64->srr0 = (uint64_t)p->p_threadstart;
		ts64->r1 = (uint64_t)(th_stack - C_ARGSAVE_LEN - C_RED_ZONE);
		ts64->r3 = (uint64_t)th_pthread;
		ts64->r4 = (uint64_t)((unsigned int)th_thport);
		ts64->r5 = (uint64_t)user_func;
		ts64->r6 = (uint64_t)user_funcarg;
		ts64->r7 = (uint64_t)user_stacksize;
		ts64->r8 = (uint64_t)uap->flags;

		thread_set_wq_state64(th, (thread_state_t)ts64);

		thread_set_cthreadself(th, (uint64_t)th_pthread, isLP64);
	}
#elif defined(__i386__)
	{
        /*
         * Set up i386 registers & function call.
         */
	if (isLP64 == 0) {
		x86_thread_state32_t state;
		x86_thread_state32_t *ts = &state;

        	ts->eip = (int)p->p_threadstart;
		ts->eax = (unsigned int)th_pthread;
		ts->ebx = (unsigned int)th_thport;
		ts->ecx = (unsigned int)user_func;
		ts->edx = (unsigned int)user_funcarg;
		ts->edi = (unsigned int)user_stacksize;
		ts->esi = (unsigned int)uap->flags;
		/*
		 * set stack pointer
		 */
        	ts->esp = (int)((vm_offset_t)(th_stack-C_32_STK_ALIGN));

		thread_set_wq_state32(th, (thread_state_t)ts);

	} else {
	        x86_thread_state64_t state64;
		x86_thread_state64_t *ts64 = &state64;

        	ts64->rip = (uint64_t)p->p_threadstart;
		ts64->rdi = (uint64_t)th_pthread;
		ts64->rsi = (uint64_t)((unsigned int)(th_thport));
		ts64->rdx = (uint64_t)user_func;
		ts64->rcx = (uint64_t)user_funcarg;
		ts64->r8 = (uint64_t)user_stacksize;
		ts64->r9 = (uint64_t)uap->flags;
		/*
		 * set stack pointer aligned to 16 byte boundary
		 */
		ts64->rsp = (uint64_t)(th_stack - C_64_REDZONE_LEN);

		thread_set_wq_state64(th, (thread_state_t)ts64);
	}
	}
#else
#error bsdthread_create  not defined for this architecture
#endif
	/* Set scheduling parameters if needed */
	if ((flags & PTHREAD_START_SETSCHED) != 0) {
		thread_extended_policy_data_t    extinfo;
		thread_precedence_policy_data_t   precedinfo;

		importance = (flags & PTHREAD_START_IMPORTANCE_MASK);
		policy = (flags >> PTHREAD_START_POLICY_BITSHIFT) & PTHREAD_START_POLICY_MASK;

		if (policy == SCHED_OTHER)
			extinfo.timeshare = 1;
		else
			extinfo.timeshare = 0;
		thread_policy_set(th, THREAD_EXTENDED_POLICY, (thread_policy_t)&extinfo, THREAD_EXTENDED_POLICY_COUNT);

#define BASEPRI_DEFAULT 31
		precedinfo.importance = (importance - BASEPRI_DEFAULT);
		thread_policy_set(th, THREAD_PRECEDENCE_POLICY, (thread_policy_t)&precedinfo, THREAD_PRECEDENCE_POLICY_COUNT);
	}

	kret = thread_resume(th);
	if (kret != KERN_SUCCESS) {
		error = EINVAL;
		goto out1;
	}
	thread_deallocate(th);	/* drop the creator reference */
#if 0
	KERNEL_DEBUG_CONSTANT(0x9000080 |DBG_FUNC_END, error, (unsigned int)th_pthread, 0, 0, 0);
#endif
	*retval = th_pthread;

	return(0);

out1:
	if (allocated != 0)
		(void)mach_vm_deallocate(vmap,  stackaddr, th_allocsize);
out:
	(void)mach_port_deallocate(get_task_ipcspace(ctask), (mach_port_name_t)th_thport);
	(void)thread_terminate(th);
	(void)thread_deallocate(th);
	return(error);
}

int       
bsdthread_terminate(__unused struct proc *p, struct bsdthread_terminate_args  *uap, __unused register_t *retval)
{
	mach_vm_offset_t  freeaddr;
	mach_vm_size_t freesize;
	kern_return_t kret;
	mach_port_name_t kthport = (mach_port_name_t)uap->port;
	mach_port_name_t sem = (mach_port_name_t)uap->sem;

	freeaddr = (mach_vm_offset_t)uap->stackaddr;
	freesize = uap->freesize;
	
#if 0
	KERNEL_DEBUG_CONSTANT(0x9000084 |DBG_FUNC_START, (unsigned int)freeaddr, (unsigned int)freesize, (unsigned int)kthport, 0xff, 0);
#endif
	if ((freesize != (mach_vm_size_t)0) && (freeaddr != (mach_vm_offset_t)0)) {
		kret = mach_vm_deallocate(current_map(), freeaddr, freesize);
		if (kret != KERN_SUCCESS) {
			return(EINVAL);
		}
	}
	
	(void) thread_terminate(current_thread());
	if (sem != MACH_PORT_NULL) {
		 kret = semaphore_signal_internal_trap(sem);
		if (kret != KERN_SUCCESS) {
			return(EINVAL);
		}
	}
	
	if (kthport != MACH_PORT_NULL)
			mach_port_deallocate(get_task_ipcspace(current_task()), kthport);
	thread_exception_return();
	panic("bsdthread_terminate: still running\n");
#if 0
	KERNEL_DEBUG_CONSTANT(0x9000084 |DBG_FUNC_END, 0, 0, 0, 0xff, 0);
#endif
	return(0);
}


int
bsdthread_register(struct proc *p, struct bsdthread_register_args  *uap, __unused register_t *retval)
{
	/* syscall randomizer test can pass bogus values */
	if (uap->pthsize > MAX_PTHREAD_SIZE) {
		return(EINVAL);
	}
	p->p_threadstart = uap->threadstart;
	p->p_wqthread = uap->wqthread;
	p->p_pthsize = uap->pthsize;

	return(0);
}




int wq_stalled_window_usecs	= WQ_STALLED_WINDOW_USECS;
int wq_reduce_pool_window_usecs	= WQ_REDUCE_POOL_WINDOW_USECS;
int wq_max_run_latency_usecs	= WQ_MAX_RUN_LATENCY_USECS;
int wq_timer_interval_msecs	= WQ_TIMER_INTERVAL_MSECS;


SYSCTL_INT(_kern, OID_AUTO, wq_stalled_window_usecs, CTLFLAG_RW,
	   &wq_stalled_window_usecs, 0, "");

SYSCTL_INT(_kern, OID_AUTO, wq_reduce_pool_window_usecs, CTLFLAG_RW,
	   &wq_reduce_pool_window_usecs, 0, "");

SYSCTL_INT(_kern, OID_AUTO, wq_max_run_latency_usecs, CTLFLAG_RW,
	   &wq_max_run_latency_usecs, 0, "");

SYSCTL_INT(_kern, OID_AUTO, wq_timer_interval_msecs, CTLFLAG_RW,
	   &wq_timer_interval_msecs, 0, "");




void
workqueue_init_lock(proc_t p)
{
        lck_mtx_init(&p->p_wqlock, pthread_lck_grp, pthread_lck_attr);
}

void
workqueue_destroy_lock(proc_t p)
{
	lck_mtx_destroy(&p->p_wqlock, pthread_lck_grp);
}

static void
workqueue_lock(proc_t p)
{
	lck_mtx_lock(&p->p_wqlock);
}

static void
workqueue_lock_spin(proc_t p)
{
	lck_mtx_lock_spin(&p->p_wqlock);
}

static void
workqueue_unlock(proc_t p)
{
	lck_mtx_unlock(&p->p_wqlock);
}



static void
workqueue_interval_timer_start(thread_call_t call, int interval_in_ms)
{
        uint64_t deadline;

	clock_interval_to_deadline(interval_in_ms, 1000 * 1000, &deadline);

	thread_call_enter_delayed(call, deadline);
}


static void
workqueue_timer(struct workqueue *wq, __unused int param1)
{
        struct timeval tv, dtv;
        uint32_t i;
	boolean_t added_more_threads = FALSE;
	boolean_t reset_maxactive = FALSE;
	boolean_t restart_timer = FALSE;
		
        microuptime(&tv);

        KERNEL_DEBUG(0xefffd108, (int)wq, 0, 0, 0, 0);

	/*
	 * check to see if the stall frequency was beyond our tolerance
	 * or we have work on the queue, but haven't scheduled any 
	 * new work within our acceptable time interval because
	 * there were no idle threads left to schedule
	 *
	 * WQ_TIMER_WATCH will only be set if we have 1 or more affinity
	 * groups that have stalled (no active threads and no idle threads)...
	 * it will not be set if all affinity groups have at least 1 thread
	 * that is currently runnable... if all processors have a runnable
	 * thread, there is no need to add more threads even if we're not
	 * scheduling new work within our allowed window... it just means
	 * that the work items are taking a long time to complete.
	 */
	if (wq->wq_flags & (WQ_ADD_TO_POOL | WQ_TIMER_WATCH)) {

		if (wq->wq_flags & WQ_ADD_TO_POOL)
		        added_more_threads = TRUE;
		else {
		        timersub(&tv, &wq->wq_lastran_ts, &dtv);

			if (((dtv.tv_sec * 1000000) + dtv.tv_usec) > wq_stalled_window_usecs)
			        added_more_threads = TRUE;
		}
		if (added_more_threads == TRUE) {
		        for (i = 0; i < wq->wq_affinity_max && wq->wq_nthreads < WORKQUEUE_MAXTHREADS; i++) {
			        (void)workqueue_addnewthread(wq);
			}
		}
	}
	timersub(&tv, &wq->wq_reduce_ts, &dtv);

	if (((dtv.tv_sec * 1000000) + dtv.tv_usec) > wq_reduce_pool_window_usecs)
	        reset_maxactive = TRUE;

	/*
	 * if the pool size has grown beyond the minimum number
	 * of threads needed to keep all of the processors busy, and
	 * the maximum number of threads scheduled concurrently during
	 * the last sample period didn't exceed half the current pool
	 * size, then its time to trim the pool size back
	 */
	if (added_more_threads == FALSE &&
	    reset_maxactive == TRUE &&
	    wq->wq_nthreads > wq->wq_affinity_max &&
	    wq->wq_max_threads_scheduled <= (wq->wq_nthreads / 2)) {
		uint32_t nthreads_to_remove;
		
		if ((nthreads_to_remove = (wq->wq_nthreads / 4)) == 0)
			nthreads_to_remove = 1;

	        for (i = 0; i < nthreads_to_remove && wq->wq_nthreads > wq->wq_affinity_max; i++)
		        workqueue_removethread(wq);
	}
	workqueue_lock_spin(wq->wq_proc);

	if (reset_maxactive == TRUE) {
	        wq->wq_max_threads_scheduled = 0;
		microuptime(&wq->wq_reduce_ts);
	}
	if (added_more_threads) {
	        wq->wq_flags &= ~(WQ_ADD_TO_POOL | WQ_TIMER_WATCH);

	        /*
		 * since we added more threads, we should be
		 * able to run some work if its still available
		 */
	        workqueue_run_nextitem(wq->wq_proc, THREAD_NULL);
		workqueue_lock_spin(wq->wq_proc);
	}
	if ((wq->wq_nthreads > wq->wq_affinity_max) ||
	    (wq->wq_flags & WQ_TIMER_WATCH)) {
	        restart_timer = TRUE;
	} else
	        wq->wq_flags &= ~WQ_TIMER_RUNNING;

	workqueue_unlock(wq->wq_proc);

	/*
	 * we needed to knock down the WQ_TIMER_RUNNING flag while behind
	 * the workqueue lock... however, we don't want to hold the lock
	 * while restarting the timer and we certainly don't want 2 or more
	 * instances of the timer... so set a local to indicate the need
	 * for a restart since the state of wq_flags may change once we
	 * drop the workqueue lock...
	 */
	if (restart_timer == TRUE)
	        workqueue_interval_timer_start(wq->wq_timer_call, wq_timer_interval_msecs);
}


static void
workqueue_callback(
		   int		type,
		   thread_t	thread)
{
	struct uthread    *uth;
	struct threadlist *tl;
	struct workqueue  *wq;

	uth = get_bsdthread_info(thread);
	tl  = uth->uu_threadlist;
	wq  = tl->th_workq;

        switch (type) {

	      case SCHED_CALL_BLOCK:
	        {
		uint32_t	old_activecount;

		old_activecount = OSAddAtomic(-1, (SInt32 *)&wq->wq_thactivecount[tl->th_affinity_tag]);

		if (old_activecount == 1 && wq->wq_itemcount) {
		        /*
			 * we were the last active thread on this affinity set
			 * and we've got work to do
			 */
		        workqueue_lock_spin(wq->wq_proc);
			/*
			 * if this thread is blocking (not parking)
			 * and the idle list is empty for this affinity group
			 * we'll count it as a 'stall'
			 */
			if ((tl->th_flags & TH_LIST_RUNNING) &&
			    TAILQ_EMPTY(&wq->wq_thidlelist[tl->th_affinity_tag]))
			        wq->wq_stalled_count++;

			workqueue_run_nextitem(wq->wq_proc, THREAD_NULL);
			/*
			 * workqueue_run_nextitem will drop the workqueue
			 * lock before it returns
			 */
		}
	        KERNEL_DEBUG(0xefffd020, (int)thread, wq->wq_threads_scheduled, tl->th_affinity_tag, 0, 0);
	        }
		break;

	      case SCHED_CALL_UNBLOCK:
		/*
		 * we cannot take the workqueue_lock here...
		 * an UNBLOCK can occur from a timer event which
		 * is run from an interrupt context... if the workqueue_lock
		 * is already held by this processor, we'll deadlock...
		 * the thread lock for the thread being UNBLOCKED
		 * is also held
		 */
		if (tl->th_unparked)
		        OSAddAtomic(-1, (SInt32 *)&tl->th_unparked);
		else
		        OSAddAtomic(1, (SInt32 *)&wq->wq_thactivecount[tl->th_affinity_tag]);

		KERNEL_DEBUG(0xefffd024, (int)thread, wq->wq_threads_scheduled, tl->th_affinity_tag, 0, 0);
		break;
	}
}

static void
workqueue_removethread(struct workqueue *wq)
{
        struct threadlist *tl;
	uint32_t	i, affinity_tag = 0;

	tl = NULL;

	workqueue_lock_spin(wq->wq_proc);
	
	for (i = 0; i < wq->wq_affinity_max; i++) {

	        affinity_tag = wq->wq_nextaffinitytag;

		if (affinity_tag == 0)
		        affinity_tag = wq->wq_affinity_max - 1;
		else
		        affinity_tag--;
		wq->wq_nextaffinitytag = affinity_tag;

		/*
		 * look for an idle thread to steal from this affinity group
		 * but don't grab the only thread associated with it
		 */
		if (!TAILQ_EMPTY(&wq->wq_thidlelist[affinity_tag]) && wq->wq_thcount[affinity_tag] > 1) {
		        tl = TAILQ_FIRST(&wq->wq_thidlelist[affinity_tag]);
			TAILQ_REMOVE(&wq->wq_thidlelist[affinity_tag], tl, th_entry);

			wq->wq_nthreads--;
			wq->wq_thcount[affinity_tag]--;

			break;
		}
	}
	workqueue_unlock(wq->wq_proc);

	if (tl != NULL) {
		thread_sched_call(tl->th_thread, NULL);
	
		if ( (tl->th_flags & TH_LIST_BLOCKED) )
		        wakeup(tl);
		else {
			/*
			 * thread was created, but never used... 
			 * need to clean up the stack and port ourselves
			 * since we're not going to spin up through the
			 * normal exit path triggered from Libc
			 */
		        (void)mach_vm_deallocate(wq->wq_map, tl->th_stackaddr, tl->th_allocsize);
			(void)mach_port_deallocate(get_task_ipcspace(wq->wq_task), (mach_port_name_t)tl->th_thport);

		        thread_terminate(tl->th_thread);
		}
		KERNEL_DEBUG(0xefffd030, (int)tl->th_thread, wq->wq_nthreads, tl->th_flags & TH_LIST_BLOCKED, 0, 0);
		/*
		 * drop our ref on the thread
		 */
		thread_deallocate(tl->th_thread);

		kfree(tl, sizeof(struct threadlist));
	}
}


static int
workqueue_addnewthread(struct workqueue *wq)
{
	struct threadlist *tl;
	struct uthread	*uth;
	kern_return_t	kret;
	thread_t	th;
	proc_t		p;
	void 	 	*sright;
	mach_vm_offset_t stackaddr;
	uint32_t	affinity_tag;

	p = wq->wq_proc;

	kret = thread_create(wq->wq_task, &th);

 	if (kret != KERN_SUCCESS)
	        return(EINVAL);

	tl = kalloc(sizeof(struct threadlist));
	bzero(tl, sizeof(struct threadlist));

#if defined(__ppc__)
	stackaddr = 0xF0000000;
#elif defined(__i386__)
	stackaddr = 0xB0000000;
#else
#error Need to define a stack address hint for this architecture
#endif
	tl->th_allocsize = PTH_DEFAULT_STACKSIZE + PTH_DEFAULT_GUARDSIZE + p->p_pthsize;

	kret = mach_vm_map(wq->wq_map, &stackaddr,
    			tl->th_allocsize,
    			page_size-1,
    			VM_MAKE_TAG(VM_MEMORY_STACK)| VM_FLAGS_ANYWHERE , NULL,
    			0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL,
    			VM_INHERIT_DEFAULT);

	if (kret != KERN_SUCCESS) {
	        kret = mach_vm_allocate(wq->wq_map,
    					&stackaddr, tl->th_allocsize,
    					VM_MAKE_TAG(VM_MEMORY_STACK) | VM_FLAGS_ANYWHERE);
	}
	if (kret == KERN_SUCCESS) {
	        /*
		 * The guard page is at the lowest address
		 * The stack base is the highest address
		 */
	        kret = mach_vm_protect(wq->wq_map, stackaddr, PTH_DEFAULT_GUARDSIZE, FALSE, VM_PROT_NONE);

		if (kret != KERN_SUCCESS)
		        (void) mach_vm_deallocate(wq->wq_map, stackaddr, tl->th_allocsize);
	}
	if (kret != KERN_SUCCESS) {
		(void) thread_terminate(th);

		kfree(tl, sizeof(struct threadlist));

	        return(EINVAL);
	}
	thread_reference(th);

	sright = (void *) convert_thread_to_port(th);
	tl->th_thport = (void *)ipc_port_copyout_send(sright, get_task_ipcspace(wq->wq_task));

	thread_static_param(th, TRUE);

        workqueue_lock_spin(p);

	affinity_tag = wq->wq_nextaffinitytag;
	wq->wq_nextaffinitytag = (affinity_tag + 1) % wq->wq_affinity_max;

        workqueue_unlock(p);

	tl->th_flags = TH_LIST_INITED | TH_LIST_SUSPENDED;

	tl->th_thread = th;
	tl->th_workq = wq;
	tl->th_stackaddr = stackaddr;
	tl->th_affinity_tag = affinity_tag;

#if defined(__ppc__)
	//ml_fp_setvalid(FALSE);
	thread_set_cthreadself(th, (uint64_t)(tl->th_stackaddr + PTH_DEFAULT_STACKSIZE + PTH_DEFAULT_GUARDSIZE), IS_64BIT_PROCESS(p));
#endif /* __ppc__ */
	/*
	 * affinity tag of 0 means no affinity...
	 * but we want our tags to be 0 based because they
	 * are used to index arrays, so...
	 * keep it 0 based internally and bump by 1 when
	 * calling out to set it
	 */
	(void)thread_affinity_set(th, affinity_tag + 1);
	thread_sched_call(th, workqueue_callback);

	uth = get_bsdthread_info(tl->th_thread);
	uth->uu_threadlist = (void *)tl;

        workqueue_lock_spin(p);

	TAILQ_INSERT_TAIL(&wq->wq_thidlelist[tl->th_affinity_tag], tl, th_entry);
	wq->wq_nthreads++;
	wq->wq_thcount[affinity_tag]++;

	KERNEL_DEBUG1(0xefffd014 | DBG_FUNC_START, (int)current_thread(), affinity_tag, wq->wq_nthreads, 0, (int)tl->th_thread);

	/*
	 * work may have come into the queue while
	 * no threads were available to run... since
	 * we're adding a new thread, go evaluate the
	 * current state
	 */
	workqueue_run_nextitem(p, THREAD_NULL);
	/*
	 * workqueue_run_nextitem is responsible for
	 * dropping the workqueue lock in all cases
	 */

	return(0);
}

int
workq_open(__unused struct proc *p, __unused struct workq_open_args  *uap, __unused register_t *retval)
{
	struct workqueue * wq;
	int size;
	char * ptr;
	int j;
	uint32_t i;
	int error = 0;
	int num_cpus;
	struct workitem * witem;
	struct workitemlist *wl;

	workqueue_lock(p);	

	if (p->p_wqptr == NULL) {
	        num_cpus = ml_get_max_cpus();

		size = (sizeof(struct workqueue)) +
		       (num_cpus * sizeof(int *)) +
		       (num_cpus * sizeof(TAILQ_HEAD(, threadlist)));

		ptr = (char *)kalloc(size);
		bzero(ptr, size);

		wq = (struct workqueue *)ptr;
		wq->wq_flags = WQ_LIST_INITED;
		wq->wq_proc = p;
		wq->wq_affinity_max = num_cpus;
		wq->wq_task = current_task();
		wq->wq_map  = current_map();

		for (i = 0; i < WORKQUEUE_NUMPRIOS; i++) {
		        wl = (struct workitemlist *)&wq->wq_list[i];
			TAILQ_INIT(&wl->wl_itemlist);
			TAILQ_INIT(&wl->wl_freelist);

			for (j = 0; j < WORKITEM_SIZE; j++) {
			        witem = &wq->wq_array[(i*WORKITEM_SIZE) + j];
				TAILQ_INSERT_TAIL(&wl->wl_freelist, witem, wi_entry);
			}
		}
		wq->wq_thactivecount = (uint32_t *)((char *)ptr + sizeof(struct workqueue));
		wq->wq_thcount       = (uint32_t *)&wq->wq_thactivecount[wq->wq_affinity_max];
		wq->wq_thidlelist    = (struct wq_thidlelist *)&wq->wq_thcount[wq->wq_affinity_max];

		for (i = 0; i < wq->wq_affinity_max; i++)
		        TAILQ_INIT(&wq->wq_thidlelist[i]);

		TAILQ_INIT(&wq->wq_thrunlist);

		p->p_wqptr = (void *)wq;
		p->p_wqsize = size;

		workqueue_unlock(p);

		wq->wq_timer_call = thread_call_allocate((thread_call_func_t)workqueue_timer, (thread_call_param_t)wq);

		for (i = 0; i < wq->wq_affinity_max; i++) {
			(void)workqueue_addnewthread(wq);
		}
		/* If unable to create any threads, return error */
		if (wq->wq_nthreads == 0)
			error = EINVAL;
		workqueue_lock_spin(p);

		microuptime(&wq->wq_reduce_ts);
		microuptime(&wq->wq_lastran_ts);
		wq->wq_max_threads_scheduled = 0;
		wq->wq_stalled_count = 0;
	}
	workqueue_unlock(p);

	return(error);
}

int
workq_ops(struct proc *p, struct workq_ops_args  *uap, __unused register_t *retval)
{
	int options	 = uap->options;
	int prio	 = uap->prio;	/* should  be used to find the right workqueue */
	user_addr_t item = uap->item;
	int error = 0;
	thread_t th = THREAD_NULL;
        struct workqueue *wq;

	prio += 2;	/* normalize prio -2 to +2 to 0 -4 */

	switch (options) {

		case WQOPS_QUEUE_ADD: {

		        KERNEL_DEBUG(0xefffd008 | DBG_FUNC_NONE, (int)item, 0, 0, 0, 0);

			if ((prio < 0) || (prio >= 5))
				return (EINVAL);

			workqueue_lock_spin(p);

			if ((wq = (struct workqueue *)p->p_wqptr) == NULL) {
			        workqueue_unlock(p);
			        return (EINVAL);
			}
			error = workqueue_additem(wq, prio, item);
			
		        }
			break;
		case WQOPS_QUEUE_REMOVE: {

			if ((prio < 0) || (prio >= 5))
				return (EINVAL);

			workqueue_lock_spin(p);

			if ((wq = (struct workqueue *)p->p_wqptr) == NULL) {
			        workqueue_unlock(p);
			        return (EINVAL);
			}
		        error = workqueue_removeitem(wq, prio, item);
			}
			break;
		case WQOPS_THREAD_RETURN: {

		        th = current_thread();

		        KERNEL_DEBUG(0xefffd004 | DBG_FUNC_END, 0, 0, 0, 0, 0);

			workqueue_lock_spin(p);

			if ((wq = (struct workqueue *)p->p_wqptr) == NULL) {
			        workqueue_unlock(p);
			        return (EINVAL);
			}
		        }
			break;
		default:
		        return (EINVAL);
	}
	workqueue_run_nextitem(p, th);
	/*
	 * workqueue_run_nextitem is responsible for
	 * dropping the workqueue lock in all cases
	 */
	return(error);
}

void
workqueue_exit(struct proc *p)
{
	struct workqueue  * wq;
	struct threadlist  * tl, *tlist;
	uint32_t i;

	if (p->p_wqptr != NULL) {

	        workqueue_lock_spin(p);

	        wq = (struct workqueue *)p->p_wqptr;
		p->p_wqptr = NULL;

		workqueue_unlock(p);

		if (wq == NULL)
		        return;
		
		if (wq->wq_flags & WQ_TIMER_RUNNING)
		        thread_call_cancel(wq->wq_timer_call);
		thread_call_free(wq->wq_timer_call);

		TAILQ_FOREACH_SAFE(tl, &wq->wq_thrunlist, th_entry, tlist) {
		        /*
			 * drop our last ref on the thread
			 */
		        thread_sched_call(tl->th_thread, NULL);
		        thread_deallocate(tl->th_thread);

			TAILQ_REMOVE(&wq->wq_thrunlist, tl, th_entry);
			kfree(tl, sizeof(struct threadlist));
		}
		for (i = 0; i < wq->wq_affinity_max; i++) {
		        TAILQ_FOREACH_SAFE(tl, &wq->wq_thidlelist[i], th_entry, tlist) {
			        /*
				 * drop our last ref on the thread
				 */
			        thread_sched_call(tl->th_thread, NULL);
				thread_deallocate(tl->th_thread);

				TAILQ_REMOVE(&wq->wq_thidlelist[i], tl, th_entry);
				kfree(tl, sizeof(struct threadlist));
			}
		}
		kfree(wq, p->p_wqsize);
	}
}

static int 
workqueue_additem(struct workqueue *wq, int prio, user_addr_t item)
{
	struct workitem	*witem;
	struct workitemlist *wl;

	wl = (struct workitemlist *)&wq->wq_list[prio];

	if (TAILQ_EMPTY(&wl->wl_freelist))
		return (ENOMEM);

	witem = (struct workitem *)TAILQ_FIRST(&wl->wl_freelist);
	TAILQ_REMOVE(&wl->wl_freelist, witem, wi_entry);

	witem->wi_item = item;
	TAILQ_INSERT_TAIL(&wl->wl_itemlist, witem, wi_entry);

	if (wq->wq_itemcount == 0) {
	        microuptime(&wq->wq_lastran_ts);
		wq->wq_stalled_count = 0;
	}
	wq->wq_itemcount++;

	return (0);
}

static int 
workqueue_removeitem(struct workqueue *wq, int prio, user_addr_t item)
{
	struct workitem *witem;
	struct workitemlist *wl;
	int error = ESRCH;

	wl = (struct workitemlist *)&wq->wq_list[prio];

	TAILQ_FOREACH(witem, &wl->wl_itemlist, wi_entry) {
		if (witem->wi_item == item) {
			TAILQ_REMOVE(&wl->wl_itemlist, witem, wi_entry);
			wq->wq_itemcount--;

			witem->wi_item = (user_addr_t)0;
			TAILQ_INSERT_HEAD(&wl->wl_freelist, witem, wi_entry);

			error = 0;
			break;
		}
	}
	if (wq->wq_itemcount == 0)
	        wq->wq_flags &= ~(WQ_ADD_TO_POOL | WQ_TIMER_WATCH);

	return (error);
}

/*
 * workqueue_run_nextitem:
 *   called with the workqueue lock held...
 *   responsible for dropping it in all cases
 */
static void
workqueue_run_nextitem(proc_t p, thread_t thread)
{
        struct workqueue *wq;
	struct workitem *witem = NULL;
	user_addr_t item = 0;
	thread_t th_to_run = THREAD_NULL;
	thread_t th_to_park = THREAD_NULL;
	int wake_thread = 0;
	int reuse_thread = 1;
	uint32_t stalled_affinity_count = 0;
	int i;
	uint32_t affinity_tag;
	struct threadlist *tl = NULL;
	struct uthread *uth = NULL;
	struct workitemlist *wl;
	boolean_t start_timer = FALSE;
	struct timeval tv, lat_tv;

	wq = (struct workqueue *)p->p_wqptr;

	KERNEL_DEBUG(0xefffd000 | DBG_FUNC_START, (int)thread, wq->wq_threads_scheduled, wq->wq_stalled_count, 0, 0);

	if (wq->wq_itemcount == 0) {
	        if ((th_to_park = thread) == THREAD_NULL)
		        goto out;
	        goto parkit;
	}
	if (thread != THREAD_NULL) {
	        /*
		 * we're a worker thread from the pool... currently we
		 * are considered 'active' which means we're counted
		 * in "wq_thactivecount"
		 */
	        uth = get_bsdthread_info(thread);
		tl = uth->uu_threadlist;

		if (wq->wq_thactivecount[tl->th_affinity_tag] == 1) {
		        /*
			 * we're the only active thread associated with our
			 * affinity group, so pick up some work and keep going
			 */
		        th_to_run = thread;
			goto pick_up_work;
		}
	}
	for (affinity_tag = 0; affinity_tag < wq->wq_affinity_max; affinity_tag++) {
	        /*
		 * look for first affinity group that is currently not active
		 * and has at least 1 idle thread
		 */
	        if (wq->wq_thactivecount[affinity_tag] == 0) {
			if (!TAILQ_EMPTY(&wq->wq_thidlelist[affinity_tag]))
			        break;
		        stalled_affinity_count++;
		}
	}
	if (thread == THREAD_NULL) {
	        /*
		 * we're not one of the 'worker' threads
		 */
	        if (affinity_tag >= wq->wq_affinity_max) {
		        /*
			 * we've already got at least 1 thread per
			 * affinity group in the active state... or
			 * we've got no idle threads to play with
			 */
		        if (stalled_affinity_count) {

				if ( !(wq->wq_flags & WQ_TIMER_RUNNING) ) {
				        wq->wq_flags |= WQ_TIMER_RUNNING;
					start_timer = TRUE;
				}
				wq->wq_flags |= WQ_TIMER_WATCH;
			}
			goto out;
		}
	} else {
	        /*
		 * we're overbooked on the affinity group we're associated with,
		 * so park this thread 
		 */
	        th_to_park = thread;

		if (affinity_tag >= wq->wq_affinity_max) {
		        /*
			 * all the affinity groups have active threads
			 * running, or there are no idle threads to 
			 * schedule
			 */
		        if (stalled_affinity_count) {

				if ( !(wq->wq_flags & WQ_TIMER_RUNNING) ) {
				        wq->wq_flags |= WQ_TIMER_RUNNING;
					start_timer = TRUE;
				}
				wq->wq_flags |= WQ_TIMER_WATCH;
			}
		        goto parkit;
		}
		/*
		 * we've got a candidate (affinity group with no currently
		 * active threads) to start a new thread on...
		 * we already know there is both work available
		 * and an idle thread with the correct affinity tag, so
		 * fall into the code that pulls a new thread and workitem...
		 * once we've kicked that thread off, we'll park this one
		 */
	}
	tl = TAILQ_FIRST(&wq->wq_thidlelist[affinity_tag]);
	TAILQ_REMOVE(&wq->wq_thidlelist[affinity_tag], tl, th_entry);
	
	th_to_run = tl->th_thread;
	TAILQ_INSERT_TAIL(&wq->wq_thrunlist, tl, th_entry);

	if ((tl->th_flags & TH_LIST_SUSPENDED) == TH_LIST_SUSPENDED) {
	        tl->th_flags &= ~TH_LIST_SUSPENDED;
		reuse_thread = 0;
	} else if ((tl->th_flags & TH_LIST_BLOCKED) == TH_LIST_BLOCKED) {
	        tl->th_flags &= ~TH_LIST_BLOCKED;
		wake_thread = 1;
	}
	tl->th_flags |= TH_LIST_RUNNING;

        wq->wq_threads_scheduled++;

	if (wq->wq_threads_scheduled > wq->wq_max_threads_scheduled)
	        wq->wq_max_threads_scheduled = wq->wq_threads_scheduled;

pick_up_work:
	for (i = 0; i < WORKQUEUE_NUMPRIOS; i++) {
	        wl = (struct workitemlist *)&wq->wq_list[i];

		if (!(TAILQ_EMPTY(&wl->wl_itemlist))) {

		        witem = TAILQ_FIRST(&wl->wl_itemlist);
			TAILQ_REMOVE(&wl->wl_itemlist, witem, wi_entry);
			wq->wq_itemcount--;

			item = witem->wi_item;
			witem->wi_item = (user_addr_t)0;
			TAILQ_INSERT_HEAD(&wl->wl_freelist, witem, wi_entry);

			break;
		}
	}
	if (witem == NULL)
	        panic("workq_run_nextitem: NULL witem");

	if (thread != th_to_run) {
	        /*
		 * we're starting up a thread from a parked/suspended condition
		 */
	        OSAddAtomic(1, (SInt32 *)&wq->wq_thactivecount[tl->th_affinity_tag]);
		OSAddAtomic(1, (SInt32 *)&tl->th_unparked);
	}
	if (wq->wq_itemcount == 0)
		wq->wq_flags &= ~WQ_TIMER_WATCH;
	else {
	        microuptime(&tv);
		/*
		 * if we had any affinity groups stall (no threads runnable)
		 * since we last scheduled an item... and
		 * the elapsed time since we last scheduled an item
		 * exceeds the latency tolerance...
		 * we ask the timer thread (which should already be running)
		 * to add some more threads to the pool
		 */
		if (wq->wq_stalled_count && !(wq->wq_flags & WQ_ADD_TO_POOL)) {
		        timersub(&tv, &wq->wq_lastran_ts, &lat_tv);

			if (((lat_tv.tv_sec * 1000000) + lat_tv.tv_usec) > wq_max_run_latency_usecs)
			        wq->wq_flags |= WQ_ADD_TO_POOL;

			KERNEL_DEBUG(0xefffd10c, wq->wq_stalled_count, lat_tv.tv_sec, lat_tv.tv_usec, wq->wq_flags, 0);
		}
		wq->wq_lastran_ts = tv;
	}
	wq->wq_stalled_count = 0;
        workqueue_unlock(p);

        KERNEL_DEBUG(0xefffd02c, wq->wq_thactivecount[0], wq->wq_thactivecount[1],
		     wq->wq_thactivecount[2], wq->wq_thactivecount[3], 0);

        KERNEL_DEBUG(0xefffd02c, wq->wq_thactivecount[4], wq->wq_thactivecount[5],
		     wq->wq_thactivecount[6], wq->wq_thactivecount[7], 0);

	/*
	 * if current thread is reused for workitem, does not return via unix_syscall
	 */
	wq_runitem(p, item, th_to_run, tl, reuse_thread, wake_thread, (thread == th_to_run));
	
	if (th_to_park == THREAD_NULL) {

	        KERNEL_DEBUG(0xefffd000 | DBG_FUNC_END, (int)thread, (int)item, wq->wq_flags, 1, 0);

		return;
	}
	workqueue_lock_spin(p);

parkit:
	wq->wq_threads_scheduled--;
	/*
	 * this is a workqueue thread with no more
	 * work to do... park it for now
	 */
	uth = get_bsdthread_info(th_to_park);
	tl = uth->uu_threadlist;
	if (tl == 0) 
	        panic("wq thread with no threadlist ");
	
	TAILQ_REMOVE(&wq->wq_thrunlist, tl, th_entry);
	tl->th_flags &= ~TH_LIST_RUNNING;

	tl->th_flags |= TH_LIST_BLOCKED;
	TAILQ_INSERT_HEAD(&wq->wq_thidlelist[tl->th_affinity_tag], tl, th_entry);

	assert_wait((caddr_t)tl, (THREAD_INTERRUPTIBLE));

	workqueue_unlock(p);

	if (start_timer)
		workqueue_interval_timer_start(wq->wq_timer_call, wq_timer_interval_msecs);

	KERNEL_DEBUG1(0xefffd018 | DBG_FUNC_START, (int)current_thread(), wq->wq_threads_scheduled, 0, 0, (int)th_to_park);

	thread_block((thread_continue_t)thread_exception_return);

	panic("unexpected return from thread_block");

out:
	workqueue_unlock(p);

	if (start_timer)
		workqueue_interval_timer_start(wq->wq_timer_call, wq_timer_interval_msecs);

	KERNEL_DEBUG(0xefffd000 | DBG_FUNC_END, (int)thread, 0, wq->wq_flags, 2, 0);

	return;
}

static void 
wq_runitem(proc_t p, user_addr_t item, thread_t th, struct threadlist *tl,
	   int reuse_thread, int wake_thread, int return_directly)
{
	int ret = 0;

	KERNEL_DEBUG1(0xefffd004 | DBG_FUNC_START, (int)current_thread(), (int)item, wake_thread, tl->th_affinity_tag, (int)th);

	ret = setup_wqthread(p, th, item, reuse_thread, tl);

	if (ret != 0)
		panic("setup_wqthread failed  %x\n", ret);

	if (return_directly) {
		thread_exception_return();

		panic("wq_runitem: thread_exception_return returned ...\n");
	}
	if (wake_thread) {
		KERNEL_DEBUG1(0xefffd018 | DBG_FUNC_END, (int)current_thread(), 0, 0, 0, (int)th);
	
		wakeup(tl);
	} else {
	        KERNEL_DEBUG1(0xefffd014 | DBG_FUNC_END, (int)current_thread(), 0, 0, 0, (int)th);

		thread_resume(th);
	}
}


int
setup_wqthread(proc_t p, thread_t th, user_addr_t item, int reuse_thread, struct threadlist *tl)
{
#if defined(__ppc__)
	/*
	 * Set up PowerPC registers...
	 * internally they are always kept as 64 bit and
	 * since the register set is the same between 32 and 64bit modes
	 * we don't need 2 different methods for setting the state
	 */
	{
	        ppc_thread_state64_t state64;
		ppc_thread_state64_t *ts64 = &state64;

		ts64->srr0 = (uint64_t)p->p_wqthread;
		ts64->r1 = (uint64_t)((tl->th_stackaddr + PTH_DEFAULT_STACKSIZE + PTH_DEFAULT_GUARDSIZE) - C_ARGSAVE_LEN - C_RED_ZONE);
		ts64->r3 = (uint64_t)(tl->th_stackaddr + PTH_DEFAULT_STACKSIZE + PTH_DEFAULT_GUARDSIZE);
		ts64->r4 = (uint64_t)((unsigned int)tl->th_thport);
		ts64->r5 = (uint64_t)(tl->th_stackaddr + PTH_DEFAULT_GUARDSIZE);
		ts64->r6 = (uint64_t)item;
		ts64->r7 = (uint64_t)reuse_thread;
		ts64->r8 = (uint64_t)0;

		thread_set_wq_state64(th, (thread_state_t)ts64);
	}
#elif defined(__i386__)
	int isLP64 = 0;

	isLP64 = IS_64BIT_PROCESS(p);
        /*
         * Set up i386 registers & function call.
         */
	if (isLP64 == 0) {
		x86_thread_state32_t state;
		x86_thread_state32_t *ts = &state;

        	ts->eip = (int)p->p_wqthread;
		ts->eax = (unsigned int)(tl->th_stackaddr + PTH_DEFAULT_STACKSIZE + PTH_DEFAULT_GUARDSIZE);
		ts->ebx = (unsigned int)tl->th_thport;
		ts->ecx = (unsigned int)(tl->th_stackaddr + PTH_DEFAULT_GUARDSIZE);
		ts->edx = (unsigned int)item;
		ts->edi = (unsigned int)reuse_thread;
		ts->esi = (unsigned int)0;
		/*
		 * set stack pointer
		 */
        	ts->esp = (int)((vm_offset_t)((tl->th_stackaddr + PTH_DEFAULT_STACKSIZE + PTH_DEFAULT_GUARDSIZE) - C_32_STK_ALIGN));

		thread_set_wq_state32(th, (thread_state_t)ts);

	} else {
	        x86_thread_state64_t state64;
		x86_thread_state64_t *ts64 = &state64;

        	ts64->rip = (uint64_t)p->p_wqthread;
		ts64->rdi = (uint64_t)(tl->th_stackaddr + PTH_DEFAULT_STACKSIZE + PTH_DEFAULT_GUARDSIZE);
		ts64->rsi = (uint64_t)((unsigned int)(tl->th_thport));
		ts64->rdx = (uint64_t)(tl->th_stackaddr + PTH_DEFAULT_GUARDSIZE);
		ts64->rcx = (uint64_t)item;
		ts64->r8 = (uint64_t)reuse_thread;
		ts64->r9 = (uint64_t)0;

		/*
		 * set stack pointer aligned to 16 byte boundary
		 */
		ts64->rsp = (uint64_t)((tl->th_stackaddr + PTH_DEFAULT_STACKSIZE + PTH_DEFAULT_GUARDSIZE) - C_64_REDZONE_LEN);

		thread_set_wq_state64(th, (thread_state_t)ts64);
	}
#else
#error setup_wqthread  not defined for this architecture
#endif
	return(0);
}

