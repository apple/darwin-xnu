/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/file_internal.h>
#include <sys/proc_internal.h>
#include <sys/kernel.h>
#include <sys/guarded.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/pthread_shims.h>

#include <mach/mach_types.h>

#include <kern/cpu_data.h>
#include <kern/mach_param.h>
#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <kern/ledger.h>
#include <kern/policy_internal.h>
#include <kern/task.h>
#include <kern/telemetry.h>
#include <kern/waitq.h>
#include <kern/sched_prim.h>
#include <kern/turnstile.h>
#include <kern/zalloc.h>
#include <kern/debug.h>

#include <pexpert/pexpert.h>

#define XNU_TEST_BITMAP
#include <kern/bits.h>

#include <sys/ulock.h>

/*
 * How ulock promotion works:
 *
 * There’s a requested policy field on every thread called ‘promotions’, which
 * expresses which ulock promotions are happening to this thread.
 * The promotion priority saturates until the promotion count goes to 0.
 *
 * We also track effective promotion qos, which is the qos before clamping.
 * This value is used for promoting a thread that another thread is waiting on,
 * so that the lock owner reinflates to the right priority after unclamping.
 *
 * This also works for non-QoS threads, which can donate base priority to QoS
 * and non-QoS threads alike.
 *
 * ulock wait applies a promotion to the owner communicated through
 * UL_UNFAIR_LOCK as waiters block, and that promotion is saturated as long as
 * there is still an owner.  In ulock wake, if the waker is still the owner,
 * then it clears its ownership and drops the boost.  It does NOT transfer
 * ownership/priority boost to the new thread.  Instead, it selects the
 * waiting thread with the highest base priority to be woken next, and
 * relies on that thread to carry the torch for the other waiting threads.
 */

static lck_grp_t *ull_lck_grp;

typedef lck_spin_t ull_lock_t;
#define ull_lock_init(ull)      lck_spin_init(&ull->ull_lock, ull_lck_grp, NULL)
#define ull_lock_destroy(ull)   lck_spin_destroy(&ull->ull_lock, ull_lck_grp)
#define ull_lock(ull)           lck_spin_lock(&ull->ull_lock)
#define ull_unlock(ull)         lck_spin_unlock(&ull->ull_lock)
#define ull_assert_owned(ull)   LCK_SPIN_ASSERT(&ull->ull_lock, LCK_ASSERT_OWNED)
#define ull_assert_notwned(ull) LCK_SPIN_ASSERT(&ull->ull_lock, LCK_ASSERT_NOTOWNED)

#define ULOCK_TO_EVENT(ull)   ((event_t)ull)
#define EVENT_TO_ULOCK(event) ((ull_t *)event)

typedef struct __attribute__((packed)) {
	user_addr_t	ulk_addr;
	pid_t		ulk_pid;
} ulk_t;

inline static bool
ull_key_match(ulk_t *a, ulk_t *b)
{
	return ((a->ulk_pid == b->ulk_pid) &&
		(a->ulk_addr == b->ulk_addr));
}

typedef struct ull {
	/*
	 * ull_owner is the most recent known value for the owner of this ulock
	 * i.e. it may be out of date WRT the real value in userspace.
	 */
	thread_t        ull_owner; /* holds +1 thread reference */
	ulk_t		ull_key;
	ulk_t		ull_saved_key;
	ull_lock_t	ull_lock;
	uint		ull_bucket_index;
	int32_t		ull_nwaiters;
	int32_t		ull_max_nwaiters;
	int32_t		ull_refcount;
	uint8_t		ull_opcode;
	struct turnstile *ull_turnstile;
	queue_chain_t	ull_hash_link;
} ull_t;

extern void ulock_initialize(void);

#define ULL_MUST_EXIST	0x0001
static ull_t *ull_get(ulk_t *, uint32_t, ull_t **);
static void ull_put(ull_t *);

#if DEVELOPMENT || DEBUG
static int ull_simulate_copyin_fault = 0;

static void
ull_dump(ull_t *ull)
{
	kprintf("ull\t%p\n", ull);
	kprintf("ull_key.ulk_pid\t%d\n", ull->ull_key.ulk_pid);
	kprintf("ull_key.ulk_addr\t%p\n", (void *)(ull->ull_key.ulk_addr));
	kprintf("ull_saved_key.ulk_pid\t%d\n", ull->ull_saved_key.ulk_pid);
	kprintf("ull_saved_key.ulk_addr\t%p\n", (void *)(ull->ull_saved_key.ulk_addr));
	kprintf("ull_nwaiters\t%d\n", ull->ull_nwaiters);
	kprintf("ull_max_nwaiters\t%d\n", ull->ull_max_nwaiters);
	kprintf("ull_refcount\t%d\n", ull->ull_refcount);
	kprintf("ull_opcode\t%d\n\n", ull->ull_opcode);
	kprintf("ull_owner\t0x%llx\n\n", thread_tid(ull->ull_owner));
	kprintf("ull_turnstile\t%p\n\n", ull->ull_turnstile);
}
#endif

typedef struct ull_bucket {
	queue_head_t ulb_head;
	lck_spin_t   ulb_lock;
} ull_bucket_t;

static int ull_hash_buckets;
static ull_bucket_t *ull_bucket;
static uint32_t ull_nzalloc = 0;
static zone_t ull_zone;

#define ull_bucket_lock(i)       lck_spin_lock(&ull_bucket[i].ulb_lock)
#define ull_bucket_unlock(i)     lck_spin_unlock(&ull_bucket[i].ulb_lock)

static __inline__ uint32_t
ull_hash_index(char *key, size_t length)
{
	uint32_t hash = jenkins_hash(key, length);

	hash &= (ull_hash_buckets - 1);

	return hash;
}

/* Ensure that the key structure is packed,
 * so that no undefined memory is passed to
 * ull_hash_index()
 */
static_assert(sizeof(ulk_t) == sizeof(user_addr_t) + sizeof(pid_t));

#define ULL_INDEX(keyp)	ull_hash_index((char *)keyp, sizeof *keyp)

void
ulock_initialize(void)
{
	ull_lck_grp = lck_grp_alloc_init("ulocks", NULL);

	assert(thread_max > 16);
	/* Size ull_hash_buckets based on thread_max.
	 * Round up to nearest power of 2, then divide by 4
	 */
	ull_hash_buckets = (1 << (bit_ceiling(thread_max) - 2));

	kprintf("%s>thread_max=%d, ull_hash_buckets=%d\n", __FUNCTION__, thread_max, ull_hash_buckets);
	assert(ull_hash_buckets >= thread_max/4);

	ull_bucket = (ull_bucket_t *)kalloc(sizeof(ull_bucket_t) * ull_hash_buckets);
	assert(ull_bucket != NULL);

	for (int i = 0; i < ull_hash_buckets; i++) {
		queue_init(&ull_bucket[i].ulb_head);
		lck_spin_init(&ull_bucket[i].ulb_lock, ull_lck_grp, NULL);
	}

	ull_zone = zinit(sizeof(ull_t),
	                 thread_max * sizeof(ull_t),
	                 0, "ulocks");

	zone_change(ull_zone, Z_NOENCRYPT, TRUE);
}

#if DEVELOPMENT || DEBUG
/* Count the number of hash entries for a given pid.
 * if pid==0, dump the whole table.
 */
static int
ull_hash_dump(pid_t pid)
{
	int count = 0;
	if (pid == 0) {
		kprintf("%s>total number of ull_t allocated %d\n", __FUNCTION__, ull_nzalloc);
		kprintf("%s>BEGIN\n", __FUNCTION__);
	}
	for (int i = 0; i < ull_hash_buckets; i++) {
		ull_bucket_lock(i);
		if (!queue_empty(&ull_bucket[i].ulb_head)) {
			ull_t *elem;
			if (pid == 0) {
				kprintf("%s>index %d:\n", __FUNCTION__, i);
			}
			qe_foreach_element(elem, &ull_bucket[i].ulb_head, ull_hash_link) {
				if ((pid == 0) || (pid == elem->ull_key.ulk_pid)) {
					ull_dump(elem);
					count++;
				}
			}
		}
		ull_bucket_unlock(i);
	}
	if (pid == 0) {
		kprintf("%s>END\n", __FUNCTION__);
		ull_nzalloc = 0;
	}
	return count;
}
#endif

static ull_t *
ull_alloc(ulk_t *key)
{
	ull_t *ull = (ull_t *)zalloc(ull_zone);
	assert(ull != NULL);

	ull->ull_refcount = 1;
	ull->ull_key = *key;
	ull->ull_saved_key = *key;
	ull->ull_bucket_index = ULL_INDEX(key);
	ull->ull_nwaiters = 0;
	ull->ull_max_nwaiters = 0;
	ull->ull_opcode = 0;

	ull->ull_owner = THREAD_NULL;
	ull->ull_turnstile = TURNSTILE_NULL;

	ull_lock_init(ull);

	ull_nzalloc++;
	return ull;
}

static void
ull_free(ull_t *ull)
{
	assert(ull->ull_owner == THREAD_NULL);
	assert(ull->ull_turnstile == TURNSTILE_NULL);

	ull_assert_notwned(ull);

	ull_lock_destroy(ull);

	zfree(ull_zone, ull);
}

/* Finds an existing ulock structure (ull_t), or creates a new one.
 * If MUST_EXIST flag is set, returns NULL instead of creating a new one.
 * The ulock structure is returned with ull_lock locked
 */
static ull_t *
ull_get(ulk_t *key, uint32_t flags, ull_t **unused_ull)
{
	ull_t *ull = NULL;
	uint i = ULL_INDEX(key);
	ull_t *new_ull = (flags & ULL_MUST_EXIST) ? NULL : ull_alloc(key);
	ull_t *elem;

	ull_bucket_lock(i);
	qe_foreach_element(elem, &ull_bucket[i].ulb_head, ull_hash_link) {
		ull_lock(elem);
		if (ull_key_match(&elem->ull_key, key)) {
			ull = elem;
			break;
		} else {
			ull_unlock(elem);
		}
	}
	if (ull == NULL) {
		if (flags & ULL_MUST_EXIST) {
			/* Must already exist (called from wake) */
			ull_bucket_unlock(i);
			assert(new_ull == NULL);
			assert(unused_ull == NULL);
			return NULL;
		}

		if (new_ull == NULL) {
			/* Alloc above failed */
			ull_bucket_unlock(i);
			return NULL;
		}

		ull = new_ull;
		ull_lock(ull);
		enqueue(&ull_bucket[i].ulb_head, &ull->ull_hash_link);
	} else if (!(flags & ULL_MUST_EXIST)) {
		assert(new_ull);
		assert(unused_ull);
		assert(*unused_ull == NULL);
		*unused_ull = new_ull;
	}

	ull->ull_refcount++;

	ull_bucket_unlock(i);

	return ull; /* still locked */
}

/*
 * Must be called with ull_lock held
 */
static void
ull_put(ull_t *ull)
{
	ull_assert_owned(ull);
	int refcount = --ull->ull_refcount;
	assert(refcount == 0 ? (ull->ull_key.ulk_pid == 0 && ull->ull_key.ulk_addr == 0) : 1);
	ull_unlock(ull);

	if (refcount > 0) {
		return;
	}

	ull_bucket_lock(ull->ull_bucket_index);
	remqueue(&ull->ull_hash_link);
	ull_bucket_unlock(ull->ull_bucket_index);

	ull_free(ull);
}

static void ulock_wait_continue(void *, wait_result_t);
static void ulock_wait_cleanup(ull_t *, thread_t, thread_t, int32_t *);

inline static int
wait_result_to_return_code(wait_result_t wr)
{
	int ret = 0;

	switch (wr) {
	case THREAD_AWAKENED:
		break;
	case THREAD_TIMED_OUT:
		ret = ETIMEDOUT;
		break;
	case THREAD_INTERRUPTED:
	case THREAD_RESTART:
	default:
		ret = EINTR;
		break;
	}

	return ret;
}

int
ulock_wait(struct proc *p, struct ulock_wait_args *args, int32_t *retval)
{
	uint opcode = args->operation & UL_OPCODE_MASK;
	uint flags = args->operation & UL_FLAGS_MASK;

	if (flags & ULF_WAIT_CANCEL_POINT) {
		__pthread_testcancel(1);
	}

	int ret = 0;
	thread_t self = current_thread();
	ulk_t key;

	/* involved threads - each variable holds +1 ref if not null */
	thread_t owner_thread   = THREAD_NULL;
	thread_t old_owner      = THREAD_NULL;

	ull_t *unused_ull = NULL;

	if ((flags & ULF_WAIT_MASK) != flags) {
		ret = EINVAL;
		goto munge_retval;
	}

	boolean_t set_owner = FALSE;

	switch (opcode) {
	case UL_UNFAIR_LOCK:
		set_owner = TRUE;
		break;
	case UL_COMPARE_AND_WAIT:
		break;
	default:
		ret = EINVAL;
		goto munge_retval;
	}

	/* 32-bit lock type for UL_COMPARE_AND_WAIT and UL_UNFAIR_LOCK */
	uint32_t value = 0;

	if ((args->addr == 0) || (args->addr % _Alignof(_Atomic(typeof(value))))) {
		ret = EINVAL;
		goto munge_retval;
	}

	key.ulk_pid = p->p_pid;
	key.ulk_addr = args->addr;

	ull_t *ull = ull_get(&key, 0, &unused_ull);
	if (ull == NULL) {
		ret = ENOMEM;
		goto munge_retval;
	}
	/* ull is locked */

	ull->ull_nwaiters++;

	if (ull->ull_nwaiters > ull->ull_max_nwaiters) {
		ull->ull_max_nwaiters = ull->ull_nwaiters;
	}

	if (ull->ull_opcode == 0) {
		ull->ull_opcode = opcode;
	} else if (ull->ull_opcode != opcode) {
		ret = EDOM;
		goto out_locked;
	}

	/*
	 * We don't want this copyin to get wedged behind VM operations,
	 * but we have to read the userspace value under the ull lock for correctness.
	 *
	 * Until <rdar://problem/24999882> exists,
	 * holding the ull spinlock across copyin forces any
	 * vm_fault we encounter to fail.
	 */
	uint64_t val64; /* copyin_word always zero-extends to 64-bits */

	int copy_ret = copyin_word(args->addr, &val64, sizeof(value));

	value = (uint32_t)val64;

#if DEVELOPMENT || DEBUG
	/* Occasionally simulate copyin finding the user address paged out */
	if (((ull_simulate_copyin_fault == p->p_pid) || (ull_simulate_copyin_fault == 1)) && (copy_ret == 0)) {
		static _Atomic int fault_inject = 0;
		if (__c11_atomic_fetch_add(&fault_inject, 1, __ATOMIC_RELAXED) % 73 == 0) {
			copy_ret = EFAULT;
		}
	}
#endif
	if (copy_ret != 0) {
		/* copyin() will return an error if the access to the user addr would have faulted,
		 * so just return and let the user level code fault it in.
		 */
		ret = copy_ret;
		goto out_locked;
	}

	if (value != args->value) {
		/* Lock value has changed from expected so bail out */
		goto out_locked;
	}

	if (set_owner) {
		mach_port_name_t owner_name = ulock_owner_value_to_port_name(args->value);
		owner_thread = port_name_to_thread_for_ulock(owner_name);

		/* HACK: don't bail on MACH_PORT_DEAD, to avoid blowing up the no-tsd pthread lock */
		if (owner_name != MACH_PORT_DEAD && owner_thread == THREAD_NULL) {
			/*
			 * Translation failed - even though the lock value is up to date,
			 * whatever was stored in the lock wasn't actually a thread port.
			 */
			ret = EOWNERDEAD;
			goto out_locked;
		}
		/* owner_thread has a +1 reference */

		/*
		 * At this point, I know:
		 * a) owner_thread is definitely the current owner, because I just read the value
		 * b) owner_thread is either:
		 *      i) holding the user lock or
		 *      ii) has just unlocked the user lock after I looked
		 *              and is heading toward the kernel to call ull_wake.
		 *              If so, it's going to have to wait for the ull mutex.
		 *
		 * Therefore, I can ask the turnstile to promote its priority, and I can rely
		 * on it to come by later to issue the wakeup and lose its promotion.
		 */

		/* Return the +1 ref from the ull_owner field */
		old_owner = ull->ull_owner;
		ull->ull_owner = THREAD_NULL;

		if (owner_thread != THREAD_NULL) {
			/* The ull_owner field now owns a +1 ref on owner_thread */
			thread_reference(owner_thread);
			ull->ull_owner = owner_thread;
		}
	}

	wait_result_t wr;
	uint32_t timeout = args->timeout;
	uint64_t deadline = TIMEOUT_WAIT_FOREVER;
	wait_interrupt_t interruptible = THREAD_ABORTSAFE;
	struct turnstile *ts;

	ts = turnstile_prepare((uintptr_t)ull, &ull->ull_turnstile,
	                       TURNSTILE_NULL, TURNSTILE_ULOCK);
	thread_set_pending_block_hint(self, kThreadWaitUserLock);

	if (flags & ULF_WAIT_WORKQ_DATA_CONTENTION) {
		interruptible |= THREAD_WAIT_NOREPORT;
	}

	if (timeout) {
		clock_interval_to_deadline(timeout, NSEC_PER_USEC, &deadline);
	}

	turnstile_update_inheritor(ts, owner_thread,
		(TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	wr = waitq_assert_wait64(&ts->ts_waitq, CAST_EVENT64_T(ULOCK_TO_EVENT(ull)),
			interruptible, deadline);

	ull_unlock(ull);

	if (unused_ull) {
		ull_free(unused_ull);
		unused_ull = NULL;
	}

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_NOT_HELD);

	if (wr == THREAD_WAITING) {
		uthread_t uthread = (uthread_t)get_bsdthread_info(self);
		uthread->uu_save.uus_ulock_wait_data.retval = retval;
		uthread->uu_save.uus_ulock_wait_data.flags = flags;
		uthread->uu_save.uus_ulock_wait_data.owner_thread = owner_thread;
		uthread->uu_save.uus_ulock_wait_data.old_owner = old_owner;
		if (set_owner && owner_thread != THREAD_NULL) {
			thread_handoff_parameter(owner_thread, ulock_wait_continue, ull);
		} else {
			assert(owner_thread == THREAD_NULL);
			thread_block_parameter(ulock_wait_continue, ull);
		}
		/* NOT REACHED */
	}

	ret = wait_result_to_return_code(wr);

	ull_lock(ull);
	turnstile_complete((uintptr_t)ull, &ull->ull_turnstile, NULL);

out_locked:
	ulock_wait_cleanup(ull, owner_thread, old_owner, retval);

	if (unused_ull) {
		ull_free(unused_ull);
		unused_ull = NULL;
	}

	assert(*retval >= 0);

munge_retval:
	if ((flags & ULF_NO_ERRNO) && (ret != 0)) {
		*retval = -ret;
		ret = 0;
	}
	return ret;
}

/*
 * Must be called with ull_lock held
 */
static void
ulock_wait_cleanup(ull_t *ull, thread_t owner_thread, thread_t old_owner, int32_t *retval)
{
	ull_assert_owned(ull);

	thread_t old_lingering_owner = THREAD_NULL;

	*retval = --ull->ull_nwaiters;
	if (ull->ull_nwaiters == 0) {
		/*
		 * If the wait was canceled early, we might need to
		 * clear out the lingering owner reference before
		 * freeing the ull.
		 */
		old_lingering_owner = ull->ull_owner;
		ull->ull_owner = THREAD_NULL;

		ull->ull_key.ulk_pid = 0;
		ull->ull_key.ulk_addr = 0;
		ull->ull_refcount--;
		assert(ull->ull_refcount > 0);
	}
	ull_put(ull);

	/* Need to be called after dropping the interlock */
	turnstile_cleanup();

	if (owner_thread != THREAD_NULL) {
		thread_deallocate(owner_thread);
	}

	if (old_owner != THREAD_NULL) {
		thread_deallocate(old_owner);
	}

	if (old_lingering_owner != THREAD_NULL) {
		thread_deallocate(old_lingering_owner);
	}

	assert(*retval >= 0);
}

__attribute__((noreturn))
static void
ulock_wait_continue(void * parameter, wait_result_t wr)
{
	thread_t self = current_thread();
	uthread_t uthread = (uthread_t)get_bsdthread_info(self);
	int ret = 0;

	ull_t *ull = (ull_t *)parameter;
	int32_t *retval = uthread->uu_save.uus_ulock_wait_data.retval;
	uint flags = uthread->uu_save.uus_ulock_wait_data.flags;
	thread_t owner_thread = uthread->uu_save.uus_ulock_wait_data.owner_thread;
	thread_t old_owner = uthread->uu_save.uus_ulock_wait_data.old_owner;

	ret = wait_result_to_return_code(wr);

	ull_lock(ull);
	turnstile_complete((uintptr_t)ull, &ull->ull_turnstile, NULL);

	ulock_wait_cleanup(ull, owner_thread, old_owner, retval);

	if ((flags & ULF_NO_ERRNO) && (ret != 0)) {
		*retval = -ret;
		ret = 0;
	}

	unix_syscall_return(ret);
}

int
ulock_wake(struct proc *p, struct ulock_wake_args *args, __unused int32_t *retval)
{
	uint opcode = args->operation & UL_OPCODE_MASK;
	uint flags = args->operation & UL_FLAGS_MASK;
	int ret = 0;
	ulk_t key;

	/* involved threads - each variable holds +1 ref if not null */
	thread_t wake_thread    = THREAD_NULL;
	thread_t old_owner      = THREAD_NULL;

	if ((flags & ULF_WAKE_MASK) != flags) {
		ret = EINVAL;
		goto munge_retval;
	}

#if DEVELOPMENT || DEBUG
	if (opcode == UL_DEBUG_HASH_DUMP_PID) {
		*retval = ull_hash_dump(p->p_pid);
		return ret;
	} else if (opcode == UL_DEBUG_HASH_DUMP_ALL) {
		*retval = ull_hash_dump(0);
		return ret;
	} else if (opcode == UL_DEBUG_SIMULATE_COPYIN_FAULT) {
		ull_simulate_copyin_fault = (int)(args->wake_value);
		return ret;
	}
#endif

	if (args->addr == 0) {
		ret = EINVAL;
		goto munge_retval;
	}

	if (flags & ULF_WAKE_THREAD) {
		if (flags & ULF_WAKE_ALL) {
			ret = EINVAL;
			goto munge_retval;
		}
		mach_port_name_t wake_thread_name = (mach_port_name_t)(args->wake_value);
		wake_thread = port_name_to_thread_for_ulock(wake_thread_name);
		if (wake_thread == THREAD_NULL) {
			ret = ESRCH;
			goto munge_retval;
		}
	}

	key.ulk_pid = p->p_pid;
	key.ulk_addr = args->addr;

	ull_t *ull = ull_get(&key, ULL_MUST_EXIST, NULL);
	if (ull == NULL) {
		if (wake_thread != THREAD_NULL) {
			thread_deallocate(wake_thread);
		}
		ret = ENOENT;
		goto munge_retval;
	}
	/* ull is locked */

	boolean_t clear_owner = FALSE; /* need to reset owner */

	switch (opcode) {
	case UL_UNFAIR_LOCK:
		clear_owner = TRUE;
		break;
	case UL_COMPARE_AND_WAIT:
		break;
	default:
		ret = EINVAL;
		goto out_locked;
	}

	if (opcode != ull->ull_opcode) {
		ret = EDOM;
		goto out_locked;
	}

	if (!clear_owner) {
		assert(ull->ull_owner == THREAD_NULL);
	}

	struct turnstile *ts;
	ts = turnstile_prepare((uintptr_t)ull, &ull->ull_turnstile,
	                       TURNSTILE_NULL, TURNSTILE_ULOCK);

	if (flags & ULF_WAKE_ALL) {
		waitq_wakeup64_all(&ts->ts_waitq, CAST_EVENT64_T(ULOCK_TO_EVENT(ull)),
			THREAD_AWAKENED, 0);
	} else if (flags & ULF_WAKE_THREAD) {
		kern_return_t kr = waitq_wakeup64_thread(&ts->ts_waitq, CAST_EVENT64_T(ULOCK_TO_EVENT(ull)),
			wake_thread, THREAD_AWAKENED);
		if (kr != KERN_SUCCESS) {
			assert(kr == KERN_NOT_WAITING);
			ret = EALREADY;
		}
	} else {
		/*
		 * TODO: WAITQ_SELECT_MAX_PRI forces a linear scan of the (hashed) global waitq.
		 * Move to a ulock-private, priority sorted waitq (i.e. SYNC_POLICY_FIXED_PRIORITY) to avoid that.
		 *
		 * TODO: 'owner is not current_thread (or null)' likely means we can avoid this wakeup
		 * <rdar://problem/25487001>
		 */
		waitq_wakeup64_one(&ts->ts_waitq, CAST_EVENT64_T(ULOCK_TO_EVENT(ull)),
			THREAD_AWAKENED, WAITQ_SELECT_MAX_PRI);
	}

	/*
	 * Reaching this point means I previously moved the lock to 'unowned' state in userspace.
	 * Therefore I need to relinquish my promotion.
	 *
	 * However, someone else could have locked it after I unlocked, and then had a third thread
	 * block on the lock, causing a promotion of some other owner.
	 *
	 * I don't want to stomp over that, so only remove the promotion if I'm the current owner.
	 */

	if (ull->ull_owner == current_thread()) {
		turnstile_update_inheritor(ts, THREAD_NULL,
			(TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
		old_owner = ull->ull_owner;
		ull->ull_owner = THREAD_NULL;
	}

	turnstile_complete((uintptr_t)ull, &ull->ull_turnstile, NULL);

out_locked:
	ull_put(ull);

	/* Need to be called after dropping the interlock */
	turnstile_cleanup();

	if (wake_thread != THREAD_NULL) {
		thread_deallocate(wake_thread);
	}

	if (old_owner != THREAD_NULL) {
		thread_deallocate(old_owner);
	}

munge_retval:
	if ((flags & ULF_NO_ERRNO) && (ret != 0)) {
		*retval = -ret;
		ret = 0;
	}
	return ret;
}

void
kdp_ulock_find_owner(__unused struct waitq * waitq, event64_t event, thread_waitinfo_t * waitinfo)
{
	ull_t *ull = EVENT_TO_ULOCK(event);
	assert(kdp_is_in_zone(ull, "ulocks"));

	if (ull->ull_opcode == UL_UNFAIR_LOCK) {// owner is only set if it's an os_unfair_lock
		waitinfo->owner = thread_tid(ull->ull_owner);
		waitinfo->context = ull->ull_key.ulk_addr;
	} else if (ull->ull_opcode == UL_COMPARE_AND_WAIT) { // otherwise, this is a spinlock
		waitinfo->owner = 0;
		waitinfo->context = ull->ull_key.ulk_addr;
	} else {
		panic("%s: Invalid ulock opcode %d addr %p", __FUNCTION__, ull->ull_opcode, (void*)ull);
	}
	return;
}
