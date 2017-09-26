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
static lck_mtx_t ull_table_lock;

#define ull_global_lock()       lck_mtx_lock(&ull_table_lock)
#define ull_global_unlock()     lck_mtx_unlock(&ull_table_lock)

#define ull_lock(ull)           lck_mtx_lock(&ull->ull_lock)
#define ull_unlock(ull)         lck_mtx_unlock(&ull->ull_lock)
#define ull_assert_owned(ull)	LCK_MTX_ASSERT(&ull->ull_lock, LCK_MTX_ASSERT_OWNED)

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
	lck_mtx_t	ull_lock;
	int32_t		ull_nwaiters;
	int32_t		ull_max_nwaiters;
	int32_t		ull_refcount;
	struct promote_token ull_promote_token;
	queue_chain_t	ull_hash_link;
	uint8_t		ull_opcode;
} ull_t;

static const bool ull_debug = false;

extern void ulock_initialize(void);

#define ULL_MUST_EXIST	0x0001
static ull_t *ull_get(ulk_t *, uint32_t);
static void ull_put(ull_t *);

static thread_t ull_promote_owner_locked(ull_t* ull, thread_t thread);

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
	kprintf("ull_promote_token\t%d, %d\n\n", ull->ull_promote_token.pt_basepri, ull->ull_promote_token.pt_qos);
}
#endif

static int ull_hash_buckets;
static queue_head_t *ull_bucket;
static uint32_t ull_nzalloc = 0;
static zone_t ull_zone;

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
	lck_mtx_init(&ull_table_lock, ull_lck_grp, NULL);

	assert(thread_max > 16);
	/* Size ull_hash_buckets based on thread_max.
	 * Round up to nearest power of 2, then divide by 4
	 */
	ull_hash_buckets = (1 << (bit_ceiling(thread_max) - 2));

	kprintf("%s>thread_max=%d, ull_hash_buckets=%d\n", __FUNCTION__, thread_max, ull_hash_buckets);
	assert(ull_hash_buckets >= thread_max/4);

	ull_bucket = (queue_head_t *)kalloc(sizeof(queue_head_t) * ull_hash_buckets);
	assert(ull_bucket != NULL);

	for (int i = 0; i < ull_hash_buckets; i++) {
		queue_init(&ull_bucket[i]);
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
	ull_global_lock();
	if (pid == 0) {
		kprintf("%s>total number of ull_t allocated %d\n", __FUNCTION__, ull_nzalloc);
		kprintf("%s>BEGIN\n", __FUNCTION__);
	}
	for (int i = 0; i < ull_hash_buckets; i++) {
		if (!queue_empty(&ull_bucket[i])) {
			ull_t *elem;
			if (pid == 0) {
				kprintf("%s>index %d:\n", __FUNCTION__, i);
			}
			qe_foreach_element(elem, &ull_bucket[i], ull_hash_link) {
				if ((pid == 0) || (pid == elem->ull_key.ulk_pid)) {
					ull_dump(elem);
					count++;
				}
			}
		}
	}
	if (pid == 0) {
		kprintf("%s>END\n", __FUNCTION__);
		ull_nzalloc = 0;
	}
	ull_global_unlock();
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
	ull->ull_nwaiters = 0;
	ull->ull_max_nwaiters = 0;
	ull->ull_opcode = 0;

	ull->ull_owner = THREAD_NULL;
	ull->ull_promote_token = PROMOTE_TOKEN_INIT;

	lck_mtx_init(&ull->ull_lock, ull_lck_grp, NULL);

	ull_nzalloc++;
	return ull;
}

static void
ull_free(ull_t *ull)
{
	assert(ull->ull_owner == THREAD_NULL);

	LCK_MTX_ASSERT(&ull->ull_lock, LCK_ASSERT_NOTOWNED);

	lck_mtx_destroy(&ull->ull_lock, ull_lck_grp);

	zfree(ull_zone, ull);
}

/* Finds an existing ulock structure (ull_t), or creates a new one.
 * If MUST_EXIST flag is set, returns NULL instead of creating a new one.
 * The ulock structure is returned with ull_lock locked
 *
 * TODO: Per-bucket lock to reduce contention on global lock
 */
static ull_t *
ull_get(ulk_t *key, uint32_t flags)
{
	ull_t *ull = NULL;
	uint i = ULL_INDEX(key);
	ull_t *elem;
	ull_global_lock();
	qe_foreach_element(elem, &ull_bucket[i], ull_hash_link) {
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
			ull_global_unlock();
			return NULL;
		}

		/* NRG maybe drop the ull_global_lock before the kalloc,
		 * then take the lock and check again for a key match
		 * and either use the new ull_t or free it.
		 */

		ull = ull_alloc(key);

		if (ull == NULL) {
			ull_global_unlock();
			return NULL;
		}

		ull_lock(ull);

		enqueue(&ull_bucket[i], &ull->ull_hash_link);
	}

	ull->ull_refcount++;

	ull_global_unlock();

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

	ull_global_lock();
	remqueue(&ull->ull_hash_link);
	ull_global_unlock();

#if DEVELOPMENT || DEBUG
	if (ull_debug) {
		kprintf("%s>", __FUNCTION__);
		ull_dump(ull);
	}
#endif
	ull_free(ull);
}

int
ulock_wait(struct proc *p, struct ulock_wait_args *args, int32_t *retval)
{
	uint opcode = args->operation & UL_OPCODE_MASK;
	uint flags = args->operation & UL_FLAGS_MASK;
	int ret = 0;
	thread_t self = current_thread();
	int id = thread_tid(self);
	ulk_t key;

	/* involved threads - each variable holds +1 ref if not null */
	thread_t owner_thread   = THREAD_NULL;
	thread_t old_owner      = THREAD_NULL;
	thread_t old_lingering_owner = THREAD_NULL;
	sched_call_t workq_callback = NULL;

	if (ull_debug) {
		kprintf("[%d]%s>ENTER opcode %d addr %llx value %llx timeout %d flags %x\n", id, __FUNCTION__, opcode, (unsigned long long)(args->addr), args->value, args->timeout, flags);
	}

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
		if (ull_debug) {
			kprintf("[%d]%s>EINVAL opcode %d addr 0x%llx flags 0x%x\n",
				id, __FUNCTION__, opcode,
				(unsigned long long)(args->addr), flags);
		}
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

	if (flags & ULF_WAIT_WORKQ_DATA_CONTENTION) {
		workq_callback = workqueue_get_sched_callback();
		workq_callback = thread_disable_sched_call(self, workq_callback);
	}

	ull_t *ull = ull_get(&key, 0);
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
		ull_unlock(ull);
		ret = EDOM;
		goto out;
	}

	/*
	 * We don't want this copyin to get wedged behind VM operations,
	 * but we have to read the userspace value under the ull lock for correctness.
	 *
	 * Until <rdar://problem/24999882> exists,
	 * fake it by disabling preemption across copyin, which forces any
	 * vm_fault we encounter to fail.
	 */
	uint64_t val64; /* copyin_word always zero-extends to 64-bits */

	disable_preemption();
	int copy_ret = copyin_word(args->addr, &val64, sizeof(value));
	enable_preemption();

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
		ull_unlock(ull);

		/* copyin() will return an error if the access to the user addr would have faulted,
		 * so just return and let the user level code fault it in.
		 */
		ret = copy_ret;
		goto out;
	}

	if (value != args->value) {
		/* Lock value has changed from expected so bail out */
		ull_unlock(ull);
		if (ull_debug) {
			kprintf("[%d]%s>Lock value %d has changed from expected %d so bail out\n",
			        id, __FUNCTION__, value, (uint32_t)(args->value));
		}
		goto out;
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
			ull_unlock(ull);
			ret = EOWNERDEAD;
			goto out;
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
		 * Therefore, I can promote its priority to match mine, and I can rely on it to
		 * come by later to issue the wakeup and lose its promotion.
		 */

		old_owner = ull_promote_owner_locked(ull, owner_thread);
	}

	wait_result_t wr;
	uint32_t timeout = args->timeout;
	thread_set_pending_block_hint(self, kThreadWaitUserLock);
	if (timeout) {
		wr = assert_wait_timeout(ULOCK_TO_EVENT(ull), THREAD_ABORTSAFE, timeout, NSEC_PER_USEC);
	} else {
		wr = assert_wait(ULOCK_TO_EVENT(ull), THREAD_ABORTSAFE);
	}

	ull_unlock(ull);

	if (ull_debug) {
		kprintf("[%d]%s>after assert_wait() returned %d\n", id, __FUNCTION__, wr);
	}

	if (set_owner && owner_thread != THREAD_NULL && wr == THREAD_WAITING) {
		wr = thread_handoff(owner_thread);
		/* owner_thread ref is consumed */
		owner_thread = THREAD_NULL;
	} else {
		/* NRG At some point this should be a continuation based block, so that we can avoid saving the full kernel context. */
		wr = thread_block(NULL);
	}
	if (ull_debug) {
		kprintf("[%d]%s>thread_block() returned %d\n", id, __FUNCTION__, wr);
	}
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

out:
	ull_lock(ull);
	*retval = --ull->ull_nwaiters;
	if (ull->ull_nwaiters == 0) {
		/*
		 * If the wait was canceled early, we might need to
		 * clear out the lingering owner reference before
		 * freeing the ull.
		 */
		if (ull->ull_owner != THREAD_NULL) {
			old_lingering_owner = ull_promote_owner_locked(ull, THREAD_NULL);
		}

		assert(ull->ull_owner == THREAD_NULL);

		ull->ull_key.ulk_pid = 0;
		ull->ull_key.ulk_addr = 0;
		ull->ull_refcount--;
		assert(ull->ull_refcount > 0);
	}
	ull_put(ull);

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

munge_retval:
	if (workq_callback) {
		thread_reenable_sched_call(self, workq_callback);
	}

	if ((flags & ULF_NO_ERRNO) && (ret != 0)) {
		*retval = -ret;
		ret = 0;
	}
	return ret;
}

int
ulock_wake(struct proc *p, struct ulock_wake_args *args, __unused int32_t *retval)
{
	uint opcode = args->operation & UL_OPCODE_MASK;
	uint flags = args->operation & UL_FLAGS_MASK;
	int ret = 0;
	int id = thread_tid(current_thread());
	ulk_t key;

	/* involved threads - each variable holds +1 ref if not null */
	thread_t wake_thread    = THREAD_NULL;
	thread_t old_owner      = THREAD_NULL;

	if (ull_debug) {
		kprintf("[%d]%s>ENTER opcode %d addr %llx flags %x\n",
		        id, __FUNCTION__, opcode, (unsigned long long)(args->addr), flags);
	}

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

	ull_t *ull = ull_get(&key, ULL_MUST_EXIST);
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
		if (ull_debug) {
			kprintf("[%d]%s>EINVAL opcode %d addr 0x%llx flags 0x%x\n",
			        id, __FUNCTION__, opcode, (unsigned long long)(args->addr), flags);
		}
		ret = EINVAL;
		goto out_locked;
	}

	if (opcode != ull->ull_opcode) {
		if (ull_debug) {
			kprintf("[%d]%s>EDOM - opcode mismatch - opcode %d addr 0x%llx flags 0x%x\n",
			        id, __FUNCTION__, opcode, (unsigned long long)(args->addr), flags);
		}
		ret = EDOM;
		goto out_locked;
	}

	if (!clear_owner) {
		assert(ull->ull_owner == THREAD_NULL);
	}

	if (flags & ULF_WAKE_ALL) {
		thread_wakeup(ULOCK_TO_EVENT(ull));
	} else if (flags & ULF_WAKE_THREAD) {
		kern_return_t kr = thread_wakeup_thread(ULOCK_TO_EVENT(ull), wake_thread);
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
		thread_wakeup_one_with_pri(ULOCK_TO_EVENT(ull), WAITQ_SELECT_MAX_PRI);
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
		old_owner = ull_promote_owner_locked(ull, THREAD_NULL);
	}

out_locked:
	ull_put(ull);

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

/*
 * Change ull_owner to be new_owner, and update it with the properties
 * of the current thread.
 *
 * Records the highest current promotion value in ull_promote_token, and applies that
 * to any new owner.
 *
 * Returns +1 ref to the old ull_owner if it is going away.
 */
static thread_t
ull_promote_owner_locked(ull_t*    ull,
                         thread_t  new_owner)
{
	if (new_owner != THREAD_NULL && ull->ull_owner == new_owner) {
		thread_user_promotion_update(new_owner, current_thread(), &ull->ull_promote_token);
		return THREAD_NULL;
	}

	thread_t old_owner = ull->ull_owner;
	ull->ull_owner = THREAD_NULL;

	if (new_owner != THREAD_NULL) {
		/* The ull_owner field now owns a +1 ref on thread */
		thread_reference(new_owner);
		ull->ull_owner = new_owner;

		thread_user_promotion_add(new_owner, current_thread(), &ull->ull_promote_token);
	} else {
		/* No new owner - clear the saturated promotion value */
		ull->ull_promote_token = PROMOTE_TOKEN_INIT;
	}

	if (old_owner != THREAD_NULL) {
		thread_user_promotion_drop(old_owner);
	}

	/* Return the +1 ref from the ull_owner field */
	return old_owner;
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
