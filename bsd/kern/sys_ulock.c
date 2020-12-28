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

#include <machine/atomic.h>

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

#include <os/hash.h>
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
#define ull_lock(ull)           lck_spin_lock_grp(&ull->ull_lock, ull_lck_grp)
#define ull_unlock(ull)         lck_spin_unlock(&ull->ull_lock)
#define ull_assert_owned(ull)   LCK_SPIN_ASSERT(&ull->ull_lock, LCK_ASSERT_OWNED)
#define ull_assert_notwned(ull) LCK_SPIN_ASSERT(&ull->ull_lock, LCK_ASSERT_NOTOWNED)

#define ULOCK_TO_EVENT(ull)   ((event_t)ull)
#define EVENT_TO_ULOCK(event) ((ull_t *)event)

typedef enum {
	ULK_INVALID = 0,
	ULK_UADDR,
	ULK_XPROC,
} ulk_type;

typedef struct {
	union {
		struct __attribute__((packed)) {
			user_addr_t     ulk_addr;
			pid_t           ulk_pid;
		};
		struct __attribute__((packed)) {
			uint64_t        ulk_object;
			uint64_t        ulk_offset;
		};
	};
	ulk_type        ulk_key_type;
} ulk_t;

#define ULK_UADDR_LEN   (sizeof(user_addr_t) + sizeof(pid_t))
#define ULK_XPROC_LEN   (sizeof(uint64_t) + sizeof(uint64_t))

inline static bool
ull_key_match(ulk_t *a, ulk_t *b)
{
	if (a->ulk_key_type != b->ulk_key_type) {
		return false;
	}

	if (a->ulk_key_type == ULK_UADDR) {
		return (a->ulk_pid == b->ulk_pid) &&
		       (a->ulk_addr == b->ulk_addr);
	}

	assert(a->ulk_key_type == ULK_XPROC);
	return (a->ulk_object == b->ulk_object) &&
	       (a->ulk_offset == b->ulk_offset);
}

typedef struct ull {
	/*
	 * ull_owner is the most recent known value for the owner of this ulock
	 * i.e. it may be out of date WRT the real value in userspace.
	 */
	thread_t        ull_owner; /* holds +1 thread reference */
	ulk_t           ull_key;
	ull_lock_t      ull_lock;
	uint            ull_bucket_index;
	int32_t         ull_nwaiters;
	int32_t         ull_refcount;
	uint8_t         ull_opcode;
	struct turnstile *ull_turnstile;
	queue_chain_t   ull_hash_link;
} ull_t;

extern void ulock_initialize(void);

#define ULL_MUST_EXIST  0x0001
static void ull_put(ull_t *);

static uint32_t ulock_adaptive_spin_usecs = 20;

SYSCTL_INT(_kern, OID_AUTO, ulock_adaptive_spin_usecs, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ulock_adaptive_spin_usecs, 0, "ulock adaptive spin duration");

#if DEVELOPMENT || DEBUG
static int ull_simulate_copyin_fault = 0;

static void
ull_dump(ull_t *ull)
{
	kprintf("ull\t%p\n", ull);
	switch (ull->ull_key.ulk_key_type) {
	case ULK_UADDR:
		kprintf("ull_key.ulk_key_type\tULK_UADDR\n");
		kprintf("ull_key.ulk_pid\t%d\n", ull->ull_key.ulk_pid);
		kprintf("ull_key.ulk_addr\t%p\n", (void *)(ull->ull_key.ulk_addr));
		break;
	case ULK_XPROC:
		kprintf("ull_key.ulk_key_type\tULK_XPROC\n");
		kprintf("ull_key.ulk_object\t%p\n", (void *)(ull->ull_key.ulk_object));
		kprintf("ull_key.ulk_offset\t%p\n", (void *)(ull->ull_key.ulk_offset));
		break;
	default:
		kprintf("ull_key.ulk_key_type\tUNKNOWN %d\n", ull->ull_key.ulk_key_type);
		break;
	}
	kprintf("ull_nwaiters\t%d\n", ull->ull_nwaiters);
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

#define ull_bucket_lock(i)       lck_spin_lock_grp(&ull_bucket[i].ulb_lock, ull_lck_grp)
#define ull_bucket_unlock(i)     lck_spin_unlock(&ull_bucket[i].ulb_lock)

static __inline__ uint32_t
ull_hash_index(const void *key, size_t length)
{
	uint32_t hash = os_hash_jenkins(key, length);

	hash &= (ull_hash_buckets - 1);

	return hash;
}

#define ULL_INDEX(keyp) ull_hash_index(keyp, keyp->ulk_key_type == ULK_UADDR ? ULK_UADDR_LEN : ULK_XPROC_LEN)

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
	assert(ull_hash_buckets >= thread_max / 4);

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
	zone_change(ull_zone, Z_CACHING_ENABLED, TRUE);
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
				if ((pid == 0) || ((elem->ull_key.ulk_key_type == ULK_UADDR) && (pid == elem->ull_key.ulk_pid))) {
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
	ull->ull_bucket_index = ULL_INDEX(key);
	ull->ull_nwaiters = 0;
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
	assert(refcount == 0 ? (ull->ull_key.ulk_key_type == ULK_INVALID) : 1);
	ull_unlock(ull);

	if (refcount > 0) {
		return;
	}

	ull_bucket_lock(ull->ull_bucket_index);
	remqueue(&ull->ull_hash_link);
	ull_bucket_unlock(ull->ull_bucket_index);

	ull_free(ull);
}

extern kern_return_t vm_map_page_info(vm_map_t map, vm_map_offset_t offset, vm_page_info_flavor_t flavor, vm_page_info_t info, mach_msg_type_number_t *count);
extern vm_map_t current_map(void);
extern boolean_t machine_thread_on_core(thread_t thread);

static int
uaddr_findobj(user_addr_t uaddr, uint64_t *objectp, uint64_t *offsetp)
{
	kern_return_t ret;
	vm_page_info_basic_data_t info;
	mach_msg_type_number_t count = VM_PAGE_INFO_BASIC_COUNT;
	ret = vm_map_page_info(current_map(), uaddr, VM_PAGE_INFO_BASIC, (vm_page_info_t)&info, &count);
	if (ret != KERN_SUCCESS) {
		return EINVAL;
	}

	if (objectp != NULL) {
		*objectp = (uint64_t)info.object_id;
	}
	if (offsetp != NULL) {
		*offsetp = (uint64_t)info.offset;
	}

	return 0;
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

static int
ulock_resolve_owner(uint32_t value, thread_t *owner)
{
	mach_port_name_t owner_name = ulock_owner_value_to_port_name(value);

	*owner = port_name_to_thread(owner_name,
	    PORT_TO_THREAD_IN_CURRENT_TASK |
	    PORT_TO_THREAD_NOT_CURRENT_THREAD);
	if (*owner == THREAD_NULL) {
		/*
		 * Translation failed - even though the lock value is up to date,
		 * whatever was stored in the lock wasn't actually a thread port.
		 */
		return owner_name == MACH_PORT_DEAD ? ESRCH : EOWNERDEAD;
	}
	return 0;
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

	bool set_owner = false;
	bool xproc = false;
	size_t lock_size = sizeof(uint32_t);
	int copy_ret;

	switch (opcode) {
	case UL_UNFAIR_LOCK:
		set_owner = true;
		break;
	case UL_COMPARE_AND_WAIT:
		break;
	case UL_COMPARE_AND_WAIT64:
		lock_size = sizeof(uint64_t);
		break;
	case UL_COMPARE_AND_WAIT_SHARED:
		xproc = true;
		break;
	case UL_COMPARE_AND_WAIT64_SHARED:
		xproc = true;
		lock_size = sizeof(uint64_t);
		break;
	default:
		ret = EINVAL;
		goto munge_retval;
	}

	uint64_t value = 0;

	if ((args->addr == 0) || (args->addr & (lock_size - 1))) {
		ret = EINVAL;
		goto munge_retval;
	}

	if (xproc) {
		uint64_t object = 0;
		uint64_t offset = 0;

		ret = uaddr_findobj(args->addr, &object, &offset);
		if (ret) {
			ret = EINVAL;
			goto munge_retval;
		}
		key.ulk_key_type = ULK_XPROC;
		key.ulk_object = object;
		key.ulk_offset = offset;
	} else {
		key.ulk_key_type = ULK_UADDR;
		key.ulk_pid = p->p_pid;
		key.ulk_addr = args->addr;
	}

	if ((flags & ULF_WAIT_ADAPTIVE_SPIN) && set_owner) {
		/*
		 * Attempt the copyin outside of the lock once,
		 *
		 * If it doesn't match (which is common), return right away.
		 *
		 * If it matches, resolve the current owner, and if it is on core,
		 * spin a bit waiting for the value to change. If the owner isn't on
		 * core, or if the value stays stable, then go on with the regular
		 * blocking code.
		 */
		uint64_t end = 0;
		uint32_t u32;

		ret = copyin_atomic32(args->addr, &u32);
		if (ret || u32 != args->value) {
			goto munge_retval;
		}
		for (;;) {
			if (owner_thread == NULL && ulock_resolve_owner(u32, &owner_thread) != 0) {
				break;
			}

			/* owner_thread may have a +1 starting here */

			if (!machine_thread_on_core(owner_thread)) {
				break;
			}
			if (end == 0) {
				clock_interval_to_deadline(ulock_adaptive_spin_usecs,
				    NSEC_PER_USEC, &end);
			} else if (mach_absolute_time() > end) {
				break;
			}
			if (copyin_atomic32_wait_if_equals(args->addr, u32) != 0) {
				goto munge_retval;
			}
		}
	}

	ull_t *ull = ull_get(&key, 0, &unused_ull);
	if (ull == NULL) {
		ret = ENOMEM;
		goto munge_retval;
	}
	/* ull is locked */

	ull->ull_nwaiters++;

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

	/* copyin_atomicXX always checks alignment */

	if (lock_size == 4) {
		uint32_t u32;
		copy_ret = copyin_atomic32(args->addr, &u32);
		value = u32;
	} else {
		copy_ret = copyin_atomic64(args->addr, &value);
	}

#if DEVELOPMENT || DEBUG
	/* Occasionally simulate copyin finding the user address paged out */
	if (((ull_simulate_copyin_fault == p->p_pid) || (ull_simulate_copyin_fault == 1)) && (copy_ret == 0)) {
		static _Atomic int fault_inject = 0;
		if (os_atomic_inc_orig(&fault_inject, relaxed) % 73 == 0) {
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
		if (owner_thread == THREAD_NULL) {
			ret = ulock_resolve_owner(args->value, &owner_thread);
			if (ret == EOWNERDEAD) {
				/*
				 * Translation failed - even though the lock value is up to date,
				 * whatever was stored in the lock wasn't actually a thread port.
				 */
				goto out_locked;
			}
			/* HACK: don't bail on MACH_PORT_DEAD, to avoid blowing up the no-tsd pthread lock */
			ret = 0;
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
	turnstile_complete((uintptr_t)ull, &ull->ull_turnstile, NULL, TURNSTILE_ULOCK);

out_locked:
	ulock_wait_cleanup(ull, owner_thread, old_owner, retval);
	owner_thread = NULL;

	if (unused_ull) {
		ull_free(unused_ull);
		unused_ull = NULL;
	}

	assert(*retval >= 0);

munge_retval:
	if (owner_thread) {
		thread_deallocate(owner_thread);
	}
	if (ret == ESTALE) {
		ret = 0;
	}
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

		memset(&ull->ull_key, 0, sizeof ull->ull_key);
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
	turnstile_complete((uintptr_t)ull, &ull->ull_turnstile, NULL, TURNSTILE_ULOCK);

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

	bool set_owner = false;
	bool xproc = false;

	switch (opcode) {
	case UL_UNFAIR_LOCK:
		set_owner = true;
		break;
	case UL_COMPARE_AND_WAIT:
	case UL_COMPARE_AND_WAIT64:
		break;
	case UL_COMPARE_AND_WAIT_SHARED:
	case UL_COMPARE_AND_WAIT64_SHARED:
		xproc = true;
		break;
	default:
		ret = EINVAL;
		goto munge_retval;
	}

	if ((flags & ULF_WAKE_MASK) != flags) {
		ret = EINVAL;
		goto munge_retval;
	}

	if ((flags & ULF_WAKE_THREAD) && ((flags & ULF_WAKE_ALL) || set_owner)) {
		ret = EINVAL;
		goto munge_retval;
	}

	if (args->addr == 0) {
		ret = EINVAL;
		goto munge_retval;
	}

	if (xproc) {
		uint64_t object = 0;
		uint64_t offset = 0;

		ret = uaddr_findobj(args->addr, &object, &offset);
		if (ret) {
			ret = EINVAL;
			goto munge_retval;
		}
		key.ulk_key_type = ULK_XPROC;
		key.ulk_object = object;
		key.ulk_offset = offset;
	} else {
		key.ulk_key_type = ULK_UADDR;
		key.ulk_pid = p->p_pid;
		key.ulk_addr = args->addr;
	}

	if (flags & ULF_WAKE_THREAD) {
		mach_port_name_t wake_thread_name = (mach_port_name_t)(args->wake_value);
		wake_thread = port_name_to_thread(wake_thread_name,
		    PORT_TO_THREAD_IN_CURRENT_TASK |
		    PORT_TO_THREAD_NOT_CURRENT_THREAD);
		if (wake_thread == THREAD_NULL) {
			ret = ESRCH;
			goto munge_retval;
		}
	}

	ull_t *ull = ull_get(&key, ULL_MUST_EXIST, NULL);
	thread_t new_owner = THREAD_NULL;
	struct turnstile *ts = TURNSTILE_NULL;
	thread_t cleanup_thread = THREAD_NULL;

	if (ull == NULL) {
		ret = ENOENT;
		goto munge_retval;
	}
	/* ull is locked */

	if (opcode != ull->ull_opcode) {
		ret = EDOM;
		goto out_ull_put;
	}

	if (set_owner) {
		if (ull->ull_owner != current_thread()) {
			/*
			 * If the current thread isn't the known owner,
			 * then this wake call was late to the party,
			 * and the kernel already knows who owns the lock.
			 *
			 * This current owner already knows the lock is contended
			 * and will redrive wakes, just bail out.
			 */
			goto out_ull_put;
		}
	} else {
		assert(ull->ull_owner == THREAD_NULL);
	}

	ts = turnstile_prepare((uintptr_t)ull, &ull->ull_turnstile,
	    TURNSTILE_NULL, TURNSTILE_ULOCK);
	assert(ts != TURNSTILE_NULL);

	if (flags & ULF_WAKE_THREAD) {
		kern_return_t kr = waitq_wakeup64_thread(&ts->ts_waitq,
		    CAST_EVENT64_T(ULOCK_TO_EVENT(ull)),
		    wake_thread, THREAD_AWAKENED);
		if (kr != KERN_SUCCESS) {
			assert(kr == KERN_NOT_WAITING);
			ret = EALREADY;
		}
	} else if (flags & ULF_WAKE_ALL) {
		if (set_owner) {
			turnstile_update_inheritor(ts, THREAD_NULL,
			    TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD);
		}
		waitq_wakeup64_all(&ts->ts_waitq, CAST_EVENT64_T(ULOCK_TO_EVENT(ull)),
		    THREAD_AWAKENED, 0);
	} else if (set_owner) {
		/*
		 * The turnstile waitq is priority ordered,
		 * and will wake up the highest priority waiter
		 * and set it as the inheritor for us.
		 */
		new_owner = waitq_wakeup64_identify(&ts->ts_waitq,
		    CAST_EVENT64_T(ULOCK_TO_EVENT(ull)),
		    THREAD_AWAKENED, WAITQ_PROMOTE_ON_WAKE);
	} else {
		waitq_wakeup64_one(&ts->ts_waitq, CAST_EVENT64_T(ULOCK_TO_EVENT(ull)),
		    THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
	}

	if (set_owner) {
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
		cleanup_thread = ull->ull_owner;
		ull->ull_owner = new_owner;
	}

	turnstile_complete((uintptr_t)ull, &ull->ull_turnstile, NULL, TURNSTILE_ULOCK);

out_ull_put:
	ull_put(ull);

	if (ts != TURNSTILE_NULL) {
		/* Need to be called after dropping the interlock */
		turnstile_cleanup();
	}

	if (cleanup_thread != THREAD_NULL) {
		thread_deallocate(cleanup_thread);
	}

munge_retval:
	if (wake_thread != THREAD_NULL) {
		thread_deallocate(wake_thread);
	}

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

	switch (ull->ull_opcode) {
	case UL_UNFAIR_LOCK:
	case UL_UNFAIR_LOCK64_SHARED:
		waitinfo->owner   = thread_tid(ull->ull_owner);
		waitinfo->context = ull->ull_key.ulk_addr;
		break;
	case UL_COMPARE_AND_WAIT:
	case UL_COMPARE_AND_WAIT64:
	case UL_COMPARE_AND_WAIT_SHARED:
	case UL_COMPARE_AND_WAIT64_SHARED:
		waitinfo->owner   = 0;
		waitinfo->context = ull->ull_key.ulk_addr;
		break;
	default:
		panic("%s: Invalid ulock opcode %d addr %p", __FUNCTION__, ull->ull_opcode, (void*)ull);
		break;
	}
	return;
}
