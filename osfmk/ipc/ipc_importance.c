/*
 * Copyright (c) 2013-2020 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/notify.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_importance.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_voucher.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>
#include <kern/mach_param.h>
#include <kern/misc_protos.h>
#include <kern/zalloc.h>
#include <kern/queue.h>
#include <kern/task.h>
#include <kern/policy_internal.h>

#include <sys/kdebug.h>

#include <mach/mach_voucher_attr_control.h>
#include <mach/machine/sdt.h>

extern int      proc_pid(void *);
extern int      proc_selfpid(void);
extern uint64_t proc_uniqueid(void *p);
extern char     *proc_name_address(void *p);

/*
 * Globals for delayed boost drop processing.
 */
static queue_head_t ipc_importance_delayed_drop_queue;
static thread_call_t ipc_importance_delayed_drop_call;
static uint64_t ipc_importance_delayed_drop_timestamp;
static boolean_t ipc_importance_delayed_drop_call_requested = FALSE;

#define DENAP_DROP_TARGET (1000 * NSEC_PER_MSEC) /* optimum denap delay */
#define DENAP_DROP_SKEW    (100 * NSEC_PER_MSEC) /* request skew for wakeup */
#define DENAP_DROP_LEEWAY  (2 * DENAP_DROP_SKEW)  /* specified wakeup leeway */

#define DENAP_DROP_DELAY (DENAP_DROP_TARGET + DENAP_DROP_SKEW)
#define DENAP_DROP_FLAGS (THREAD_CALL_DELAY_SYS_NORMAL | THREAD_CALL_DELAY_LEEWAY)

/*
 * Importance Voucher Attribute Manager
 */
static LCK_SPIN_DECLARE_ATTR(ipc_importance_lock_data, &ipc_lck_grp, &ipc_lck_attr);

#define ipc_importance_lock() \
	lck_spin_lock_grp(&ipc_importance_lock_data, &ipc_lck_grp)
#define ipc_importance_lock_try() \
	lck_spin_try_lock_grp(&ipc_importance_lock_data, &ipc_lck_grp)
#define ipc_importance_unlock() \
	lck_spin_unlock(&ipc_importance_lock_data)
#define ipc_importance_assert_held() \
	lck_spin_assert(&ipc_importance_lock_data, LCK_ASSERT_OWNED)

#if IIE_REF_DEBUG
#define incr_ref_counter(x) (os_atomic_inc(&(x), relaxed))

static inline
uint32_t
ipc_importance_reference_internal(ipc_importance_elem_t elem)
{
	incr_ref_counter(elem->iie_refs_added);
	return os_atomic_inc(&elem->iie_bits, relaxed) & IIE_REFS_MASK;
}

static inline
uint32_t
ipc_importance_release_internal(ipc_importance_elem_t elem)
{
	incr_ref_counter(elem->iie_refs_dropped);
	return os_atomic_dec(&elem->iie_bits, relaxed) & IIE_REFS_MASK;
}

static inline
uint32_t
ipc_importance_task_reference_internal(ipc_importance_task_t task_imp)
{
	uint32_t out;
	out = ipc_importance_reference_internal(&task_imp->iit_elem);
	incr_ref_counter(task_imp->iit_elem.iie_task_refs_added);
	return out;
}

static inline
uint32_t
ipc_importance_task_release_internal(ipc_importance_task_t task_imp)
{
	uint32_t out;

	assert(1 < IIT_REFS(task_imp));
	incr_ref_counter(task_imp->iit_elem.iie_task_refs_dropped);
	out = ipc_importance_release_internal(&task_imp->iit_elem);
	return out;
}

static inline
void
ipc_importance_counter_init(ipc_importance_elem_t elem)
{
	elem->iie_refs_added = 0;
	elem->iie_refs_dropped = 0;
	elem->iie_kmsg_refs_added = 0;
	elem->iie_kmsg_refs_inherited = 0;
	elem->iie_kmsg_refs_coalesced = 0;
	elem->iie_kmsg_refs_dropped = 0;
	elem->iie_task_refs_added = 0;
	elem->iie_task_refs_added_inherit_from = 0;
	elem->iie_task_refs_added_transition = 0;
	elem->iie_task_refs_self_added = 0;
	elem->iie_task_refs_inherited = 0;
	elem->iie_task_refs_coalesced = 0;
	elem->iie_task_refs_dropped = 0;
}
#else
#define incr_ref_counter(x)
#endif

#if DEVELOPMENT || DEBUG
static queue_head_t global_iit_alloc_queue =
    QUEUE_HEAD_INITIALIZER(global_iit_alloc_queue);
#endif

static ZONE_DECLARE(ipc_importance_task_zone, "ipc task importance",
    sizeof(struct ipc_importance_task), ZC_NOENCRYPT);
static ZONE_DECLARE(ipc_importance_inherit_zone, "ipc importance inherit",
    sizeof(struct ipc_importance_inherit), ZC_NOENCRYPT);
static zone_t ipc_importance_inherit_zone;

static ipc_voucher_attr_control_t ipc_importance_control;

static boolean_t ipc_importance_task_check_transition(ipc_importance_task_t task_imp,
    iit_update_type_t type, uint32_t delta);

static void ipc_importance_task_propagate_assertion_locked(ipc_importance_task_t task_imp,
    iit_update_type_t type, boolean_t update_task_imp);

static ipc_importance_inherit_t ipc_importance_inherit_from_task(task_t from_task, task_t to_task);

/*
 *	Routine:	ipc_importance_kmsg_link
 *	Purpose:
 *		Link the kmsg onto the appropriate propagation chain.
 *		If the element is a task importance, we link directly
 *		on its propagation chain. Otherwise, we link onto the
 *		destination task of the inherit.
 *	Conditions:
 *		Importance lock held.
 *		Caller is donating an importance elem reference to the kmsg.
 */
static void
ipc_importance_kmsg_link(
	ipc_kmsg_t              kmsg,
	ipc_importance_elem_t   elem)
{
	ipc_importance_elem_t link_elem;

	assert(IIE_NULL == kmsg->ikm_importance);

	link_elem = (IIE_TYPE_INHERIT == IIE_TYPE(elem)) ?
	    (ipc_importance_elem_t)((ipc_importance_inherit_t)elem)->iii_to_task :
	    elem;

	queue_enter(&link_elem->iie_kmsgs, kmsg, ipc_kmsg_t, ikm_inheritance);
	kmsg->ikm_importance = elem;
}

/*
 *	Routine:	ipc_importance_kmsg_unlink
 *	Purpose:
 *		Unlink the kmsg from its current propagation chain.
 *		If the element is a task importance, we unlink directly
 *		from its propagation chain. Otherwise, we unlink from the
 *		destination task of the inherit.
 *	Returns:
 *		The reference to the importance element it was linked on.
 *	Conditions:
 *		Importance lock held.
 *		Caller is responsible for dropping reference on returned elem.
 */
static ipc_importance_elem_t
ipc_importance_kmsg_unlink(
	ipc_kmsg_t              kmsg)
{
	ipc_importance_elem_t elem = kmsg->ikm_importance;

	if (IIE_NULL != elem) {
		ipc_importance_elem_t unlink_elem;

		unlink_elem = (IIE_TYPE_INHERIT == IIE_TYPE(elem)) ?
		    (ipc_importance_elem_t)((ipc_importance_inherit_t)elem)->iii_to_task :
		    elem;

		queue_remove(&unlink_elem->iie_kmsgs, kmsg, ipc_kmsg_t, ikm_inheritance);
		kmsg->ikm_importance = IIE_NULL;
	}
	return elem;
}

/*
 *	Routine:	ipc_importance_inherit_link
 *	Purpose:
 *		Link the inherit onto the appropriate propagation chain.
 *		If the element is a task importance, we link directly
 *		on its propagation chain. Otherwise, we link onto the
 *		destination task of the inherit.
 *	Conditions:
 *		Importance lock held.
 *		Caller is donating an elem importance reference to the inherit.
 */
static void
ipc_importance_inherit_link(
	ipc_importance_inherit_t inherit,
	ipc_importance_elem_t elem)
{
	ipc_importance_task_t link_task;

	assert(IIE_NULL == inherit->iii_from_elem);
	link_task = (IIE_TYPE_INHERIT == IIE_TYPE(elem)) ?
	    ((ipc_importance_inherit_t)elem)->iii_to_task :
	    (ipc_importance_task_t)elem;

	queue_enter(&link_task->iit_inherits, inherit,
	    ipc_importance_inherit_t, iii_inheritance);
	inherit->iii_from_elem = elem;
}

/*
 *	Routine:	ipc_importance_inherit_find
 *	Purpose:
 *		Find an existing inherit that links the from element to the
 *		to_task at a given nesting depth.  As inherits from other
 *		inherits are actually linked off the original inherit's donation
 *		receiving task, we have to conduct our search from there if
 *		the from element is an inherit.
 *	Returns:
 *		A pointer (not a reference) to the matching inherit.
 *	Conditions:
 *		Importance lock held.
 */
static ipc_importance_inherit_t
ipc_importance_inherit_find(
	ipc_importance_elem_t from,
	ipc_importance_task_t to_task,
	unsigned int depth)
{
	ipc_importance_task_t link_task;
	ipc_importance_inherit_t inherit;

	link_task = (IIE_TYPE_INHERIT == IIE_TYPE(from)) ?
	    ((ipc_importance_inherit_t)from)->iii_to_task :
	    (ipc_importance_task_t)from;

	queue_iterate(&link_task->iit_inherits, inherit,
	    ipc_importance_inherit_t, iii_inheritance) {
		if (inherit->iii_to_task == to_task && inherit->iii_depth == depth) {
			return inherit;
		}
	}
	return III_NULL;
}

/*
 *	Routine:	ipc_importance_inherit_unlink
 *	Purpose:
 *		Unlink the inherit from its current propagation chain.
 *		If the element is a task importance, we unlink directly
 *		from its propagation chain. Otherwise, we unlink from the
 *		destination task of the inherit.
 *	Returns:
 *		The reference to the importance element it was linked on.
 *	Conditions:
 *		Importance lock held.
 *		Caller is responsible for dropping reference on returned elem.
 */
static ipc_importance_elem_t
ipc_importance_inherit_unlink(
	ipc_importance_inherit_t inherit)
{
	ipc_importance_elem_t elem = inherit->iii_from_elem;

	if (IIE_NULL != elem) {
		ipc_importance_task_t unlink_task;

		unlink_task = (IIE_TYPE_INHERIT == IIE_TYPE(elem)) ?
		    ((ipc_importance_inherit_t)elem)->iii_to_task :
		    (ipc_importance_task_t)elem;

		queue_remove(&unlink_task->iit_inherits, inherit,
		    ipc_importance_inherit_t, iii_inheritance);
		inherit->iii_from_elem = IIE_NULL;
	}
	return elem;
}

/*
 *	Routine:	ipc_importance_reference
 *	Purpose:
 *		Add a reference to the importance element.
 *	Conditions:
 *		Caller must hold a reference on the element.
 */
void
ipc_importance_reference(ipc_importance_elem_t elem)
{
	assert(0 < IIE_REFS(elem));
	ipc_importance_reference_internal(elem);
}

/*
 *	Routine:	ipc_importance_release_locked
 *	Purpose:
 *		Release a reference on an importance attribute value,
 *		unlinking and deallocating the attribute if the last reference.
 *	Conditions:
 *		Entered with importance lock held, leaves with it unlocked.
 */
static void
ipc_importance_release_locked(ipc_importance_elem_t elem)
{
	assert(0 < IIE_REFS(elem));

#if IMPORTANCE_DEBUG
	ipc_importance_inherit_t temp_inherit;
	ipc_importance_task_t link_task;
	ipc_kmsg_t temp_kmsg;
	uint32_t expected = 0;

	if (0 < elem->iie_made) {
		expected++;
	}

	link_task = (IIE_TYPE_INHERIT == IIE_TYPE(elem)) ?
	    ((ipc_importance_inherit_t)elem)->iii_to_task :
	    (ipc_importance_task_t)elem;

	queue_iterate(&link_task->iit_kmsgs, temp_kmsg, ipc_kmsg_t, ikm_inheritance)
	if (temp_kmsg->ikm_importance == elem) {
		expected++;
	}
	queue_iterate(&link_task->iit_inherits, temp_inherit,
	    ipc_importance_inherit_t, iii_inheritance)
	if (temp_inherit->iii_from_elem == elem) {
		expected++;
	}
	if (IIE_REFS(elem) < expected + 1) {
		panic("ipc_importance_release_locked (%p)", elem);
	}
#endif /* IMPORTANCE_DEBUG */

	if (0 < ipc_importance_release_internal(elem)) {
		ipc_importance_unlock();
		return;
	}

	/* last ref */

	switch (IIE_TYPE(elem)) {
	/* just a "from" task reference to drop */
	case IIE_TYPE_TASK:
	{
		ipc_importance_task_t task_elem;

		task_elem = (ipc_importance_task_t)elem;

		/* the task can't still hold a reference on the task importance */
		assert(TASK_NULL == task_elem->iit_task);

#if DEVELOPMENT || DEBUG
		queue_remove(&global_iit_alloc_queue, task_elem, ipc_importance_task_t, iit_allocation);
#endif

		ipc_importance_unlock();

		zfree(ipc_importance_task_zone, task_elem);
		break;
	}

	/* dropping an inherit element */
	case IIE_TYPE_INHERIT:
	{
		ipc_importance_inherit_t inherit = (ipc_importance_inherit_t)elem;
		ipc_importance_task_t to_task = inherit->iii_to_task;
		ipc_importance_elem_t from_elem;

		assert(IIT_NULL != to_task);
		assert(ipc_importance_task_is_any_receiver_type(to_task));

		/* unlink the inherit from its source element */
		from_elem = ipc_importance_inherit_unlink(inherit);
		assert(IIE_NULL != from_elem);

		/*
		 * The attribute might have pending external boosts if the attribute
		 * was given out during exec, drop them from the appropriate destination
		 * task.
		 *
		 * The attribute will not have any pending external boosts if the
		 * attribute was given out to voucher system since it would have been
		 * dropped by ipc_importance_release_value, but there is not way to
		 * detect that, thus if the attribute has a pending external boost,
		 * drop them from the appropriate destination task.
		 *
		 * The inherit attribute from exec and voucher system would not
		 * get deduped to each other, thus dropping the external boost
		 * from destination task at two different places will not have
		 * any unintended side effects.
		 */
		assert(inherit->iii_externcnt >= inherit->iii_externdrop);
		if (inherit->iii_donating) {
			uint32_t assertcnt = III_EXTERN(inherit);

			assert(ipc_importance_task_is_any_receiver_type(to_task));
			assert(to_task->iit_externcnt >= inherit->iii_externcnt);
			assert(to_task->iit_externdrop >= inherit->iii_externdrop);
			to_task->iit_externcnt -= inherit->iii_externcnt;
			to_task->iit_externdrop -= inherit->iii_externdrop;
			inherit->iii_externcnt = 0;
			inherit->iii_externdrop = 0;
			inherit->iii_donating = FALSE;

			/* adjust the internal assertions - and propagate as needed */
			if (ipc_importance_task_check_transition(to_task, IIT_UPDATE_DROP, assertcnt)) {
				ipc_importance_task_propagate_assertion_locked(to_task, IIT_UPDATE_DROP, TRUE);
			}
		} else {
			inherit->iii_externcnt = 0;
			inherit->iii_externdrop = 0;
		}

		/* release the reference on the source element */
		ipc_importance_release_locked(from_elem);
		/* unlocked on return */

		/* release the reference on the destination task */
		ipc_importance_task_release(to_task);

		/* free the inherit */
		zfree(ipc_importance_inherit_zone, inherit);
		break;
	}
	}
}

/*
 *	Routine:	ipc_importance_release
 *	Purpose:
 *		Release a reference on an importance attribute value,
 *		unlinking and deallocating the attribute if the last reference.
 *	Conditions:
 *		nothing locked on entrance, nothing locked on exit.
 *		May block.
 */
void
ipc_importance_release(ipc_importance_elem_t elem)
{
	if (IIE_NULL == elem) {
		return;
	}

	ipc_importance_lock();
	ipc_importance_release_locked(elem);
	/* unlocked */
}

/*
 *	Routine:	ipc_importance_task_reference
 *
 *
 *	Purpose:
 *		Retain a reference on a task importance attribute value.
 *	Conditions:
 *		nothing locked on entrance, nothing locked on exit.
 *		caller holds a reference already.
 */
void
ipc_importance_task_reference(ipc_importance_task_t task_elem)
{
	if (IIT_NULL == task_elem) {
		return;
	}
#if IIE_REF_DEBUG
	incr_ref_counter(task_elem->iit_elem.iie_task_refs_added);
#endif
	ipc_importance_reference(&task_elem->iit_elem);
}

/*
 *	Routine:	ipc_importance_task_release
 *	Purpose:
 *		Release a reference on a task importance attribute value,
 *		unlinking and deallocating the attribute if the last reference.
 *	Conditions:
 *		nothing locked on entrance, nothing locked on exit.
 *		May block.
 */
void
ipc_importance_task_release(ipc_importance_task_t task_elem)
{
	if (IIT_NULL == task_elem) {
		return;
	}

	ipc_importance_lock();
#if IIE_REF_DEBUG
	incr_ref_counter(task_elem->iit_elem.iie_task_refs_dropped);
#endif
	ipc_importance_release_locked(&task_elem->iit_elem);
	/* unlocked */
}

/*
 *	Routine:	ipc_importance_task_release_locked
 *	Purpose:
 *		Release a reference on a task importance attribute value,
 *		unlinking and deallocating the attribute if the last reference.
 *	Conditions:
 *		importance lock held on entry, nothing locked on exit.
 *		May block.
 */
static void
ipc_importance_task_release_locked(ipc_importance_task_t task_elem)
{
	if (IIT_NULL == task_elem) {
		ipc_importance_unlock();
		return;
	}
#if IIE_REF_DEBUG
	incr_ref_counter(task_elem->iit_elem.iie_task_refs_dropped);
#endif
	ipc_importance_release_locked(&task_elem->iit_elem);
	/* unlocked */
}

/*
 * Routines for importance donation/inheritance/boosting
 */


/*
 * External importance assertions are managed by the process in userspace
 * Internal importance assertions are the responsibility of the kernel
 * Assertions are changed from internal to external via task_importance_externalize_assertion
 */

/*
 *	Routine:	ipc_importance_task_check_transition
 *	Purpose:
 *		Increase or decrement the internal task importance counter of the
 *		specified task and determine if propagation and a task policy
 *		update is required.
 *
 *		If it is already enqueued for a policy update, steal it from that queue
 *		(as we are reversing that update before it happens).
 *
 *	Conditions:
 *		Called with the importance lock held.
 *		It is the caller's responsibility to perform the propagation of the
 *		transition and/or policy changes by checking the return value.
 */
static boolean_t
ipc_importance_task_check_transition(
	ipc_importance_task_t task_imp,
	iit_update_type_t type,
	uint32_t delta)
{
#if IMPORTANCE_TRACE
	task_t target_task = task_imp->iit_task;
#endif
	boolean_t boost = (IIT_UPDATE_HOLD == type);
	boolean_t before_boosted, after_boosted;

	ipc_importance_assert_held();

	if (!ipc_importance_task_is_any_receiver_type(task_imp)) {
		return FALSE;
	}

#if IMPORTANCE_TRACE
	int target_pid = task_pid(target_task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (((boost) ? IMP_HOLD : IMP_DROP) | TASK_POLICY_INTERNAL))) | DBG_FUNC_START,
	    proc_selfpid(), target_pid, task_imp->iit_assertcnt, IIT_EXTERN(task_imp), 0);
#endif

	/* snapshot the effective boosting status before making any changes */
	before_boosted = (task_imp->iit_assertcnt > 0);

	/* Adjust the assertcnt appropriately */
	if (boost) {
		task_imp->iit_assertcnt += delta;
#if IMPORTANCE_TRACE
		DTRACE_BOOST6(send_boost, task_t, target_task, int, target_pid,
		    task_t, current_task(), int, proc_selfpid(), int, delta, int, task_imp->iit_assertcnt);
#endif
	} else {
		// assert(delta <= task_imp->iit_assertcnt);
		if (task_imp->iit_assertcnt < delta + IIT_EXTERN(task_imp)) {
			/* TODO: Turn this back into a panic <rdar://problem/12592649> */
			task_imp->iit_assertcnt = IIT_EXTERN(task_imp);
		} else {
			task_imp->iit_assertcnt -= delta;
		}
#if IMPORTANCE_TRACE
		// This convers both legacy and voucher-based importance.
		DTRACE_BOOST4(drop_boost, task_t, target_task, int, target_pid, int, delta, int, task_imp->iit_assertcnt);
#endif
	}

#if IMPORTANCE_TRACE
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (((boost) ? IMP_HOLD : IMP_DROP) | TASK_POLICY_INTERNAL))) | DBG_FUNC_END,
	    proc_selfpid(), target_pid, task_imp->iit_assertcnt, IIT_EXTERN(task_imp), 0);
#endif

	/* did the change result in an effective donor status change? */
	after_boosted = (task_imp->iit_assertcnt > 0);

	if (after_boosted != before_boosted) {
		/*
		 * If the task importance is already on an update queue, we just reversed the need for a
		 * pending policy update.  If the queue is any other than the delayed-drop-queue, pull it
		 * off that queue and release the reference it got going onto the update queue.  If it is
		 * the delayed-drop-queue we leave it in place in case it comes back into the drop state
		 * before its time delay is up.
		 *
		 * We still need to propagate the change downstream to reverse the assertcnt effects,
		 * but we no longer need to update this task's boost policy state.
		 *
		 * Otherwise, mark it as needing a policy update.
		 */
		assert(0 == task_imp->iit_updatepolicy);
		if (NULL != task_imp->iit_updateq) {
			if (&ipc_importance_delayed_drop_queue != task_imp->iit_updateq) {
				queue_remove(task_imp->iit_updateq, task_imp, ipc_importance_task_t, iit_updates);
				task_imp->iit_updateq = NULL;
				ipc_importance_task_release_internal(task_imp); /* can't be last ref */
			}
		} else {
			task_imp->iit_updatepolicy = 1;
		}
		return TRUE;
	}

	return FALSE;
}


/*
 *	Routine:	ipc_importance_task_propagate_helper
 *	Purpose:
 *		Increase or decrement the internal task importance counter of all
 *		importance tasks inheriting from the specified one.  If this causes
 *		that importance task to change state, add it to the list of tasks
 *		to do a policy update against.
 *	Conditions:
 *		Called with the importance lock held.
 *		It is the caller's responsibility to iterate down the generated list
 *		and propagate any subsequent assertion changes from there.
 */
static void
ipc_importance_task_propagate_helper(
	ipc_importance_task_t task_imp,
	iit_update_type_t type,
	queue_t propagation)
{
	ipc_importance_task_t temp_task_imp;

	/*
	 * iterate the downstream kmsgs, adjust their boosts,
	 * and capture the next task to adjust for each message
	 */

	ipc_kmsg_t temp_kmsg;

	queue_iterate(&task_imp->iit_kmsgs, temp_kmsg, ipc_kmsg_t, ikm_inheritance) {
		mach_msg_header_t *hdr = temp_kmsg->ikm_header;
		mach_port_delta_t delta;
		ipc_port_t port;

		/* toggle the kmsg importance bit as a barrier to parallel adjusts */
		if (IIT_UPDATE_HOLD == type) {
			if (MACH_MSGH_BITS_RAISED_IMPORTANCE(hdr->msgh_bits)) {
				continue;
			}

			/* mark the message as now carrying importance */
			hdr->msgh_bits |= MACH_MSGH_BITS_RAISEIMP;
			delta = 1;
		} else {
			if (!MACH_MSGH_BITS_RAISED_IMPORTANCE(hdr->msgh_bits)) {
				continue;
			}

			/* clear the message as now carrying importance */
			hdr->msgh_bits &= ~MACH_MSGH_BITS_RAISEIMP;
			delta = -1;
		}

		/* determine the task importance to adjust as result (if any) */
		port = hdr->msgh_remote_port;
		assert(IP_VALID(port));
		ip_lock(port);
		temp_task_imp = IIT_NULL;
		if (!ipc_port_importance_delta_internal(port, IPID_OPTION_NORMAL, &delta, &temp_task_imp)) {
			ip_unlock(port);
		}

		/* no task importance to adjust associated with the port? */
		if (IIT_NULL == temp_task_imp) {
			continue;
		}

		/* hold a reference on temp_task_imp */

		/* Adjust the task assertions and determine if an edge was crossed */
		if (ipc_importance_task_check_transition(temp_task_imp, type, 1)) {
			incr_ref_counter(temp_task_imp->iit_elem.iie_task_refs_added_transition);
			queue_enter(propagation, temp_task_imp, ipc_importance_task_t, iit_props);
			/* reference donated */
		} else {
			ipc_importance_task_release_internal(temp_task_imp);
		}
	}

	/*
	 * iterate the downstream importance inherits
	 * and capture the next task importance to boost for each
	 */
	ipc_importance_inherit_t temp_inherit;

	queue_iterate(&task_imp->iit_inherits, temp_inherit, ipc_importance_inherit_t, iii_inheritance) {
		uint32_t assertcnt = III_EXTERN(temp_inherit);

		temp_task_imp = temp_inherit->iii_to_task;
		assert(IIT_NULL != temp_task_imp);

		if (IIT_UPDATE_HOLD == type) {
			/* if no undropped externcnts in the inherit, nothing to do */
			if (0 == assertcnt) {
				assert(temp_inherit->iii_donating == FALSE);
				continue;
			}

			/* nothing to do if the inherit is already donating (forced donation) */
			if (temp_inherit->iii_donating) {
				continue;
			}

			/* mark it donating and contribute to the task externcnts */
			temp_inherit->iii_donating = TRUE;
			temp_task_imp->iit_externcnt += temp_inherit->iii_externcnt;
			temp_task_imp->iit_externdrop += temp_inherit->iii_externdrop;
		} else {
			/* if no contributing assertions, move on */
			if (0 == assertcnt) {
				assert(temp_inherit->iii_donating == FALSE);
				continue;
			}

			/* nothing to do if the inherit is not donating */
			if (!temp_inherit->iii_donating) {
				continue;
			}

			/* mark it no longer donating */
			temp_inherit->iii_donating = FALSE;

			/* remove the contribution the inherit made to the to-task */
			assert(IIT_EXTERN(temp_task_imp) >= III_EXTERN(temp_inherit));
			assert(temp_task_imp->iit_externcnt >= temp_inherit->iii_externcnt);
			assert(temp_task_imp->iit_externdrop >= temp_inherit->iii_externdrop);
			temp_task_imp->iit_externcnt -= temp_inherit->iii_externcnt;
			temp_task_imp->iit_externdrop -= temp_inherit->iii_externdrop;
		}

		/* Adjust the task assertions and determine if an edge was crossed */
		assert(ipc_importance_task_is_any_receiver_type(temp_task_imp));
		if (ipc_importance_task_check_transition(temp_task_imp, type, assertcnt)) {
			ipc_importance_task_reference(temp_task_imp);
			incr_ref_counter(temp_task_imp->iit_elem.iie_task_refs_added_transition);
			queue_enter(propagation, temp_task_imp, ipc_importance_task_t, iit_props);
		}
	}
}

/*
 *	Routine:	ipc_importance_task_process_updates
 *	Purpose:
 *	        Process the queue of task importances and apply the policy
 *		update called for.  Only process tasks in the queue with an
 *		update timestamp less than the supplied max.
 *	Conditions:
 *		Called and returns with importance locked.
 *		May drop importance lock and block temporarily.
 */
static void
ipc_importance_task_process_updates(
	queue_t   supplied_queue,
	boolean_t boost,
	uint64_t  max_timestamp)
{
	ipc_importance_task_t task_imp;
	queue_head_t second_chance;
	queue_t queue = supplied_queue;

	/*
	 * This queue will hold the task's we couldn't trylock on first pass.
	 * By using a second (private) queue, we guarantee all tasks that get
	 * entered on this queue have a timestamp under the maximum.
	 */
	queue_init(&second_chance);

	/* process any resulting policy updates */
retry:
	while (!queue_empty(queue)) {
		task_t target_task;
		struct task_pend_token pend_token = {};

		task_imp = (ipc_importance_task_t)queue_first(queue);
		assert(0 == task_imp->iit_updatepolicy);
		assert(queue == task_imp->iit_updateq);

		/* if timestamp is too big, we're done */
		if (task_imp->iit_updatetime > max_timestamp) {
			break;
		}

		/* we were given a reference on each task in the queue */

		/* remove it from the supplied queue */
		queue_remove(queue, task_imp, ipc_importance_task_t, iit_updates);
		task_imp->iit_updateq = NULL;

		target_task = task_imp->iit_task;

		/* Is it well on the way to exiting? */
		if (TASK_NULL == target_task) {
			ipc_importance_task_release_locked(task_imp);
			/* importance unlocked */
			ipc_importance_lock();
			continue;
		}

		/* Has the update been reversed on the hysteresis queue? */
		if (0 < task_imp->iit_assertcnt &&
		    queue == &ipc_importance_delayed_drop_queue) {
			ipc_importance_task_release_locked(task_imp);
			/* importance unlocked */
			ipc_importance_lock();
			continue;
		}

		/*
		 * Can we get the task lock out-of-order?
		 * If not, stick this back on the second-chance queue.
		 */
		if (!task_lock_try(target_task)) {
			boolean_t should_wait_lock = (queue == &second_chance);
			task_imp->iit_updateq = &second_chance;

			/*
			 * If we're already processing second-chances on
			 * tasks, keep this task on the front of the queue.
			 * We will wait for the task lock before coming
			 * back and trying again, and we have a better
			 * chance of re-acquiring the lock if we come back
			 * to it right away.
			 */
			if (should_wait_lock) {
				task_reference(target_task);
				queue_enter_first(&second_chance, task_imp,
				    ipc_importance_task_t, iit_updates);
			} else {
				queue_enter(&second_chance, task_imp,
				    ipc_importance_task_t, iit_updates);
			}
			ipc_importance_unlock();

			if (should_wait_lock) {
				task_lock(target_task);
				task_unlock(target_task);
				task_deallocate(target_task);
			}

			ipc_importance_lock();
			continue;
		}

		/* is it going away? */
		if (!target_task->active) {
			task_unlock(target_task);
			ipc_importance_task_release_locked(task_imp);
			/* importance unlocked */
			ipc_importance_lock();
			continue;
		}

		/* take a task reference for while we don't have the importance lock */
		task_reference(target_task);

		/* count the transition */
		if (boost) {
			task_imp->iit_transitions++;
		}

		ipc_importance_unlock();

		/* apply the policy adjust to the target task (while it is still locked) */
		task_update_boost_locked(target_task, boost, &pend_token);

		/* complete the policy update with the task unlocked */
		ipc_importance_task_release(task_imp);
		task_unlock(target_task);
		task_policy_update_complete_unlocked(target_task, &pend_token);
		task_deallocate(target_task);

		ipc_importance_lock();
	}

	/* If there are tasks we couldn't update the first time, try again */
	if (!queue_empty(&second_chance)) {
		queue = &second_chance;
		goto retry;
	}
}


/*
 *	Routine:	ipc_importance_task_delayed_drop_scan
 *	Purpose:
 *	        The thread call routine to scan the delayed drop queue,
 *		requesting all updates with a deadline up to the last target
 *		for the thread-call (which is DENAP_DROP_SKEW beyond the first
 *		thread's optimum delay).
 *		update to drop its boost.
 *	Conditions:
 *		Nothing locked
 */
static void
ipc_importance_task_delayed_drop_scan(
	__unused void *arg1,
	__unused void *arg2)
{
	ipc_importance_lock();

	/* process all queued task drops with timestamps up to TARGET(first)+SKEW */
	ipc_importance_task_process_updates(&ipc_importance_delayed_drop_queue,
	    FALSE,
	    ipc_importance_delayed_drop_timestamp);

	/* importance lock may have been temporarily dropped */

	/* If there are any entries left in the queue, re-arm the call here */
	if (!queue_empty(&ipc_importance_delayed_drop_queue)) {
		ipc_importance_task_t task_imp;
		uint64_t deadline;
		uint64_t leeway;

		task_imp = (ipc_importance_task_t)queue_first(&ipc_importance_delayed_drop_queue);

		nanoseconds_to_absolutetime(DENAP_DROP_DELAY, &deadline);
		deadline += task_imp->iit_updatetime;
		ipc_importance_delayed_drop_timestamp = deadline;

		nanoseconds_to_absolutetime(DENAP_DROP_LEEWAY, &leeway);

		thread_call_enter_delayed_with_leeway(
			ipc_importance_delayed_drop_call,
			NULL,
			deadline,
			leeway,
			DENAP_DROP_FLAGS);
	} else {
		ipc_importance_delayed_drop_call_requested = FALSE;
	}
	ipc_importance_unlock();
}

/*
 *	Routine:	ipc_importance_task_delayed_drop
 *	Purpose:
 *		Queue the specified task importance for delayed policy
 *		update to drop its boost.
 *	Conditions:
 *		Called with the importance lock held.
 */
static void
ipc_importance_task_delayed_drop(ipc_importance_task_t task_imp)
{
	uint64_t timestamp = mach_absolute_time(); /* no mach_approximate_time() in kernel */

	assert(ipc_importance_delayed_drop_call != NULL);

	/*
	 * If still on an update queue from a previous change,
	 * remove it first (and use that reference).  Otherwise, take
	 * a new reference for the delay drop update queue.
	 */
	if (NULL != task_imp->iit_updateq) {
		queue_remove(task_imp->iit_updateq, task_imp,
		    ipc_importance_task_t, iit_updates);
	} else {
		ipc_importance_task_reference_internal(task_imp);
	}

	task_imp->iit_updateq = &ipc_importance_delayed_drop_queue;
	task_imp->iit_updatetime = timestamp;

	queue_enter(&ipc_importance_delayed_drop_queue, task_imp,
	    ipc_importance_task_t, iit_updates);

	/* request the delayed thread-call if not already requested */
	if (!ipc_importance_delayed_drop_call_requested) {
		uint64_t deadline;
		uint64_t leeway;

		nanoseconds_to_absolutetime(DENAP_DROP_DELAY, &deadline);
		deadline += task_imp->iit_updatetime;
		ipc_importance_delayed_drop_timestamp = deadline;

		nanoseconds_to_absolutetime(DENAP_DROP_LEEWAY, &leeway);

		ipc_importance_delayed_drop_call_requested = TRUE;
		thread_call_enter_delayed_with_leeway(
			ipc_importance_delayed_drop_call,
			NULL,
			deadline,
			leeway,
			DENAP_DROP_FLAGS);
	}
}


/*
 *	Routine:	ipc_importance_task_propagate_assertion_locked
 *	Purpose:
 *		Propagate the importance transition type to every item
 *		If this causes a boost to be applied, determine if that
 *		boost should propagate downstream.
 *	Conditions:
 *		Called with the importance lock held.
 */
static void
ipc_importance_task_propagate_assertion_locked(
	ipc_importance_task_t task_imp,
	iit_update_type_t type,
	boolean_t update_task_imp)
{
	boolean_t boost = (IIT_UPDATE_HOLD == type);
	ipc_importance_task_t temp_task_imp;
	queue_head_t propagate;
	queue_head_t updates;

	queue_init(&updates);
	queue_init(&propagate);

	ipc_importance_assert_held();

	/*
	 * If we're going to update the policy for the provided task,
	 * enqueue it on the propagate queue itself.  Otherwise, only
	 * enqueue downstream things.
	 */
	if (update_task_imp) {
		ipc_importance_task_reference(task_imp);
		incr_ref_counter(task_imp->iit_elem.iie_task_refs_added_transition);
		queue_enter(&propagate, task_imp, ipc_importance_task_t, iit_props);
	} else {
		ipc_importance_task_propagate_helper(task_imp, type, &propagate);
	}

	/*
	 * for each item on the propagation list, propagate any change downstream,
	 * adding new tasks to propagate further if they transistioned as well.
	 */
	while (!queue_empty(&propagate)) {
		boolean_t need_update;

		queue_remove_first(&propagate, temp_task_imp, ipc_importance_task_t, iit_props);
		/* hold a reference on temp_task_imp */

		assert(IIT_NULL != temp_task_imp);

		/* only propagate for receivers not already marked as a donor */
		if (!ipc_importance_task_is_marked_donor(temp_task_imp) &&
		    ipc_importance_task_is_marked_receiver(temp_task_imp)) {
			ipc_importance_task_propagate_helper(temp_task_imp, type, &propagate);
		}

		/* if we have a policy update to apply, enqueue a reference for later processing */
		need_update = (0 != temp_task_imp->iit_updatepolicy);
		temp_task_imp->iit_updatepolicy = 0;
		if (need_update && TASK_NULL != temp_task_imp->iit_task) {
			if (NULL == temp_task_imp->iit_updateq) {
				/*
				 * If a downstream task that needs an update is subjects to AppNap,
				 * drop boosts according to the delay hysteresis.  Otherwise,
				 * immediate update it.
				 */
				if (!boost && temp_task_imp != task_imp &&
				    ipc_importance_delayed_drop_call != NULL &&
				    ipc_importance_task_is_marked_denap_receiver(temp_task_imp)) {
					ipc_importance_task_delayed_drop(temp_task_imp);
				} else {
					temp_task_imp->iit_updatetime = 0;
					temp_task_imp->iit_updateq = &updates;
					ipc_importance_task_reference_internal(temp_task_imp);
					if (boost) {
						queue_enter(&updates, temp_task_imp,
						    ipc_importance_task_t, iit_updates);
					} else {
						queue_enter_first(&updates, temp_task_imp,
						    ipc_importance_task_t, iit_updates);
					}
				}
			} else {
				/* Must already be on the AppNap hysteresis queue */
				assert(ipc_importance_delayed_drop_call != NULL);
				assert(ipc_importance_task_is_marked_denap_receiver(temp_task_imp));
			}
		}

		ipc_importance_task_release_internal(temp_task_imp);
	}

	/* apply updates to task (may drop importance lock) */
	if (!queue_empty(&updates)) {
		ipc_importance_task_process_updates(&updates, boost, 0);
	}
}

/*
 *	Routine:	ipc_importance_task_hold_internal_assertion_locked
 *	Purpose:
 *		Increment the assertion count on the task importance.
 *		If this results in a boost state change in that task,
 *		prepare to update task policy for this task AND, if
 *		if not just waking out of App Nap, all down-stream
 *		tasks that have a similar transition through inheriting
 *		this update.
 *	Conditions:
 *		importance locked on entry and exit.
 *		May temporarily drop importance lock and block.
 */
static kern_return_t
ipc_importance_task_hold_internal_assertion_locked(ipc_importance_task_t task_imp, uint32_t count)
{
	if (ipc_importance_task_check_transition(task_imp, IIT_UPDATE_HOLD, count)) {
		ipc_importance_task_propagate_assertion_locked(task_imp, IIT_UPDATE_HOLD, TRUE);
	}
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_importance_task_drop_internal_assertion_locked
 *	Purpose:
 *		Decrement the assertion count on the task importance.
 *		If this results in a boost state change in that task,
 *		prepare to update task policy for this task AND, if
 *		if not just waking out of App Nap, all down-stream
 *		tasks that have a similar transition through inheriting
 *		this update.
 *	Conditions:
 *		importance locked on entry and exit.
 *		May temporarily drop importance lock and block.
 */
static kern_return_t
ipc_importance_task_drop_internal_assertion_locked(ipc_importance_task_t task_imp, uint32_t count)
{
	if (ipc_importance_task_check_transition(task_imp, IIT_UPDATE_DROP, count)) {
		ipc_importance_task_propagate_assertion_locked(task_imp, IIT_UPDATE_DROP, TRUE);
	}
	return KERN_SUCCESS;
}

/*
 *      Routine:        ipc_importance_task_hold_internal_assertion
 *      Purpose:
 *              Increment the assertion count on the task importance.
 *              If this results in a 0->1 change in that count,
 *              prepare to update task policy for this task AND
 *              (potentially) all down-stream tasks that have a
 *		similar transition through inheriting this update.
 *      Conditions:
 *              Nothing locked
 *              May block after dropping importance lock.
 */
int
ipc_importance_task_hold_internal_assertion(ipc_importance_task_t task_imp, uint32_t count)
{
	int ret = KERN_SUCCESS;

	if (ipc_importance_task_is_any_receiver_type(task_imp)) {
		ipc_importance_lock();
		ret = ipc_importance_task_hold_internal_assertion_locked(task_imp, count);
		ipc_importance_unlock();
	}
	return ret;
}

/*
 *	Routine:	ipc_importance_task_drop_internal_assertion
 *	Purpose:
 *		Decrement the assertion count on the task importance.
 *		If this results in a X->0 change in that count,
 *		prepare to update task policy for this task AND
 *		all down-stream tasks that have a similar transition
 *		through inheriting this drop update.
 *	Conditions:
 *		Nothing locked on entry.
 *		May block after dropping importance lock.
 */
kern_return_t
ipc_importance_task_drop_internal_assertion(ipc_importance_task_t task_imp, uint32_t count)
{
	kern_return_t ret = KERN_SUCCESS;

	if (ipc_importance_task_is_any_receiver_type(task_imp)) {
		ipc_importance_lock();
		ret = ipc_importance_task_drop_internal_assertion_locked(task_imp, count);
		ipc_importance_unlock();
	}
	return ret;
}

/*
 *      Routine:        ipc_importance_task_hold_file_lock_assertion
 *      Purpose:
 *              Increment the file lock assertion count on the task importance.
 *              If this results in a 0->1 change in that count,
 *              prepare to update task policy for this task AND
 *              (potentially) all down-stream tasks that have a
 *		similar transition through inheriting this update.
 *      Conditions:
 *              Nothing locked
 *              May block after dropping importance lock.
 */
kern_return_t
ipc_importance_task_hold_file_lock_assertion(ipc_importance_task_t task_imp, uint32_t count)
{
	kern_return_t ret = KERN_SUCCESS;

	if (ipc_importance_task_is_any_receiver_type(task_imp)) {
		ipc_importance_lock();
		ret = ipc_importance_task_hold_internal_assertion_locked(task_imp, count);
		if (KERN_SUCCESS == ret) {
			task_imp->iit_filelocks += count;
		}
		ipc_importance_unlock();
	}
	return ret;
}

/*
 *	Routine:	ipc_importance_task_drop_file_lock_assertion
 *	Purpose:
 *		Decrement the assertion count on the task importance.
 *		If this results in a X->0 change in that count,
 *		prepare to update task policy for this task AND
 *		all down-stream tasks that have a similar transition
 *		through inheriting this drop update.
 *	Conditions:
 *		Nothing locked on entry.
 *		May block after dropping importance lock.
 */
kern_return_t
ipc_importance_task_drop_file_lock_assertion(ipc_importance_task_t task_imp, uint32_t count)
{
	kern_return_t ret = KERN_SUCCESS;

	if (ipc_importance_task_is_any_receiver_type(task_imp)) {
		ipc_importance_lock();
		if (count <= task_imp->iit_filelocks) {
			task_imp->iit_filelocks -= count;
			ret = ipc_importance_task_drop_internal_assertion_locked(task_imp, count);
		} else {
			ret = KERN_INVALID_ARGUMENT;
		}
		ipc_importance_unlock();
	}
	return ret;
}

/*
 *	Routine:	ipc_importance_task_hold_legacy_external_assertion
 *	Purpose:
 *		Increment the external assertion count on the task importance.
 *		This cannot result in an 0->1 transition, as the caller must
 *		already hold an external boost.
 *	Conditions:
 *		Nothing locked on entry.
 *		May block after dropping importance lock.
 *		A queue of task importance structures is returned
 *		by ipc_importance_task_hold_assertion_locked(). Each
 *		needs to be updated (outside the importance lock hold).
 */
kern_return_t
ipc_importance_task_hold_legacy_external_assertion(ipc_importance_task_t task_imp, uint32_t count)
{
	task_t target_task;
	uint32_t target_assertcnt;
	uint32_t target_externcnt;
	uint32_t target_legacycnt;

	kern_return_t ret;

	ipc_importance_lock();
	target_task = task_imp->iit_task;

#if IMPORTANCE_TRACE
	int target_pid = task_pid(target_task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (IMP_HOLD | TASK_POLICY_EXTERNAL))) | DBG_FUNC_START,
	    proc_selfpid(), target_pid, task_imp->iit_assertcnt, IIT_LEGACY_EXTERN(task_imp), 0);
#endif

	if (IIT_LEGACY_EXTERN(task_imp) == 0) {
		/* Only allowed to take a new boost assertion when holding an external boost */
		/* save data for diagnostic printf below */
		target_assertcnt = task_imp->iit_assertcnt;
		target_externcnt = IIT_EXTERN(task_imp);
		target_legacycnt = IIT_LEGACY_EXTERN(task_imp);
		ret = KERN_FAILURE;
		count = 0;
	} else {
		assert(ipc_importance_task_is_any_receiver_type(task_imp));
		assert(0 < task_imp->iit_assertcnt);
		assert(0 < IIT_EXTERN(task_imp));
		task_imp->iit_assertcnt += count;
		task_imp->iit_externcnt += count;
		task_imp->iit_legacy_externcnt += count;
		ret = KERN_SUCCESS;
	}
	ipc_importance_unlock();

#if IMPORTANCE_TRACE
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (IMP_HOLD | TASK_POLICY_EXTERNAL))) | DBG_FUNC_END,
	    proc_selfpid(), target_pid, task_imp->iit_assertcnt, IIT_LEGACY_EXTERN(task_imp), 0);
	// This covers the legacy case where a task takes an extra boost.
	DTRACE_BOOST5(receive_boost, task_t, target_task, int, target_pid, int, proc_selfpid(), int, count, int, task_imp->iit_assertcnt);
#endif

	if (KERN_FAILURE == ret && target_task != TASK_NULL) {
		printf("BUG in process %s[%d]: "
		    "attempt to acquire an additional legacy external boost assertion without holding an existing legacy external assertion. "
		    "(%d total, %d external, %d legacy-external)\n",
		    proc_name_address(target_task->bsd_info), task_pid(target_task),
		    target_assertcnt, target_externcnt, target_legacycnt);
	}

	return ret;
}

/*
 *	Routine:	ipc_importance_task_drop_legacy_external_assertion
 *	Purpose:
 *		Drop the legacy external assertion count on the task and
 *		reflect that change to total external assertion count and
 *		then onto the internal importance count.
 *
 *		If this results in a X->0 change in the internal,
 *		count, prepare to update task policy for this task AND
 *		all down-stream tasks that have a similar transition
 *		through inheriting this update.
 *	Conditions:
 *		Nothing locked on entry.
 */
kern_return_t
ipc_importance_task_drop_legacy_external_assertion(ipc_importance_task_t task_imp, uint32_t count)
{
	int ret = KERN_SUCCESS;
	task_t target_task;
	uint32_t target_assertcnt;
	uint32_t target_externcnt;
	uint32_t target_legacycnt;

	if (count > 1) {
		return KERN_INVALID_ARGUMENT;
	}

	ipc_importance_lock();
	target_task = task_imp->iit_task;

#if IMPORTANCE_TRACE
	int target_pid = task_pid(target_task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (IMP_DROP | TASK_POLICY_EXTERNAL))) | DBG_FUNC_START,
	    proc_selfpid(), target_pid, task_imp->iit_assertcnt, IIT_LEGACY_EXTERN(task_imp), 0);
#endif

	if (count > IIT_LEGACY_EXTERN(task_imp)) {
		/* Process over-released its boost count - save data for diagnostic printf */
		/* TODO: If count > 1, we should clear out as many external assertions as there are left. */
		target_assertcnt = task_imp->iit_assertcnt;
		target_externcnt = IIT_EXTERN(task_imp);
		target_legacycnt = IIT_LEGACY_EXTERN(task_imp);
		ret = KERN_FAILURE;
	} else {
		/*
		 * decrement legacy external count from the top level and reflect
		 * into internal for this and all subsequent updates.
		 */
		assert(ipc_importance_task_is_any_receiver_type(task_imp));
		assert(IIT_EXTERN(task_imp) >= count);

		task_imp->iit_legacy_externdrop += count;
		task_imp->iit_externdrop += count;

		/* reset extern counters (if appropriate) */
		if (IIT_LEGACY_EXTERN(task_imp) == 0) {
			if (IIT_EXTERN(task_imp) != 0) {
				task_imp->iit_externcnt -= task_imp->iit_legacy_externcnt;
				task_imp->iit_externdrop -= task_imp->iit_legacy_externdrop;
			} else {
				task_imp->iit_externcnt = 0;
				task_imp->iit_externdrop = 0;
			}
			task_imp->iit_legacy_externcnt = 0;
			task_imp->iit_legacy_externdrop = 0;
		}

		/* reflect the drop to the internal assertion count (and effect any importance change) */
		if (ipc_importance_task_check_transition(task_imp, IIT_UPDATE_DROP, count)) {
			ipc_importance_task_propagate_assertion_locked(task_imp, IIT_UPDATE_DROP, TRUE);
		}
		ret = KERN_SUCCESS;
	}

#if IMPORTANCE_TRACE
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, (IMP_DROP | TASK_POLICY_EXTERNAL))) | DBG_FUNC_END,
	    proc_selfpid(), target_pid, task_imp->iit_assertcnt, IIT_LEGACY_EXTERN(task_imp), 0);
#endif

	ipc_importance_unlock();

	/* delayed printf for user-supplied data failures */
	if (KERN_FAILURE == ret && TASK_NULL != target_task) {
		printf("BUG in process %s[%d]: over-released legacy external boost assertions (%d total, %d external, %d legacy-external)\n",
		    proc_name_address(target_task->bsd_info), task_pid(target_task),
		    target_assertcnt, target_externcnt, target_legacycnt);
	}

	return ret;
}


#if LEGACY_IMPORTANCE_DELIVERY
/* Transfer an assertion to legacy userspace responsibility */
static kern_return_t
ipc_importance_task_externalize_legacy_assertion(ipc_importance_task_t task_imp, uint32_t count, __unused int sender_pid)
{
	task_t target_task;

	assert(IIT_NULL != task_imp);
	target_task = task_imp->iit_task;

	if (TASK_NULL == target_task ||
	    !ipc_importance_task_is_any_receiver_type(task_imp)) {
		return KERN_FAILURE;
	}

#if IMPORTANCE_TRACE
	int target_pid = task_pid(target_task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, IMP_EXTERN)) | DBG_FUNC_START,
	    proc_selfpid(), target_pid, task_imp->iit_assertcnt, IIT_EXTERN(task_imp), 0);
#endif

	ipc_importance_lock();
	/* assert(task_imp->iit_assertcnt >= IIT_EXTERN(task_imp) + count); */
	assert(IIT_EXTERN(task_imp) >= IIT_LEGACY_EXTERN(task_imp));
	task_imp->iit_legacy_externcnt += count;
	task_imp->iit_externcnt += count;
	ipc_importance_unlock();

#if IMPORTANCE_TRACE
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_ASSERTION, IMP_EXTERN)) | DBG_FUNC_END,
	    proc_selfpid(), target_pid, task_imp->iit_assertcnt, IIT_LEGACY_EXTERN(task_imp), 0);
	// This is the legacy boosting path
	DTRACE_BOOST5(receive_boost, task_t, target_task, int, target_pid, int, sender_pid, int, count, int, IIT_LEGACY_EXTERN(task_imp));
#endif /* IMPORTANCE_TRACE */

	return KERN_SUCCESS;
}
#endif /* LEGACY_IMPORTANCE_DELIVERY */

/*
 *	Routine:	ipc_importance_task_update_live_donor
 *	Purpose:
 *		Read the live donor status and update the live_donor bit/propagate the change in importance.
 *	Conditions:
 *		Nothing locked on entrance, nothing locked on exit.
 *
 *		TODO: Need tracepoints around this function...
 */
void
ipc_importance_task_update_live_donor(ipc_importance_task_t task_imp)
{
	uint32_t task_live_donor;
	boolean_t before_donor;
	boolean_t after_donor;
	task_t target_task;

	assert(task_imp != NULL);

	/*
	 * Nothing to do if the task is not marked as expecting
	 * live donor updates.
	 */
	if (!ipc_importance_task_is_marked_live_donor(task_imp)) {
		return;
	}

	ipc_importance_lock();

	/* If the task got disconnected on the way here, no use (or ability) adjusting live donor status */
	target_task = task_imp->iit_task;
	if (TASK_NULL == target_task) {
		ipc_importance_unlock();
		return;
	}
	before_donor = ipc_importance_task_is_marked_donor(task_imp);

	/* snapshot task live donor status - may change, but another call will accompany the change */
	task_live_donor = target_task->effective_policy.tep_live_donor;

#if IMPORTANCE_TRACE
	int target_pid = task_pid(target_task);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_DONOR_CHANGE, IMP_DONOR_UPDATE_LIVE_DONOR_STATE)) | DBG_FUNC_START,
	    target_pid, task_imp->iit_donor, task_live_donor, before_donor, 0);
#endif

	/* update the task importance live donor status based on the task's value */
	task_imp->iit_donor = task_live_donor;

	after_donor = ipc_importance_task_is_marked_donor(task_imp);

	/* Has the effectiveness of being a donor changed as a result of this update? */
	if (before_donor != after_donor) {
		iit_update_type_t type;

		/* propagate assertions without updating the current task policy (already handled) */
		if (0 == before_donor) {
			task_imp->iit_transitions++;
			type = IIT_UPDATE_HOLD;
		} else {
			type = IIT_UPDATE_DROP;
		}
		ipc_importance_task_propagate_assertion_locked(task_imp, type, FALSE);
	}

#if IMPORTANCE_TRACE
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_DONOR_CHANGE, IMP_DONOR_UPDATE_LIVE_DONOR_STATE)) | DBG_FUNC_END,
	    target_pid, task_imp->iit_donor, task_live_donor, after_donor, 0);
#endif

	ipc_importance_unlock();
}


/*
 *	Routine:	ipc_importance_task_mark_donor
 *	Purpose:
 *		Set the task importance donor flag.
 *	Conditions:
 *		Nothing locked on entrance, nothing locked on exit.
 *
 *		This is only called while the task is being constructed,
 *		so no need to update task policy or propagate downstream.
 */
void
ipc_importance_task_mark_donor(ipc_importance_task_t task_imp, boolean_t donating)
{
	assert(task_imp != NULL);

	ipc_importance_lock();

	int old_donor = task_imp->iit_donor;

	task_imp->iit_donor = (donating ? 1 : 0);

	if (task_imp->iit_donor > 0 && old_donor == 0) {
		task_imp->iit_transitions++;
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    (IMPORTANCE_CODE(IMP_DONOR_CHANGE, IMP_DONOR_INIT_DONOR_STATE)) | DBG_FUNC_NONE,
	    task_pid(task_imp->iit_task), donating,
	    old_donor, task_imp->iit_donor, 0);

	ipc_importance_unlock();
}

/*
 *	Routine:	ipc_importance_task_marked_donor
 *	Purpose:
 *		Query the donor flag for the given task importance.
 *	Conditions:
 *		May be called without taking the importance lock.
 *		In that case, donor status can change so you must
 *		check only once for each donation event.
 */
boolean_t
ipc_importance_task_is_marked_donor(ipc_importance_task_t task_imp)
{
	if (IIT_NULL == task_imp) {
		return FALSE;
	}
	return 0 != task_imp->iit_donor;
}

/*
 *	Routine:	ipc_importance_task_mark_live_donor
 *	Purpose:
 *		Indicate that the task is eligible for live donor updates.
 *	Conditions:
 *		Nothing locked on entrance, nothing locked on exit.
 *
 *		This is only called while the task is being constructed.
 */
void
ipc_importance_task_mark_live_donor(ipc_importance_task_t task_imp, boolean_t live_donating)
{
	assert(task_imp != NULL);

	ipc_importance_lock();
	task_imp->iit_live_donor = (live_donating ? 1 : 0);
	ipc_importance_unlock();
}

/*
 *	Routine:	ipc_importance_task_is_marked_live_donor
 *	Purpose:
 *		Query the live donor and donor flags for the given task importance.
 *	Conditions:
 *		May be called without taking the importance lock.
 *		In that case, donor status can change so you must
 *		check only once for each donation event.
 */
boolean_t
ipc_importance_task_is_marked_live_donor(ipc_importance_task_t task_imp)
{
	if (IIT_NULL == task_imp) {
		return FALSE;
	}
	return 0 != task_imp->iit_live_donor;
}

/*
 *	Routine:	ipc_importance_task_is_donor
 *	Purpose:
 *		Query the full donor status for the given task importance.
 *	Conditions:
 *		May be called without taking the importance lock.
 *		In that case, donor status can change so you must
 *		check only once for each donation event.
 */
boolean_t
ipc_importance_task_is_donor(ipc_importance_task_t task_imp)
{
	if (IIT_NULL == task_imp) {
		return FALSE;
	}
	return ipc_importance_task_is_marked_donor(task_imp) ||
	       (ipc_importance_task_is_marked_receiver(task_imp) &&
	       task_imp->iit_assertcnt > 0);
}

/*
 *	Routine:	ipc_importance_task_is_never_donor
 *	Purpose:
 *		Query if a given task can ever donate importance.
 *	Conditions:
 *		May be called without taking the importance lock.
 *		Condition is permanent for a give task.
 */
boolean_t
ipc_importance_task_is_never_donor(ipc_importance_task_t task_imp)
{
	if (IIT_NULL == task_imp) {
		return FALSE;
	}
	return !ipc_importance_task_is_marked_donor(task_imp) &&
	       !ipc_importance_task_is_marked_live_donor(task_imp) &&
	       !ipc_importance_task_is_marked_receiver(task_imp);
}

/*
 *	Routine:	ipc_importance_task_mark_receiver
 *	Purpose:
 *		Update the task importance receiver flag.
 *	Conditions:
 *		Nothing locked on entrance, nothing locked on exit.
 *		This can only be invoked before the task is discoverable,
 *		so no worries about atomicity(?)
 */
void
ipc_importance_task_mark_receiver(ipc_importance_task_t task_imp, boolean_t receiving)
{
	assert(task_imp != NULL);

	ipc_importance_lock();
	if (receiving) {
		assert(task_imp->iit_assertcnt == 0);
		assert(task_imp->iit_externcnt == 0);
		assert(task_imp->iit_externdrop == 0);
		assert(task_imp->iit_denap == 0);
		task_imp->iit_receiver = 1;  /* task can receive importance boost */
	} else if (task_imp->iit_receiver) {
		assert(task_imp->iit_denap == 0);
		if (task_imp->iit_assertcnt != 0 || IIT_EXTERN(task_imp) != 0) {
			panic("disabling imp_receiver on task with pending importance boosts!");
		}
		task_imp->iit_receiver = 0;
	}
	ipc_importance_unlock();
}


/*
 *	Routine:	ipc_importance_task_marked_receiver
 *	Purpose:
 *		Query the receiver flag for the given task importance.
 *	Conditions:
 *		May be called without taking the importance lock as
 *		the importance flag can never change after task init.
 */
boolean_t
ipc_importance_task_is_marked_receiver(ipc_importance_task_t task_imp)
{
	return IIT_NULL != task_imp && 0 != task_imp->iit_receiver;
}


/*
 *	Routine:	ipc_importance_task_mark_denap_receiver
 *	Purpose:
 *		Update the task importance de-nap receiver flag.
 *	Conditions:
 *		Nothing locked on entrance, nothing locked on exit.
 *		This can only be invoked before the task is discoverable,
 *		so no worries about atomicity(?)
 */
void
ipc_importance_task_mark_denap_receiver(ipc_importance_task_t task_imp, boolean_t denap)
{
	assert(task_imp != NULL);

	ipc_importance_lock();
	if (denap) {
		assert(task_imp->iit_assertcnt == 0);
		assert(task_imp->iit_externcnt == 0);
		assert(task_imp->iit_receiver == 0);
		task_imp->iit_denap = 1;  /* task can receive de-nap boost */
	} else if (task_imp->iit_denap) {
		assert(task_imp->iit_receiver == 0);
		if (0 < task_imp->iit_assertcnt || 0 < IIT_EXTERN(task_imp)) {
			panic("disabling de-nap on task with pending de-nap boosts!");
		}
		task_imp->iit_denap = 0;
	}
	ipc_importance_unlock();
}


/*
 *	Routine:	ipc_importance_task_marked_denap_receiver
 *	Purpose:
 *		Query the de-nap receiver flag for the given task importance.
 *	Conditions:
 *		May be called without taking the importance lock as
 *		the de-nap flag can never change after task init.
 */
boolean_t
ipc_importance_task_is_marked_denap_receiver(ipc_importance_task_t task_imp)
{
	return IIT_NULL != task_imp && 0 != task_imp->iit_denap;
}

/*
 *	Routine:	ipc_importance_task_is_denap_receiver
 *	Purpose:
 *		Query the full de-nap receiver status for the given task importance.
 *		For now, that is simply whether the receiver flag is set.
 *	Conditions:
 *		May be called without taking the importance lock as
 *		the de-nap receiver flag can never change after task init.
 */
boolean_t
ipc_importance_task_is_denap_receiver(ipc_importance_task_t task_imp)
{
	return ipc_importance_task_is_marked_denap_receiver(task_imp);
}

/*
 *	Routine:	ipc_importance_task_is_any_receiver_type
 *	Purpose:
 *		Query if the task is marked to receive boosts - either
 *		importance or denap.
 *	Conditions:
 *		May be called without taking the importance lock as both
 *		the importance and de-nap receiver flags can never change
 *		after task init.
 */
boolean_t
ipc_importance_task_is_any_receiver_type(ipc_importance_task_t task_imp)
{
	return ipc_importance_task_is_marked_receiver(task_imp) ||
	       ipc_importance_task_is_marked_denap_receiver(task_imp);
}

#if 0 /* currently unused */

/*
 *	Routine:	ipc_importance_inherit_reference
 *	Purpose:
 *		Add a reference to the inherit importance element.
 *	Conditions:
 *		Caller most hold a reference on the inherit element.
 */
static inline void
ipc_importance_inherit_reference(ipc_importance_inherit_t inherit)
{
	ipc_importance_reference(&inherit->iii_elem);
}
#endif /* currently unused */

/*
 *	Routine:	ipc_importance_inherit_release_locked
 *	Purpose:
 *		Release a reference on an inherit importance attribute value,
 *		unlinking and deallocating the attribute if the last reference.
 *	Conditions:
 *		Entered with importance lock held, leaves with it unlocked.
 */
static inline void
ipc_importance_inherit_release_locked(ipc_importance_inherit_t inherit)
{
	ipc_importance_release_locked(&inherit->iii_elem);
}

#if 0 /* currently unused */
/*
 *	Routine:	ipc_importance_inherit_release
 *	Purpose:
 *		Release a reference on an inherit importance attribute value,
 *		unlinking and deallocating the attribute if the last reference.
 *	Conditions:
 *		nothing locked on entrance, nothing locked on exit.
 *		May block.
 */
void
ipc_importance_inherit_release(ipc_importance_inherit_t inherit)
{
	if (III_NULL != inherit) {
		ipc_importance_release(&inherit->iii_elem);
	}
}
#endif /* 0 currently unused */

/*
 *	Routine:	ipc_importance_for_task
 *	Purpose:
 *		Create a reference for the specified task's base importance
 *		element.  If the base importance element doesn't exist, make it and
 *		bind it to the active task.  If the task is inactive, there isn't
 *		any need to return a new reference.
 *	Conditions:
 *		If made is true, a "made" reference is returned (for donating to
 *		the voucher system).  Otherwise	an internal reference is returned.
 *
 *		Nothing locked on entry.  May block.
 */
ipc_importance_task_t
ipc_importance_for_task(task_t task, boolean_t made)
{
	ipc_importance_task_t task_elem;
	boolean_t first_pass = TRUE;

	assert(TASK_NULL != task);

retry:
	/* No use returning anything for inactive task */
	if (!task->active) {
		return IIT_NULL;
	}

	ipc_importance_lock();
	task_elem = task->task_imp_base;
	if (IIT_NULL != task_elem) {
		/* Add a made reference (borrowing active task ref to do it) */
		if (made) {
			if (0 == task_elem->iit_made++) {
				assert(IIT_REFS_MAX > IIT_REFS(task_elem));
				ipc_importance_task_reference_internal(task_elem);
			}
		} else {
			assert(IIT_REFS_MAX > IIT_REFS(task_elem));
			ipc_importance_task_reference_internal(task_elem);
		}
		ipc_importance_unlock();
		return task_elem;
	}
	ipc_importance_unlock();

	if (!first_pass) {
		return IIT_NULL;
	}
	first_pass = FALSE;

	/* Need to make one - may race with others (be prepared to drop) */
	task_elem = zalloc_flags(ipc_importance_task_zone, Z_WAITOK | Z_ZERO);
	if (IIT_NULL == task_elem) {
		goto retry;
	}

	task_elem->iit_bits = IIE_TYPE_TASK | 2; /* one for task, one for return/made */
	task_elem->iit_made = (made) ? 1 : 0;
	task_elem->iit_task = task; /* take actual ref when we're sure */
#if IIE_REF_DEBUG
	ipc_importance_counter_init(&task_elem->iit_elem);
#endif
	queue_init(&task_elem->iit_kmsgs);
	queue_init(&task_elem->iit_inherits);

	ipc_importance_lock();
	if (!task->active) {
		ipc_importance_unlock();
		zfree(ipc_importance_task_zone, task_elem);
		return IIT_NULL;
	}

	/* did we lose the race? */
	if (IIT_NULL != task->task_imp_base) {
		ipc_importance_unlock();
		zfree(ipc_importance_task_zone, task_elem);
		goto retry;
	}

	/* we won the race */
	task->task_imp_base = task_elem;
	task_reference(task);
#if DEVELOPMENT || DEBUG
	queue_enter(&global_iit_alloc_queue, task_elem, ipc_importance_task_t, iit_allocation);
	task_importance_update_owner_info(task);
#endif
	ipc_importance_unlock();

	return task_elem;
}

#if DEVELOPMENT || DEBUG
void
task_importance_update_owner_info(task_t task)
{
	if (task != TASK_NULL && task->task_imp_base != IIT_NULL) {
		ipc_importance_task_t task_elem = task->task_imp_base;

		task_elem->iit_bsd_pid = task_pid(task);
		if (task->bsd_info) {
			strncpy(&task_elem->iit_procname[0], proc_name_address(task->bsd_info), 16);
			task_elem->iit_procname[16] = '\0';
		} else {
			strncpy(&task_elem->iit_procname[0], "unknown", 16);
		}
	}
}
#endif

/*
 *	Routine:	ipc_importance_reset_locked
 *	Purpose:
 *		Reset a task's IPC importance (the task is going away or exec'ing)
 *
 *		Remove the donor bit and legacy externalized assertions from the
 *		current task importance and see if that wipes out downstream donations.
 *	Conditions:
 *		importance lock held.
 */

static void
ipc_importance_reset_locked(ipc_importance_task_t task_imp, boolean_t donor)
{
	boolean_t before_donor, after_donor;

	/* remove the donor bit, live-donor bit and externalized boosts */
	before_donor = ipc_importance_task_is_donor(task_imp);
	if (donor) {
		task_imp->iit_donor = 0;
	}
	assert(IIT_LEGACY_EXTERN(task_imp) <= IIT_EXTERN(task_imp));
	assert(task_imp->iit_legacy_externcnt <= task_imp->iit_externcnt);
	assert(task_imp->iit_legacy_externdrop <= task_imp->iit_externdrop);
	task_imp->iit_externcnt -= task_imp->iit_legacy_externcnt;
	task_imp->iit_externdrop -= task_imp->iit_legacy_externdrop;

	/* assert(IIT_LEGACY_EXTERN(task_imp) <= task_imp->iit_assertcnt); */
	if (IIT_EXTERN(task_imp) < task_imp->iit_assertcnt) {
		task_imp->iit_assertcnt -= IIT_LEGACY_EXTERN(task_imp);
	} else {
		task_imp->iit_assertcnt = IIT_EXTERN(task_imp);
	}
	task_imp->iit_legacy_externcnt = 0;
	task_imp->iit_legacy_externdrop = 0;
	after_donor = ipc_importance_task_is_donor(task_imp);

#if DEVELOPMENT || DEBUG
	if (task_imp->iit_assertcnt > 0 && task_imp->iit_live_donor) {
		printf("Live donor task %s[%d] still has %d importance assertions after reset\n",
		    task_imp->iit_procname, task_imp->iit_bsd_pid, task_imp->iit_assertcnt);
	}
#endif

	/* propagate a downstream drop if there was a change in donor status */
	if (after_donor != before_donor) {
		ipc_importance_task_propagate_assertion_locked(task_imp, IIT_UPDATE_DROP, FALSE);
	}
}

/*
 *	Routine:	ipc_importance_reset
 *	Purpose:
 *		Reset a task's IPC importance
 *
 *		The task is being reset, although staying around. Arrange to have the
 *		external state of the task reset from the importance.
 *	Conditions:
 *		importance lock not held.
 */

void
ipc_importance_reset(ipc_importance_task_t task_imp, boolean_t donor)
{
	if (IIT_NULL == task_imp) {
		return;
	}
	ipc_importance_lock();
	ipc_importance_reset_locked(task_imp, donor);
	ipc_importance_unlock();
}

/*
 *	Routine:	ipc_importance_disconnect_task
 *	Purpose:
 *		Disconnect a task from its importance.
 *
 *		Clear the task pointer from the importance and drop the
 *		reference the task held on the importance object.  Before
 *		doing that, reset the effects the current task holds on
 *		the importance and see if that wipes out downstream donations.
 *
 *		We allow the upstream boosts to continue to affect downstream
 *		even though the local task is being effectively pulled from
 *		the chain.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_importance_disconnect_task(task_t task)
{
	ipc_importance_task_t task_imp;

	task_lock(task);
	ipc_importance_lock();
	task_imp = task->task_imp_base;

	/* did somebody beat us to it? */
	if (IIT_NULL == task_imp) {
		ipc_importance_unlock();
		task_unlock(task);
		return;
	}

	/* disconnect the task from this importance */
	assert(task_imp->iit_task == task);
	task_imp->iit_task = TASK_NULL;
	task->task_imp_base = IIT_NULL;
	task_unlock(task);

	/* reset the effects the current task hold on the importance */
	ipc_importance_reset_locked(task_imp, TRUE);

	ipc_importance_task_release_locked(task_imp);
	/* importance unlocked */

	/* deallocate the task now that the importance is unlocked */
	task_deallocate(task);
}

/*
 *	Routine:	ipc_importance_exec_switch_task
 *	Purpose:
 *		Switch importance task base from old task to new task in exec.
 *
 *		Create an ipc importance linkage from old task to new task,
 *		once the linkage is created, switch the importance task base
 *		from old task to new task. After the switch, the linkage will
 *		represent importance linkage from new task to old task with
 *		watch port importance inheritance linked to new task.
 *	Conditions:
 *		Nothing locked.
 *		Returns a reference on importance inherit.
 */
ipc_importance_inherit_t
ipc_importance_exec_switch_task(
	task_t old_task,
	task_t new_task)
{
	ipc_importance_inherit_t inherit = III_NULL;
	ipc_importance_task_t old_task_imp = IIT_NULL;
	ipc_importance_task_t new_task_imp = IIT_NULL;

	task_importance_reset(old_task);

	/* Create an importance linkage from old_task to new_task */
	inherit = ipc_importance_inherit_from_task(old_task, new_task);

	/* Switch task importance base from old task to new task */
	ipc_importance_lock();

	old_task_imp = old_task->task_imp_base;
	new_task_imp = new_task->task_imp_base;

	old_task_imp->iit_task = new_task;
	new_task_imp->iit_task = old_task;

	old_task->task_imp_base = new_task_imp;
	new_task->task_imp_base = old_task_imp;

#if DEVELOPMENT || DEBUG
	/*
	 * Update the pid an proc name for importance base if any
	 */
	task_importance_update_owner_info(new_task);
#endif
	ipc_importance_unlock();

	return inherit;
}

/*
 *	Routine:	ipc_importance_check_circularity
 *	Purpose:
 *		Check if queueing "port" in a message for "dest"
 *		would create a circular group of ports and messages.
 *
 *		If no circularity (FALSE returned), then "port"
 *		is changed from "in limbo" to "in transit".
 *
 *		That is, we want to set port->ip_destination == dest,
 *		but guaranteeing that this doesn't create a circle
 *		port->ip_destination->ip_destination->... == port
 *
 *		Additionally, if port was successfully changed to "in transit",
 *		propagate boost assertions from the "in limbo" port to all
 *		the ports in the chain, and, if the destination task accepts
 *		boosts, to the destination task.
 *
 *	Conditions:
 *		No ports locked.  References held for "port" and "dest".
 */

boolean_t
ipc_importance_check_circularity(
	ipc_port_t      port,
	ipc_port_t      dest)
{
	ipc_importance_task_t imp_task = IIT_NULL;
	ipc_importance_task_t release_imp_task = IIT_NULL;
	boolean_t imp_lock_held = FALSE;
	int assertcnt = 0;
	ipc_port_t base;
	struct turnstile *send_turnstile = TURNSTILE_NULL;
	struct task_watchport_elem *watchport_elem = NULL;
	bool took_base_ref = false;

	assert(port != IP_NULL);
	assert(dest != IP_NULL);

	if (port == dest) {
		return TRUE;
	}
	base = dest;

	/* Check if destination needs a turnstile */
	ipc_port_send_turnstile_prepare(dest);

	/* port is in limbo, so donation status is safe to latch */
	if (port->ip_impdonation != 0) {
		imp_lock_held = TRUE;
		ipc_importance_lock();
	}

	/*
	 *	First try a quick check that can run in parallel.
	 *	No circularity if dest is not in transit.
	 */
	ip_lock(port);

	/*
	 * Even if port is just carrying assertions for others,
	 * we need the importance lock.
	 */
	if (port->ip_impcount > 0 && !imp_lock_held) {
		if (!ipc_importance_lock_try()) {
			ip_unlock(port);
			ipc_importance_lock();
			ip_lock(port);
		}
		imp_lock_held = TRUE;
	}

	if (ip_lock_try(dest)) {
		if (!ip_active(dest) ||
		    (dest->ip_receiver_name != MACH_PORT_NULL) ||
		    (dest->ip_destination == IP_NULL)) {
			goto not_circular;
		}

		/* dest is in transit; further checking necessary */

		ip_unlock(dest);
	}
	ip_unlock(port);

	/*
	 * We're about to pay the cost to serialize,
	 * just go ahead and grab importance lock.
	 */
	if (!imp_lock_held) {
		ipc_importance_lock();
		imp_lock_held = TRUE;
	}

	ipc_port_multiple_lock(); /* massive serialization */

	took_base_ref = ipc_port_destination_chain_lock(dest, &base);
	/* all ports in chain from dest to base, inclusive, are locked */

	if (port == base) {
		/* circularity detected! */

		ipc_port_multiple_unlock();

		/* port (== base) is in limbo */

		require_ip_active(port);
		assert(port->ip_receiver_name == MACH_PORT_NULL);
		assert(port->ip_destination == IP_NULL);
		assert(!took_base_ref);

		base = dest;
		while (base != IP_NULL) {
			ipc_port_t next;

			/* base is in transit or in limbo */

			require_ip_active(base);
			assert(base->ip_receiver_name == MACH_PORT_NULL);

			next = base->ip_destination;
			ip_unlock(base);
			base = next;
		}

		if (imp_lock_held) {
			ipc_importance_unlock();
		}

		ipc_port_send_turnstile_complete(dest);
		return TRUE;
	}

	/*
	 *	The guarantee:  lock port while the entire chain is locked.
	 *	Once port is locked, we can take a reference to dest,
	 *	add port to the chain, and unlock everything.
	 */

	ip_lock(port);
	ipc_port_multiple_unlock();

not_circular:
	/* port is in limbo */
	imq_lock(&port->ip_messages);

	require_ip_active(port);
	assert(port->ip_receiver_name == MACH_PORT_NULL);
	assert(port->ip_destination == IP_NULL);

	/* Port is being enqueued in a kmsg, remove the watchport boost in order to push on destination port */
	watchport_elem = ipc_port_clear_watchport_elem_internal(port);

	/* Check if the port is being enqueued as a part of sync bootstrap checkin */
	if (dest->ip_specialreply && dest->ip_sync_bootstrap_checkin) {
		port->ip_sync_bootstrap_checkin = 1;
	}

	ip_reference(dest);
	port->ip_destination = dest;

	/* must have been in limbo or still bound to a task */
	assert(port->ip_tempowner != 0);

	/*
	 * We delayed dropping assertions from a specific task.
	 * Cache that info now (we'll drop assertions and the
	 * task reference below).
	 */
	release_imp_task = port->ip_imp_task;
	if (IIT_NULL != release_imp_task) {
		port->ip_imp_task = IIT_NULL;
	}
	assertcnt = port->ip_impcount;

	/* take the port out of limbo w.r.t. assertions */
	port->ip_tempowner = 0;

	/*
	 * Setup linkage for source port if it has a send turnstile i.e. it has
	 * a thread waiting in send or has a port enqueued in it or has sync ipc
	 * push from a special reply port.
	 */
	if (port_send_turnstile(port)) {
		send_turnstile = turnstile_prepare((uintptr_t)port,
		    port_send_turnstile_address(port),
		    TURNSTILE_NULL, TURNSTILE_SYNC_IPC);

		turnstile_update_inheritor(send_turnstile, port_send_turnstile(dest),
		    (TURNSTILE_INHERITOR_TURNSTILE | TURNSTILE_IMMEDIATE_UPDATE));

		/* update complete and turnstile complete called after dropping all locks */
	}
	imq_unlock(&port->ip_messages);

	/* now unlock chain */

	ip_unlock(port);

	for (;;) {
		ipc_port_t next;
		/* every port along chain track assertions behind it */
		ipc_port_impcount_delta(dest, assertcnt, base);

		if (dest == base) {
			break;
		}

		/* port is in transit */

		require_ip_active(dest);
		assert(dest->ip_receiver_name == MACH_PORT_NULL);
		assert(dest->ip_destination != IP_NULL);
		assert(dest->ip_tempowner == 0);

		next = dest->ip_destination;
		ip_unlock(dest);
		dest = next;
	}

	/* base is not in transit */
	assert(!ip_active(base) ||
	    (base->ip_receiver_name != MACH_PORT_NULL) ||
	    (base->ip_destination == IP_NULL));

	/*
	 * Find the task to boost (if any).
	 * We will boost "through" ports that don't know
	 * about inheritance to deliver receive rights that
	 * do.
	 */
	if (ip_active(base) && (assertcnt > 0)) {
		assert(imp_lock_held);
		if (base->ip_tempowner != 0) {
			if (IIT_NULL != base->ip_imp_task) {
				/* specified tempowner task */
				imp_task = base->ip_imp_task;
				assert(ipc_importance_task_is_any_receiver_type(imp_task));
			}
			/* otherwise don't boost current task */
		} else if (base->ip_receiver_name != MACH_PORT_NULL) {
			ipc_space_t space = base->ip_receiver;

			/* only spaces with boost-accepting tasks */
			if (space->is_task != TASK_NULL &&
			    ipc_importance_task_is_any_receiver_type(space->is_task->task_imp_base)) {
				imp_task = space->is_task->task_imp_base;
			}
		}

		/* take reference before unlocking base */
		if (imp_task != IIT_NULL) {
			ipc_importance_task_reference(imp_task);
		}
	}

	ip_unlock(base);
	if (took_base_ref) {
		ip_release(base);
	}

	/* All locks dropped, call turnstile_update_inheritor_complete for source port's turnstile */
	if (send_turnstile) {
		turnstile_update_inheritor_complete(send_turnstile, TURNSTILE_INTERLOCK_NOT_HELD);

		/* Take the mq lock to call turnstile complete */
		imq_lock(&port->ip_messages);
		turnstile_complete((uintptr_t)port, port_send_turnstile_address(port), NULL, TURNSTILE_SYNC_IPC);
		send_turnstile = TURNSTILE_NULL;
		imq_unlock(&port->ip_messages);
		turnstile_cleanup();
	}

	/*
	 * Transfer assertions now that the ports are unlocked.
	 * Avoid extra overhead if transferring to/from the same task.
	 *
	 * NOTE: If a transfer is occurring, the new assertions will
	 * be added to imp_task BEFORE the importance lock is unlocked.
	 * This is critical - to avoid decrements coming from the kmsgs
	 * beating the increment to the task.
	 */
	boolean_t transfer_assertions = (imp_task != release_imp_task);

	if (imp_task != IIT_NULL) {
		assert(imp_lock_held);
		if (transfer_assertions) {
			ipc_importance_task_hold_internal_assertion_locked(imp_task, assertcnt);
		}
	}

	if (release_imp_task != IIT_NULL) {
		assert(imp_lock_held);
		if (transfer_assertions) {
			ipc_importance_task_drop_internal_assertion_locked(release_imp_task, assertcnt);
		}
	}

	if (imp_lock_held) {
		ipc_importance_unlock();
	}

	if (imp_task != IIT_NULL) {
		ipc_importance_task_release(imp_task);
	}

	if (release_imp_task != IIT_NULL) {
		ipc_importance_task_release(release_imp_task);
	}

	if (watchport_elem) {
		task_watchport_elem_deallocate(watchport_elem);
	}

	return FALSE;
}

/*
 *	Routine:	ipc_importance_send
 *	Purpose:
 *		Post the importance voucher attribute [if sent] or a static
 *		importance boost depending upon options and conditions.
 *	Conditions:
 *		Destination port locked on entry and exit, may be dropped during the call.
 *	Returns:
 *		A boolean identifying if the port lock was tempoarily dropped.
 */
boolean_t
ipc_importance_send(
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option)
{
	ipc_port_t port = kmsg->ikm_header->msgh_remote_port;
	boolean_t port_lock_dropped = FALSE;
	ipc_importance_elem_t elem;
	task_t task;
	ipc_importance_task_t task_imp;
	kern_return_t kr;

	assert(IP_VALID(port));

	/* If no donation to be made, return quickly */
	if ((port->ip_impdonation == 0) ||
	    (option & MACH_SEND_NOIMPORTANCE) != 0) {
		return port_lock_dropped;
	}

	task = current_task();

	/* If forced sending a static boost, go update the port */
	if ((option & MACH_SEND_IMPORTANCE) != 0) {
		/* acquire the importance lock while trying to hang on to port lock */
		if (!ipc_importance_lock_try()) {
			port_lock_dropped = TRUE;
			ip_unlock(port);
			ipc_importance_lock();
		}
		goto portupdate;
	}

	task_imp = task->task_imp_base;
	assert(IIT_NULL != task_imp);

	/* If the sender can never donate importance, nothing to do */
	if (ipc_importance_task_is_never_donor(task_imp)) {
		return port_lock_dropped;
	}

	elem = IIE_NULL;

	/* If importance receiver and passing a voucher, look for importance in there */
	if (IP_VALID(kmsg->ikm_voucher) &&
	    ipc_importance_task_is_marked_receiver(task_imp)) {
		mach_voucher_attr_value_handle_t vals[MACH_VOUCHER_ATTR_VALUE_MAX_NESTED];
		mach_voucher_attr_value_handle_array_size_t val_count;
		ipc_voucher_t voucher;

		assert(ip_kotype(kmsg->ikm_voucher) == IKOT_VOUCHER);
		voucher = (ipc_voucher_t)ip_get_kobject(kmsg->ikm_voucher);

		/* check to see if the voucher has an importance attribute */
		val_count = MACH_VOUCHER_ATTR_VALUE_MAX_NESTED;
		kr = mach_voucher_attr_control_get_values(ipc_importance_control, voucher,
		    vals, &val_count);
		assert(KERN_SUCCESS == kr);

		/*
		 * Only use importance associated with our task (either directly
		 * or through an inherit that donates to our task).
		 */
		if (0 < val_count) {
			ipc_importance_elem_t check_elem;

			check_elem = (ipc_importance_elem_t)vals[0];
			assert(IIE_NULL != check_elem);
			if (IIE_TYPE_INHERIT == IIE_TYPE(check_elem)) {
				ipc_importance_inherit_t inherit;
				inherit = (ipc_importance_inherit_t) check_elem;
				if (inherit->iii_to_task == task_imp) {
					elem = check_elem;
				}
			} else if (check_elem == (ipc_importance_elem_t)task_imp) {
				elem = check_elem;
			}
		}
	}

	/* If we haven't found an importance attribute to send yet, use the task's */
	if (IIE_NULL == elem) {
		elem = (ipc_importance_elem_t)task_imp;
	}

	/* take a reference for the message to hold */
	ipc_importance_reference_internal(elem);

	/* acquire the importance lock while trying to hang on to port lock */
	if (!ipc_importance_lock_try()) {
		port_lock_dropped = TRUE;
		ip_unlock(port);
		ipc_importance_lock();
	}

	/* link kmsg onto the donor element propagation chain */
	ipc_importance_kmsg_link(kmsg, elem);
	/* elem reference transfered to kmsg */

	incr_ref_counter(elem->iie_kmsg_refs_added);

	/* If the sender isn't currently a donor, no need to apply boost */
	if (!ipc_importance_task_is_donor(task_imp)) {
		ipc_importance_unlock();

		/* re-acquire port lock, if needed */
		if (TRUE == port_lock_dropped) {
			ip_lock(port);
		}

		return port_lock_dropped;
	}

portupdate:
	/* Mark the fact that we are (currently) donating through this message */
	kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_RAISEIMP;

	/*
	 * If we need to relock the port, do it with the importance still locked.
	 * This assures we get to add the importance boost through the port to
	 * the task BEFORE anyone else can attempt to undo that operation if
	 * the sender lost donor status.
	 */
	if (TRUE == port_lock_dropped) {
		ip_lock(port);
	}

	ipc_importance_assert_held();

#if IMPORTANCE_TRACE
	if (kdebug_enable) {
		mach_msg_max_trailer_t *dbgtrailer = (mach_msg_max_trailer_t *)
		    ((vm_offset_t)kmsg->ikm_header + mach_round_msg(kmsg->ikm_header->msgh_size));
		unsigned int sender_pid = dbgtrailer->msgh_audit.val[5];
		mach_msg_id_t imp_msgh_id = kmsg->ikm_header->msgh_id;
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_MSG, IMP_MSG_SEND)) | DBG_FUNC_START,
		    task_pid(task), sender_pid, imp_msgh_id, 0, 0);
	}
#endif /* IMPORTANCE_TRACE */

	mach_port_delta_t delta = 1;
	boolean_t need_port_lock;
	task_imp = IIT_NULL;

	/* adjust port boost count (with importance and port locked) */
	need_port_lock = ipc_port_importance_delta_internal(port, IPID_OPTION_NORMAL, &delta, &task_imp);
	/* hold a reference on task_imp */

	/* if we need to adjust a task importance as a result, apply that here */
	if (IIT_NULL != task_imp && delta != 0) {
		assert(delta == 1);

		/* if this results in a change of state, propagate the transistion */
		if (ipc_importance_task_check_transition(task_imp, IIT_UPDATE_HOLD, delta)) {
			/* can't hold the port lock during task transition(s) */
			if (!need_port_lock) {
				need_port_lock = TRUE;
				ip_unlock(port);
			}
			ipc_importance_task_propagate_assertion_locked(task_imp, IIT_UPDATE_HOLD, TRUE);
		}
	}

	if (task_imp) {
		ipc_importance_task_release_locked(task_imp);
		/* importance unlocked */
	} else {
		ipc_importance_unlock();
	}

	if (need_port_lock) {
		port_lock_dropped = TRUE;
		ip_lock(port);
	}

	return port_lock_dropped;
}

/*
 *	Routine:	ipc_importance_inherit_from_kmsg
 *	Purpose:
 *		Create a "made" reference for an importance attribute representing
 *		an inheritance between the sender of a message (if linked) and the
 *		current task importance.  If the message is not linked, a static
 *		boost may be created, based on the boost state of the message.
 *
 *		Any transfer from kmsg linkage to inherit linkage must be atomic.
 *
 *		If the task is inactive, there isn't any need to return a new reference.
 *	Conditions:
 *		Nothing locked on entry.  May block.
 */
static ipc_importance_inherit_t
ipc_importance_inherit_from_kmsg(ipc_kmsg_t kmsg)
{
	ipc_importance_task_t   task_imp = IIT_NULL;
	ipc_importance_elem_t   from_elem = kmsg->ikm_importance;
	ipc_importance_elem_t   elem;
	task_t  task_self = current_task();

	ipc_port_t port = kmsg->ikm_header->msgh_remote_port;
	ipc_importance_inherit_t inherit = III_NULL;
	ipc_importance_inherit_t alloc = III_NULL;
	boolean_t cleared_self_donation = FALSE;
	boolean_t donating;
	uint32_t depth = 1;

	/* The kmsg must have an importance donor or static boost to proceed */
	if (IIE_NULL == kmsg->ikm_importance &&
	    !MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits)) {
		return III_NULL;
	}

	/*
	 * No need to set up an inherit linkage if the dest isn't a receiver
	 * of one type or the other.
	 */
	if (!ipc_importance_task_is_any_receiver_type(task_self->task_imp_base)) {
		ipc_importance_lock();
		goto out_locked;
	}

	/* Grab a reference on the importance of the destination */
	task_imp = ipc_importance_for_task(task_self, FALSE);

	ipc_importance_lock();

	if (IIT_NULL == task_imp) {
		goto out_locked;
	}

	incr_ref_counter(task_imp->iit_elem.iie_task_refs_added_inherit_from);

	/* If message is already associated with an inherit... */
	if (IIE_TYPE_INHERIT == IIE_TYPE(from_elem)) {
		ipc_importance_inherit_t from_inherit = (ipc_importance_inherit_t)from_elem;

		/* already targeting our task? - just use it */
		if (from_inherit->iii_to_task == task_imp) {
			/* clear self-donation if not also present in inherit */
			if (!from_inherit->iii_donating &&
			    MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits)) {
				kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_RAISEIMP;
				cleared_self_donation = TRUE;
			}
			inherit = from_inherit;
		} else if (III_DEPTH_MAX == III_DEPTH(from_inherit)) {
			ipc_importance_task_t to_task;
			ipc_importance_elem_t unlinked_from;

			/*
			 * Chain too long. Switch to looking
			 * directly at the from_inherit's to-task
			 * as our source of importance.
			 */
			to_task = from_inherit->iii_to_task;
			ipc_importance_task_reference(to_task);
			from_elem = (ipc_importance_elem_t)to_task;
			depth = III_DEPTH_RESET | 1;

			/* Fixup the kmsg linkage to reflect change */
			unlinked_from = ipc_importance_kmsg_unlink(kmsg);
			assert(unlinked_from == (ipc_importance_elem_t)from_inherit);
			ipc_importance_kmsg_link(kmsg, from_elem);
			ipc_importance_inherit_release_locked(from_inherit);
			/* importance unlocked */
			ipc_importance_lock();
		} else {
			/* inheriting from an inherit */
			depth = from_inherit->iii_depth + 1;
		}
	}

	/*
	 * Don't allow a task to inherit from itself (would keep it permanently
	 * boosted even if all other donors to the task went away).
	 */

	if (from_elem == (ipc_importance_elem_t)task_imp) {
		goto out_locked;
	}

	/*
	 * But if the message isn't associated with any linked source, it is
	 * intended to be permanently boosting (static boost from kernel).
	 * In that case DO let the process permanently boost itself.
	 */
	if (IIE_NULL == from_elem) {
		assert(MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits));
		ipc_importance_task_reference_internal(task_imp);
		from_elem = (ipc_importance_elem_t)task_imp;
	}

	/*
	 * Now that we have the from_elem figured out,
	 * check to see if we already have an inherit for this pairing
	 */
	while (III_NULL == inherit) {
		inherit = ipc_importance_inherit_find(from_elem, task_imp, depth);

		/* Do we have to allocate a new inherit */
		if (III_NULL == inherit) {
			if (III_NULL != alloc) {
				break;
			}

			/* allocate space */
			ipc_importance_unlock();
			alloc = (ipc_importance_inherit_t)
			    zalloc(ipc_importance_inherit_zone);
			ipc_importance_lock();
		}
	}

	/* snapshot the donating status while we have importance locked */
	donating = MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits);

	if (III_NULL != inherit) {
		/* We found one, piggyback on that */
		assert(0 < III_REFS(inherit));
		assert(0 < IIE_REFS(inherit->iii_from_elem));
		assert(inherit->iii_externcnt >= inherit->iii_made);

		/* add in a made reference */
		if (0 == inherit->iii_made++) {
			assert(III_REFS_MAX > III_REFS(inherit));
			ipc_importance_inherit_reference_internal(inherit);
		}

		/* Reflect the inherit's change of status into the task boosts */
		if (0 == III_EXTERN(inherit)) {
			assert(!inherit->iii_donating);
			inherit->iii_donating = donating;
			if (donating) {
				task_imp->iit_externcnt += inherit->iii_externcnt;
				task_imp->iit_externdrop += inherit->iii_externdrop;
			}
		} else {
			assert(donating == inherit->iii_donating);
		}

		/* add in a external reference for this use of the inherit */
		inherit->iii_externcnt++;
	} else {
		/* initialize the previously allocated space */
		inherit = alloc;
		inherit->iii_bits = IIE_TYPE_INHERIT | 1;
		inherit->iii_made = 1;
		inherit->iii_externcnt = 1;
		inherit->iii_externdrop = 0;
		inherit->iii_depth = depth;
		inherit->iii_to_task = task_imp;
		inherit->iii_from_elem = IIE_NULL;
		queue_init(&inherit->iii_kmsgs);

		if (donating) {
			inherit->iii_donating = TRUE;
		} else {
			inherit->iii_donating = FALSE;
		}

		/*
		 * Chain our new inherit on the element it inherits from.
		 * The new inherit takes our reference on from_elem.
		 */
		ipc_importance_inherit_link(inherit, from_elem);

#if IIE_REF_DEBUG
		ipc_importance_counter_init(&inherit->iii_elem);
		from_elem->iie_kmsg_refs_inherited++;
		task_imp->iit_elem.iie_task_refs_inherited++;
#endif
	}

out_locked:
	/*
	 * for those paths that came straight here: snapshot the donating status
	 * (this should match previous snapshot for other paths).
	 */
	donating = MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits);

	/* unlink the kmsg inheritance (if any) */
	elem = ipc_importance_kmsg_unlink(kmsg);
	assert(elem == from_elem);

	/* If found inherit and donating, reflect that in the task externcnt */
	if (III_NULL != inherit && donating) {
		task_imp->iit_externcnt++;
		/* The owner of receive right might have changed, take the internal assertion */
		ipc_importance_task_hold_internal_assertion_locked(task_imp, 1);
		/* may have dropped and retaken importance lock */
	}

	/* If we didn't create a new inherit, we have some resources to release */
	if (III_NULL == inherit || inherit != alloc) {
		if (IIE_NULL != from_elem) {
			if (III_NULL != inherit) {
				incr_ref_counter(from_elem->iie_kmsg_refs_coalesced);
			} else {
				incr_ref_counter(from_elem->iie_kmsg_refs_dropped);
			}
			ipc_importance_release_locked(from_elem);
			/* importance unlocked */
		} else {
			ipc_importance_unlock();
		}

		if (IIT_NULL != task_imp) {
			if (III_NULL != inherit) {
				incr_ref_counter(task_imp->iit_elem.iie_task_refs_coalesced);
			}
			ipc_importance_task_release(task_imp);
		}

		if (III_NULL != alloc) {
			zfree(ipc_importance_inherit_zone, alloc);
		}
	} else {
		/* from_elem and task_imp references transferred to new inherit */
		ipc_importance_unlock();
	}

	/*
	 * decrement port boost count
	 * This is OK to do without the importance lock as we atomically
	 * unlinked the kmsg and snapshot the donating state while holding
	 * the importance lock
	 */
	if (donating || cleared_self_donation) {
		ip_lock(port);
		/* drop importance from port and destination task */
		if (ipc_port_importance_delta(port, IPID_OPTION_NORMAL, -1) == FALSE) {
			ip_unlock(port);
		}
	}

	if (III_NULL != inherit) {
		/* have an associated importance attr, even if currently not donating */
		kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_RAISEIMP;
	} else {
		/* we won't have an importance attribute associated with our message */
		kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_RAISEIMP;
	}

	return inherit;
}

/*
 *	Routine:	ipc_importance_inherit_from_task
 *	Purpose:
 *		Create a reference for an importance attribute representing
 *		an inheritance between the to_task and from_task. The iii
 *		created will be marked as III_FLAGS_FOR_OTHERS.
 *
 *		It will not dedup any iii which are not marked as III_FLAGS_FOR_OTHERS.
 *
 *		If the task is inactive, there isn't any need to return a new reference.
 *	Conditions:
 *		Nothing locked on entry.  May block.
 *		It should not be called from voucher subsystem.
 */
static ipc_importance_inherit_t
ipc_importance_inherit_from_task(
	task_t from_task,
	task_t to_task)
{
	ipc_importance_task_t   to_task_imp = IIT_NULL;
	ipc_importance_task_t   from_task_imp = IIT_NULL;
	ipc_importance_elem_t   from_elem = IIE_NULL;

	ipc_importance_inherit_t inherit = III_NULL;
	ipc_importance_inherit_t alloc = III_NULL;
	boolean_t donating;
	uint32_t depth = 1;

	to_task_imp = ipc_importance_for_task(to_task, FALSE);
	from_task_imp = ipc_importance_for_task(from_task, FALSE);
	from_elem = (ipc_importance_elem_t)from_task_imp;

	ipc_importance_lock();

	if (IIT_NULL == to_task_imp || IIT_NULL == from_task_imp) {
		goto out_locked;
	}

	/*
	 * No need to set up an inherit linkage if the to_task or from_task
	 * isn't a receiver of one type or the other.
	 */
	if (!ipc_importance_task_is_any_receiver_type(to_task_imp) ||
	    !ipc_importance_task_is_any_receiver_type(from_task_imp)) {
		goto out_locked;
	}

	/* Do not allow to create a linkage to self */
	if (to_task_imp == from_task_imp) {
		goto out_locked;
	}

	incr_ref_counter(to_task_imp->iit_elem.iie_task_refs_added_inherit_from);
	incr_ref_counter(from_elem->iie_kmsg_refs_added);

	/*
	 * Now that we have the from_elem figured out,
	 * check to see if we already have an inherit for this pairing
	 */
	while (III_NULL == inherit) {
		inherit = ipc_importance_inherit_find(from_elem, to_task_imp, depth);

		/* Do we have to allocate a new inherit */
		if (III_NULL == inherit) {
			if (III_NULL != alloc) {
				break;
			}

			/* allocate space */
			ipc_importance_unlock();
			alloc = (ipc_importance_inherit_t)
			    zalloc(ipc_importance_inherit_zone);
			ipc_importance_lock();
		}
	}

	/* snapshot the donating status while we have importance locked */
	donating = ipc_importance_task_is_donor(from_task_imp);

	if (III_NULL != inherit) {
		/* We found one, piggyback on that */
		assert(0 < III_REFS(inherit));
		assert(0 < IIE_REFS(inherit->iii_from_elem));

		/* Take a reference for inherit */
		assert(III_REFS_MAX > III_REFS(inherit));
		ipc_importance_inherit_reference_internal(inherit);

		/* Reflect the inherit's change of status into the task boosts */
		if (0 == III_EXTERN(inherit)) {
			assert(!inherit->iii_donating);
			inherit->iii_donating = donating;
			if (donating) {
				to_task_imp->iit_externcnt += inherit->iii_externcnt;
				to_task_imp->iit_externdrop += inherit->iii_externdrop;
			}
		} else {
			assert(donating == inherit->iii_donating);
		}

		/* add in a external reference for this use of the inherit */
		inherit->iii_externcnt++;
	} else {
		/* initialize the previously allocated space */
		inherit = alloc;
		inherit->iii_bits = IIE_TYPE_INHERIT | 1;
		inherit->iii_made = 0;
		inherit->iii_externcnt = 1;
		inherit->iii_externdrop = 0;
		inherit->iii_depth = depth;
		inherit->iii_to_task = to_task_imp;
		inherit->iii_from_elem = IIE_NULL;
		queue_init(&inherit->iii_kmsgs);

		if (donating) {
			inherit->iii_donating = TRUE;
		} else {
			inherit->iii_donating = FALSE;
		}

		/*
		 * Chain our new inherit on the element it inherits from.
		 * The new inherit takes our reference on from_elem.
		 */
		ipc_importance_inherit_link(inherit, from_elem);

#if IIE_REF_DEBUG
		ipc_importance_counter_init(&inherit->iii_elem);
		from_elem->iie_kmsg_refs_inherited++;
		task_imp->iit_elem.iie_task_refs_inherited++;
#endif
	}

out_locked:

	/* If found inherit and donating, reflect that in the task externcnt */
	if (III_NULL != inherit && donating) {
		to_task_imp->iit_externcnt++;
		/* take the internal assertion */
		ipc_importance_task_hold_internal_assertion_locked(to_task_imp, 1);
		/* may have dropped and retaken importance lock */
	}

	/* If we didn't create a new inherit, we have some resources to release */
	if (III_NULL == inherit || inherit != alloc) {
		if (IIE_NULL != from_elem) {
			if (III_NULL != inherit) {
				incr_ref_counter(from_elem->iie_kmsg_refs_coalesced);
			} else {
				incr_ref_counter(from_elem->iie_kmsg_refs_dropped);
			}
			ipc_importance_release_locked(from_elem);
			/* importance unlocked */
		} else {
			ipc_importance_unlock();
		}

		if (IIT_NULL != to_task_imp) {
			if (III_NULL != inherit) {
				incr_ref_counter(to_task_imp->iit_elem.iie_task_refs_coalesced);
			}
			ipc_importance_task_release(to_task_imp);
		}

		if (III_NULL != alloc) {
			zfree(ipc_importance_inherit_zone, alloc);
		}
	} else {
		/* from_elem and to_task_imp references transferred to new inherit */
		ipc_importance_unlock();
	}

	return inherit;
}

/*
 *	Routine:	ipc_importance_receive
 *	Purpose:
 *		Process importance attributes in a received message.
 *
 *		If an importance voucher attribute was sent, transform
 *		that into an attribute value reflecting the inheritance
 *		from the sender to the receiver.
 *
 *		If a static boost is received (or the voucher isn't on
 *		a voucher-based boost), export a static boost.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_importance_receive(
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option)
{
	int impresult = -1;

#if IMPORTANCE_TRACE || LEGACY_IMPORTANCE_DELIVERY
	task_t task_self = current_task();
	unsigned int sender_pid = ((mach_msg_max_trailer_t *)
	    ((vm_offset_t)kmsg->ikm_header +
	    mach_round_msg(kmsg->ikm_header->msgh_size)))->msgh_audit.val[5];
#endif

	/* convert to a voucher with an inherit importance attribute? */
	if ((option & MACH_RCV_VOUCHER) != 0) {
		uint8_t recipes[2 * sizeof(ipc_voucher_attr_recipe_data_t) +
		sizeof(mach_voucher_attr_value_handle_t)];
		ipc_voucher_attr_raw_recipe_array_size_t recipe_size = 0;
		ipc_voucher_attr_recipe_t recipe = (ipc_voucher_attr_recipe_t)recipes;
		ipc_voucher_t recv_voucher;
		mach_voucher_attr_value_handle_t handle;
		ipc_importance_inherit_t inherit;
		kern_return_t kr;

		/* set up recipe to copy the old voucher */
		if (IP_VALID(kmsg->ikm_voucher)) {
			ipc_voucher_t sent_voucher = (ipc_voucher_t)ip_get_kobject(kmsg->ikm_voucher);

			recipe->key = MACH_VOUCHER_ATTR_KEY_ALL;
			recipe->command = MACH_VOUCHER_ATTR_COPY;
			recipe->previous_voucher = sent_voucher;
			recipe->content_size = 0;
			recipe_size += sizeof(*recipe);
		}

		/*
		 * create an inheritance attribute from the kmsg (may be NULL)
		 * transferring any boosts from the kmsg linkage through the
		 * port directly to the new inheritance object.
		 */
		inherit = ipc_importance_inherit_from_kmsg(kmsg);
		handle = (mach_voucher_attr_value_handle_t)inherit;

		assert(IIE_NULL == kmsg->ikm_importance);

		/*
		 * Only create a new voucher if we have an inherit object
		 * (from the ikm_importance field of the incoming message), OR
		 * we have a valid incoming voucher. If we have neither of
		 * these things then there is no need to create a new voucher.
		 */
		if (IP_VALID(kmsg->ikm_voucher) || inherit != III_NULL) {
			/* replace the importance attribute with the handle we created */
			/*  our made reference on the inherit is donated to the voucher */
			recipe = (ipc_voucher_attr_recipe_t)&recipes[recipe_size];
			recipe->key = MACH_VOUCHER_ATTR_KEY_IMPORTANCE;
			recipe->command = MACH_VOUCHER_ATTR_SET_VALUE_HANDLE;
			recipe->previous_voucher = IPC_VOUCHER_NULL;
			recipe->content_size = sizeof(mach_voucher_attr_value_handle_t);
			*(mach_voucher_attr_value_handle_t *)(void *)recipe->content = handle;
			recipe_size += sizeof(*recipe) + sizeof(mach_voucher_attr_value_handle_t);

			kr = ipc_voucher_attr_control_create_mach_voucher(ipc_importance_control,
			    recipes,
			    recipe_size,
			    &recv_voucher);
			assert(KERN_SUCCESS == kr);

			/* swap the voucher port (and set voucher bits in case it didn't already exist) */
			kmsg->ikm_header->msgh_bits |= (MACH_MSG_TYPE_MOVE_SEND << 16);
			ipc_port_release_send(kmsg->ikm_voucher);
			kmsg->ikm_voucher = convert_voucher_to_port(recv_voucher);
			if (III_NULL != inherit) {
				impresult = 2;
			}
		}
	} else { /* Don't want a voucher */
		/* got linked importance? have to drop */
		if (IIE_NULL != kmsg->ikm_importance) {
			ipc_importance_elem_t elem;

			ipc_importance_lock();
			elem = ipc_importance_kmsg_unlink(kmsg);
#if IIE_REF_DEBUG
			elem->iie_kmsg_refs_dropped++;
#endif
			ipc_importance_release_locked(elem);
			/* importance unlocked */
		}

		/* With kmsg unlinked, can safely examine message importance attribute. */
		if (MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits)) {
			ipc_port_t port = kmsg->ikm_header->msgh_remote_port;
#if LEGACY_IMPORTANCE_DELIVERY
			ipc_importance_task_t task_imp = task_self->task_imp_base;

			/* The owner of receive right might have changed, take the internal assertion */
			if (KERN_SUCCESS == ipc_importance_task_hold_internal_assertion(task_imp, 1)) {
				ipc_importance_task_externalize_legacy_assertion(task_imp, 1, sender_pid);
				impresult = 1;
			} else
#endif
			{
				/* The importance boost never applied to task (clear the bit) */
				kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_RAISEIMP;
				impresult = 0;
			}

			/* Drop the boost on the port and the owner of the receive right */
			ip_lock(port);
			if (ipc_port_importance_delta(port, IPID_OPTION_NORMAL, -1) == FALSE) {
				ip_unlock(port);
			}
		}
	}

#if IMPORTANCE_TRACE
	if (-1 < impresult) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_MSG, IMP_MSG_DELV)) | DBG_FUNC_NONE,
		    sender_pid, task_pid(task_self),
		    kmsg->ikm_header->msgh_id, impresult, 0);
	}
	if (impresult == 2) {
		/*
		 * This probe only covers new voucher-based path.  Legacy importance
		 * will trigger the probe in ipc_importance_task_externalize_assertion()
		 * above and have impresult==1 here.
		 */
		DTRACE_BOOST5(receive_boost, task_t, task_self, int, task_pid(task_self), int, sender_pid, int, 1, int, task_self->task_imp_base->iit_assertcnt);
	}
#endif /* IMPORTANCE_TRACE */
}

/*
 *	Routine:	ipc_importance_unreceive
 *	Purpose:
 *		Undo receive of importance attributes in a message.
 *
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_importance_unreceive(
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       __unused option)
{
	/* importance should already be in the voucher and out of the kmsg */
	assert(IIE_NULL == kmsg->ikm_importance);

	/* See if there is a legacy boost to be dropped from receiver */
	if (MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits)) {
		ipc_importance_task_t task_imp;

		kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_RAISEIMP;
		task_imp = current_task()->task_imp_base;
		if (!IP_VALID(kmsg->ikm_voucher) && IIT_NULL != task_imp) {
			ipc_importance_task_drop_legacy_external_assertion(task_imp, 1);
		}
		/*
		 * ipc_kmsg_copyout_dest() will consume the voucher
		 * and any contained importance.
		 */
	}
}

/*
 *	Routine:	ipc_importance_clean
 *	Purpose:
 *		Clean up importance state in a kmsg that is being cleaned.
 *		Unlink the importance chain if one was set up, and drop
 *		the reference this kmsg held on the donor.  Then check to
 *		if importance was carried to the port, and remove that if
 *		needed.
 *	Conditions:
 *		Nothing locked.
 */
void
ipc_importance_clean(
	ipc_kmsg_t              kmsg)
{
	ipc_port_t              port;

	/* Is the kmsg still linked? If so, remove that first */
	if (IIE_NULL != kmsg->ikm_importance) {
		ipc_importance_elem_t   elem;

		ipc_importance_lock();
		elem = ipc_importance_kmsg_unlink(kmsg);
		assert(IIE_NULL != elem);
		ipc_importance_release_locked(elem);
		/* importance unlocked */
	}

	/* See if there is a legacy importance boost to be dropped from port */
	if (MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits)) {
		kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_RAISEIMP;
		port = kmsg->ikm_header->msgh_remote_port;
		if (IP_VALID(port)) {
			ip_lock(port);
			/* inactive ports already had their importance boosts dropped */
			if (!ip_active(port) ||
			    ipc_port_importance_delta(port, IPID_OPTION_NORMAL, -1) == FALSE) {
				ip_unlock(port);
			}
		}
	}
}

void
ipc_importance_assert_clean(__assert_only ipc_kmsg_t kmsg)
{
	assert(IIE_NULL == kmsg->ikm_importance);
	assert(!MACH_MSGH_BITS_RAISED_IMPORTANCE(kmsg->ikm_header->msgh_bits));
}

/*
 * IPC Importance Attribute Manager definition
 */

static kern_return_t
ipc_importance_release_value(
	ipc_voucher_attr_manager_t              manager,
	mach_voucher_attr_key_t                 key,
	mach_voucher_attr_value_handle_t        value,
	mach_voucher_attr_value_reference_t     sync);

static kern_return_t
ipc_importance_get_value(
	ipc_voucher_attr_manager_t                      manager,
	mach_voucher_attr_key_t                         key,
	mach_voucher_attr_recipe_command_t              command,
	mach_voucher_attr_value_handle_array_t          prev_values,
	mach_voucher_attr_value_handle_array_size_t     prev_value_count,
	mach_voucher_attr_content_t                     content,
	mach_voucher_attr_content_size_t                content_size,
	mach_voucher_attr_value_handle_t                *out_value,
	mach_voucher_attr_value_flags_t                 *out_flags,
	ipc_voucher_t                                   *out_value_voucher);

static kern_return_t
ipc_importance_extract_content(
	ipc_voucher_attr_manager_t                      manager,
	mach_voucher_attr_key_t                         key,
	mach_voucher_attr_value_handle_array_t          values,
	mach_voucher_attr_value_handle_array_size_t     value_count,
	mach_voucher_attr_recipe_command_t              *out_command,
	mach_voucher_attr_content_t                     out_content,
	mach_voucher_attr_content_size_t                *in_out_content_size);

static kern_return_t
ipc_importance_command(
	ipc_voucher_attr_manager_t                      manager,
	mach_voucher_attr_key_t                         key,
	mach_voucher_attr_value_handle_array_t          values,
	mach_msg_type_number_t                          value_count,
	mach_voucher_attr_command_t                     command,
	mach_voucher_attr_content_t                     in_content,
	mach_voucher_attr_content_size_t                in_content_size,
	mach_voucher_attr_content_t                     out_content,
	mach_voucher_attr_content_size_t                *out_content_size);

static void
ipc_importance_manager_release(
	ipc_voucher_attr_manager_t              manager);

const struct ipc_voucher_attr_manager ipc_importance_manager = {
	.ivam_release_value =   ipc_importance_release_value,
	.ivam_get_value =       ipc_importance_get_value,
	.ivam_extract_content = ipc_importance_extract_content,
	.ivam_command =         ipc_importance_command,
	.ivam_release =         ipc_importance_manager_release,
	.ivam_flags =           IVAM_FLAGS_NONE,
};

#define IMPORTANCE_ASSERT_KEY(key) assert(MACH_VOUCHER_ATTR_KEY_IMPORTANCE == (key))
#define IMPORTANCE_ASSERT_MANAGER(manager) assert(&ipc_importance_manager == (manager))

/*
 *	Routine:	ipc_importance_release_value [Voucher Attribute Manager Interface]
 *	Purpose:
 *		Release what the voucher system believes is the last "made" reference
 *		on an importance attribute value handle.  The sync parameter is used to
 *		avoid races with new made references concurrently being returned to the
 *		voucher system in other threads.
 *	Conditions:
 *		Nothing locked on entry.  May block.
 */
static kern_return_t
ipc_importance_release_value(
	ipc_voucher_attr_manager_t              __assert_only manager,
	mach_voucher_attr_key_t                 __assert_only key,
	mach_voucher_attr_value_handle_t        value,
	mach_voucher_attr_value_reference_t     sync)
{
	ipc_importance_elem_t elem;

	IMPORTANCE_ASSERT_MANAGER(manager);
	IMPORTANCE_ASSERT_KEY(key);
	assert(0 < sync);

	elem = (ipc_importance_elem_t)value;

	ipc_importance_lock();

	/* Any oustanding made refs? */
	if (sync != elem->iie_made) {
		assert(sync < elem->iie_made);
		ipc_importance_unlock();
		return KERN_FAILURE;
	}

	/* clear made */
	elem->iie_made = 0;

	/*
	 * If there are pending external boosts represented by this attribute,
	 * drop them from the apropriate task
	 */
	if (IIE_TYPE_INHERIT == IIE_TYPE(elem)) {
		ipc_importance_inherit_t inherit = (ipc_importance_inherit_t)elem;

		assert(inherit->iii_externcnt >= inherit->iii_externdrop);

		if (inherit->iii_donating) {
			ipc_importance_task_t imp_task = inherit->iii_to_task;
			uint32_t assertcnt = III_EXTERN(inherit);

			assert(ipc_importance_task_is_any_receiver_type(imp_task));
			assert(imp_task->iit_externcnt >= inherit->iii_externcnt);
			assert(imp_task->iit_externdrop >= inherit->iii_externdrop);
			imp_task->iit_externcnt -= inherit->iii_externcnt;
			imp_task->iit_externdrop -= inherit->iii_externdrop;
			inherit->iii_externcnt = 0;
			inherit->iii_externdrop = 0;
			inherit->iii_donating = FALSE;

			/* adjust the internal assertions - and propagate if needed */
			if (ipc_importance_task_check_transition(imp_task, IIT_UPDATE_DROP, assertcnt)) {
				ipc_importance_task_propagate_assertion_locked(imp_task, IIT_UPDATE_DROP, TRUE);
			}
		} else {
			inherit->iii_externcnt = 0;
			inherit->iii_externdrop = 0;
		}
	}

	/* drop the made reference on elem */
	ipc_importance_release_locked(elem);
	/* returns unlocked */

	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_importance_get_value [Voucher Attribute Manager Interface]
 *	Purpose:
 *		Convert command and content data into a reference on a [potentially new]
 *		attribute value.  The importance attribute manager will only allow the
 *		caller to get a value for the current task's importance, or to redeem
 *		an importance attribute from an existing voucher.
 *	Conditions:
 *		Nothing locked on entry.  May block.
 */
static kern_return_t
ipc_importance_get_value(
	ipc_voucher_attr_manager_t                      __assert_only manager,
	mach_voucher_attr_key_t                         __assert_only key,
	mach_voucher_attr_recipe_command_t              command,
	mach_voucher_attr_value_handle_array_t          prev_values,
	mach_voucher_attr_value_handle_array_size_t     prev_value_count,
	mach_voucher_attr_content_t                     __unused content,
	mach_voucher_attr_content_size_t                content_size,
	mach_voucher_attr_value_handle_t                *out_value,
	mach_voucher_attr_value_flags_t                 *out_flags,
	ipc_voucher_t                                   *out_value_voucher)
{
	ipc_importance_elem_t elem;
	task_t self;

	IMPORTANCE_ASSERT_MANAGER(manager);
	IMPORTANCE_ASSERT_KEY(key);

	if (0 != content_size) {
		return KERN_INVALID_ARGUMENT;
	}

	*out_flags = MACH_VOUCHER_ATTR_VALUE_FLAGS_NONE;
	/* never an out voucher */

	switch (command) {
	case MACH_VOUCHER_ATTR_REDEEM:

		/* redeem of previous values is the value */
		if (0 < prev_value_count) {
			elem = (ipc_importance_elem_t)prev_values[0];
			assert(IIE_NULL != elem);

			ipc_importance_lock();
			assert(0 < elem->iie_made);
			elem->iie_made++;
			ipc_importance_unlock();

			*out_value = prev_values[0];
			return KERN_SUCCESS;
		}

		/* redeem of default is default */
		*out_value = 0;
		*out_value_voucher = IPC_VOUCHER_NULL;
		return KERN_SUCCESS;

	case MACH_VOUCHER_ATTR_IMPORTANCE_SELF:
		self = current_task();

		elem = (ipc_importance_elem_t)ipc_importance_for_task(self, TRUE);
		/* made reference added (or IIE_NULL which isn't referenced) */

		*out_value = (mach_voucher_attr_value_handle_t)elem;
		*out_value_voucher = IPC_VOUCHER_NULL;
		return KERN_SUCCESS;

	default:
		/*
		 * every other command is unknown
		 *
		 * Specifically, there is no mechanism provided to construct an
		 * importance attribute for a task/process from just a pid or
		 * task port.  It has to be copied (or redeemed) from a previous
		 * voucher that has it.
		 */
		return KERN_INVALID_ARGUMENT;
	}
}

/*
 *	Routine:	ipc_importance_extract_content [Voucher Attribute Manager Interface]
 *	Purpose:
 *		Extract meaning from the attribute value present in a voucher.  While
 *		the real goal is to provide commands and data that can reproduce the
 *		voucher's value "out of thin air", this isn't possible with importance
 *		attribute values.  Instead, return debug info to help track down dependencies.
 *	Conditions:
 *		Nothing locked on entry.  May block.
 */
static kern_return_t
ipc_importance_extract_content(
	ipc_voucher_attr_manager_t                      __assert_only manager,
	mach_voucher_attr_key_t                         __assert_only key,
	mach_voucher_attr_value_handle_array_t          values,
	mach_voucher_attr_value_handle_array_size_t     value_count,
	mach_voucher_attr_recipe_command_t              *out_command,
	mach_voucher_attr_content_t                     out_content,
	mach_voucher_attr_content_size_t                *in_out_content_size)
{
	mach_voucher_attr_content_size_t size = 0;
	ipc_importance_elem_t elem;
	unsigned int i;

	IMPORTANCE_ASSERT_MANAGER(manager);
	IMPORTANCE_ASSERT_KEY(key);

	/* the first non-default value provides the data */
	for (i = 0; i < value_count && *in_out_content_size > 0; i++) {
		elem = (ipc_importance_elem_t)values[i];
		if (IIE_NULL == elem) {
			continue;
		}

		snprintf((char *)out_content, *in_out_content_size, "Importance for pid ");
		size = (mach_voucher_attr_content_size_t)strlen((char *)out_content);

		for (;;) {
			ipc_importance_inherit_t inherit = III_NULL;
			ipc_importance_task_t task_imp;
			task_t task;
			int t_pid;

			if (IIE_TYPE_TASK == IIE_TYPE(elem)) {
				task_imp = (ipc_importance_task_t)elem;
				task = task_imp->iit_task;
				t_pid = (TASK_NULL != task) ?
				    task_pid(task) : -1;
				snprintf((char *)out_content + size, *in_out_content_size - size, "%d", t_pid);
			} else {
				inherit = (ipc_importance_inherit_t)elem;
				task_imp = inherit->iii_to_task;
				task = task_imp->iit_task;
				t_pid = (TASK_NULL != task) ?
				    task_pid(task) : -1;
				snprintf((char *)out_content + size, *in_out_content_size - size,
				    "%d (%d of %d boosts) %s from pid ", t_pid,
				    III_EXTERN(inherit), inherit->iii_externcnt,
				    (inherit->iii_donating) ? "donated" : "linked");
			}

			size = (mach_voucher_attr_content_size_t)strlen((char *)out_content);

			if (III_NULL == inherit) {
				break;
			}

			elem = inherit->iii_from_elem;
		}
		size++; /* account for NULL */
	}
	*out_command = MACH_VOUCHER_ATTR_NOOP; /* cannot be used to regenerate value */
	*in_out_content_size = size;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_importance_command [Voucher Attribute Manager Interface]
 *	Purpose:
 *		Run commands against the importance attribute value found in a voucher.
 *		No such commands are currently supported.
 *	Conditions:
 *		Nothing locked on entry.  May block.
 */
static kern_return_t
ipc_importance_command(
	ipc_voucher_attr_manager_t              __assert_only manager,
	mach_voucher_attr_key_t                 __assert_only key,
	mach_voucher_attr_value_handle_array_t  values,
	mach_msg_type_number_t                  value_count,
	mach_voucher_attr_command_t             command,
	mach_voucher_attr_content_t             in_content,
	mach_voucher_attr_content_size_t        in_content_size,
	mach_voucher_attr_content_t             out_content,
	mach_voucher_attr_content_size_t        *out_content_size)
{
	ipc_importance_inherit_t inherit;
	ipc_importance_task_t to_task;
	uint32_t refs, *outrefsp;
	mach_msg_type_number_t i;
	uint32_t externcnt;

	IMPORTANCE_ASSERT_MANAGER(manager);
	IMPORTANCE_ASSERT_KEY(key);

	if (in_content_size != sizeof(refs) ||
	    (*out_content_size != 0 && *out_content_size != sizeof(refs))) {
		return KERN_INVALID_ARGUMENT;
	}
	refs = *(uint32_t *)(void *)in_content;
	outrefsp = (*out_content_size != 0) ? (uint32_t *)(void *)out_content : NULL;

	if (MACH_VOUCHER_IMPORTANCE_ATTR_DROP_EXTERNAL != command) {
		return KERN_NOT_SUPPORTED;
	}

	/* the first non-default value of the apropos type provides the data */
	inherit = III_NULL;
	for (i = 0; i < value_count; i++) {
		ipc_importance_elem_t elem = (ipc_importance_elem_t)values[i];

		if (IIE_NULL != elem && IIE_TYPE_INHERIT == IIE_TYPE(elem)) {
			inherit = (ipc_importance_inherit_t)elem;
			break;
		}
	}
	if (III_NULL == inherit) {
		return KERN_INVALID_ARGUMENT;
	}

	ipc_importance_lock();

	if (0 == refs) {
		if (NULL != outrefsp) {
			*outrefsp = III_EXTERN(inherit);
		}
		ipc_importance_unlock();
		return KERN_SUCCESS;
	}

	to_task = inherit->iii_to_task;
	assert(ipc_importance_task_is_any_receiver_type(to_task));

	/* if not donating to a denap receiver, it was called incorrectly */
	if (!ipc_importance_task_is_marked_denap_receiver(to_task)) {
		ipc_importance_unlock();
		return KERN_INVALID_TASK; /* keeps dispatch happy */
	}

	/* Enough external references left to drop? */
	if (III_EXTERN(inherit) < refs) {
		ipc_importance_unlock();
		return KERN_FAILURE;
	}

	/* re-base external and internal counters at the inherit and the to-task (if apropos) */
	if (inherit->iii_donating) {
		assert(IIT_EXTERN(to_task) >= III_EXTERN(inherit));
		assert(to_task->iit_externcnt >= inherit->iii_externcnt);
		assert(to_task->iit_externdrop >= inherit->iii_externdrop);
		inherit->iii_externdrop += refs;
		to_task->iit_externdrop += refs;
		externcnt = III_EXTERN(inherit);
		if (0 == externcnt) {
			inherit->iii_donating = FALSE;
			to_task->iit_externcnt -= inherit->iii_externcnt;
			to_task->iit_externdrop -= inherit->iii_externdrop;


			/* Start AppNap delay hysteresis - even if not the last boost for the task. */
			if (ipc_importance_delayed_drop_call != NULL &&
			    ipc_importance_task_is_marked_denap_receiver(to_task)) {
				ipc_importance_task_delayed_drop(to_task);
			}

			/* drop task assertions associated with the dropped boosts */
			if (ipc_importance_task_check_transition(to_task, IIT_UPDATE_DROP, refs)) {
				ipc_importance_task_propagate_assertion_locked(to_task, IIT_UPDATE_DROP, TRUE);
				/* may have dropped and retaken importance lock */
			}
		} else {
			/* assert(to_task->iit_assertcnt >= refs + externcnt); */
			/* defensive deduction in case of assertcnt underflow */
			if (to_task->iit_assertcnt > refs + externcnt) {
				to_task->iit_assertcnt -= refs;
			} else {
				to_task->iit_assertcnt = externcnt;
			}
		}
	} else {
		inherit->iii_externdrop += refs;
		externcnt = III_EXTERN(inherit);
	}

	/* capture result (if requested) */
	if (NULL != outrefsp) {
		*outrefsp = externcnt;
	}

	ipc_importance_unlock();
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_importance_manager_release [Voucher Attribute Manager Interface]
 *	Purpose:
 *		Release the Voucher system's reference on the IPC importance attribute
 *		manager.
 *	Conditions:
 *		As this can only occur after the manager drops the Attribute control
 *		reference granted back at registration time, and that reference is never
 *		dropped, this should never be called.
 */
__abortlike
static void
ipc_importance_manager_release(
	ipc_voucher_attr_manager_t              __assert_only manager)
{
	IMPORTANCE_ASSERT_MANAGER(manager);
	panic("Voucher importance manager released");
}

/*
 *	Routine:	ipc_importance_init
 *	Purpose:
 *		Initialize the  IPC importance manager.
 *	Conditions:
 *		Zones and Vouchers are already initialized.
 */
void
ipc_importance_init(void)
{
	kern_return_t kr;

	kr = ipc_register_well_known_mach_voucher_attr_manager(&ipc_importance_manager,
	    (mach_voucher_attr_value_handle_t)0,
	    MACH_VOUCHER_ATTR_KEY_IMPORTANCE,
	    &ipc_importance_control);
	if (KERN_SUCCESS != kr) {
		printf("Voucher importance manager register returned %d", kr);
	}
}

/*
 *	Routine:	ipc_importance_thread_call_init
 *	Purpose:
 *		Initialize the IPC importance code dependent upon
 *		thread-call support being available.
 *	Conditions:
 *		Thread-call mechanism is already initialized.
 */
void
ipc_importance_thread_call_init(void)
{
	/* initialize delayed drop queue and thread-call */
	queue_init(&ipc_importance_delayed_drop_queue);
	ipc_importance_delayed_drop_call =
	    thread_call_allocate(ipc_importance_task_delayed_drop_scan, NULL);
	if (NULL == ipc_importance_delayed_drop_call) {
		panic("ipc_importance_init");
	}
}

/*
 * Routing: task_importance_list_pids
 * Purpose: list pids where task in donating importance.
 * Conditions: To be called only from kdp stackshot code.
 *             Will panic the system otherwise.
 */
extern int
task_importance_list_pids(task_t task, int flags, char *pid_list, unsigned int max_count)
{
	if (kdp_lck_spin_is_acquired(&ipc_importance_lock_data) ||
	    max_count < 1 ||
	    task->task_imp_base == IIT_NULL ||
	    pid_list == NULL ||
	    flags != TASK_IMP_LIST_DONATING_PIDS) {
		return 0;
	}
	unsigned int pidcount = 0;
	task_t temp_task;
	ipc_importance_task_t task_imp = task->task_imp_base;
	ipc_kmsg_t temp_kmsg;
	ipc_importance_inherit_t temp_inherit;
	ipc_importance_elem_t elem;
	int target_pid = 0, previous_pid;

	queue_iterate(&task_imp->iit_inherits, temp_inherit, ipc_importance_inherit_t, iii_inheritance) {
		/* check space in buffer */
		if (pidcount >= max_count) {
			break;
		}
		previous_pid = target_pid;
		target_pid = -1;

		if (temp_inherit->iii_donating) {
#if DEVELOPMENT || DEBUG
			target_pid = temp_inherit->iii_to_task->iit_bsd_pid;
#else
			temp_task = temp_inherit->iii_to_task->iit_task;
			if (temp_task != TASK_NULL) {
				target_pid = task_pid(temp_task);
			}
#endif
		}

		if (target_pid != -1 && previous_pid != target_pid) {
			memcpy(pid_list, &target_pid, sizeof(target_pid));
			pid_list += sizeof(target_pid);
			pidcount++;
		}
	}

	target_pid = 0;
	queue_iterate(&task_imp->iit_kmsgs, temp_kmsg, ipc_kmsg_t, ikm_inheritance) {
		if (pidcount >= max_count) {
			break;
		}
		previous_pid = target_pid;
		target_pid = -1;
		elem = temp_kmsg->ikm_importance;
		temp_task = TASK_NULL;

		if (elem == IIE_NULL) {
			continue;
		}

		if (!(temp_kmsg->ikm_header && MACH_MSGH_BITS_RAISED_IMPORTANCE(temp_kmsg->ikm_header->msgh_bits))) {
			continue;
		}

		if (IIE_TYPE_TASK == IIE_TYPE(elem) &&
		    (((ipc_importance_task_t)elem)->iit_task != TASK_NULL)) {
			target_pid = task_pid(((ipc_importance_task_t)elem)->iit_task);
		} else {
			temp_inherit = (ipc_importance_inherit_t)elem;
#if DEVELOPMENT || DEBUG
			target_pid = temp_inherit->iii_to_task->iit_bsd_pid;
#else
			temp_task = temp_inherit->iii_to_task->iit_task;
			if (temp_task != TASK_NULL) {
				target_pid = task_pid(temp_task);
			}
#endif
		}

		if (target_pid != -1 && previous_pid != target_pid) {
			memcpy(pid_list, &target_pid, sizeof(target_pid));
			pid_list += sizeof(target_pid);
			pidcount++;
		}
	}

	return pidcount;
}
