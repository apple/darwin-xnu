/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#include <machine/machine_cpu.h>
#include <kern/locks.h>
#include <kern/mpsc_queue.h>
#include <kern/thread.h>

#pragma mark Single Consumer calls

__attribute__((noinline))
static mpsc_queue_chain_t
_mpsc_queue_wait_for_enqueuer(struct mpsc_queue_chain *_Atomic *ptr)
{
	return hw_wait_while_equals((void **)ptr, NULL);
}

void
mpsc_queue_restore_batch(mpsc_queue_head_t q, mpsc_queue_chain_t first,
    mpsc_queue_chain_t last)
{
	mpsc_queue_chain_t head = os_atomic_load(&q->mpqh_head.mpqc_next, relaxed);

	os_atomic_store(&last->mpqc_next, head, relaxed);

	if (head == NULL &&
	    !os_atomic_cmpxchg(&q->mpqh_tail, &q->mpqh_head, last, release)) {
		head = os_atomic_load(&q->mpqh_head.mpqc_next, relaxed);
		if (__improbable(head == NULL)) {
			head = _mpsc_queue_wait_for_enqueuer(&q->mpqh_head.mpqc_next);
		}
		os_atomic_store(&last->mpqc_next, head, relaxed);
	}

	os_atomic_store(&q->mpqh_head.mpqc_next, first, relaxed);
}

mpsc_queue_chain_t
mpsc_queue_dequeue_batch(mpsc_queue_head_t q, mpsc_queue_chain_t *tail_out,
    os_atomic_dependency_t dependency)
{
	mpsc_queue_chain_t head, tail;

	q = os_atomic_inject_dependency(q, dependency);

	tail = os_atomic_load(&q->mpqh_tail, relaxed);
	if (__improbable(tail == &q->mpqh_head)) {
		*tail_out = NULL;
		return NULL;
	}

	head = os_atomic_load(&q->mpqh_head.mpqc_next, relaxed);
	if (__improbable(head == NULL)) {
		head = _mpsc_queue_wait_for_enqueuer(&q->mpqh_head.mpqc_next);
	}
	os_atomic_store(&q->mpqh_head.mpqc_next, NULL, relaxed);
	/*
	 * 22708742: set tail to &q->mpqh_head with release, so that NULL write
	 * to head above doesn't clobber the head set by concurrent enqueuer
	 *
	 * The other half of the seq_cst is required to pair with any enqueuer that
	 * contributed to an element in this list (pairs with the release fence in
	 * __mpsc_queue_append_update_tail().
	 *
	 * Making this seq_cst instead of acq_rel makes mpsc_queue_append*()
	 * visibility transitive (when items hop from one queue to the next)
	 * which is expected by clients implicitly.
	 *
	 * Note that this is the same number of fences that a traditional lock
	 * would have, but as a once-per-batch cost.
	 */
	*tail_out = os_atomic_xchg(&q->mpqh_tail, &q->mpqh_head, seq_cst);

	return head;
}

mpsc_queue_chain_t
mpsc_queue_batch_next(mpsc_queue_chain_t cur, mpsc_queue_chain_t tail)
{
	mpsc_queue_chain_t elm = NULL;
	if (cur == tail || cur == NULL) {
		return elm;
	}

	elm = os_atomic_load(&cur->mpqc_next, relaxed);
	if (__improbable(elm == NULL)) {
		elm = _mpsc_queue_wait_for_enqueuer(&cur->mpqc_next);
	}
	return elm;
}

#pragma mark "GCD"-like facilities

static void _mpsc_daemon_queue_drain(mpsc_daemon_queue_t, thread_t);
static void _mpsc_daemon_queue_enqueue(mpsc_daemon_queue_t, mpsc_queue_chain_t);

/* thread based queues */

static void
_mpsc_queue_thread_continue(void *param, wait_result_t wr __unused)
{
	mpsc_daemon_queue_t dq = param;
	mpsc_daemon_queue_kind_t kind = dq->mpd_kind;
	thread_t self = dq->mpd_thread;

	__builtin_assume(self != THREAD_NULL);

	if (kind == MPSC_QUEUE_KIND_THREAD_CRITICAL) {
		self->options |= TH_OPT_SYSTEM_CRITICAL;
	}

	assert(dq->mpd_thread == current_thread());
	_mpsc_daemon_queue_drain(dq, self);

	if (kind == MPSC_QUEUE_KIND_THREAD_CRITICAL) {
		self->options &= ~TH_OPT_SYSTEM_CRITICAL;
	}

	thread_block_parameter(_mpsc_queue_thread_continue, dq);
}

static void
_mpsc_queue_thread_wakeup(mpsc_daemon_queue_t dq)
{
	thread_wakeup_thread((event_t)dq, dq->mpd_thread);
}

static kern_return_t
_mpsc_daemon_queue_init_with_thread(mpsc_daemon_queue_t dq,
    mpsc_daemon_invoke_fn_t invoke, int pri, const char *name,
    mpsc_daemon_queue_kind_t kind)
{
	kern_return_t kr;

	*dq = (struct mpsc_daemon_queue){
		.mpd_kind   = kind,
		.mpd_invoke = invoke,
		.mpd_queue  = MPSC_QUEUE_INITIALIZER(dq->mpd_queue),
		.mpd_chain  = { MPSC_QUEUE_NOTQUEUED_MARKER },
	};

	kr = kernel_thread_create(_mpsc_queue_thread_continue, dq, pri,
	    &dq->mpd_thread);
	if (kr == KERN_SUCCESS) {
		thread_set_thread_name(dq->mpd_thread, name);
		thread_start_in_assert_wait(dq->mpd_thread, (event_t)dq, THREAD_UNINT);
		thread_deallocate(dq->mpd_thread);
	}
	return kr;
}

kern_return_t
mpsc_daemon_queue_init_with_thread(mpsc_daemon_queue_t dq,
    mpsc_daemon_invoke_fn_t invoke, int pri, const char *name)
{
	return _mpsc_daemon_queue_init_with_thread(dq, invoke, pri, name,
	           MPSC_QUEUE_KIND_THREAD);
}

/* thread-call based queues */

static void
_mpsc_queue_thread_call_drain(thread_call_param_t arg0,
    thread_call_param_t arg1 __unused)
{
	_mpsc_daemon_queue_drain((mpsc_daemon_queue_t)arg0, NULL);
}

static void
_mpsc_queue_thread_call_wakeup(mpsc_daemon_queue_t dq)
{
	thread_call_enter(dq->mpd_call);
}

void
mpsc_daemon_queue_init_with_thread_call(mpsc_daemon_queue_t dq,
    mpsc_daemon_invoke_fn_t invoke, thread_call_priority_t pri)
{
	*dq = (struct mpsc_daemon_queue){
		.mpd_kind   = MPSC_QUEUE_KIND_THREAD_CALL,
		.mpd_invoke = invoke,
		.mpd_queue  = MPSC_QUEUE_INITIALIZER(dq->mpd_queue),
		.mpd_chain  = { MPSC_QUEUE_NOTQUEUED_MARKER },
	};
	dq->mpd_call = thread_call_allocate_with_options(
		_mpsc_queue_thread_call_drain, dq, pri, THREAD_CALL_OPTIONS_ONCE);
}

/* nested queues */

void
mpsc_daemon_queue_nested_invoke(mpsc_queue_chain_t elm,
    __unused mpsc_daemon_queue_t tq)
{
	mpsc_daemon_queue_t dq;
	dq = mpsc_queue_element(elm, struct mpsc_daemon_queue, mpd_chain);
	_mpsc_daemon_queue_drain(dq, NULL);
}

static void
_mpsc_daemon_queue_nested_wakeup(mpsc_daemon_queue_t dq)
{
	_mpsc_daemon_queue_enqueue(dq->mpd_target, &dq->mpd_chain);
}

void
mpsc_daemon_queue_init_with_target(mpsc_daemon_queue_t dq,
    mpsc_daemon_invoke_fn_t invoke, mpsc_daemon_queue_t target)
{
	*dq = (struct mpsc_daemon_queue){
		.mpd_kind   = MPSC_QUEUE_KIND_NESTED,
		.mpd_invoke = invoke,
		.mpd_target = target,
		.mpd_queue  = MPSC_QUEUE_INITIALIZER(dq->mpd_queue),
		.mpd_chain  = { MPSC_QUEUE_NOTQUEUED_MARKER },
	};
}

/* enqueue, drain & cancelation */

static void
_mpsc_daemon_queue_drain(mpsc_daemon_queue_t dq, thread_t self)
{
	mpsc_daemon_invoke_fn_t invoke = dq->mpd_invoke;
	mpsc_queue_chain_t head, cur, tail;
	mpsc_daemon_queue_state_t st;

again:
	/*
	 * Most of the time we're woken up because we're dirty,
	 * This atomic xor sets DRAINING and clears WAKEUP in a single atomic
	 * in that case.
	 *
	 * However, if we're woken up for cancelation, the state may be reduced to
	 * the CANCELED bit set only, and then the xor will actually set WAKEUP.
	 * We need to correct this and clear it back to avoid looping below.
	 * This is safe to do as no one is allowed to enqueue more work after
	 * cancelation has happened.
	 *
	 * We use `st` as a dependency token to pair with the release fence in
	 * _mpsc_daemon_queue_enqueue() which gives us the guarantee that the update
	 * to the tail of the MPSC queue that made it non empty is visible to us.
	 */
	st = os_atomic_xor(&dq->mpd_state,
	    MPSC_QUEUE_STATE_DRAINING | MPSC_QUEUE_STATE_WAKEUP, dependency);
	assert(st & MPSC_QUEUE_STATE_DRAINING);
	if (__improbable(st & MPSC_QUEUE_STATE_WAKEUP)) {
		assert(st & MPSC_QUEUE_STATE_CANCELED);
		os_atomic_andnot(&dq->mpd_state, MPSC_QUEUE_STATE_WAKEUP, relaxed);
	}

	os_atomic_dependency_t dep = os_atomic_make_dependency((uintptr_t)st);
	while ((head = mpsc_queue_dequeue_batch(&dq->mpd_queue, &tail, dep))) {
		mpsc_queue_batch_foreach_safe(cur, head, tail) {
			os_atomic_store(&cur->mpqc_next,
			    MPSC_QUEUE_NOTQUEUED_MARKER, relaxed);
			invoke(cur, dq);
		}
	}

	if (self) {
		assert_wait((event_t)dq, THREAD_UNINT);
	}

	/*
	 * Unlike GCD no fence is necessary here: there is no concept similar
	 * to "dispatch_sync()" that would require changes this thread made to be
	 * visible to other threads as part of the mpsc_daemon_queue machinery.
	 *
	 * Making updates that happened on the daemon queue visible to other threads
	 * is the responsibility of the client.
	 */
	st = os_atomic_andnot(&dq->mpd_state, MPSC_QUEUE_STATE_DRAINING, relaxed);

	/*
	 * A wakeup has happened while we were draining,
	 * which means that the queue did an [ empty -> non empty ]
	 * transition during our drain.
	 *
	 * Chances are we already observed and drained everything,
	 * but we need to be absolutely sure, so start a drain again
	 * as the enqueuer observed the DRAINING bit and has skipped calling
	 * _mpsc_daemon_queue_wakeup().
	 */
	if (__improbable(st & MPSC_QUEUE_STATE_WAKEUP)) {
		if (self) {
			clear_wait(self, THREAD_AWAKENED);
		}
		goto again;
	}

	/* dereferencing `dq` past this point is unsafe */

	if (__improbable(st & MPSC_QUEUE_STATE_CANCELED)) {
		thread_wakeup(&dq->mpd_state);
		if (self) {
			clear_wait(self, THREAD_AWAKENED);
			thread_terminate_self();
			__builtin_unreachable();
		}
	}
}

static void
_mpsc_daemon_queue_wakeup(mpsc_daemon_queue_t dq)
{
	switch (dq->mpd_kind) {
	case MPSC_QUEUE_KIND_NESTED:
		_mpsc_daemon_queue_nested_wakeup(dq);
		break;
	case MPSC_QUEUE_KIND_THREAD:
	case MPSC_QUEUE_KIND_THREAD_CRITICAL:
		_mpsc_queue_thread_wakeup(dq);
		break;
	case MPSC_QUEUE_KIND_THREAD_CALL:
		_mpsc_queue_thread_call_wakeup(dq);
		break;
	default:
		panic("mpsc_queue[%p]: invalid kind (%d)", dq, dq->mpd_kind);
	}
}

static void
_mpsc_daemon_queue_enqueue(mpsc_daemon_queue_t dq, mpsc_queue_chain_t elm)
{
	mpsc_daemon_queue_state_t st;

	if (mpsc_queue_append(&dq->mpd_queue, elm)) {
		/*
		 * Pairs with the acquire fence in _mpsc_daemon_queue_drain().
		 */
		st = os_atomic_or_orig(&dq->mpd_state, MPSC_QUEUE_STATE_WAKEUP, release);
		if (__improbable(st & MPSC_QUEUE_STATE_CANCELED)) {
			panic("mpsc_queue[%p]: use after cancelation", dq);
		}

		if ((st & (MPSC_QUEUE_STATE_DRAINING | MPSC_QUEUE_STATE_WAKEUP)) == 0) {
			_mpsc_daemon_queue_wakeup(dq);
		}
	}
}

void
mpsc_daemon_enqueue(mpsc_daemon_queue_t dq, mpsc_queue_chain_t elm,
    mpsc_queue_options_t options)
{
	if (options & MPSC_QUEUE_DISABLE_PREEMPTION) {
		disable_preemption();
	}

	_mpsc_daemon_queue_enqueue(dq, elm);

	if (options & MPSC_QUEUE_DISABLE_PREEMPTION) {
		enable_preemption();
	}
}

void
mpsc_daemon_queue_cancel_and_wait(mpsc_daemon_queue_t dq)
{
	mpsc_daemon_queue_state_t st;

	assert_wait((event_t)&dq->mpd_state, THREAD_UNINT);

	st = os_atomic_or_orig(&dq->mpd_state, MPSC_QUEUE_STATE_CANCELED, relaxed);
	if (__improbable(st & MPSC_QUEUE_STATE_CANCELED)) {
		panic("mpsc_queue[%p]: cancelled twice (%x)", dq, st);
	}

	if (dq->mpd_kind == MPSC_QUEUE_KIND_NESTED && st == 0) {
		clear_wait(current_thread(), THREAD_AWAKENED);
	} else {
		disable_preemption();
		_mpsc_daemon_queue_wakeup(dq);
		enable_preemption();
		thread_block(THREAD_CONTINUE_NULL);
	}

	switch (dq->mpd_kind) {
	case MPSC_QUEUE_KIND_NESTED:
		dq->mpd_target = NULL;
		break;
	case MPSC_QUEUE_KIND_THREAD:
	case MPSC_QUEUE_KIND_THREAD_CRITICAL:
		dq->mpd_thread = NULL;
		break;
	case MPSC_QUEUE_KIND_THREAD_CALL:
		thread_call_cancel_wait(dq->mpd_call);
		thread_call_free(dq->mpd_call);
		dq->mpd_call = NULL;
		break;
	default:
		panic("mpsc_queue[%p]: invalid kind (%d)", dq, dq->mpd_kind);
	}
	dq->mpd_kind = MPSC_QUEUE_KIND_UNKNOWN;
}

#pragma mark deferred deallocation daemon

static struct mpsc_daemon_queue thread_deferred_deallocation_queue;

void
thread_deallocate_daemon_init(void)
{
	kern_return_t kr;

	kr = _mpsc_daemon_queue_init_with_thread(&thread_deferred_deallocation_queue,
	    mpsc_daemon_queue_nested_invoke, MINPRI_KERNEL,
	    "daemon.deferred-deallocation", MPSC_QUEUE_KIND_THREAD_CRITICAL);
	if (kr != KERN_SUCCESS) {
		panic("thread_deallocate_daemon_init: creating daemon failed (%d)", kr);
	}
}

void
thread_deallocate_daemon_register_queue(mpsc_daemon_queue_t dq,
    mpsc_daemon_invoke_fn_t invoke)
{
	mpsc_daemon_queue_init_with_target(dq, invoke,
	    &thread_deferred_deallocation_queue);
}
