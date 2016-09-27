/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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
#include <kern/ipc_tt.h> /* port_name_to_task */
#include <kern/thread.h>
#include <kern/machine.h>
#include <kern/kalloc.h>
#include <mach/mach_types.h>
#include <sys/errno.h>
#include <sys/ktrace.h>

#include <kperf/action.h>
#include <kperf/buffer.h>
#include <kperf/kdebug_trigger.h>
#include <kperf/kperf.h>
#include <kperf/kperf_timer.h>
#include <kperf/pet.h>
#include <kperf/sample.h>

lck_grp_t kperf_lck_grp;

/* thread on CPUs before starting the PET thread */
thread_t *kperf_thread_on_cpus = NULL;

/* one wired sample buffer per CPU */
static struct kperf_sample *intr_samplev;
static unsigned int intr_samplec = 0;

/* current sampling status */
static unsigned sampling_status = KPERF_SAMPLING_OFF;

/* only init once */
static boolean_t kperf_initted = FALSE;

/* whether or not to callback to kperf on context switch */
boolean_t kperf_on_cpu_active = FALSE;

struct kperf_sample *
kperf_intr_sample_buffer(void)
{
	unsigned ncpu = cpu_number();

	assert(ml_get_interrupts_enabled() == FALSE);
	assert(ncpu < intr_samplec);

	return &(intr_samplev[ncpu]);
}

/* setup interrupt sample buffers */
int
kperf_init(void)
{
	static lck_grp_attr_t lck_grp_attr;

	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	unsigned ncpus = 0;
	int err;

	if (kperf_initted) {
		return 0;
	}

	lck_grp_attr_setdefault(&lck_grp_attr);
	lck_grp_init(&kperf_lck_grp, "kperf", &lck_grp_attr);

	ncpus = machine_info.logical_cpu_max;

	/* create buffers to remember which threads don't need to be sampled by PET */
	kperf_thread_on_cpus = kalloc_tag(ncpus * sizeof(*kperf_thread_on_cpus),
	                                  VM_KERN_MEMORY_DIAG);
	if (kperf_thread_on_cpus == NULL) {
		err = ENOMEM;
		goto error;
	}
	bzero(kperf_thread_on_cpus, ncpus * sizeof(*kperf_thread_on_cpus));

	/* create the interrupt buffers */
	intr_samplec = ncpus;
	intr_samplev = kalloc_tag(ncpus * sizeof(*intr_samplev),
	                          VM_KERN_MEMORY_DIAG);
	if (intr_samplev == NULL) {
		err = ENOMEM;
		goto error;
	}
	bzero(intr_samplev, ncpus * sizeof(*intr_samplev));

	/* create kdebug trigger filter buffers */
	if ((err = kperf_kdebug_init())) {
		goto error;
	}

	kperf_initted = TRUE;
	return 0;

error:
	if (intr_samplev) {
		kfree(intr_samplev, ncpus * sizeof(*intr_samplev));
		intr_samplev = NULL;
		intr_samplec = 0;
	}

	if (kperf_thread_on_cpus) {
		kfree(kperf_thread_on_cpus, ncpus * sizeof(*kperf_thread_on_cpus));
		kperf_thread_on_cpus = NULL;
	}

	return err;
}

void
kperf_reset(void)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	/* turn off sampling first */
	(void)kperf_sampling_disable();

	/* cleanup miscellaneous configuration first */
	(void)kperf_kdbg_cswitch_set(0);
	(void)kperf_set_lightweight_pet(0);
	kperf_kdebug_reset();

	/* timers, which require actions, first */
	kperf_timer_reset();
	kperf_action_reset();
}

void
kperf_on_cpu_internal(thread_t thread, thread_continue_t continuation,
                      uintptr_t *starting_fp)
{
	if (kperf_kdebug_cswitch) {
		/* trace the new thread's PID for Instruments */
		int pid = task_pid(get_threadtask(thread));

		BUF_DATA(PERF_TI_CSWITCH, thread_tid(thread), pid);
	}
	if (kperf_lightweight_pet_active) {
		kperf_pet_on_cpu(thread, continuation, starting_fp);
	}
}

void
kperf_on_cpu_update(void)
{
	kperf_on_cpu_active = kperf_kdebug_cswitch ||
	                      kperf_lightweight_pet_active;
}

/* random misc-ish functions */
uint32_t
kperf_get_thread_flags(thread_t thread)
{
	return thread->kperf_flags;
}

void
kperf_set_thread_flags(thread_t thread, uint32_t flags)
{
	thread->kperf_flags = flags;
}

unsigned int
kperf_sampling_status(void)
{
	return sampling_status;
}

int
kperf_sampling_enable(void)
{
	if (sampling_status == KPERF_SAMPLING_ON) {
		return 0;
	}

	if (sampling_status != KPERF_SAMPLING_OFF) {
		panic("kperf: sampling was %d when asked to enable", sampling_status);
	}

	/* make sure interrupt tables and actions are initted */
	if (!kperf_initted || (kperf_action_get_count() == 0)) {
		return ECANCELED;
	}

	/* mark as running */
	sampling_status = KPERF_SAMPLING_ON;
	kperf_lightweight_pet_active_update();

	/* tell timers to enable */
	kperf_timer_go();

	return 0;
}

int
kperf_sampling_disable(void)
{
	if (sampling_status != KPERF_SAMPLING_ON) {
		return 0;
	}

	/* mark a shutting down */
	sampling_status = KPERF_SAMPLING_SHUTDOWN;

	/* tell timers to disable */
	kperf_timer_stop();

	/* mark as off */
	sampling_status = KPERF_SAMPLING_OFF;
	kperf_lightweight_pet_active_update();

	return 0;
}

boolean_t
kperf_thread_get_dirty(thread_t thread)
{
	return (thread->c_switch != thread->kperf_c_switch);
}

void
kperf_thread_set_dirty(thread_t thread, boolean_t dirty)
{
	if (dirty) {
		thread->kperf_c_switch = thread->c_switch - 1;
	} else {
		thread->kperf_c_switch = thread->c_switch;
	}
}

int
kperf_port_to_pid(mach_port_name_t portname)
{
	task_t task;
	int pid;

	if (!MACH_PORT_VALID(portname)) {
		return -1;
	}

	task = port_name_to_task(portname);

	if (task == TASK_NULL) {
		return -1;
	}

	pid = task_pid(task);

	task_deallocate_internal(task);

	return pid;
}
