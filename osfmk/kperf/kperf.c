/*
 * Copyright (c) 2011-2018 Apple Computer, Inc. All rights reserved.
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
#include <kperf/kptimer.h>
#include <kperf/lazy.h>
#include <kperf/pet.h>
#include <kperf/sample.h>

/* from libkern/libkern.h */
extern uint64_t strtouq(const char *, char **, int);

LCK_GRP_DECLARE(kperf_lck_grp, "kperf");

/* one wired sample buffer per CPU */
static struct kperf_sample *intr_samplev;
static unsigned int intr_samplec = 0;

/* current sampling status */
enum kperf_sampling kperf_status = KPERF_SAMPLING_OFF;

/*
 * Only set up kperf once.
 */
static bool kperf_is_setup = false;

/* whether or not to callback to kperf on context switch */
boolean_t kperf_on_cpu_active = FALSE;

unsigned int kperf_thread_blocked_action;
unsigned int kperf_cpu_sample_action;

struct kperf_sample *
kperf_intr_sample_buffer(void)
{
	unsigned ncpu = cpu_number();

	assert(ml_get_interrupts_enabled() == FALSE);
	assert(ncpu < intr_samplec);

	return &(intr_samplev[ncpu]);
}

void
kperf_init_early(void)
{
	/*
	 * kperf allocates based on the number of CPUs and requires them to all be
	 * accounted for.
	 */
	ml_wait_max_cpus();

	boolean_t found_kperf = FALSE;
	char kperf_config_str[64];
	found_kperf = PE_parse_boot_arg_str("kperf", kperf_config_str, sizeof(kperf_config_str));
	if (found_kperf && kperf_config_str[0] != '\0') {
		kperf_kernel_configure(kperf_config_str);
	}
}

void
kperf_init(void)
{
	kptimer_init();
}

void
kperf_setup(void)
{
	if (kperf_is_setup) {
		return;
	}

	intr_samplec = machine_info.logical_cpu_max;
	size_t intr_samplev_size = intr_samplec * sizeof(*intr_samplev);
	intr_samplev = kalloc_tag(intr_samplev_size, VM_KERN_MEMORY_DIAG);
	memset(intr_samplev, 0, intr_samplev_size);

	kperf_kdebug_setup();

	kperf_is_setup = true;
}

void
kperf_reset(void)
{
	/*
	 * Make sure samples aren't being taken before tearing everything down.
	 */
	(void)kperf_disable_sampling();

	kperf_lazy_reset();
	(void)kperf_kdbg_cswitch_set(0);
	kperf_kdebug_reset();
	kptimer_reset();
	kppet_reset();

	/*
	 * Most of the other systems call into actions, so reset them last.
	 */
	kperf_action_reset();
}

void
kperf_kernel_configure(const char *config)
{
	int pairs = 0;
	char *end;
	bool pet = false;

	assert(config != NULL);

	ktrace_start_single_threaded();

	ktrace_kernel_configure(KTRACE_KPERF);

	if (config[0] == 'p') {
		pet = true;
		config++;
	}

	do {
		uint32_t action_samplers;
		uint64_t timer_period_ns;
		uint64_t timer_period;

		pairs += 1;
		kperf_action_set_count(pairs);
		kptimer_set_count(pairs);

		action_samplers = (uint32_t)strtouq(config, &end, 0);
		if (config == end) {
			kprintf("kperf: unable to parse '%s' as action sampler\n", config);
			goto out;
		}
		config = end;

		kperf_action_set_samplers(pairs, action_samplers);

		if (config[0] == '\0') {
			kprintf("kperf: missing timer period in config\n");
			goto out;
		}
		config++;

		timer_period_ns = strtouq(config, &end, 0);
		if (config == end) {
			kprintf("kperf: unable to parse '%s' as timer period\n", config);
			goto out;
		}
		nanoseconds_to_absolutetime(timer_period_ns, &timer_period);
		config = end;

		kptimer_set_period(pairs - 1, timer_period);
		kptimer_set_action(pairs - 1, pairs);

		if (pet) {
			kptimer_set_pet_timerid(pairs - 1);
			kppet_set_lightweight_pet(1);
			pet = false;
		}
	} while (*(config++) == ',');

	int error = kperf_enable_sampling();
	if (error) {
		printf("kperf: cannot enable sampling at boot: %d\n", error);
	}

out:
	ktrace_end_single_threaded();
}

void kperf_on_cpu_internal(thread_t thread, thread_continue_t continuation,
    uintptr_t *starting_fp);
void
kperf_on_cpu_internal(thread_t thread, thread_continue_t continuation,
    uintptr_t *starting_fp)
{
	if (kperf_kdebug_cswitch) {
		/* trace the new thread's PID for Instruments */
		int pid = task_pid(get_threadtask(thread));
		BUF_DATA(PERF_TI_CSWITCH, thread_tid(thread), pid);
	}
	if (kppet_lightweight_active) {
		kppet_on_cpu(thread, continuation, starting_fp);
	}
	if (kperf_lazy_wait_action != 0) {
		kperf_lazy_wait_sample(thread, continuation, starting_fp);
	}
}

void
kperf_on_cpu_update(void)
{
	kperf_on_cpu_active = kperf_kdebug_cswitch ||
	    kppet_lightweight_active ||
	    kperf_lazy_wait_action != 0;
}

bool
kperf_is_sampling(void)
{
	return kperf_status == KPERF_SAMPLING_ON;
}

int
kperf_enable_sampling(void)
{
	if (kperf_status == KPERF_SAMPLING_ON) {
		return 0;
	}

	if (kperf_status != KPERF_SAMPLING_OFF) {
		panic("kperf: sampling was %d when asked to enable", kperf_status);
	}

	/* make sure interrupt tables and actions are initted */
	if (!kperf_is_setup || (kperf_action_get_count() == 0)) {
		return ECANCELED;
	}

	kperf_status = KPERF_SAMPLING_ON;
	kppet_lightweight_active_update();
	kptimer_start();

	return 0;
}

int
kperf_disable_sampling(void)
{
	if (kperf_status != KPERF_SAMPLING_ON) {
		return 0;
	}

	/* mark a shutting down */
	kperf_status = KPERF_SAMPLING_SHUTDOWN;

	/* tell timers to disable */
	kptimer_stop();

	/* mark as off */
	kperf_status = KPERF_SAMPLING_OFF;
	kppet_lightweight_active_update();

	return 0;
}

void
kperf_timer_expire(void *param0, void * __unused param1)
{
	processor_t processor = param0;
	int cpuid = processor->cpu_id;

	kptimer_expire(processor, cpuid, mach_absolute_time());
}

boolean_t
kperf_thread_get_dirty(thread_t thread)
{
	return thread->c_switch != thread->kperf_c_switch;
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
	if (!MACH_PORT_VALID(portname)) {
		return -1;
	}

	task_t task = port_name_to_task(portname);
	if (task == TASK_NULL) {
		return -1;
	}

	pid_t pid = task_pid(task);

	os_ref_count_t __assert_only count = task_deallocate_internal(task);
	assert(count != 0);

	return pid;
}
