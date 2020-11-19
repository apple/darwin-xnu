#include "hvtest_arm64.h"
#include "hvtest_guest.h"

#include <ptrauth.h>
#include <darwintest.h>
#include <darwintest_perf.h>
#include <mach/mach.h>
#include <stdatomic.h>
#include <stdlib.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm.hv"),
	T_META_REQUIRES_SYSCTL_EQ("kern.hv_support", 1),
	// Temporary workaround for not providing an x86_64 slice
	T_META_REQUIRES_SYSCTL_EQ("hw.optional.arm64", 1)
	);

#define SET_PC(vcpu, symbol) \
{ \
	vcpu_entry_function entry = ptrauth_strip(&symbol, 0); \
	uint64_t entry_addr = (uintptr_t)entry; \
	(void)hv_vcpu_set_reg(vcpu, HV_REG_PC, entry_addr); \
}

// Note that expect_*(), set_reg(), and get_reg() cannot be used in benchmarks,
// as the T_ASSERT() checks they perform are severely detrimental to results.
//
// The helpers below should be used in their place.

static void
quick_bump_pc(hv_vcpu_t vcpu, const bool forward)
{
	uint64_t pc;
	(void)hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
	pc = forward ? pc + 4 : pc - 4;
	(void)hv_vcpu_set_reg(vcpu, HV_REG_PC, pc);
}

static void
vtimer_benchmark(hv_vcpu_t vcpu, hv_vcpu_exit_t *exit)
{
	dt_stat_thread_cycles_t stat = dt_stat_thread_cycles_create(
		"VTimer interruption");
	SET_PC(vcpu, spin_vcpu_entry);
	set_sys_reg(vcpu, HV_SYS_REG_CNTV_CVAL_EL0, 0);
	set_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0, 1);
	// Dry-run twice to ensure that the timer is re-armed.
	run_to_next_vm_fault(vcpu, exit);
	T_ASSERT_EQ_UINT(exit->reason, HV_EXIT_REASON_VTIMER_ACTIVATED,
	    "check for timer");
	hv_vcpu_set_vtimer_mask(vcpu, false);
	run_to_next_vm_fault(vcpu, exit);
	T_ASSERT_EQ_UINT(exit->reason, HV_EXIT_REASON_VTIMER_ACTIVATED,
	    "check for timer");
	hv_vcpu_set_vtimer_mask(vcpu, false);
	T_STAT_MEASURE_LOOP(stat) {
		hv_vcpu_run(vcpu);
		hv_vcpu_set_vtimer_mask(vcpu, false);
	}
	dt_stat_finalize(stat);
	// Disable the timer before running other benchmarks, otherwise they will be
	// interrupted.
	set_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0, 0);
}

static void
trap_benchmark(dt_stat_thread_cycles_t trap_stat, hv_vcpu_t vcpu,
    hv_vcpu_exit_t *exit, const uint64_t batch, const bool increment_pc)
{
	while (!dt_stat_stable(trap_stat)) {
		set_reg(vcpu, HV_REG_X0, batch);
		dt_stat_token start = dt_stat_thread_cycles_begin(trap_stat);
		for (uint32_t i = 0; i < batch; i++) {
			hv_vcpu_run(vcpu);
			if (increment_pc) {
				quick_bump_pc(vcpu, true);
			}
		}
		dt_stat_thread_cycles_end_batch(trap_stat, (int)batch, start);
		expect_hvc(vcpu, exit, 2);
	}
	dt_stat_finalize(trap_stat);
}

static void
mrs_bench_kernel(hv_vcpu_t vcpu, hv_vcpu_exit_t *exit, const char *name)
{
	const uint64_t batch = 1000;
	SET_PC(vcpu, mrs_actlr_bench_loop);
	set_control(vcpu, _HV_CONTROL_FIELD_HCR,
	    get_control(vcpu, _HV_CONTROL_FIELD_HCR) & ~HCR_TACR);
	dt_stat_thread_cycles_t stat = dt_stat_thread_cycles_create(name);
	while (!dt_stat_stable(stat)) {
		set_reg(vcpu, HV_REG_X0, batch);
		dt_stat_token start = dt_stat_thread_cycles_begin(stat);
		hv_vcpu_run(vcpu);
		dt_stat_thread_cycles_end_batch(stat, (int)batch, start);
		T_QUIET; T_ASSERT_EQ_UINT(exit->reason, HV_EXIT_REASON_EXCEPTION,
		    "check for exception");
		T_QUIET; T_ASSERT_EQ(exit->exception.syndrome >> 26, 0x16,
		    "check for HVC64");
	}
	dt_stat_finalize(stat);
}

static void *
trap_bench_monitor(void *arg __unused, hv_vcpu_t vcpu, hv_vcpu_exit_t *exit)
{
	// In all benchmark testcases using quick_run_vcpu(), dry run all guest code
	// to fault in pages so that run_to_next_vm_fault() isn't needed while
	// recording measurements.

	vtimer_benchmark(vcpu, exit);

	// dry-run hvc_bench_loop
	SET_PC(vcpu, hvc_bench_loop);
	set_reg(vcpu, HV_REG_X0, 1);
	expect_hvc(vcpu, exit, 1);
	expect_hvc(vcpu, exit, 2);

	SET_PC(vcpu, hvc_bench_loop);
	trap_benchmark(dt_stat_thread_cycles_create("HVC handled by VMM"),
	    vcpu, exit, 1000, false);

	// dry-run data_abort_bench_loop
	SET_PC(vcpu, data_abort_bench_loop);
	set_reg(vcpu, HV_REG_X0, 1);
	expect_trapped_store(vcpu, exit, get_reserved_start());
	expect_hvc(vcpu, exit, 2);

	SET_PC(vcpu, data_abort_bench_loop);
	trap_benchmark(dt_stat_thread_cycles_create("data abort handled by VMM"),
	    vcpu, exit, 1000, true);

	// dry-run mrs_actlr_bench_loop
	SET_PC(vcpu, mrs_actlr_bench_loop);
	set_reg(vcpu, HV_REG_X0, 1);
	set_control(vcpu, _HV_CONTROL_FIELD_HCR,
	    get_control(vcpu, _HV_CONTROL_FIELD_HCR) & ~HCR_TACR);
	// Confirm no visible trap from MRS
	expect_hvc(vcpu, exit, 2);

	mrs_bench_kernel(vcpu, exit, "MRS trap handled by kernel");

	SET_PC(vcpu, mrs_actlr_bench_loop);
	set_reg(vcpu, HV_REG_X0, 1);
	set_control(vcpu, _HV_CONTROL_FIELD_HCR,
	    get_control(vcpu, _HV_CONTROL_FIELD_HCR) | HCR_TACR);
	// Confirm MRS trap from test loop
	expect_exception(vcpu, exit, 0x18);
	quick_bump_pc(vcpu, true);
	expect_hvc(vcpu, exit, 2);
	SET_PC(vcpu, mrs_actlr_bench_loop);
	trap_benchmark(dt_stat_thread_cycles_create("MRS trap handled by VMM"),
	    vcpu, exit, 1000, true);

	SET_PC(vcpu, activate_debug);
	expect_hvc(vcpu, exit, 0);

	SET_PC(vcpu, hvc_bench_loop);
	trap_benchmark(dt_stat_thread_cycles_create(
		    "debug-enabled HVC handled by VMM"), vcpu, exit, 1000, false);

	mrs_bench_kernel(vcpu, exit, "debug-enabled MRS trap handled by kernel");

	return NULL;
}

T_DECL(trap_benchmark, "trap-processing benchmark")
{
	vm_setup();
	pthread_t vcpu_thread = create_vcpu_thread(hvc_bench_loop, 0,
	    trap_bench_monitor, NULL);
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu_thread, NULL), "join vcpu");
	vm_cleanup();
}

static semaphore_t sem1;
static semaphore_t sem2;
static _Atomic uint32_t stage;

static void
switch_and_return(bool leader)
{
	// wait_semaphore, signal_semaphore
	(void)semaphore_wait_signal(leader ? sem2 : sem1, leader ? sem1 : sem2);
}

static void *
vcpu_switch_leader(void *arg __unused, hv_vcpu_t vcpu, hv_vcpu_exit_t *exit)
{
	dt_stat_thread_cycles_t baseline = dt_stat_thread_cycles_create(
		"baseline VCPU run, no switch");
	dt_stat_thread_cycles_t thread = dt_stat_thread_cycles_create(
		"VCPU-thread switch");
	dt_stat_thread_cycles_t basic = dt_stat_thread_cycles_create(
		"basic VCPU-VCPU switch");
	dt_stat_thread_cycles_t baseline_debug = dt_stat_thread_cycles_create(
		"baseline debug-enabled VCPU run, no switch");
	dt_stat_thread_cycles_t basic_debug = dt_stat_thread_cycles_create(
		"basic VCPU <-> debug-enabled VCPU switch");
	dt_stat_thread_cycles_t debug_debug = dt_stat_thread_cycles_create(
		"debug-enabled VCPU <-> debug-enabled VCPU switch");

	bind_to_cpu(0);

	// Activate minimal VCPU state
	SET_PC(vcpu, hvc_loop);
	expect_hvc(vcpu, exit, 0);
	T_STAT_MEASURE_LOOP(baseline) {
		hv_vcpu_run(vcpu);
	}
	dt_stat_finalize(baseline);

	T_STAT_MEASURE_LOOP(thread) {
		hv_vcpu_run(vcpu);
		switch_and_return(true);
	}
	dt_stat_finalize(thread);
	atomic_store_explicit(&stage, 1, memory_order_relaxed);

	T_STAT_MEASURE_LOOP(basic) {
		hv_vcpu_run(vcpu);
		switch_and_return(true);
	}
	dt_stat_finalize(basic);
	atomic_store_explicit(&stage, 2, memory_order_relaxed);

	T_STAT_MEASURE_LOOP(basic_debug) {
		hv_vcpu_run(vcpu);
		switch_and_return(true);
	}
	dt_stat_finalize(basic_debug);
	atomic_store_explicit(&stage, 3, memory_order_relaxed);

	SET_PC(vcpu, activate_debug);
	expect_hvc(vcpu, exit, 0);
	SET_PC(vcpu, hvc_loop);
	T_STAT_MEASURE_LOOP(baseline_debug) {
		hv_vcpu_run(vcpu);
	}
	dt_stat_finalize(baseline_debug);

	T_STAT_MEASURE_LOOP(debug_debug) {
		hv_vcpu_run(vcpu);
		switch_and_return(true);
	}
	dt_stat_finalize(debug_debug);
	atomic_store_explicit(&stage, 4, memory_order_relaxed);

	T_ASSERT_MACH_SUCCESS(semaphore_signal(sem1), "final signal to follower");

	return NULL;
}

static void *
vcpu_switch_follower(void *arg __unused, hv_vcpu_t vcpu, hv_vcpu_exit_t *exit)
{
	bind_to_cpu(0);

	// Don't signal until we've been signaled once.
	T_ASSERT_MACH_SUCCESS(semaphore_wait(sem1),
	    "wait for first signal from leader");

	// For a baseline, don't enter the VCPU at all. This should result in a
	// negligible VCPU switch cost.
	while (atomic_load_explicit(&stage, memory_order_relaxed) == 0) {
		switch_and_return(false);
	}

	// Enter the VCPU once to activate a minimal amount of state.
	SET_PC(vcpu, hvc_loop);
	expect_hvc(vcpu, exit, 0);

	while (atomic_load_explicit(&stage, memory_order_relaxed) == 1) {
		hv_vcpu_run(vcpu);
		switch_and_return(false);
	}

	// Use debug state
	SET_PC(vcpu, activate_debug);
	expect_hvc(vcpu, exit, 0);
	SET_PC(vcpu, hvc_loop);

	while (atomic_load_explicit(&stage, memory_order_relaxed) == 2) {
		hv_vcpu_run(vcpu);
		switch_and_return(false);
	}

	while (atomic_load_explicit(&stage, memory_order_relaxed) == 3) {
		hv_vcpu_run(vcpu);
		switch_and_return(false);
	}

	return NULL;
}

T_DECL(vcpu_switch_benchmark, "vcpu state-switching benchmarks",
    T_META_BOOTARGS_SET("enable_skstb=1"))
{
	bind_to_cpu(0);

	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &sem1,
	    SYNC_POLICY_FIFO, 0), "semaphore_create 1");
	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &sem2,
	    SYNC_POLICY_FIFO, 0), "semaphore_create 2");

	vm_setup();
	pthread_t vcpu1_thread = create_vcpu_thread(hvc_loop, 0,
	    vcpu_switch_leader, NULL);
	pthread_t vcpu2_thread = create_vcpu_thread(hvc_loop, 0,
	    vcpu_switch_follower, NULL);

	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu1_thread, NULL), "join vcpu1");
	T_ASSERT_POSIX_SUCCESS(pthread_join(vcpu2_thread, NULL), "join vcpu2");

	vm_cleanup();
}

struct thread_params {
	uint32_t id;
	uint32_t iter;
	pthread_t thread;
};

static void *
run_cancel_monitor(void *arg, hv_vcpu_t vcpu, hv_vcpu_exit_t *exit __unused)
{
	struct thread_params *param = (struct thread_params *)arg;
	dt_stat_time_t s = dt_stat_time_create("hv_vcpus_exit time vcpu%u",
	    param->id);
	while (!dt_stat_stable(s)) {
		dt_stat_token start = dt_stat_time_begin(s);
		for (uint32_t i = 0; i < param->iter; i++) {
			hv_vcpus_exit(&vcpu, 1);
		}
		dt_stat_time_end_batch(s, (int)param->iter, start);
	}
	dt_stat_finalize(s);
	return NULL;
}

static void
run_cancel_call(uint32_t vcpu_count, uint32_t iter)
{
	struct thread_params *threads = calloc(vcpu_count, sizeof(*threads));
	vm_setup();
	for (uint32_t i = 0; i < vcpu_count; i++) {
		threads[i].id = i;
		threads[i].iter = iter;
		threads[i].thread = create_vcpu_thread(hvc_loop, 0, run_cancel_monitor,
		    &threads[i]);
	}
	for (uint32_t i = 0; i < vcpu_count; i++) {
		T_ASSERT_POSIX_SUCCESS(pthread_join(threads[i].thread, NULL),
		    "join vcpu%u", i);
	}
	free(threads);
	vm_cleanup();
}

T_DECL(api_benchmarks, "API call parallel performance")
{
	run_cancel_call(1, 1000);
	run_cancel_call(4, 1000);
}
