#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>

#include <sys/kdebug.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.perf.kdebug"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false)
);

//
// Helper functions for direct control over the kernel trace facility.
//

static void _sysctl_reset() {
	int mib[] = { CTL_KERN, KERN_KDEBUG, KERN_KDREMOVE };
	if(sysctl(mib, 3, NULL, NULL, NULL, 0)) {
		T_FAIL("KERN_KDREMOVE sysctl failed");
	}
}

static void _sysctl_setbuf(uint32_t capacity) {
	int mib[] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETBUF, (int)capacity };
	if (sysctl(mib, 4, NULL, NULL, NULL, 0)) {
		T_FAIL("KERN_KDSETBUF sysctl failed");
	}
}

static void _sysctl_setup() {
	int mib[] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETUP };
	if (sysctl(mib, 3, NULL, NULL, NULL, 0)) {
		T_FAIL("KERN_KDSETUP sysctl failed");
	}
}

static void _sysctl_enable(int value)
{
	int mib[] = { CTL_KERN, KERN_KDEBUG, KERN_KDENABLE, value };
	if (sysctl(mib, 4, NULL, NULL, NULL, 0) < 0) {
		T_FAIL("KERN_KDENABLE sysctl failed");
	}
}

static void _sysctl_enable_typefilter(uint8_t* type_filter_bitmap) {
	int mib[] = { CTL_KERN, KERN_KDEBUG, KERN_KDSET_TYPEFILTER };
	size_t needed = KDBG_TYPEFILTER_BITMAP_SIZE;
	if(sysctl(mib, 3, type_filter_bitmap, &needed, NULL, 0)) {
		T_FAIL("KERN_KDSET_TYPEFILTER sysctl failed");
	}
}

static void _sysctl_nowrap(bool is_nowrap) {
	int mib[] = { CTL_KERN, KERN_KDEBUG, is_nowrap ? KERN_KDEFLAGS : KERN_KDDFLAGS, KDBG_NOWRAP };
	if (sysctl(mib, 4, NULL, NULL, NULL, 0)) {
		T_FAIL("KDBG_NOWRAP sysctl failed");
	}
}

static void enable_tracing(bool value) {
	_sysctl_enable(value ? KDEBUG_ENABLE_TRACE : 0);
}

static void enable_typefilter_all_reject() {
	uint8_t type_filter_bitmap[KDBG_TYPEFILTER_BITMAP_SIZE];
	memset(type_filter_bitmap, 0, sizeof(type_filter_bitmap));
	_sysctl_enable_typefilter(type_filter_bitmap);
}

static void enable_typefilter_all_pass() {
	uint8_t type_filter_bitmap[KDBG_TYPEFILTER_BITMAP_SIZE];
	memset(type_filter_bitmap, 0xff, sizeof(type_filter_bitmap));
	_sysctl_enable_typefilter(type_filter_bitmap);
}

static void loop_kdebug_trace(dt_stat_time_t s) {
	do {
		dt_stat_token start = dt_stat_time_begin(s);
		for (uint32_t i = 0; i<100; i++) {
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
			kdebug_trace(0x97000000 | DBG_FUNC_NONE, i, i, i, i);
		}
		dt_stat_time_end_batch(s, 1000, start);
	} while (!dt_stat_stable(s));
}

static void loop_getppid(dt_stat_time_t s) {
	do {
		dt_stat_token start = dt_stat_time_begin(s);
		for (uint32_t i = 0; i<100; i++) {
			getppid();
			getppid();
			getppid();
			getppid();
			getppid();
			getppid();
			getppid();
			getppid();
			getppid();
			getppid();
		}
		dt_stat_time_end_batch(s, 1000, start);
	} while (!dt_stat_stable(s));
}

static void reset_kdebug_trace(void) {
	_sysctl_reset();
}

static void test(const char* test_name, void (^pretest_setup)(void), void (*test)(dt_stat_time_t s)) {
	T_ATEND(reset_kdebug_trace);
	_sysctl_reset();
	_sysctl_setbuf(1000000);
	_sysctl_nowrap(false);
	_sysctl_setup();

	pretest_setup();

	dt_stat_time_t s = dt_stat_time_create("%s", test_name);

	test(s);

	dt_stat_finalize(s);
}

//
// Begin tests...
//

T_DECL(kdebug_trace_baseline_syscall,
       "Test the latency of a syscall while kernel tracing is disabled") {
	test("kdebug_trace_baseline_syscall", ^{ enable_tracing(false); }, loop_getppid);
}

T_DECL(kdebug_trace_kdbg_disabled,
       "Test the latency of kdebug_trace while kernel tracing is disabled") {
	test("kdebug_trace_kdbg_disabled", ^{ enable_tracing(false); }, loop_kdebug_trace);
}

T_DECL(kdebug_trace_kdbg_enabled,
       "Test the latency of kdebug_trace while kernel tracing is enabled with no typefilter") {
	test("kdebug_trace_kdbg_enabled", ^{ enable_tracing(true); }, loop_kdebug_trace);
}

T_DECL(kdebug_trace_kdbg_enabled_typefilter_pass,
       "Test the latency of kdebug_trace while kernel tracing is enabled with a typefilter that passes the event") {
	test("kdebug_trace_kdbg_enabled_typefilter_pass", ^{ enable_tracing(true); enable_typefilter_all_pass(); }, loop_kdebug_trace);
}

T_DECL(kdebug_trace_kdbg_enabled_typefilter_reject,
       "Test the latency of kdebug_trace while kernel tracing is enabled with a typefilter that rejects the event") {
	test("kdebug_trace_kdbg_enabled_typefilter_reject", ^{ enable_tracing(true); enable_typefilter_all_reject(); }, loop_kdebug_trace);
}
