// Copyright (c) 2016-2020 Apple Computer, Inc.  All rights reserved.

#include <CoreSymbolication/CoreSymbolication.h>
#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <execinfo.h>
#include <pthread.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#define USER_FRAMES (12)
#define MAX_SYSCALL_SETUP_FRAMES (2)
#define NON_RECURSE_FRAMES (2)

static const char *user_bt[USER_FRAMES] = {
	"backtrace_thread",
	"recurse_a", "recurse_b", "recurse_a", "recurse_b",
	"recurse_a", "recurse_b", "recurse_a", "recurse_b",
	"recurse_a", "recurse_b", "expect_callstack",
};

struct callstack_exp {
	bool in_syscall_setup;
	unsigned int syscall_frames;
	const char **callstack;
	size_t callstack_len;
	unsigned int nchecked;
};

static void
expect_frame(struct callstack_exp *cs, CSSymbolRef symbol,
    unsigned long addr, unsigned int bt_idx)
{
	if (CSIsNull(symbol)) {
		if (!cs->in_syscall_setup) {
			T_FAIL("invalid symbol for address %#lx at frame %d", addr,
			    bt_idx);
		}
		return;
	}

	const char *name = CSSymbolGetName(symbol);
	if (name) {
		if (cs->in_syscall_setup) {
			if (strcmp(name, cs->callstack[cs->callstack_len - 1]) == 0) {
				cs->in_syscall_setup = false;
				cs->syscall_frames = bt_idx;
				T_LOG("found start of controlled stack at frame %u, expected "
				    "index %zu", cs->syscall_frames, cs->callstack_len - 1);
			} else {
				T_LOG("found syscall setup symbol %s at frame %u", name,
				    bt_idx);
			}
		}
		if (!cs->in_syscall_setup) {
			if (cs->nchecked >= cs->callstack_len) {
				T_LOG("frame %2u: skipping system frame %s", bt_idx, name);
			} else {
				size_t frame_idx = cs->callstack_len - cs->nchecked - 1;
				T_EXPECT_EQ_STR(name, cs->callstack[frame_idx],
				    "frame %2zu: saw '%s', expected '%s'",
				    frame_idx, name, cs->callstack[frame_idx]);
			}
			cs->nchecked++;
		}
	} else {
		if (!cs->in_syscall_setup) {
			T_ASSERT_NOTNULL(name, NULL, "symbol should not be NULL");
		}
	}
}

static bool
is_kernel_64_bit(void)
{
	static dispatch_once_t k64_once;
	static bool k64 = false;
	dispatch_once(&k64_once, ^{
		int errb;
		int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 /* kernproc */ };

		struct kinfo_proc kp;
		size_t len = sizeof(kp);

		errb = sysctl(mib, sizeof(mib) / sizeof(mib[0]), &kp, &len, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(errb,
		"sysctl({ CTL_KERN, KERN_PROC, KERN_PROC_PID, 0})");

		k64 = kp.kp_proc.p_flag & P_LP64;
		T_LOG("executing with a %s-bit kernel", k64 ? "64" : "32");
	});
	return k64;
}

// Use an extra, non-inlineable function so that any frames after expect_stack
// can be safely ignored.  This insulates the test from changes in how syscalls
// are called by Libc and the kernel.
static int __attribute__((noinline, not_tail_called))
backtrace_current_thread_wrapper(uint64_t *bt, size_t *bt_filled)
{
	int ret = sysctlbyname("kern.backtrace.user", bt, bt_filled, NULL, 0);
	getpid(); // Really prevent tail calls.
	return ret;
}

static void __attribute__((noinline, not_tail_called))
expect_callstack(void)
{
	uint64_t bt[USER_FRAMES + MAX_SYSCALL_SETUP_FRAMES] = { 0 };

	static CSSymbolicatorRef user_symb;
	static dispatch_once_t expect_stack_once;
	dispatch_once(&expect_stack_once, ^{
		user_symb = CSSymbolicatorCreateWithTask(mach_task_self());
		T_QUIET; T_ASSERT_FALSE(CSIsNull(user_symb), NULL);
		T_QUIET; T_ASSERT_TRUE(CSSymbolicatorIsTaskValid(user_symb), NULL);
	});

	size_t bt_filled = USER_FRAMES + MAX_SYSCALL_SETUP_FRAMES;
	int ret = backtrace_current_thread_wrapper(bt, &bt_filled);
	if (ret == -1 && errno == ENOENT) {
		T_SKIP("release kernel: kern.backtrace.user sysctl returned ENOENT");
	}
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(\"kern.backtrace.user\")");
	T_LOG("kernel returned %zu frame backtrace", bt_filled);

	unsigned int bt_len = (unsigned int)bt_filled;
	T_EXPECT_GE(bt_len, (unsigned int)USER_FRAMES,
	    "at least %u frames should be present in backtrace", USER_FRAMES);
	T_EXPECT_LE(bt_len, (unsigned int)USER_FRAMES + MAX_SYSCALL_SETUP_FRAMES,
	    "at most %u frames should be present in backtrace",
	    USER_FRAMES + MAX_SYSCALL_SETUP_FRAMES);

	struct callstack_exp callstack = {
		.in_syscall_setup = true,
		.syscall_frames = 0,
		.callstack = user_bt,
		.callstack_len = USER_FRAMES,
		.nchecked = 0,
	};
	for (unsigned int i = 0; i < bt_len; i++) {
		uintptr_t addr;
#if !defined(__LP64__)
		// Backtrace frames come out as kernel words; convert them back to user
		// uintptr_t for 32-bit processes.
		if (is_kernel_64_bit()) {
			addr = (uintptr_t)(bt[i]);
		} else {
			addr = (uintptr_t)(((uint32_t *)bt)[i]);
		}
#else // defined(__LP32__)
		addr = (uintptr_t)bt[i];
#endif // defined(__LP32__)

		CSSymbolRef symbol = CSSymbolicatorGetSymbolWithAddressAtTime(
			user_symb, addr, kCSNow);
		expect_frame(&callstack, symbol, addr, i);
	}

	T_EXPECT_GE(callstack.nchecked, USER_FRAMES,
	    "checked enough frames for correct symbols");
}

static int __attribute__((noinline, not_tail_called))
recurse_a(unsigned int frames);
static int __attribute__((noinline, not_tail_called))
recurse_b(unsigned int frames);

static int __attribute__((noinline, not_tail_called))
recurse_a(unsigned int frames)
{
	if (frames == 1) {
		expect_callstack();
		getpid(); // Really prevent tail calls.
		return 0;
	}

	return recurse_b(frames - 1) + 1;
}

static int __attribute__((noinline, not_tail_called))
recurse_b(unsigned int frames)
{
	if (frames == 1) {
		expect_callstack();
		getpid(); // Really prevent tail calls.
		return 0;
	}

	return recurse_a(frames - 1) + 1;
}

static void *
backtrace_thread(void *arg)
{
#pragma unused(arg)
	unsigned int calls;

	// backtrace_thread, recurse_a, recurse_b, ..., __sysctlbyname
	//
	// Always make one less call for this frame (backtrace_thread).
	calls = USER_FRAMES - NON_RECURSE_FRAMES;

	T_LOG("backtrace thread calling into %d frames (already at %d frames)",
	    calls, NON_RECURSE_FRAMES);
	(void)recurse_a(calls);
	return NULL;
}

T_DECL(backtrace_user, "test that the kernel can backtrace user stacks",
    T_META_CHECK_LEAKS(false), T_META_ALL_VALID_ARCHS(true))
{
	pthread_t thread;

	// Run the test from a different thread to insulate it from libdarwintest
	// setup.
	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_create(&thread, NULL, backtrace_thread,
	    NULL), "create additional thread to backtrace");

	T_QUIET; T_ASSERT_POSIX_ZERO(pthread_join(thread, NULL), NULL);
}

T_DECL(backtrace_user_bounds,
    "test that the kernel doesn't write frames out of expected bounds")
{
	uint64_t bt_init[USER_FRAMES] = {};
	size_t bt_filled = USER_FRAMES, bt_filled_after = 0;
	int error = 0;
	kern_return_t kr = KERN_FAILURE;
	void *bt_page = NULL;
	void *guard_page = NULL;
	void *bt_start = NULL;

	// The backtrace addresses come back as kernel words.
	size_t kword_size = is_kernel_64_bit() ? 8 : 4;

	// Get an idea of how many frames to expect.
	int ret = sysctlbyname("kern.backtrace.user", bt_init, &bt_filled, NULL, 0);
	if (ret == -1 && errno == ENOENT) {
		T_SKIP("release kernel: kern.backtrace.user missing");
	}
	T_ASSERT_POSIX_SUCCESS(error, "sysctlbyname(\"kern.backtrace.user\")");

	// Allocate two pages -- a first one that's valid and a second that
	// will be non-writeable to catch a copyout that's too large.
	bt_page = mmap(NULL, vm_page_size * 2, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	T_WITH_ERRNO;
	T_ASSERT_NE(bt_page, MAP_FAILED, "allocated backtrace pages");
	guard_page = (char *)bt_page + vm_page_size;

	error = mprotect(guard_page, vm_page_size, PROT_READ);
	T_ASSERT_POSIX_SUCCESS(error, "mprotect(..., PROT_READ) guard page");

	// Ensure the pages are set up as expected.
	kr = vm_write(mach_task_self(), (vm_address_t)bt_page,
	    (vm_offset_t)&(int){ 12345 }, sizeof(int));
	T_ASSERT_MACH_SUCCESS(kr,
	    "should succeed in writing to backtrace page");
	kr = vm_write(mach_task_self(), (vm_address_t)guard_page,
	    (vm_offset_t)&(int){ 12345 }, sizeof(int));
	T_ASSERT_NE(kr, KERN_SUCCESS, "should fail to write to guard page");

	// Ask the kernel to write the backtrace just before the guard page.
	bt_start = (char *)guard_page - (kword_size * bt_filled);
	bt_filled_after = bt_filled;

	error = sysctlbyname("kern.backtrace.user", bt_start, &bt_filled_after,
	    NULL, 0);
	T_EXPECT_POSIX_SUCCESS(error,
	    "sysctlbyname(\"kern.backtrace.user\") just before guard page");
	T_EXPECT_EQ(bt_filled, bt_filled_after,
	    "both calls to backtrace should have filled in the same number of "
	    "frames");

	// Expect the kernel to fault when writing too far.
	bt_start = (char *)bt_start + 1;
	bt_filled_after = bt_filled;
	error = sysctlbyname("kern.backtrace.user", bt_start, &bt_filled_after,
	    NULL, 0);
	T_EXPECT_POSIX_FAILURE(error, EFAULT,
	    "sysctlbyname(\"kern.backtrace.user\") should fault one byte into "
	    "guard page");
}
