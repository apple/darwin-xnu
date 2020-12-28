/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

// #define STANDALONE

#ifndef STANDALONE
#include <darwintest.h>
#endif
#include <architecture/i386/table.h>
#include <i386/user_ldt.h>
#include <mach/i386/vm_param.h>
#include <mach/i386/thread_status.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <ldt_mach_exc.h>

#ifndef STANDALONE
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.intel"),
	T_META_CHECK_LEAKS(false)
	);
#endif

#define COMPAT_MODE_CS_SELECTOR 0x1f
#define SYSENTER_SELECTOR 0xb
/* #define DEBUG 1 */
#define P2ROUNDUP(x, align)     (-(-((long)x) & -((long)align)))
#define MSG 2048

#define NORMAL_RUN_TIME  (10)
#define TIMEOUT_OVERHEAD (10)

/*
 * General theory of operation:
 * ----------------------------
 * (1) Ensure that all code and data to be accessed from compatibility mode is
 *     located in the low 4GiB of virtual address space.
 * (2) Allocate required segments via the i386_set_ldt() system call, making
 *     sure to set the descriptor type correctly (code vs. data).  Creating
 *     64-bit code segments is not allowed (just use the existing 0x2b selector.)
 * (3) Once you know which selector is associated with the desired code, use a
 *     trampoline (or thunk) to (a) switch to a stack that's located below 4GiB
 *     and (b) save ABI-mandated caller-saved state so that if it's trashed by
 *     compatibility-mode code, it can be restored before returning to 64-bit
 *     mode (if desired), and finally (c) long-jump or long-call (aka far call)
 *     to the segment and desired offset (this example uses an offset of 0 for
 *     simplicity.)
 * (4) Once in compatibility mode, if a framework call or system call is required,
 *     the code must trampoline back to 64-bit mode to do so.  System calls from
 *     compatibility mode code are not supported and will result in invalid opcode
 *     exceptions.  This example includes a simple 64-bit trampoline (which must
 *     be located in the low 4GiB of virtual address space, since it's executed
 *     by compatibility-mode code.)  Note that since the 64-bit ABI mandates that
 *     the stack must be aligned to a 16-byte boundary, the sample trampoline
 *     performs that rounding, to simplify compatibility-mode code.  Additionally,
 *     since 64-bit native code makes use of thread-local storage, the user-mode
 *     GSbase must be restored.  This sample includes two ways to do that-- (a) by
 *     calling into a C implementation that associates the thread-local storage
 *     pointer with a stack range (which will be unique for each thread.), and
 *     (b) by storing the original GSbase in a block of memory installed into
 *     GSbase before calling into compatibility-mode code.  A special machdep
 *     system call restores GSbase as needed.  Note that the sample trampoline
 *     does not save and restore %gs (or most other register state, so that is an
 *     area that may be tailored to the application's requirements.)
 * (5) Once running in compatibility mode, should synchronous or asynchronous
 *     exceptions occur, this sample shows how a mach exception handler (running
 *     in a detached thread, handling exceptions for the entire task) can catch
 *     such exceptions and manipulate thread state to perform recovery (or not.)
 *     Other ways to handle exceptions include installing per-thread exception
 *     servers.  Alternatively, BSD signal handlers can be used.  Note that once a
 *     process installs a custom LDT, *ALL* future signal deliveries will include
 *     ucontext pointers to mcontext structures that include enhanced thread
 *     state embedded (e.g. the %ds, %es, %ss, and GSBase registers) [This assumes
 *     that the SA_SIGINFO is passed to sigaction(2) when registering handlers].
 *     The mcontext size (part of the ucontext) can be used to differentiate between
 *     different mcontext flavors (e.g. those with/without full thread state plus
 *     x87 FP state, AVX state, or AVX2/3 state).
 */

/*
 * This test exercises the custom LDT functionality exposed via the i386_{get,set}_ldt
 * system calls.
 *
 * Tests include:
 * (1a) Exception handling (due to an exception or another thread sending a signal) while
 *      running in compatibility mode;
 * (1b) Signal handling while running in compatibility mode;
 * (2)  Thunking back to 64-bit mode and executing a framework function (e.g. printf)
 * (3)  Ensuring that transitions to compatibility mode and back to 64-bit mode
 *      do not negatively impact system calls and framework calls in 64-bit mode
 * (4)  Use of thread_get_state / thread_set_state to configure a thread to
 *      execute in compatibility mode with the proper LDT code segment (this is
 *      effectively what the exception handler does when the passed-in new_state
 *      is changed (or what the BSD signal handler return handling does when the
 *      mcontext is modified).)
 * (5)  Ensure that compatibility mode code cannot make system calls via sysenter or
 *      old-style int {0x80..0x82}.
 * (6)  Negative testing to ensure errors are returned if the consumer tries
 *      to set a disallowed segment type / Long flag. [TBD]
 */

/*
 * Note that these addresses are not necessarily available due to ASLR, so
 * a robust implementation should determine the proper range to use via
 * another means.
 */
#ifndef STANDALONE
/* libdarwintest needs LOTs of stack */
#endif
#define FIXED_STACK_SIZE (PAGE_SIZE * 16)
#define FIXED_TRAMP_MAXLEN (PAGE_SIZE * 8)

#pragma pack(1)
typedef struct {
	uint64_t off;
	uint16_t seg;
} far_call_t;
#pragma pack()

typedef struct {
	uint64_t stack_base;
	uint64_t stack_limit;
	uint64_t GSbase;
} stackaddr_to_gsbase_t;

typedef struct thread_arg {
	pthread_mutex_t         mutex;
	pthread_cond_t          condvar;
	volatile boolean_t      done;
	uint32_t                compat_stackaddr;       /* Compatibility mode stack address */
} thread_arg_t;

typedef struct custom_tsd {
	struct custom_tsd *     this_tsd_base;
	uint64_t                orig_tsd_base;
} custom_tsd_t;

typedef uint64_t (*compat_tramp_t)(far_call_t *fcp, void *lowmemstk, uint64_t arg_for_32bit,
    uint64_t callback, uint64_t absolute_addr_of_thunk64);

#define GS_RELATIVE volatile __attribute__((address_space(256)))
static custom_tsd_t GS_RELATIVE *mytsd = (custom_tsd_t GS_RELATIVE *)0;

static far_call_t input_desc = { .seg = COMPAT_MODE_CS_SELECTOR, .off = 0 };
static uint64_t stackAddr = 0;
static compat_tramp_t thunkit = NULL;
static uint64_t thunk64_addr;
/* stack2gs[0] is initialized in map_lowmem_stack() */
static stackaddr_to_gsbase_t stack2gs[] = { { 0 } };

extern int compat_mode_trampoline(far_call_t *, void *, uint64_t);
extern void long_mode_trampoline(void);
extern boolean_t mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

extern void code_32(void);

kern_return_t catch_mach_exception_raise_state_identity(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count);

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt);

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt);

extern void _thread_set_tsd_base(uint64_t);
static uint64_t stack_range_to_GSbase(uint64_t stackptr, uint64_t GSbase);
void restore_gsbase(uint64_t stackptr);

static uint64_t
get_gsbase(void)
{
	struct thread_identifier_info tiinfo;
	unsigned int info_count = THREAD_IDENTIFIER_INFO_COUNT;
	kern_return_t kr;

	if ((kr = thread_info(mach_thread_self(), THREAD_IDENTIFIER_INFO,
	    (thread_info_t) &tiinfo, &info_count)) != KERN_SUCCESS) {
		fprintf(stderr, "Could not get tsd base address.  This will not end well.\n");
		return 0;
	}

	return (uint64_t)tiinfo.thread_handle;
}

void
restore_gsbase(uint64_t stackptr)
{
	/* Restore GSbase so tsd is accessible in long mode */
	uint64_t orig_GSbase = stack_range_to_GSbase(stackptr, 0);

	assert(orig_GSbase != 0);
	_thread_set_tsd_base(orig_GSbase);
}

/*
 * Though we've directed all exceptions through the catch_mach_exception_raise_state_identity
 * entry point, we still must provide these two other entry points, otherwise a linker error
 * will occur.
 */
kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
#pragma unused(exception_port, thread, task, exception, code, codeCnt, flavor, old_state, old_stateCnt, new_state, new_stateCnt)
	fprintf(stderr, "Unexpected exception handler called: %s\n", __func__);
	return KERN_FAILURE;
}

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
#pragma unused(exception_port, exception, code, codeCnt, flavor, old_state, old_stateCnt, new_state, new_stateCnt)
	fprintf(stderr, "Unexpected exception handler called: %s\n", __func__);
	return KERN_FAILURE;
}

static void
handle_arithmetic_exception(_STRUCT_X86_THREAD_FULL_STATE64 *xtfs64, uint64_t *ip_skip_countp)
{
	fprintf(stderr, "Caught divide-error exception\n");
	fprintf(stderr, "cs=0x%x rip=0x%x gs=0x%x ss=0x%x rsp=0x%llx\n",
	    (unsigned)xtfs64->__ss64.__cs,
	    (unsigned)xtfs64->__ss64.__rip, (unsigned)xtfs64->__ss64.__gs,
	    (unsigned)xtfs64->__ss, xtfs64->__ss64.__rsp);
	*ip_skip_countp = 2;
}

static void
handle_badinsn_exception(_STRUCT_X86_THREAD_FULL_STATE64 *xtfs64, uint64_t __unused *ip_skip_countp)
{
	extern void first_invalid_opcode(void);
	extern void last_invalid_opcode(void);

	uint64_t start_addr = ((uintptr_t)first_invalid_opcode - (uintptr_t)code_32);
	uint64_t end_addr = ((uintptr_t)last_invalid_opcode - (uintptr_t)code_32);

	fprintf(stderr, "Caught invalid opcode exception\n");
	fprintf(stderr, "cs=%x rip=%x gs=%x ss=0x%x rsp=0x%llx | handling between 0x%llx and 0x%llx\n",
	    (unsigned)xtfs64->__ss64.__cs,
	    (unsigned)xtfs64->__ss64.__rip, (unsigned)xtfs64->__ss64.__gs,
	    (unsigned)xtfs64->__ss, xtfs64->__ss64.__rsp,
	    start_addr, end_addr);

	/*
	 * We expect to handle 4 invalid opcode exceptions:
	 * (1) sysenter
	 * (2) int $0x80
	 * (3) int $0x81
	 * (4) int $0x82
	 * (Note that due to the way the invalid opcode indication was implemented,
	 * %rip is already set to the next instruction.)
	 */
	if (xtfs64->__ss64.__rip >= start_addr && xtfs64->__ss64.__rip <= end_addr) {
		/*
		 * On return from the failed sysenter, %cs is changed to the
		 * sysenter code selector and %ss is set to 0x23, so switch them
		 * back to sane values.
		 */
		if ((unsigned)xtfs64->__ss64.__cs == SYSENTER_SELECTOR) {
			xtfs64->__ss64.__cs = COMPAT_MODE_CS_SELECTOR;
			xtfs64->__ss = 0x23; /* XXX */
		}
	}
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int * flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t * new_stateCnt)
{
#pragma unused(exception_port, thread, task)

	_STRUCT_X86_THREAD_FULL_STATE64 *xtfs64 = (_STRUCT_X86_THREAD_FULL_STATE64 *)(void *)old_state;
	_STRUCT_X86_THREAD_FULL_STATE64 *new_xtfs64 = (_STRUCT_X86_THREAD_FULL_STATE64 *)(void *)new_state;
	uint64_t rip_skip_count = 0;

	/*
	 * Check the exception code and thread state.
	 * If we were executing 32-bit code (or 64-bit code on behalf of
	 * 32-bit code), we could update the thread state to effectively longjmp
	 * back to a safe location where the victim thread can recover.
	 * Then again, we could return KERN_NOT_SUPPORTED and allow the process
	 * to be nuked.
	 */

	switch (exception) {
	case EXC_ARITHMETIC:
		if (codeCnt >= 1 && code[0] == EXC_I386_DIV) {
			handle_arithmetic_exception(xtfs64, &rip_skip_count);
		}
		break;

	case EXC_BAD_INSTRUCTION:
	{
		if (codeCnt >= 1 && code[0] == EXC_I386_INVOP) {
			handle_badinsn_exception(xtfs64, &rip_skip_count);
		}
		break;
	}

	default:
		fprintf(stderr, "Unsupported catch_mach_exception_raise_state_identity: code 0x%llx sub 0x%llx\n",
		    code[0], codeCnt > 1 ? code[1] : 0LL);
		fprintf(stderr, "flavor=%d %%cs=0x%x %%rip=0x%llx\n", *flavor, (unsigned)xtfs64->__ss64.__cs,
		    xtfs64->__ss64.__rip);
	}

	/*
	 * If this exception happened in compatibility mode,
	 * assume it was the intentional division-by-zero and set the
	 * new state's cs register to just after the div instruction
	 * to enable the thread to resume.
	 */
	if ((unsigned)xtfs64->__ss64.__cs == COMPAT_MODE_CS_SELECTOR) {
		*new_stateCnt = old_stateCnt;
		*new_xtfs64 = *xtfs64;
		new_xtfs64->__ss64.__rip += rip_skip_count;
		fprintf(stderr, "new cs=0x%x rip=0x%llx\n", (unsigned)new_xtfs64->__ss64.__cs,
		    new_xtfs64->__ss64.__rip);
		return KERN_SUCCESS;
	} else {
		return KERN_NOT_SUPPORTED;
	}
}

static void *
handle_exceptions(void *arg)
{
	mach_port_t ePort = (mach_port_t)arg;
	kern_return_t kret;

	kret = mach_msg_server(mach_exc_server, MACH_MSG_SIZE_RELIABLE, ePort, 0);
	if (kret != KERN_SUCCESS) {
		fprintf(stderr, "mach_msg_server: %s (%d)", mach_error_string(kret), kret);
	}

	return NULL;
}

static void
init_task_exception_server(void)
{
	kern_return_t kr;
	task_t me = mach_task_self();
	pthread_t handler_thread;
	pthread_attr_t  attr;
	mach_port_t ePort;

	kr = mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, &ePort);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "allocate receive right: %d\n", kr);
		return;
	}

	kr = mach_port_insert_right(me, ePort, ePort, MACH_MSG_TYPE_MAKE_SEND);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "insert right into port=[%d]: %d\n", ePort, kr);
		return;
	}

	kr = task_set_exception_ports(me, EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC, ePort,
	    (exception_behavior_t)(EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES), x86_THREAD_FULL_STATE64);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "abort: error setting task exception ports on task=[%d], handler=[%d]: %d\n", me, ePort, kr);
		exit(1);
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&handler_thread, &attr, handle_exceptions, (void *)(uintptr_t)ePort) != 0) {
		perror("pthread create error");
		return;
	}

	pthread_attr_destroy(&attr);
}

static union ldt_entry *descs = 0;
static uint64_t idx;
static int saw_ud2 = 0;
static boolean_t ENV_set_ldt_in_sighandler = FALSE;

static void
signal_handler(int signo, siginfo_t *sinfop, void *ucontext)
{
	uint64_t rip_skip_count = 0;
	ucontext_t *uctxp = (ucontext_t *)ucontext;
	union {
		_STRUCT_MCONTEXT_AVX512_64 *avx512_basep;
		_STRUCT_MCONTEXT_AVX512_64_FULL *avx512_fullp;
		_STRUCT_MCONTEXT_AVX64 *avx64_basep;
		_STRUCT_MCONTEXT_AVX64_FULL *avx64_fullp;
		_STRUCT_MCONTEXT64 *fp_basep;
		_STRUCT_MCONTEXT64_FULL *fp_fullp;
	} mctx;

	mctx.fp_fullp = (_STRUCT_MCONTEXT64_FULL *)uctxp->uc_mcontext;

	/*
	 * Note that GSbase must be restored before calling into any frameworks
	 * that might access anything %gs-relative (e.g. TSD) if the signal
	 * handler was triggered while the thread was running with a non-default
	 * (system-established) GSbase.
	 */

	if ((signo != SIGFPE && signo != SIGILL) || sinfop->si_signo != signo) {
#ifndef STANDALONE
		T_ASSERT_FAIL("Unexpected signal %d\n", signo);
#else
		restore_gsbase(mctx.fp_fullp->__ss.__ss64.__rsp);
		fprintf(stderr, "Not handling signal %d\n", signo);
		abort();
#endif
	}

	if (uctxp->uc_mcsize == sizeof(_STRUCT_MCONTEXT_AVX512_64) ||
	    uctxp->uc_mcsize == sizeof(_STRUCT_MCONTEXT_AVX64) ||
	    uctxp->uc_mcsize == sizeof(_STRUCT_MCONTEXT64)) {
		_STRUCT_X86_THREAD_STATE64 *ss64 = &mctx.fp_basep->__ss;

		/*
		 * The following block is an illustration of what NOT to do.
		 * Configuring an LDT for the first time in a signal handler
		 * will likely cause the process to crash.
		 */
		if (ENV_set_ldt_in_sighandler == TRUE && !saw_ud2) {
			/* Set the LDT: */
			int cnt = i386_set_ldt((int)idx, &descs[idx], 1);
			if (cnt != (int)idx) {
#ifdef DEBUG
				fprintf(stderr, "i386_set_ldt unexpectedly returned %d (errno = %s)\n", cnt, strerror(errno));
#endif
#ifndef STANDALONE
				T_LOG("i386_set_ldt unexpectedly returned %d (errno: %s)\n", cnt, strerror(errno));
				T_ASSERT_FAIL("i386_set_ldt failure");
#else
				exit(1);
#endif
			}
#ifdef DEBUG
			printf("i386_set_ldt returned %d\n", cnt);
#endif
			ss64->__rip += 2;       /* ud2 is 2 bytes */

			saw_ud2 = 1;

			/*
			 * When we return here, the sigreturn processing code will try to copy a FULL
			 * thread context from the signal stack, which will likely cause the resumed
			 * thread to fault and be terminated.
			 */
			return;
		}

		restore_gsbase(ss64->__rsp);

		/*
		 * If we're in this block, either we are dispatching a signal received
		 * before we installed a custom LDT or we are on a kernel without
		 * BSD-signalling-sending-full-thread-state support.  It's likely the latter case.
		 */
#ifndef STANDALONE
		T_ASSERT_FAIL("This system doesn't support BSD signals with full thread state.");
#else
		fprintf(stderr, "This system doesn't support BSD signals with full thread state.  Aborting.\n");
		abort();
#endif
	} else if (uctxp->uc_mcsize == sizeof(_STRUCT_MCONTEXT_AVX512_64_FULL) ||
	    uctxp->uc_mcsize == sizeof(_STRUCT_MCONTEXT_AVX64_FULL) ||
	    uctxp->uc_mcsize == sizeof(_STRUCT_MCONTEXT64_FULL)) {
		_STRUCT_X86_THREAD_FULL_STATE64 *ss64 = &mctx.fp_fullp->__ss;

		/*
		 * Since we're handing this signal on the same thread, we may need to
		 * restore GSbase.
		 */
		uint64_t orig_gsbase = stack_range_to_GSbase(ss64->__ss64.__rsp, 0);
		if (orig_gsbase != 0 && orig_gsbase != ss64->__gsbase) {
			restore_gsbase(ss64->__ss64.__rsp);
		}

		if (signo == SIGFPE) {
			handle_arithmetic_exception(ss64, &rip_skip_count);
		} else if (signo == SIGILL) {
			handle_badinsn_exception(ss64, &rip_skip_count);
		}

		/*
		 * If this exception happened in compatibility mode,
		 * assume it was the intentional division-by-zero and set the
		 * new state's cs register to just after the div instruction
		 * to enable the thread to resume.
		 */
		if ((unsigned)ss64->__ss64.__cs == COMPAT_MODE_CS_SELECTOR) {
			ss64->__ss64.__rip += rip_skip_count;
			fprintf(stderr, "new cs=0x%x rip=0x%llx\n", (unsigned)ss64->__ss64.__cs,
			    ss64->__ss64.__rip);
		}
	} else {
		_STRUCT_X86_THREAD_STATE64 *ss64 = &mctx.fp_basep->__ss;

		restore_gsbase(ss64->__rsp);
#ifndef STANDALONE
		T_ASSERT_FAIL("Unknown mcontext size %lu: Aborting.", uctxp->uc_mcsize);
#else
		fprintf(stderr, "Unknown mcontext size %lu: Aborting.\n", uctxp->uc_mcsize);
		abort();
#endif
	}
}

static void
setup_signal_handling(void)
{
	int rv;

	struct sigaction sa = {
		.__sigaction_u = { .__sa_sigaction = signal_handler },
		.sa_flags = SA_SIGINFO
	};

	sigfillset(&sa.sa_mask);

	rv = sigaction(SIGFPE, &sa, NULL);
	if (rv != 0) {
#ifndef STANDALONE
		T_ASSERT_FAIL("Failed to configure SIGFPE signal handler\n");
#else
		fprintf(stderr, "Failed to configure SIGFPE signal handler\n");
		abort();
#endif
	}

	rv = sigaction(SIGILL, &sa, NULL);
	if (rv != 0) {
#ifndef STANDALONE
		T_ASSERT_FAIL("Failed to configure SIGILL signal handler\n");
#else
		fprintf(stderr, "Failed to configure SIGILL signal handler\n");
		abort();
#endif
	}
}

static void
teardown_signal_handling(void)
{
	if (signal(SIGFPE, SIG_DFL) == SIG_ERR) {
#ifndef STANDALONE
		T_ASSERT_FAIL("Error resetting SIGFPE signal disposition\n");
#else
		fprintf(stderr, "Error resetting SIGFPE signal disposition\n");
		abort();
#endif
	}

	if (signal(SIGILL, SIG_DFL) == SIG_ERR) {
#ifndef STANDALONE
		T_ASSERT_FAIL("Error resetting SIGILL signal disposition\n");
#else
		fprintf(stderr, "Error resetting SIGILL signal disposition\n");
		abort();
#endif
	}
}

#ifdef DEBUG
static void
dump_desc(union ldt_entry *entp)
{
	printf("base %p lim %p type 0x%x dpl %x present %x opsz %x granular %x\n",
	    (void *)(uintptr_t)(entp->code.base00 + (entp->code.base16 << 16) + (entp->code.base24 << 24)),
	    (void *)(uintptr_t)(entp->code.limit00 + (entp->code.limit16 << 16)),
	    entp->code.type,
	    entp->code.dpl,
	    entp->code.present,
	    entp->code.opsz,
	    entp->code.granular);
}
#endif

static int
map_lowmem_stack(void **lowmemstk)
{
	void *addr;
	int err;

	if ((addr = mmap(0, FIXED_STACK_SIZE + PAGE_SIZE, PROT_READ | PROT_WRITE,
	    MAP_32BIT | MAP_PRIVATE | MAP_ANON, -1, 0)) == MAP_FAILED) {
		return errno;
	}

	if ((uintptr_t)addr > 0xFFFFF000ULL) {
		/* Error: This kernel does not support MAP_32BIT or there's a bug. */
#ifndef STANDALONE
		T_ASSERT_FAIL("%s: failed to map a 32-bit-accessible stack", __func__);
#else
		fprintf(stderr, "This kernel returned a virtual address > 4G (%p) despite MAP_32BIT.  Aborting.\n", addr);
		exit(1);
#endif
	}

	/* Enforce one page of redzone at the bottom of the stack */
	if (mprotect(addr, PAGE_SIZE, PROT_NONE) < 0) {
		err = errno;
		(void) munmap(addr, FIXED_STACK_SIZE + PAGE_SIZE);
		return err;
	}

	if (lowmemstk) {
		stack2gs[0].stack_base = (uintptr_t)addr + PAGE_SIZE;
		stack2gs[0].stack_limit = stack2gs[0].stack_base + FIXED_STACK_SIZE;
		*lowmemstk = (void *)((uintptr_t)addr + PAGE_SIZE);
	}

	return 0;
}

static int
map_32bit_code_impl(uint8_t *code_src, size_t code_len, void **codeptr,
    size_t szlimit)
{
	void *addr;
	size_t sz = (size_t)P2ROUNDUP(code_len, (unsigned)PAGE_SIZE);

	if (code_len > szlimit) {
		return E2BIG;
	}

#ifdef DEBUG
	printf("size = %lu, szlimit = %u\n", sz, (unsigned)szlimit);
#endif

	if ((addr = mmap(0, sz, PROT_READ | PROT_WRITE | PROT_EXEC,
	    MAP_32BIT | MAP_PRIVATE | MAP_ANON, -1, 0)) == MAP_FAILED) {
		return errno;
	}

	if ((uintptr_t)addr > 0xFFFFF000ULL) {
		/* Error: This kernel does not support MAP_32BIT or there's a bug. */
#ifndef STANDALONE
		T_ASSERT_FAIL("%s: failed to map a 32-bit-accessible trampoline", __func__);
#else
		fprintf(stderr, "This kernel returned a virtual address > 4G (%p) despite MAP_32BIT.  Aborting.\n", addr);
		exit(1);
#endif
	}

#ifdef DEBUG
	printf("Mapping code @%p..%p => %p..%p\n", (void *)code_src,
	    (void *)((uintptr_t)code_src + (unsigned)code_len),
	    addr, (void *)((uintptr_t)addr + (unsigned)code_len));
#endif

	bcopy(code_src, addr, code_len);

	/* Fill the rest of the page with NOPs */
	if ((sz - code_len) > 0) {
		memset((void *)((uintptr_t)addr + code_len), 0x90, sz - code_len);
	}

	if (codeptr) {
		*codeptr = addr;
	}

	return 0;
}

static int
map_32bit_trampoline(compat_tramp_t *lowmemtrampp)
{
	extern int compat_mode_trampoline_len;

	return map_32bit_code_impl((uint8_t *)&compat_mode_trampoline,
	           (size_t)compat_mode_trampoline_len, (void **)lowmemtrampp,
	           FIXED_TRAMP_MAXLEN);
}

static uint64_t
stack_range_to_GSbase(uint64_t stackptr, uint64_t GSbase)
{
	unsigned long i;

	for (i = 0; i < sizeof(stack2gs) / sizeof(stack2gs[0]); i++) {
		if (stackptr >= stack2gs[i].stack_base &&
		    stackptr < stack2gs[i].stack_limit) {
			if (GSbase != 0) {
#ifdef DEBUG
				fprintf(stderr, "Updated gsbase for stack at 0x%llx..0x%llx to 0x%llx\n",
				    stack2gs[i].stack_base, stack2gs[i].stack_limit, GSbase);
#endif
				stack2gs[i].GSbase = GSbase;
			}
			return stack2gs[i].GSbase;
		}
	}
	return 0;
}

static uint64_t
call_compatmode(uint32_t stackaddr, uint64_t compat_arg, uint64_t callback)
{
	uint64_t rv;

	/*
	 * Depending on how this is used, this allocation may need to be
	 * made with an allocator that returns virtual addresses below 4G.
	 */
	custom_tsd_t *new_GSbase = malloc(PAGE_SIZE);

	/*
	 * Change the GSbase (so things like printf will fail unless GSbase is
	 * restored)
	 */
	if (new_GSbase != NULL) {
#ifdef DEBUG
		fprintf(stderr, "Setting new GS base: %p\n", (void *)new_GSbase);
#endif
		new_GSbase->this_tsd_base = new_GSbase;
		new_GSbase->orig_tsd_base = get_gsbase();
		_thread_set_tsd_base((uintptr_t)new_GSbase);
	} else {
#ifndef STANDALONE
		T_ASSERT_FAIL("Failed to allocate a page for new GSbase");
#else
		fprintf(stderr, "Failed to allocate a page for new GSbase");
		abort();
#endif
	}

	rv = thunkit(&input_desc, (void *)(uintptr_t)stackaddr, compat_arg,
	    callback, thunk64_addr);

	restore_gsbase(stackaddr);

	free(new_GSbase);

	return rv;
}

static uint64_t
get_cursp(void)
{
	uint64_t curstk;
	__asm__ __volatile__ ("movq %%rsp, %0" : "=r" (curstk) :: "memory");
	return curstk;
}

static void
hello_from_32bit(void)
{
	uint64_t cur_tsd_base = (uint64_t)(uintptr_t)mytsd->this_tsd_base;
	restore_gsbase(get_cursp());

	printf("Hello on behalf of 32-bit compatibility mode!\n");

	_thread_set_tsd_base(cur_tsd_base);
}

/*
 * Thread for executing 32-bit code
 */
static void *
thread_32bit(void *arg)
{
	thread_arg_t *targp = (thread_arg_t *)arg;
	uint64_t cthread_self = 0;

	/* Save the GSbase for context switch back to 64-bit mode */
	cthread_self = get_gsbase();

	/*
	 * Associate GSbase with the compat-mode stack (which will be used for long mode
	 * thunk calls as well.)
	 */
	(void)stack_range_to_GSbase(targp->compat_stackaddr, cthread_self);

#ifdef DEBUG
	printf("[thread %p] tsd base => %p\n", (void *)pthread_self(), (void *)cthread_self);
#endif

	pthread_mutex_lock(&targp->mutex);

	do {
		if (targp->done == FALSE) {
			pthread_cond_wait(&targp->condvar, &targp->mutex);
		}

		/* Finally, execute the test */
		if (call_compatmode(targp->compat_stackaddr, 0,
		    (uint64_t)&hello_from_32bit) == 1) {
			printf("32-bit code test passed\n");
		} else {
			printf("32-bit code test failed\n");
		}
	} while (targp->done == FALSE);

	pthread_mutex_unlock(&targp->mutex);

	return 0;
}

static void
join_32bit_thread(pthread_t *thridp, thread_arg_t *cmargp)
{
	(void)pthread_mutex_lock(&cmargp->mutex);
	cmargp->done = TRUE;
	(void)pthread_cond_signal(&cmargp->condvar);
	(void)pthread_mutex_unlock(&cmargp->mutex);
	(void)pthread_join(*thridp, NULL);
	*thridp = 0;
}

static int
create_worker_thread(thread_arg_t *cmargp, uint32_t stackaddr, pthread_t *cmthreadp)
{
	*cmargp = (thread_arg_t) { .mutex = PTHREAD_MUTEX_INITIALIZER,
		                   .condvar = PTHREAD_COND_INITIALIZER,
		                   .done = FALSE,
		                   .compat_stackaddr = stackaddr };

	return pthread_create(cmthreadp, NULL, thread_32bit, cmargp);
}

static void
ldt64_test_setup(pthread_t *cmthreadp, thread_arg_t *cmargp, boolean_t setldt_in_sighandler)
{
	extern void thunk64(void);
	extern void thunk64_movabs(void);
	int cnt = 0, err;
	void *addr;
	uintptr_t code_addr;
	uintptr_t thunk64_movabs_addr;

	descs = malloc(sizeof(union ldt_entry) * 256);
	if (descs == 0) {
#ifndef STANDALONE
		T_ASSERT_FAIL("Could not allocate descriptor storage");
#else
		fprintf(stderr, "Could not allocate descriptor storage\n");
		abort();
#endif
	}

#ifdef DEBUG
	printf("32-bit code is at %p\n", (void *)&code_32);
#endif

	if ((err = map_lowmem_stack(&addr)) != 0) {
#ifndef STANDALONE
		T_ASSERT_FAIL("failed to mmap lowmem stack: %s", strerror(err));
#else
		fprintf(stderr, "Failed to mmap lowmem stack: %s\n", strerror(err));
		exit(1);
#endif
	}

	stackAddr = (uintptr_t)addr + FIXED_STACK_SIZE - 16;
#ifdef DEBUG
	printf("lowstack addr = %p\n", (void *)stackAddr);
#endif

	if ((err = map_32bit_trampoline(&thunkit)) != 0) {
#ifndef STANDALONE
		T_LOG("Failed to map trampoline into lowmem: %s\n", strerror(err));
		T_ASSERT_FAIL("Failed to map trampoline into lowmem");
#else
		fprintf(stderr, "Failed to map trampoline into lowmem: %s\n", strerror(err));
		exit(1);
#endif
	}

	/*
	 * Store long_mode_trampoline's address into the constant part of the movabs
	 * instruction in thunk64
	 */
	thunk64_movabs_addr = (uintptr_t)thunkit + ((uintptr_t)thunk64_movabs - (uintptr_t)compat_mode_trampoline);
	*((uint64_t *)(thunk64_movabs_addr + 2)) = (uint64_t)&long_mode_trampoline;

	bzero(descs, sizeof(union ldt_entry) * 256);

	if ((cnt = i386_get_ldt(0, descs, 1)) <= 0) {
#ifndef STANDALONE
		T_LOG("i386_get_ldt unexpectedly returned %d (errno: %s)\n", cnt, strerror(errno));
		T_ASSERT_FAIL("i386_get_ldt failure");
#else
		fprintf(stderr, "i386_get_ldt unexpectedly returned %d (errno: %s)\n", cnt, strerror(errno));
		exit(1);
#endif
	}

#ifdef DEBUG
	printf("i386_get_ldt returned %d\n", cnt);
#endif

	idx = (unsigned)cnt;      /* Put the desired descriptor in the first available slot */

	/*
	 * code_32's address for the purposes of this descriptor is the base mapped address of
	 * the thunkit function + the offset of code_32 from compat_mode_trampoline.
	 */
	code_addr = (uintptr_t)thunkit + ((uintptr_t)code_32 - (uintptr_t)compat_mode_trampoline);
	thunk64_addr = (uintptr_t)thunkit + ((uintptr_t)thunk64 - (uintptr_t)compat_mode_trampoline);

	/* Initialize desired descriptor */
	descs[idx].code.limit00 = (unsigned short)(((code_addr >> 12) + 1) & 0xFFFF);
	descs[idx].code.limit16 = (unsigned char)((((code_addr >> 12) + 1) >> 16) & 0xF);
	descs[idx].code.base00 = (unsigned short)((code_addr) & 0xFFFF);
	descs[idx].code.base16 = (unsigned char)((code_addr >> 16) & 0xFF);
	descs[idx].code.base24 = (unsigned char)((code_addr >> 24) & 0xFF);
	descs[idx].code.type = DESC_CODE_READ;
	descs[idx].code.opsz = DESC_CODE_32B;
	descs[idx].code.granular = DESC_GRAN_PAGE;
	descs[idx].code.dpl = 3;
	descs[idx].code.present = 1;

	if (setldt_in_sighandler == FALSE) {
		/* Set the LDT: */
		cnt = i386_set_ldt((int)idx, &descs[idx], 1);
		if (cnt != (int)idx) {
#ifndef STANDALONE
			T_LOG("i386_set_ldt unexpectedly returned %d (errno: %s)\n", cnt, strerror(errno));
			T_ASSERT_FAIL("i386_set_ldt failure");
#else
			fprintf(stderr, "i386_set_ldt unexpectedly returned %d (errno: %s)\n", cnt, strerror(errno));
			exit(1);
#endif
		}
#ifdef DEBUG
		printf("i386_set_ldt returned %d\n", cnt);
#endif
	} else {
		__asm__ __volatile__ ("ud2" ::: "memory");
	}


	/* Read back the LDT to ensure it was set properly */
	if ((cnt = i386_get_ldt(0, descs, (int)idx)) > 0) {
#ifdef DEBUG
		for (int i = 0; i < cnt; i++) {
			dump_desc(&descs[i]);
		}
#endif
	} else {
#ifndef STANDALONE
		T_LOG("i386_get_ldt unexpectedly returned %d (errno: %s)\n", cnt, strerror(errno));
		T_ASSERT_FAIL("i386_get_ldt failure");
#else
		fprintf(stderr, "i386_get_ldt unexpectedly returned %d (errno: %s)\n", cnt, strerror(errno));
		exit(1);
#endif
	}

	free(descs);

	if ((err = create_worker_thread(cmargp, (uint32_t)stackAddr, cmthreadp)) != 0) {
#ifdef DEBUG
		fprintf(stderr, "Fatal: Could not create thread: %s\n", strerror(err));
#endif
#ifndef STANDALONE
		T_LOG("Fatal: Could not create thread: %s\n", strerror(err));
		T_ASSERT_FAIL("Thread creation failure");
#else
		exit(1);
#endif
	}
}

#ifdef STANDALONE
static void
test_ldt64_with_bsdsig(void)
#else
/*
 * Main test declarations
 */
T_DECL(ldt64_with_bsd_sighandling,
    "Ensures that a 64-bit process can create LDT entries and can execute code in "
    "compatibility mode with BSD signal handling",
    T_META_TIMEOUT(NORMAL_RUN_TIME + TIMEOUT_OVERHEAD))
#endif
{
	pthread_t cmthread;
	thread_arg_t cmarg;

	setup_signal_handling();

#ifndef STANDALONE
	T_SETUPBEGIN;
#endif
	ENV_set_ldt_in_sighandler = (getenv("LDT_SET_IN_SIGHANDLER") != NULL) ? TRUE : FALSE;
	ldt64_test_setup(&cmthread, &cmarg, ENV_set_ldt_in_sighandler);
#ifndef STANDALONE
	T_SETUPEND;
#endif

	join_32bit_thread(&cmthread, &cmarg);

	teardown_signal_handling();

#ifndef STANDALONE
	T_PASS("Successfully completed ldt64 test with BSD signal handling");
#else
	fprintf(stderr, "PASSED: ldt64_with_bsd_signal_handling\n");
#endif
}

#ifdef STANDALONE
static void
test_ldt64_with_machexc(void)
#else
T_DECL(ldt64_with_mach_exception_handling,
    "Ensures that a 64-bit process can create LDT entries and can execute code in "
    "compatibility mode with Mach exception handling",
    T_META_TIMEOUT(NORMAL_RUN_TIME + TIMEOUT_OVERHEAD))
#endif
{
	pthread_t cmthread;
	thread_arg_t cmarg;

#ifndef STANDALONE
	T_SETUPBEGIN;
#endif
	ldt64_test_setup(&cmthread, &cmarg, FALSE);
#ifndef STANDALONE
	T_SETUPEND;
#endif

	/* Now repeat with Mach exception handling */
	init_task_exception_server();

	join_32bit_thread(&cmthread, &cmarg);

#ifndef STANDALONE
	T_PASS("Successfully completed ldt64 test with mach exception handling");
#else
	fprintf(stderr, "PASSED: ldt64_with_mach_exception_handling\n");
#endif
}

#ifdef STANDALONE
int
main(int __unused argc, char ** __unused argv)
{
	test_ldt64_with_bsdsig();
	test_ldt64_with_machexc();
}
#endif
