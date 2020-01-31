/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <mach_assert.h>
#include <mach_kdp.h>
#include <kdp/kdp.h>
#include <kdp/kdp_core.h>
#include <kdp/kdp_internal.h>
#include <kdp/kdp_callout.h>
#include <kern/cpu_number.h>
#include <kern/kalloc.h>
#include <kern/spl.h>
#include <kern/thread.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/clock.h>
#include <kern/telemetry.h>
#include <kern/ecc.h>
#include <kern/kern_cdata.h>
#include <kern/zalloc.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <sys/pgo.h>
#include <console/serial_protos.h>

#if !(MACH_KDP && CONFIG_KDP_INTERACTIVE_DEBUGGING)
#include <kdp/kdp_udp.h>
#endif
#include <kern/processor.h>

#if defined(__i386__) || defined(__x86_64__)
#include <i386/cpu_threads.h>
#include <i386/pmCPU.h>
#endif

#include <IOKit/IOPlatformExpert.h>
#include <machine/pal_routines.h>

#include <sys/kdebug.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/OSAtomic.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/section_keywords.h>
#include <uuid/uuid.h>
#include <mach_debug/zone_info.h>

#include <os/log_private.h>

#if CONFIG_EMBEDDED
#include <pexpert/pexpert.h> /* For gPanicBase */
#include <arm/caches_internal.h>
#include <arm/misc_protos.h>
extern volatile struct xnu_hw_shmem_dbg_command_info *hwsd_info;
#endif

#if CONFIG_XNUPOST
#include <tests/xnupost.h>
extern int vsnprintf(char *, size_t, const char *, va_list);
#endif

unsigned int    halt_in_debugger = 0;
unsigned int    current_debugger = 0;
unsigned int    active_debugger = 0;
unsigned int    panicDebugging = FALSE;
unsigned int    kdebug_serial = FALSE;
unsigned int    kernel_debugger_entry_count = 0;

#if !defined (__x86_64__)
struct additional_panic_data_buffer *panic_data_buffers = NULL;
#endif

#if defined(__arm__)
#define TRAP_DEBUGGER __asm__ volatile("trap")
#elif defined(__arm64__)
/*
 * Magic number; this should be identical to the __arm__ encoding for trap.
 */
#define TRAP_DEBUGGER __asm__ volatile(".long 0xe7ffdeff")
#elif defined (__x86_64__)
#define TRAP_DEBUGGER __asm__("int3")
#else
#error No TRAP_DEBUGGER for this architecture
#endif

#if defined(__i386__) || defined(__x86_64__)
#define panic_stop()    pmCPUHalt(PM_HALT_PANIC)
#else
#define panic_stop()    panic_spin_forever()
#endif

#define CPUDEBUGGEROP PROCESSOR_DATA(current_processor(), debugger_state).db_current_op
#define CPUDEBUGGERMSG PROCESSOR_DATA(current_processor(), debugger_state).db_message
#define CPUPANICSTR PROCESSOR_DATA(current_processor(), debugger_state).db_panic_str
#define CPUPANICARGS PROCESSOR_DATA(current_processor(), debugger_state).db_panic_args
#define CPUPANICOPTS PROCESSOR_DATA(current_processor(), debugger_state).db_panic_options
#define CPUPANICDATAPTR PROCESSOR_DATA(current_processor(), debugger_state).db_panic_data_ptr
#define CPUDEBUGGERSYNC PROCESSOR_DATA(current_processor(), debugger_state).db_proceed_on_sync_failure
#define CPUDEBUGGERCOUNT PROCESSOR_DATA(current_processor(), debugger_state).db_entry_count
#define CPUDEBUGGERRET PROCESSOR_DATA(current_processor(), debugger_state).db_op_return
#define CPUPANICCALLER PROCESSOR_DATA(current_processor(), debugger_state).db_panic_caller

#if DEVELOPMENT || DEBUG
#define DEBUGGER_DEBUGGING_NESTED_PANIC_IF_REQUESTED(requested)                                 \
MACRO_BEGIN                                                                                     \
	if (requested) {                                                                        \
	        volatile int *badpointer = (int *)4;                                                    \
	        *badpointer = 0;                                                                \
	}                                                                                       \
MACRO_END
#endif /* DEVELOPMENT || DEBUG */

debugger_op debugger_current_op = DBOP_NONE;
const char *debugger_panic_str = NULL;
va_list *debugger_panic_args = NULL;
void *debugger_panic_data = NULL;
uint64_t debugger_panic_options = 0;
const char *debugger_message = NULL;
unsigned long debugger_panic_caller = 0;

void panic_trap_to_debugger(const char *panic_format_str, va_list *panic_args, unsigned int reason, void *ctx,
    uint64_t panic_options_mask, void *panic_data, unsigned long panic_caller);
static void kdp_machine_reboot_type(unsigned int type);
__attribute__((noreturn)) void panic_spin_forever(void);
extern kern_return_t do_stackshot(void);

int mach_assert = 1;

#define NESTEDDEBUGGERENTRYMAX 5

#if CONFIG_EMBEDDED
#define DEBUG_BUF_SIZE (4096)
#define KDBG_TRACE_PANIC_FILENAME "/var/log/panic.trace"
#else
/*
 * EXTENDED_/DEBUG_BUF_SIZE can't grow without updates to SMC and iBoot to store larger panic logs on co-processor systems */
#define DEBUG_BUF_SIZE ((3 * PAGE_SIZE) + offsetof(struct macos_panic_header, mph_data))
#define EXTENDED_DEBUG_BUF_SIZE 0x0013ff80
static_assert(((EXTENDED_DEBUG_BUF_SIZE % PANIC_FLUSH_BOUNDARY) == 0), "Extended debug buf size must match SMC alignment requirements");
#define KDBG_TRACE_PANIC_FILENAME "/var/tmp/panic.trace"
#endif

/* debug_buf is directly linked with iBoot panic region for embedded targets */
#if CONFIG_EMBEDDED
char *debug_buf_base = NULL;
char *debug_buf_ptr = NULL;
unsigned int debug_buf_size = 0;
#else
char debug_buf[DEBUG_BUF_SIZE];
struct macos_panic_header *panic_info = (struct macos_panic_header *)debug_buf;
char *debug_buf_base = (debug_buf + offsetof(struct macos_panic_header, mph_data));
char *debug_buf_ptr = (debug_buf + offsetof(struct macos_panic_header, mph_data));

/*
 * We don't include the size of the panic header in the length of the data we actually write.
 * On co-processor platforms, we lose sizeof(struct macos_panic_header) bytes from the end of
 * the end of the log because we only support writing (3*PAGESIZE) bytes.
 */
unsigned int debug_buf_size = (DEBUG_BUF_SIZE - offsetof(struct macos_panic_header, mph_data));

boolean_t extended_debug_log_enabled = FALSE;
#endif

/* Debugger state */
atomic_int     debugger_cpu = ATOMIC_VAR_INIT(DEBUGGER_NO_CPU);
boolean_t      debugger_allcpus_halted = FALSE;
boolean_t      debugger_safe_to_return = TRUE;
unsigned int   debugger_context = 0;

static char model_name[64];
unsigned char *kernel_uuid;

boolean_t kernelcache_uuid_valid = FALSE;
uuid_t kernelcache_uuid;
uuid_string_t kernelcache_uuid_string;

/*
 * By default we treat Debugger() the same as calls to panic(), unless
 * we have debug boot-args present and the DB_KERN_DUMP_ON_NMI *NOT* set.
 * If DB_KERN_DUMP_ON_NMI is *NOT* set, return from Debugger() is supported.
 *
 * Return from Debugger() is currently only implemented on x86
 */
static boolean_t debugger_is_panic = TRUE;

#if DEVELOPMENT || DEBUG
boolean_t debug_boot_arg_inited = FALSE;
#endif

SECURITY_READ_ONLY_LATE(unsigned int) debug_boot_arg;

char kernel_uuid_string[37]; /* uuid_string_t */
char kernelcache_uuid_string[37]; /* uuid_string_t */
char   panic_disk_error_description[512];
size_t panic_disk_error_description_size = sizeof(panic_disk_error_description);

extern unsigned int write_trace_on_panic;
int kext_assertions_enable =
#if DEBUG || DEVELOPMENT
    TRUE;
#else
    FALSE;
#endif

void
panic_init(void)
{
	unsigned long uuidlen = 0;
	void *uuid;

	uuid = getuuidfromheader(&_mh_execute_header, &uuidlen);
	if ((uuid != NULL) && (uuidlen == sizeof(uuid_t))) {
		kernel_uuid = uuid;
		uuid_unparse_upper(*(uuid_t *)uuid, kernel_uuid_string);
	}

	if (!PE_parse_boot_argn("assertions", &mach_assert, sizeof(mach_assert))) {
		mach_assert = 1;
	}

	/*
	 * Initialize the value of the debug boot-arg
	 */
	debug_boot_arg = 0;
#if ((CONFIG_EMBEDDED && MACH_KDP) || defined(__x86_64__))
	if (PE_parse_boot_argn("debug", &debug_boot_arg, sizeof(debug_boot_arg))) {
#if DEVELOPMENT || DEBUG
		if (debug_boot_arg & DB_HALT) {
			halt_in_debugger = 1;
		}
#endif

#if CONFIG_EMBEDDED
		if (debug_boot_arg & DB_NMI) {
			panicDebugging  = TRUE;
		}
#else
		panicDebugging = TRUE;
#if KDEBUG_MOJO_TRACE
		if (debug_boot_arg & DB_PRT_KDEBUG) {
			kdebug_serial = TRUE;
		}
#endif
#endif /* CONFIG_EMBEDDED */
	}
#endif /* ((CONFIG_EMBEDDED && MACH_KDP) || defined(__x86_64__)) */

#if DEVELOPMENT || DEBUG
	debug_boot_arg_inited = TRUE;
#endif

#if !CONFIG_EMBEDDED
	/*
	 * By default we treat Debugger() the same as calls to panic(), unless
	 * we have debug boot-args present and the DB_KERN_DUMP_ON_NMI *NOT* set.
	 * If DB_KERN_DUMP_ON_NMI is *NOT* set, return from Debugger() is supported.
	 * This is because writing an on-device corefile is a destructive operation.
	 *
	 * Return from Debugger() is currently only implemented on x86
	 */
	if (PE_i_can_has_debugger(NULL) && !(debug_boot_arg & DB_KERN_DUMP_ON_NMI)) {
		debugger_is_panic = FALSE;
	}
#endif
}

#if defined (__x86_64__)
void
extended_debug_log_init(void)
{
	assert(coprocessor_paniclog_flush);
	/*
	 * Allocate an extended panic log buffer that has space for the panic
	 * stackshot at the end. Update the debug buf pointers appropriately
	 * to point at this new buffer.
	 */
	char *new_debug_buf = kalloc(EXTENDED_DEBUG_BUF_SIZE);
	/*
	 * iBoot pre-initializes the panic region with the NULL character. We set this here
	 * so we can accurately calculate the CRC for the region without needing to flush the
	 * full region over SMC.
	 */
	memset(new_debug_buf, '\0', EXTENDED_DEBUG_BUF_SIZE);

	panic_info = (struct macos_panic_header *)new_debug_buf;
	debug_buf_ptr = debug_buf_base = (new_debug_buf + offsetof(struct macos_panic_header, mph_data));
	debug_buf_size = (EXTENDED_DEBUG_BUF_SIZE - offsetof(struct macos_panic_header, mph_data));

	extended_debug_log_enabled = TRUE;
}
#endif /* defined (__x86_64__) */

void
debug_log_init(void)
{
#if CONFIG_EMBEDDED
	if (!gPanicBase) {
		printf("debug_log_init: Error!! gPanicBase is still not initialized\n");
		return;
	}
	/* Shift debug buf start location and size by the length of the panic header */
	debug_buf_base = (char *)gPanicBase + sizeof(struct embedded_panic_header);
	debug_buf_ptr = debug_buf_base;
	debug_buf_size = gPanicSize - sizeof(struct embedded_panic_header);
#else
	bzero(panic_info, DEBUG_BUF_SIZE);

	assert(debug_buf_base != NULL);
	assert(debug_buf_ptr != NULL);
	assert(debug_buf_size != 0);
#endif
}

static void
DebuggerLock()
{
	int my_cpu = cpu_number();
	int debugger_exp_cpu = DEBUGGER_NO_CPU;
	assert(ml_get_interrupts_enabled() == FALSE);

	if (debugger_cpu == my_cpu) {
		return;
	}

	while (!atomic_compare_exchange_strong(&debugger_cpu, &debugger_exp_cpu, my_cpu)) {
		debugger_exp_cpu = DEBUGGER_NO_CPU;
	}

	return;
}

static void
DebuggerUnlock()
{
	assert(debugger_cpu == cpu_number());

	/*
	 * We don't do an atomic exchange here in case
	 * there's another CPU spinning to acquire the debugger_lock
	 * and we never get a chance to update it. We already have the
	 * lock so we can simply store DEBUGGER_NO_CPU and follow with
	 * a barrier.
	 */
	debugger_cpu = DEBUGGER_NO_CPU;
	OSMemoryBarrier();

	return;
}

static kern_return_t
DebuggerHaltOtherCores(boolean_t proceed_on_failure)
{
#if CONFIG_EMBEDDED
	return DebuggerXCallEnter(proceed_on_failure);
#else /* CONFIG_EMBEDDED */
#pragma unused(proceed_on_failure)
	mp_kdp_enter(proceed_on_failure);
	return KERN_SUCCESS;
#endif
}

static void
DebuggerResumeOtherCores()
{
#if CONFIG_EMBEDDED
	DebuggerXCallReturn();
#else /* CONFIG_EMBEDDED */
	mp_kdp_exit();
#endif
}

static void
DebuggerSaveState(debugger_op db_op, const char *db_message, const char *db_panic_str,
    va_list *db_panic_args, uint64_t db_panic_options, void *db_panic_data_ptr,
    boolean_t db_proceed_on_sync_failure, unsigned long db_panic_caller)
{
	CPUDEBUGGEROP = db_op;

	/* Preserve the original panic message */
	if (CPUDEBUGGERCOUNT == 1 || CPUPANICSTR == NULL) {
		CPUDEBUGGERMSG = db_message;
		CPUPANICSTR = db_panic_str;
		CPUPANICARGS = db_panic_args;
		CPUPANICDATAPTR = db_panic_data_ptr;
		CPUPANICCALLER = db_panic_caller;
	} else if (CPUDEBUGGERCOUNT > 1 && db_panic_str != NULL) {
		kprintf("Nested panic detected:");
		if (db_panic_str != NULL) {
			_doprnt(db_panic_str, db_panic_args, PE_kputc, 0);
		}
	}

	CPUDEBUGGERSYNC = db_proceed_on_sync_failure;
	CPUDEBUGGERRET = KERN_SUCCESS;

	/* Reset these on any nested panics */
	CPUPANICOPTS = db_panic_options;

	return;
}

/*
 * Save the requested debugger state/action into the current processor's processor_data
 * and trap to the debugger.
 */
kern_return_t
DebuggerTrapWithState(debugger_op db_op, const char *db_message, const char *db_panic_str,
    va_list *db_panic_args, uint64_t db_panic_options, void *db_panic_data_ptr,
    boolean_t db_proceed_on_sync_failure, unsigned long db_panic_caller)
{
	kern_return_t ret;

	assert(ml_get_interrupts_enabled() == FALSE);
	DebuggerSaveState(db_op, db_message, db_panic_str, db_panic_args,
	    db_panic_options, db_panic_data_ptr,
	    db_proceed_on_sync_failure, db_panic_caller);

	TRAP_DEBUGGER;

	ret = CPUDEBUGGERRET;

	DebuggerSaveState(DBOP_NONE, NULL, NULL, NULL, 0, NULL, FALSE, 0);

	return ret;
}

void __attribute__((noinline))
Assert(
	const char      *file,
	int             line,
	const char      *expression
	)
{
	if (!mach_assert) {
		kprintf("%s:%d non-fatal Assertion: %s", file, line, expression);
		return;
	}

	panic_plain("%s:%d Assertion failed: %s", file, line, expression);
}


void
Debugger(const char *message)
{
	DebuggerWithContext(0, NULL, message, DEBUGGER_OPTION_NONE);
}

void
DebuggerWithContext(unsigned int reason, void *ctx, const char *message,
    uint64_t debugger_options_mask)
{
	spl_t previous_interrupts_state;
	boolean_t old_doprnt_hide_pointers = doprnt_hide_pointers;

	previous_interrupts_state = ml_set_interrupts_enabled(FALSE);
	disable_preemption();

	CPUDEBUGGERCOUNT++;

	if (CPUDEBUGGERCOUNT > NESTEDDEBUGGERENTRYMAX) {
		static boolean_t in_panic_kprintf = FALSE;

		/* Notify any listeners that we've started a panic */
		PEHaltRestart(kPEPanicBegin);

		if (!in_panic_kprintf) {
			in_panic_kprintf = TRUE;
			kprintf("Detected nested debugger entry count exceeding %d\n",
			    NESTEDDEBUGGERENTRYMAX);
			in_panic_kprintf = FALSE;
		}

		if (!panicDebugging) {
			kdp_machine_reboot_type(kPEPanicRestartCPU);
		}

		panic_spin_forever();
	}

#if DEVELOPMENT || DEBUG
	DEBUGGER_DEBUGGING_NESTED_PANIC_IF_REQUESTED((debugger_options_mask & DEBUGGER_OPTION_RECURPANIC_ENTRY));
#endif

	doprnt_hide_pointers = FALSE;

	if (ctx != NULL) {
		DebuggerSaveState(DBOP_DEBUGGER, message,
		    NULL, NULL, debugger_options_mask, NULL, TRUE, 0);
		handle_debugger_trap(reason, 0, 0, ctx);
		DebuggerSaveState(DBOP_NONE, NULL, NULL,
		    NULL, 0, NULL, FALSE, 0);
	} else {
		DebuggerTrapWithState(DBOP_DEBUGGER, message,
		    NULL, NULL, debugger_options_mask, NULL, TRUE, 0);
	}

	CPUDEBUGGERCOUNT--;
	doprnt_hide_pointers = old_doprnt_hide_pointers;
	enable_preemption();
	ml_set_interrupts_enabled(previous_interrupts_state);
}

static struct kdp_callout {
	struct kdp_callout * callout_next;
	kdp_callout_fn_t callout_fn;
	boolean_t callout_in_progress;
	void * callout_arg;
} * kdp_callout_list = NULL;

/*
 * Called from kernel context to register a kdp event callout.
 */
void
kdp_register_callout(kdp_callout_fn_t fn, void * arg)
{
	struct kdp_callout * kcp;
	struct kdp_callout * list_head;

	kcp = kalloc(sizeof(*kcp));
	if (kcp == NULL) {
		panic("kdp_register_callout() kalloc failed");
	}

	kcp->callout_fn = fn;
	kcp->callout_arg = arg;
	kcp->callout_in_progress = FALSE;

	/* Lock-less list insertion using compare and exchange. */
	do {
		list_head = kdp_callout_list;
		kcp->callout_next = list_head;
	} while (!OSCompareAndSwapPtr(list_head, kcp, &kdp_callout_list));
}

static void
kdp_callouts(kdp_event_t event)
{
	struct kdp_callout      *kcp = kdp_callout_list;

	while (kcp) {
		if (!kcp->callout_in_progress) {
			kcp->callout_in_progress = TRUE;
			kcp->callout_fn(kcp->callout_arg, event);
			kcp->callout_in_progress = FALSE;
		}
		kcp = kcp->callout_next;
	}
}

#if !defined (__x86_64__)
/*
 * Register an additional buffer with data to include in the panic log
 *
 * <rdar://problem/50137705> tracks supporting more than one buffer
 *
 * Note that producer_name and buf should never be de-allocated as we reference these during panic.
 */
void
register_additional_panic_data_buffer(const char *producer_name, void *buf, int len)
{
	if (panic_data_buffers != NULL) {
		panic("register_additional_panic_data_buffer called with buffer already registered");
	}

	if (producer_name == NULL || (strlen(producer_name) == 0)) {
		panic("register_additional_panic_data_buffer called with invalid producer_name");
	}

	if (buf == NULL) {
		panic("register_additional_panic_data_buffer called with invalid buffer pointer");
	}

	if ((len <= 0) || (len > ADDITIONAL_PANIC_DATA_BUFFER_MAX_LEN)) {
		panic("register_additional_panic_data_buffer called with invalid length");
	}

	struct additional_panic_data_buffer *new_panic_data_buffer = kalloc(sizeof(struct additional_panic_data_buffer));
	new_panic_data_buffer->producer_name = producer_name;
	new_panic_data_buffer->buf = buf;
	new_panic_data_buffer->len = len;

	if (!OSCompareAndSwapPtr(NULL, new_panic_data_buffer, &panic_data_buffers)) {
		panic("register_additional_panic_data_buffer called with buffer already registered");
	}

	return;
}
#endif /* !defined (__x86_64__) */

/*
 * An overview of the xnu panic path:
 *
 * Several panic wrappers (panic(), panic_with_options(), etc.) all funnel into panic_trap_to_debugger().
 * panic_trap_to_debugger() sets the panic state in the current processor's processor_data_t prior
 * to trapping into the debugger. Once we trap to the debugger, we end up in handle_debugger_trap()
 * which tries to acquire the panic lock by atomically swapping the current CPU number into debugger_cpu.
 * debugger_cpu acts as a synchronization point, from which the winning CPU can halt the other cores and
 * continue to debugger_collect_diagnostics() where we write the paniclog, corefile (if appropriate) and proceed
 * according to the device's boot-args.
 */
#undef panic
void
panic(const char *str, ...)
{
	va_list panic_str_args;

	va_start(panic_str_args, str);
	panic_trap_to_debugger(str, &panic_str_args, 0, NULL, 0, NULL, (unsigned long)(char *)__builtin_return_address(0));
	va_end(panic_str_args);
}

void
panic_with_options(unsigned int reason, void *ctx, uint64_t debugger_options_mask, const char *str, ...)
{
	va_list panic_str_args;

	va_start(panic_str_args, str);
	panic_trap_to_debugger(str, &panic_str_args, reason, ctx, (debugger_options_mask & ~DEBUGGER_INTERNAL_OPTIONS_MASK),
	    NULL, (unsigned long)(char *)__builtin_return_address(0));
	va_end(panic_str_args);
}

#if defined (__x86_64__)
/*
 * panic_with_thread_context() is used on x86 platforms to specify a different thread that should be backtraced in the paniclog.
 * We don't generally need this functionality on embedded platforms because embedded platforms include a panic time stackshot
 * from customer devices. We plumb the thread pointer via the debugger trap mechanism and backtrace the kernel stack from the
 * thread when writing the panic log.
 *
 * NOTE: panic_with_thread_context() should be called with an explicit thread reference held on the passed thread.
 */
void
panic_with_thread_context(unsigned int reason, void *ctx, uint64_t debugger_options_mask, thread_t thread, const char *str, ...)
{
	va_list panic_str_args;

	assert_thread_magic(thread);

	/* Take a reference on the thread so it doesn't disappear by the time we try to backtrace it */
	thread_reference(thread);

	va_start(panic_str_args, str);
	panic_trap_to_debugger(str, &panic_str_args, reason, ctx, ((debugger_options_mask & ~DEBUGGER_INTERNAL_OPTIONS_MASK) | DEBUGGER_INTERNAL_OPTION_THREAD_BACKTRACE),
	    thread, (unsigned long)(char *)__builtin_return_address(0));

	va_end(panic_str_args);
}
#endif /* defined (__x86_64__) */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
void
panic_trap_to_debugger(const char *panic_format_str, va_list *panic_args, unsigned int reason, void *ctx,
    uint64_t panic_options_mask, void *panic_data_ptr, unsigned long panic_caller)
{
#pragma clang diagnostic pop

#if defined(__x86_64__) && (DEVELOPMENT || DEBUG)
	/* Turn off I/O tracing once we've panicked */
	mmiotrace_enabled = 0;
#endif

	if (ml_wants_panic_trap_to_debugger()) {
		ml_panic_trap_to_debugger(panic_format_str, panic_args, reason, ctx, panic_options_mask, panic_caller);

		/*
		 * This should not return, but we return here for the tail call
		 * as it simplifies the backtrace.
		 */
		return;
	}

	CPUDEBUGGERCOUNT++;

	if (CPUDEBUGGERCOUNT > NESTEDDEBUGGERENTRYMAX) {
		static boolean_t in_panic_kprintf = FALSE;

		/* Notify any listeners that we've started a panic */
		PEHaltRestart(kPEPanicBegin);

		if (!in_panic_kprintf) {
			in_panic_kprintf = TRUE;
			kprintf("Detected nested debugger entry count exceeding %d\n",
			    NESTEDDEBUGGERENTRYMAX);
			in_panic_kprintf = FALSE;
		}

		if (!panicDebugging) {
			kdp_machine_reboot_type(kPEPanicRestartCPU);
		}

		panic_spin_forever();
	}

#if DEVELOPMENT || DEBUG
	DEBUGGER_DEBUGGING_NESTED_PANIC_IF_REQUESTED((panic_options_mask & DEBUGGER_OPTION_RECURPANIC_ENTRY));
#endif

#if CONFIG_EMBEDDED
	if (PE_arm_debug_panic_hook) {
		PE_arm_debug_panic_hook(panic_format_str);
	}
#endif

#if defined (__x86_64__)
	plctrace_disable();
#endif

	if (write_trace_on_panic && kdebug_enable) {
		if (get_preemption_level() == 0 && !ml_at_interrupt_context()) {
			ml_set_interrupts_enabled(TRUE);
			KDBG_RELEASE(TRACE_PANIC);
			kdbg_dump_trace_to_file(KDBG_TRACE_PANIC_FILENAME);
		}
	}

	ml_set_interrupts_enabled(FALSE);
	disable_preemption();

#if defined (__x86_64__)
	pmSafeMode(x86_lcpu(), PM_SAFE_FL_SAFE);
#endif /* defined (__x86_64__) */

	/* Never hide pointers from panic logs. */
	doprnt_hide_pointers = FALSE;

	if (ctx != NULL) {
		/*
		 * We called into panic from a trap, no need to trap again. Set the
		 * state on the current CPU and then jump to handle_debugger_trap.
		 */
		DebuggerSaveState(DBOP_PANIC, "panic",
		    panic_format_str, panic_args,
		    panic_options_mask, panic_data_ptr, TRUE, panic_caller);
		handle_debugger_trap(reason, 0, 0, ctx);
	}

#if defined(__arm64__)
	/*
	 *  Signal to fastsim that it should open debug ports (nop on hardware)
	 */
	__asm__         volatile ("HINT 0x45");
#endif /* defined(__arm64__) */

	DebuggerTrapWithState(DBOP_PANIC, "panic", panic_format_str,
	    panic_args, panic_options_mask, panic_data_ptr, TRUE, panic_caller);

	/*
	 * Not reached.
	 */
	panic_stop();
}

__attribute__((noreturn))
void
panic_spin_forever()
{
	paniclog_append_noflush("\nPlease go to https://panic.apple.com to report this panic\n");

	for (;;) {
	}
}

static void
kdp_machine_reboot_type(unsigned int type)
{
	printf("Attempting system restart...");
	PEHaltRestart(type);
	halt_all_cpus(TRUE);
}

void
kdp_machine_reboot(void)
{
	kdp_machine_reboot_type(kPEPanicRestartCPU);
}

/*
 * Gather and save diagnostic information about a panic (or Debugger call).
 *
 * On embedded, Debugger and Panic are treated very similarly -- WDT uses Debugger so we can
 * theoretically return from it. On desktop, Debugger is treated as a conventional debugger -- i.e no
 * paniclog is written and no core is written unless we request a core on NMI.
 *
 * This routine handles kicking off local coredumps, paniclogs, calling into the Debugger/KDP (if it's configured),
 * and calling out to any other functions we have for collecting diagnostic info.
 */
static void
debugger_collect_diagnostics(unsigned int exception, unsigned int code, unsigned int subcode, void *state)
{
#if DEVELOPMENT || DEBUG
	DEBUGGER_DEBUGGING_NESTED_PANIC_IF_REQUESTED((debugger_panic_options & DEBUGGER_OPTION_RECURPANIC_PRELOG));
#endif

#if defined(__x86_64__)
	kprintf("Debugger called: <%s>\n", debugger_message ? debugger_message : "");
#endif
	/*
	 * DB_HALT (halt_in_debugger) can be requested on startup, we shouldn't generate
	 * a coredump/paniclog for this type of debugger entry. If KDP isn't configured,
	 * we'll just spin in kdp_raise_exception.
	 */
	if (debugger_current_op == DBOP_DEBUGGER && halt_in_debugger) {
		kdp_raise_exception(exception, code, subcode, state);
		if (debugger_safe_to_return && !debugger_is_panic) {
			return;
		}
	}

	if ((debugger_current_op == DBOP_PANIC) ||
	    ((debugger_current_op == DBOP_DEBUGGER) && debugger_is_panic)) {
		/*
		 * Attempt to notify listeners once and only once that we've started
		 * panicking. Only do this for Debugger() calls if we're treating
		 * Debugger() calls like panic().
		 */
		PEHaltRestart(kPEPanicBegin);

		/*
		 * Set the begin pointer in the panic log structure. We key off of this
		 * static variable rather than contents from the panic header itself in case someone
		 * has stomped over the panic_info structure. Also initializes the header magic.
		 */
		static boolean_t began_writing_paniclog = FALSE;
		if (!began_writing_paniclog) {
			PE_init_panicheader();
			began_writing_paniclog = TRUE;
		} else {
			/*
			 * If we reached here, update the panic header to keep it as consistent
			 * as possible during a nested panic
			 */
			PE_update_panicheader_nestedpanic();
		}
	}

	/*
	 * Write panic string if this was a panic.
	 *
	 * TODO: Consider moving to SavePanicInfo as this is part of the panic log.
	 */
	if (debugger_current_op == DBOP_PANIC) {
		paniclog_append_noflush("panic(cpu %d caller 0x%lx): ", (unsigned) cpu_number(), debugger_panic_caller);
		if (debugger_panic_str) {
			_doprnt(debugger_panic_str, debugger_panic_args, consdebug_putc, 0);
		}
		paniclog_append_noflush("\n");
	}
#if defined(__x86_64__)
	else if (((debugger_current_op == DBOP_DEBUGGER) && debugger_is_panic)) {
		paniclog_append_noflush("Debugger called: <%s>\n", debugger_message ? debugger_message : "");
	}

	/*
	 * Debugger() is treated like panic() on embedded -- for example we use it for WDT
	 * panics (so we need to write a paniclog). On desktop Debugger() is used in the
	 * conventional sense.
	 */
	if (debugger_current_op == DBOP_PANIC || ((debugger_current_op == DBOP_DEBUGGER) && debugger_is_panic))
#endif
	{
		kdp_callouts(KDP_EVENT_PANICLOG);

		/*
		 * Write paniclog and panic stackshot (if supported)
		 * TODO: Need to clear panic log when return from debugger
		 * hooked up for embedded
		 */
		SavePanicInfo(debugger_message, debugger_panic_data, debugger_panic_options);

#if DEVELOPMENT || DEBUG
		DEBUGGER_DEBUGGING_NESTED_PANIC_IF_REQUESTED((debugger_panic_options & DEBUGGER_OPTION_RECURPANIC_POSTLOG));
#endif

		/* DEBUGGER_OPTION_PANICLOGANDREBOOT is used for two finger resets on embedded so we get a paniclog */
		if (debugger_panic_options & DEBUGGER_OPTION_PANICLOGANDREBOOT) {
			PEHaltRestart(kPEPanicRestartCPU);
		}
	}

#if CONFIG_KDP_INTERACTIVE_DEBUGGING
	/*
	 * If reboot on panic is enabled and the caller of panic indicated that we should skip
	 * local coredumps, don't try to write these and instead go straight to reboot. This
	 * allows us to persist any data that's stored in the panic log.
	 */
	if ((debugger_panic_options & DEBUGGER_OPTION_SKIP_LOCAL_COREDUMP) &&
	    (debug_boot_arg & DB_REBOOT_POST_CORE)) {
		kdp_machine_reboot_type(kPEPanicRestartCPU);
	}

	/*
	 * Consider generating a local corefile if the infrastructure is configured
	 * and we haven't disabled on-device coredumps.
	 */
	if (!(debug_boot_arg & DB_DISABLE_LOCAL_CORE)) {
		if (!kdp_has_polled_corefile()) {
			if (debug_boot_arg & (DB_KERN_DUMP_ON_PANIC | DB_KERN_DUMP_ON_NMI)) {
				paniclog_append_noflush("skipping local kernel core because core file could not be opened prior to panic (error : 0x%x)",
				    kdp_polled_corefile_error());
#if CONFIG_EMBEDDED
				panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_COREDUMP_FAILED;
				paniclog_flush();
#else /* CONFIG_EMBEDDED */
				if (panic_info->mph_panic_log_offset != 0) {
					panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_COREDUMP_FAILED;
					paniclog_flush();
				}
#endif /* CONFIG_EMBEDDED */
			}
		} else {
			int ret = -1;

#if defined (__x86_64__)
			/* On x86 we don't do a coredump on Debugger unless the DB_KERN_DUMP_ON_NMI boot-arg is specified. */
			if (debugger_current_op != DBOP_DEBUGGER || (debug_boot_arg & DB_KERN_DUMP_ON_NMI))
#endif
			{
				/*
				 * Doing an on-device coredump leaves the disk driver in a state
				 * that can not be resumed.
				 */
				debugger_safe_to_return = FALSE;
				begin_panic_transfer();
				ret = kern_dump(KERN_DUMP_DISK);
				abort_panic_transfer();

#if DEVELOPMENT || DEBUG
				DEBUGGER_DEBUGGING_NESTED_PANIC_IF_REQUESTED((debugger_panic_options & DEBUGGER_OPTION_RECURPANIC_POSTCORE));
#endif
			}

			/*
			 * If DB_REBOOT_POST_CORE is set, then reboot if coredump is sucessfully saved
			 * or if option to ignore failures is set.
			 */
			if ((debug_boot_arg & DB_REBOOT_POST_CORE) &&
			    ((ret == 0) || (debugger_panic_options & DEBUGGER_OPTION_ATTEMPTCOREDUMPANDREBOOT))) {
				kdp_machine_reboot_type(kPEPanicRestartCPU);
			}
		}
	}

	if (debug_boot_arg & DB_REBOOT_ALWAYS) {
		kdp_machine_reboot_type(kPEPanicRestartCPU);
	}

	/* If KDP is configured, try to trap to the debugger */
	if (current_debugger != NO_CUR_DB) {
		kdp_raise_exception(exception, code, subcode, state);
		/*
		 * Only return if we entered via Debugger and it's safe to return
		 * (we halted the other cores successfully, this isn't a nested panic, etc)
		 */
		if (debugger_current_op == DBOP_DEBUGGER &&
		    debugger_safe_to_return &&
		    kernel_debugger_entry_count == 1 &&
		    !debugger_is_panic) {
			return;
		}
	}

#if CONFIG_EMBEDDED
	if (panicDebugging) {
		/* If panic debugging is configured, spin for astris to connect */
		panic_spin_shmcon();
	}
#endif /* CONFIG_EMBEDDED */
#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */

	if (!panicDebugging) {
		kdp_machine_reboot_type(kPEPanicRestartCPU);
	}

	panic_spin_forever();
}

#if INTERRUPT_MASKED_DEBUG
uint64_t debugger_trap_timestamps[9];
# define DEBUGGER_TRAP_TIMESTAMP(i) debugger_trap_timestamps[i] = mach_absolute_time();
#else
# define DEBUGGER_TRAP_TIMESTAMP(i)
#endif

void
handle_debugger_trap(unsigned int exception, unsigned int code, unsigned int subcode, void *state)
{
	unsigned int initial_not_in_kdp = not_in_kdp;
	kern_return_t ret;
	debugger_op db_prev_op = debugger_current_op;

	DEBUGGER_TRAP_TIMESTAMP(0);

	DebuggerLock();
	ret = DebuggerHaltOtherCores(CPUDEBUGGERSYNC);

	DEBUGGER_TRAP_TIMESTAMP(1);

#if INTERRUPT_MASKED_DEBUG
	if (serialmode & SERIALMODE_OUTPUT) {
		ml_spin_debug_reset(current_thread());
	}
#endif
	if (ret != KERN_SUCCESS) {
		CPUDEBUGGERRET = ret;
		DebuggerUnlock();
		return;
	}

	/* Update the global panic/debugger nested entry level */
	kernel_debugger_entry_count = CPUDEBUGGERCOUNT;

	/*
	 * TODO: Should we do anything special for nested panics here? i.e. if we've trapped more than twice
	 * should we call into the debugger if it's configured and then reboot if the panic log has been written?
	 */

	if (CPUDEBUGGEROP == DBOP_NONE) {
		/* If there was no debugger context setup, we trapped due to a software breakpoint */
		debugger_current_op = DBOP_BREAKPOINT;
	} else {
		/* Not safe to return from a nested panic/debugger call */
		if (debugger_current_op == DBOP_PANIC ||
		    debugger_current_op == DBOP_DEBUGGER) {
			debugger_safe_to_return = FALSE;
		}

		debugger_current_op = CPUDEBUGGEROP;

		/* Only overwrite the panic message if there is none already - save the data from the first call */
		if (debugger_panic_str == NULL) {
			debugger_panic_str = CPUPANICSTR;
			debugger_panic_args = CPUPANICARGS;
			debugger_panic_data = CPUPANICDATAPTR;
			debugger_message = CPUDEBUGGERMSG;
			debugger_panic_caller = CPUPANICCALLER;
		}

		debugger_panic_options = CPUPANICOPTS;
	}

	/*
	 * Clear the op from the processor debugger context so we can handle
	 * breakpoints in the debugger
	 */
	CPUDEBUGGEROP = DBOP_NONE;

	DEBUGGER_TRAP_TIMESTAMP(2);

	kdp_callouts(KDP_EVENT_ENTER);
	not_in_kdp = 0;

	DEBUGGER_TRAP_TIMESTAMP(3);

	if (debugger_current_op == DBOP_BREAKPOINT) {
		kdp_raise_exception(exception, code, subcode, state);
	} else if (debugger_current_op == DBOP_STACKSHOT) {
		CPUDEBUGGERRET = do_stackshot();
#if PGO
	} else if (debugger_current_op == DBOP_RESET_PGO_COUNTERS) {
		CPUDEBUGGERRET = do_pgo_reset_counters();
#endif
	} else {
		debugger_collect_diagnostics(exception, code, subcode, state);
	}

	DEBUGGER_TRAP_TIMESTAMP(4);

	not_in_kdp = initial_not_in_kdp;
	kdp_callouts(KDP_EVENT_EXIT);

	DEBUGGER_TRAP_TIMESTAMP(5);

	if (debugger_current_op != DBOP_BREAKPOINT) {
		debugger_panic_str = NULL;
		debugger_panic_args = NULL;
		debugger_panic_data = NULL;
		debugger_panic_options = 0;
		debugger_message = NULL;
	}

	/* Restore the previous debugger state */
	debugger_current_op = db_prev_op;

	DEBUGGER_TRAP_TIMESTAMP(6);

	DebuggerResumeOtherCores();

	DEBUGGER_TRAP_TIMESTAMP(7);

	DebuggerUnlock();

	DEBUGGER_TRAP_TIMESTAMP(8);

	return;
}

__attribute__((noinline, not_tail_called))
void
log(__unused int level, char *fmt, ...)
{
	void *caller = __builtin_return_address(0);
	va_list listp;
	va_list listp2;


#ifdef lint
	level++;
#endif /* lint */
#ifdef  MACH_BSD
	va_start(listp, fmt);
	va_copy(listp2, listp);

	disable_preemption();
	_doprnt(fmt, &listp, cons_putc_locked, 0);
	enable_preemption();

	va_end(listp);

	os_log_with_args(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, fmt, listp2, caller);
	va_end(listp2);
#endif
}

/*
 * Per <rdar://problem/24974766>, skip appending log messages to
 * the new logging infrastructure in contexts where safety is
 * uncertain. These contexts include:
 *   - When we're in the debugger
 *   - We're in a panic
 *   - Interrupts are disabled
 *   - Or Pre-emption is disabled
 * In all the above cases, it is potentially unsafe to log messages.
 */

boolean_t
oslog_is_safe(void)
{
	return kernel_debugger_entry_count == 0 &&
	       not_in_kdp == 1 &&
	       get_preemption_level() == 0 &&
	       ml_get_interrupts_enabled() == TRUE;
}

boolean_t
debug_mode_active(void)
{
	return (0 != kernel_debugger_entry_count != 0) || (0 == not_in_kdp);
}

void
debug_putc(char c)
{
	if ((debug_buf_size != 0) &&
	    ((debug_buf_ptr - debug_buf_base) < (int)debug_buf_size)) {
		*debug_buf_ptr = c;
		debug_buf_ptr++;
	}
}

#if defined (__x86_64__)
struct pasc {
	unsigned a: 7;
	unsigned b: 7;
	unsigned c: 7;
	unsigned d: 7;
	unsigned e: 7;
	unsigned f: 7;
	unsigned g: 7;
	unsigned h: 7;
}  __attribute__((packed));

typedef struct pasc pasc_t;

/*
 * In-place packing routines -- inefficient, but they're called at most once.
 * Assumes "buflen" is a multiple of 8. Used for compressing paniclogs on x86.
 */
int
packA(char *inbuf, uint32_t length, uint32_t buflen)
{
	unsigned int i, j = 0;
	pasc_t pack;

	length = MIN(((length + 7) & ~7), buflen);

	for (i = 0; i < length; i += 8) {
		pack.a = inbuf[i];
		pack.b = inbuf[i + 1];
		pack.c = inbuf[i + 2];
		pack.d = inbuf[i + 3];
		pack.e = inbuf[i + 4];
		pack.f = inbuf[i + 5];
		pack.g = inbuf[i + 6];
		pack.h = inbuf[i + 7];
		bcopy((char *) &pack, inbuf + j, 7);
		j += 7;
	}
	return j;
}

void
unpackA(char *inbuf, uint32_t length)
{
	pasc_t packs;
	unsigned i = 0;
	length = (length * 8) / 7;

	while (i < length) {
		packs = *(pasc_t *)&inbuf[i];
		bcopy(&inbuf[i + 7], &inbuf[i + 8], MAX(0, (int) (length - i - 8)));
		inbuf[i++] = packs.a;
		inbuf[i++] = packs.b;
		inbuf[i++] = packs.c;
		inbuf[i++] = packs.d;
		inbuf[i++] = packs.e;
		inbuf[i++] = packs.f;
		inbuf[i++] = packs.g;
		inbuf[i++] = packs.h;
	}
}
#endif /* defined (__x86_64__) */

extern void *proc_name_address(void *p);

static void
panic_display_process_name(void)
{
	/* because of scoping issues len(p_comm) from proc_t is hard coded here */
	char proc_name[17] = "Unknown";
	task_t ctask = 0;
	void *cbsd_info = 0;

	if (ml_nofault_copy((vm_offset_t)&current_thread()->task, (vm_offset_t) &ctask, sizeof(task_t)) == sizeof(task_t)) {
		if (ml_nofault_copy((vm_offset_t)&ctask->bsd_info, (vm_offset_t)&cbsd_info, sizeof(cbsd_info)) == sizeof(cbsd_info)) {
			if (cbsd_info && (ml_nofault_copy((vm_offset_t) proc_name_address(cbsd_info), (vm_offset_t) &proc_name, sizeof(proc_name)) > 0)) {
				proc_name[sizeof(proc_name) - 1] = '\0';
			}
		}
	}
	paniclog_append_noflush("\nBSD process name corresponding to current thread: %s\n", proc_name);
}

unsigned
panic_active(void)
{
	return debugger_panic_str != (char *) 0;
}

void
populate_model_name(char *model_string)
{
	strlcpy(model_name, model_string, sizeof(model_name));
}

void
panic_display_model_name(void)
{
	char tmp_model_name[sizeof(model_name)];

	if (ml_nofault_copy((vm_offset_t) &model_name, (vm_offset_t) &tmp_model_name, sizeof(model_name)) != sizeof(model_name)) {
		return;
	}

	tmp_model_name[sizeof(tmp_model_name) - 1] = '\0';

	if (tmp_model_name[0] != 0) {
		paniclog_append_noflush("System model name: %s\n", tmp_model_name);
	}
}

void
panic_display_kernel_uuid(void)
{
	char tmp_kernel_uuid[sizeof(kernel_uuid_string)];

	if (ml_nofault_copy((vm_offset_t) &kernel_uuid_string, (vm_offset_t) &tmp_kernel_uuid, sizeof(kernel_uuid_string)) != sizeof(kernel_uuid_string)) {
		return;
	}

	if (tmp_kernel_uuid[0] != '\0') {
		paniclog_append_noflush("Kernel UUID: %s\n", tmp_kernel_uuid);
	}
}

void
panic_display_kernel_aslr(void)
{
	if (vm_kernel_slide) {
		paniclog_append_noflush("Kernel slide:     0x%016lx\n", (unsigned long) vm_kernel_slide);
		paniclog_append_noflush("Kernel text base: %p\n", (void *) vm_kernel_stext);
	}
}

void
panic_display_hibb(void)
{
#if defined(__i386__) || defined (__x86_64__)
	paniclog_append_noflush("__HIB  text base: %p\n", (void *) vm_hib_base);
#endif
}

static void
panic_display_uptime(void)
{
	uint64_t        uptime;
	absolutetime_to_nanoseconds(mach_absolute_time(), &uptime);

	paniclog_append_noflush("\nSystem uptime in nanoseconds: %llu\n", uptime);
}

static void
panic_display_disk_errors(void)
{
	if (panic_disk_error_description[0]) {
		panic_disk_error_description[sizeof(panic_disk_error_description) - 1] = '\0';
		paniclog_append_noflush("Root disk errors: \"%s\"\n", panic_disk_error_description);
	}
};

extern const char version[];
extern char osversion[];

static volatile uint32_t config_displayed = 0;

__private_extern__ void
panic_display_system_configuration(boolean_t launchd_exit)
{
	if (!launchd_exit) {
		panic_display_process_name();
	}
	if (OSCompareAndSwap(0, 1, &config_displayed)) {
		char buf[256];
		if (!launchd_exit && strlcpy(buf, PE_boot_args(), sizeof(buf))) {
			paniclog_append_noflush("Boot args: %s\n", buf);
		}
		paniclog_append_noflush("\nMac OS version:\n%s\n",
		    (osversion[0] != 0) ? osversion : "Not yet set");
		paniclog_append_noflush("\nKernel version:\n%s\n", version);
		panic_display_kernel_uuid();
		if (!launchd_exit) {
			panic_display_kernel_aslr();
			panic_display_hibb();
			panic_display_pal_info();
		}
		panic_display_model_name();
		panic_display_disk_errors();
		if (!launchd_exit) {
			panic_display_uptime();
			panic_display_zprint();
#if CONFIG_ZLEAKS
			panic_display_ztrace();
#endif /* CONFIG_ZLEAKS */
			kext_dump_panic_lists(&paniclog_append_noflush);
		}
	}
}

extern unsigned int     stack_total;
extern unsigned long long stack_allocs;

#if defined (__x86_64__)
extern unsigned int     inuse_ptepages_count;
extern long long alloc_ptepages_count;
#endif

extern boolean_t panic_include_zprint;
extern mach_memory_info_t *panic_kext_memory_info;
extern vm_size_t panic_kext_memory_size;

__private_extern__ void
panic_display_zprint()
{
	if (panic_include_zprint == TRUE) {
		unsigned int    i;
		struct zone     zone_copy;

		paniclog_append_noflush("%-20s %10s %10s\n", "Zone Name", "Cur Size", "Free Size");
		for (i = 0; i < num_zones; i++) {
			if (ml_nofault_copy((vm_offset_t)(&zone_array[i]), (vm_offset_t)&zone_copy, sizeof(struct zone)) == sizeof(struct zone)) {
				if (zone_copy.cur_size > (1024 * 1024)) {
					paniclog_append_noflush("%-20s %10lu %10lu\n", zone_copy.zone_name, (uintptr_t)zone_copy.cur_size, (uintptr_t)(zone_copy.countfree * zone_copy.elem_size));
				}
			}
		}

		paniclog_append_noflush("%-20s %10lu\n", "Kernel Stacks", (uintptr_t)(kernel_stack_size * stack_total));

#if defined (__x86_64__)
		paniclog_append_noflush("%-20s %10lu\n", "PageTables", (uintptr_t)(PAGE_SIZE * inuse_ptepages_count));
#endif

		paniclog_append_noflush("%-20s %10lu\n", "Kalloc.Large", (uintptr_t)kalloc_large_total);
		if (panic_kext_memory_info) {
			mach_memory_info_t *mem_info = panic_kext_memory_info;
			paniclog_append_noflush("\n%-5s %10s\n", "Kmod", "Size");
			for (i = 0; i < (panic_kext_memory_size / sizeof(mach_zone_info_t)); i++) {
				if (((mem_info[i].flags & VM_KERN_SITE_TYPE) == VM_KERN_SITE_KMOD) && (mem_info[i].size > (1024 * 1024))) {
					paniclog_append_noflush("%-5lld %10lld\n", mem_info[i].site, mem_info[i].size);
				}
			}
		}
	}
}

#if CONFIG_ECC_LOGGING
__private_extern__ void
panic_display_ecc_errors()
{
	uint32_t count = ecc_log_get_correction_count();

	if (count > 0) {
		paniclog_append_noflush("ECC Corrections:%u\n", count);
	}
}
#endif /* CONFIG_ECC_LOGGING */

#if CONFIG_ZLEAKS
extern boolean_t        panic_include_ztrace;
extern struct ztrace* top_ztrace;
void panic_print_symbol_name(vm_address_t search);

/*
 * Prints the backtrace most suspected of being a leaker, if we paniced in the zone allocator.
 * top_ztrace and panic_include_ztrace comes from osfmk/kern/zalloc.c
 */
__private_extern__ void
panic_display_ztrace(void)
{
	if (panic_include_ztrace == TRUE) {
		unsigned int i = 0;
		boolean_t keepsyms = FALSE;

		PE_parse_boot_argn("keepsyms", &keepsyms, sizeof(keepsyms));
		struct ztrace top_ztrace_copy;

		/* Make sure not to trip another panic if there's something wrong with memory */
		if (ml_nofault_copy((vm_offset_t)top_ztrace, (vm_offset_t)&top_ztrace_copy, sizeof(struct ztrace)) == sizeof(struct ztrace)) {
			paniclog_append_noflush("\nBacktrace suspected of leaking: (outstanding bytes: %lu)\n", (uintptr_t)top_ztrace_copy.zt_size);
			/* Print the backtrace addresses */
			for (i = 0; (i < top_ztrace_copy.zt_depth && i < MAX_ZTRACE_DEPTH); i++) {
				paniclog_append_noflush("%p ", top_ztrace_copy.zt_stack[i]);
				if (keepsyms) {
					panic_print_symbol_name((vm_address_t)top_ztrace_copy.zt_stack[i]);
				}
				paniclog_append_noflush("\n");
			}
			/* Print any kexts in that backtrace, along with their link addresses so we can properly blame them */
			kmod_panic_dump((vm_offset_t *)&top_ztrace_copy.zt_stack[0], top_ztrace_copy.zt_depth);
		} else {
			paniclog_append_noflush("\nCan't access top_ztrace...\n");
		}
		paniclog_append_noflush("\n");
	}
}
#endif /* CONFIG_ZLEAKS */

#if !CONFIG_TELEMETRY
int
telemetry_gather(user_addr_t buffer __unused, uint32_t *length __unused, boolean_t mark __unused)
{
	return KERN_NOT_SUPPORTED;
}
#endif

#include <machine/machine_cpu.h>

uint32_t kern_feature_overrides = 0;

boolean_t
kern_feature_override(uint32_t fmask)
{
	if (kern_feature_overrides == 0) {
		uint32_t fdisables = 0;
		/* Expected to be first invoked early, in a single-threaded
		 * environment
		 */
		if (PE_parse_boot_argn("validation_disables", &fdisables, sizeof(fdisables))) {
			fdisables |= KF_INITIALIZED;
			kern_feature_overrides = fdisables;
		} else {
			kern_feature_overrides |= KF_INITIALIZED;
		}
	}
	return (kern_feature_overrides & fmask) == fmask;
}
