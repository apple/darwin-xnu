/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
 * file: pe_kprintf.c
 *    i386 platform expert debugging output initialization.
 */
#include <stdarg.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <kern/debug.h>
#include <kern/simple_lock.h>
#include <i386/machine_cpu.h>
#include <i386/mp.h>
#include <machine/pal_routines.h>
#include <i386/proc_reg.h>
#include <os/log_private.h>
#include <libkern/section_keywords.h>
#include <kern/processor.h>
#include <kern/clock.h>
#include <mach/clock_types.h>

extern uint64_t LockTimeOut;

/* Globals */
typedef void (*PE_kputc_t)(char);

#if XNU_TARGET_OS_OSX
PE_kputc_t PE_kputc;
#else
SECURITY_READ_ONLY_LATE(PE_kputc_t) PE_kputc;
#endif

#if DEVELOPMENT || DEBUG
/* DEBUG kernel starts with true serial, but
 * may later disable or switch to video
 * console */
SECURITY_READ_ONLY_LATE(unsigned int) disable_serial_output = FALSE;
#else
SECURITY_READ_ONLY_LATE(unsigned int) disable_serial_output = TRUE;
#endif

static SIMPLE_LOCK_DECLARE(kprintf_lock, 0);

__startup_func
static void
PE_init_kprintf(void)
{
	if (PE_state.initialized == FALSE) {
		panic("Platform Expert not initialized");
	}

	unsigned int new_disable_serial_output = TRUE;

	if (debug_boot_arg & DB_KPRT) {
		new_disable_serial_output = FALSE;
	}

	/* If we are newly enabling serial, make sure we only
	 * call pal_serial_init() if our previous state was
	 * not enabled */
	if (!new_disable_serial_output && (!disable_serial_output || pal_serial_init())) {
		PE_kputc = pal_serial_putc;
	} else {
		PE_kputc = cnputc_unbuffered;
	}

	disable_serial_output = new_disable_serial_output;
}
STARTUP(KPRINTF, STARTUP_RANK_FIRST, PE_init_kprintf);

#if CONFIG_NO_KPRINTF_STRINGS
/* Prevent CPP from breaking the definition below */
#undef kprintf
#endif

#ifdef MP_DEBUG
static void
_kprintf(const char *format, ...)
{
	va_list   listp;

	va_start(listp, format);
	_doprnt(format, &listp, PE_kputc, 16);
	va_end(listp);
}
#define MP_DEBUG_KPRINTF(x...)  _kprintf(x)
#else  /* MP_DEBUG */
#define MP_DEBUG_KPRINTF(x...)
#endif /* MP_DEBUG */

static int cpu_last_locked = 0;

#define KPRINTF_LOCKWAIT_PATIENT (LockTimeOut)
#define KPRINTF_LOCKWAIT_IMPATIENT (LockTimeOut >> 4)

__attribute__((noinline, not_tail_called))
void
kprintf(const char *fmt, ...)
{
	va_list    listp;
	va_list    listp2;
	boolean_t  state;
	boolean_t  in_panic_context = FALSE;
	unsigned int kprintf_lock_grabbed;
	void      *caller = __builtin_return_address(0);

	if (!disable_serial_output) {
		boolean_t early = FALSE;
		uint64_t gsbase = rdmsr64(MSR_IA32_GS_BASE);
		if (gsbase == EARLY_GSBASE_MAGIC || gsbase == 0) {
			early = TRUE;
		}
		/* If PE_kputc has not yet been initialized, don't
		 * take any locks, just dump to serial */
		if (!PE_kputc || early) {
			va_start(listp, fmt);
			va_copy(listp2, listp);

			_doprnt_log(fmt, &listp, pal_serial_putc, 16);
			va_end(listp);

			// If interrupts are enabled
			if (ml_get_interrupts_enabled()) {
				os_log_with_args(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, fmt, listp2, caller);
			}
			va_end(listp2);
			return;
		}

		va_start(listp, fmt);
		va_copy(listp2, listp);

		state = ml_set_interrupts_enabled(FALSE);

		pal_preemption_assert();

		in_panic_context = debug_is_current_cpu_in_panic_state();

		// If current CPU is in panic context, be a little more impatient.
		kprintf_lock_grabbed = simple_lock_try_lock_mp_signal_safe_loop_duration(&kprintf_lock,
		    in_panic_context ? KPRINTF_LOCKWAIT_IMPATIENT : KPRINTF_LOCKWAIT_PATIENT,
		    LCK_GRP_NULL);

		if (cpu_number() != cpu_last_locked) {
			MP_DEBUG_KPRINTF("[cpu%d...]\n", cpu_number());
			cpu_last_locked = cpu_number();
		}

		_doprnt(fmt, &listp, PE_kputc, 16);

		if (kprintf_lock_grabbed) {
			simple_unlock(&kprintf_lock);
		}

		ml_set_interrupts_enabled(state);

		va_end(listp);

		// If interrupts are enabled
		if (ml_get_interrupts_enabled()) {
			os_log_with_args(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, fmt, listp2, caller);
		}
		va_end(listp2);
	} else {
		if (ml_get_interrupts_enabled()) {
			va_start(listp, fmt);
			os_log_with_args(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, fmt, listp, caller);
			va_end(listp);
		}
	}
}

extern void kprintf_break_lock(void);
void
kprintf_break_lock(void)
{
	simple_lock_init(&kprintf_lock, 0);
}
