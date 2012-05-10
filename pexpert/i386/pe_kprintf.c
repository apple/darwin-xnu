/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <i386/mp.h>
#include <machine/pal_routines.h>
#include <i386/proc_reg.h>

/* Globals */
void (*PE_kputc)(char c);

#if DEBUG
/* DEBUG kernel starts with true serial, but
 * may later disable or switch to video
 * console */
unsigned int disable_serial_output = FALSE;
#else
unsigned int disable_serial_output = TRUE;
#endif

decl_simple_lock_data(static, kprintf_lock)

void PE_init_kprintf(boolean_t vm_initialized)
{
	unsigned int	boot_arg;

	if (PE_state.initialized == FALSE)
		panic("Platform Expert not initialized");

	if (!vm_initialized) {
		unsigned int new_disable_serial_output = TRUE;

		simple_lock_init(&kprintf_lock, 0);

		if (PE_parse_boot_argn("debug", &boot_arg, sizeof (boot_arg)))
			if (boot_arg & DB_KPRT)
				new_disable_serial_output = FALSE;

		/* If we are newly enabling serial, make sure we only
		 * call pal_serial_init() if our previous state was
		 * not enabled */
		if (!new_disable_serial_output && (!disable_serial_output || pal_serial_init()))
			PE_kputc = pal_serial_putc;
		else
			PE_kputc = cnputc;

		disable_serial_output = new_disable_serial_output;
	}
}

#if CONFIG_NO_KPRINTF_STRINGS
/* Prevent CPP from breaking the definition below */
#undef kprintf
#endif

#ifdef MP_DEBUG
static void _kprintf(const char *format, ...)
{
	va_list   listp;

        va_start(listp, format);
        _doprnt(format, &listp, PE_kputc, 16);
        va_end(listp);
}
#define MP_DEBUG_KPRINTF(x...)	_kprintf(x)
#else  /* MP_DEBUG */
#define MP_DEBUG_KPRINTF(x...)
#endif /* MP_DEBUG */

static int cpu_last_locked = 0;
void kprintf(const char *fmt, ...)
{
	va_list   listp;
	boolean_t state;

	if (!disable_serial_output) {
		boolean_t early = FALSE;
		if (rdmsr64(MSR_IA32_GS_BASE) == 0) {
			early = TRUE;
		}
		/* If PE_kputc has not yet been initialized, don't
		 * take any locks, just dump to serial */
		if (!PE_kputc || early) {
			va_start(listp, fmt);
			_doprnt(fmt, &listp, pal_serial_putc, 16);
			va_end(listp);
			return;
		}

		/*
		 * Spin to get kprintf lock but re-enable interrupts while
		 * failing.
		 * This allows interrupts to be handled while waiting but
		 * interrupts are disabled once we have the lock.
		 */
		state = ml_set_interrupts_enabled(FALSE);

		pal_preemption_assert();

		while (!simple_lock_try(&kprintf_lock)) {
			ml_set_interrupts_enabled(state);
			ml_set_interrupts_enabled(FALSE);
		}

		if (cpu_number() != cpu_last_locked) {
			MP_DEBUG_KPRINTF("[cpu%d...]\n", cpu_number());
			cpu_last_locked = cpu_number();
		}

		va_start(listp, fmt);
		_doprnt(fmt, &listp, PE_kputc, 16);
		va_end(listp);

		simple_unlock(&kprintf_lock);
		ml_set_interrupts_enabled(state);
	}
}

extern void kprintf_break_lock(void);
void
kprintf_break_lock(void)
{
	simple_lock_init(&kprintf_lock, 0);
}
