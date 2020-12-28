/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
 */
/*
 * file: pe_kprintf.c
 *    arm platform expert debugging output initialization.
 */
#include <stdarg.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <kern/debug.h>
#include <kern/simple_lock.h>
#include <os/log_private.h>
#include <libkern/section_keywords.h>

/* Globals */
void            (*PE_kputc)(char c) = 0;

SECURITY_READ_ONLY_LATE(unsigned int)    disable_serial_output = TRUE;

decl_simple_lock_data(static, kprintf_lock);

static void serial_putc_crlf(char c);

void
PE_init_kprintf(boolean_t vm_initialized)
{
	unsigned int    boot_arg;

	if (PE_state.initialized == FALSE) {
		panic("Platform Expert not initialized");
	}

	if (!vm_initialized) {
		simple_lock_init(&kprintf_lock, 0);

		if (PE_parse_boot_argn("debug", &boot_arg, sizeof(boot_arg))) {
			if (boot_arg & DB_KPRT) {
				disable_serial_output = FALSE;
			}
		}

		if (serial_init()) {
			PE_kputc = serial_putc_crlf;
		} else {
			PE_kputc = cnputc;
		}
	}
}

#ifdef MP_DEBUG
static void
_kprintf(const char *format, ...)
{
	va_list         listp;

	va_start(listp, format);
	_doprnt_log(format, &listp, PE_kputc, 16);
	va_end(listp);
}
#define MP_DEBUG_KPRINTF(x...)  _kprintf(x)
#else                           /* MP_DEBUG */
#define MP_DEBUG_KPRINTF(x...)
#endif                          /* MP_DEBUG */

#if CONFIG_NO_KPRINTF_STRINGS
/* Prevent CPP from breaking the definition below */
#undef kprintf
#endif

static int      cpu_last_locked = 0;

__attribute__((noinline, not_tail_called))
void
kprintf(const char *fmt, ...)
{
	va_list         listp;
	va_list         listp2;
	boolean_t       state;
	void           *caller = __builtin_return_address(0);

	if (!disable_serial_output) {
		/*
		 * Spin to get kprintf lock but re-enable interrupts while failing.
		 * This allows interrupts to be handled while waiting but
		 * interrupts are disabled once we have the lock.
		 */
		state = ml_set_interrupts_enabled(FALSE);
		while (!simple_lock_try(&kprintf_lock, LCK_GRP_NULL)) {
			ml_set_interrupts_enabled(state);
			ml_set_interrupts_enabled(FALSE);
		}

		if (cpu_number() != cpu_last_locked) {
			MP_DEBUG_KPRINTF("[cpu%d...]\n", cpu_number());
			cpu_last_locked = cpu_number();
		}

		va_start(listp, fmt);
		va_copy(listp2, listp);
		_doprnt_log(fmt, &listp, PE_kputc, 16);
		va_end(listp);

		simple_unlock(&kprintf_lock);

#if INTERRUPT_MASKED_DEBUG
		/*
		 * kprintf holds interrupts disabled for far too long
		 * and would trip the spin-debugger.  If we are about to reenable
		 * interrupts then clear the timer and avoid panicking on the delay.
		 * Otherwise, let the code that printed with interrupt disabled
		 * take the panic when it reenables interrupts.
		 * Hopefully one day this is fixed so that this workaround is unnecessary.
		 */
		if (state == TRUE) {
			ml_spin_debug_clear_self();
		}
#endif
		ml_set_interrupts_enabled(state);

		// If interrupts are enabled
		if (ml_get_interrupts_enabled()) {
			os_log_with_args(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, fmt, listp2, caller);
		}
		va_end(listp2);
	} else {
		// If interrupts are enabled
		if (ml_get_interrupts_enabled()) {
			va_start(listp, fmt);
			os_log_with_args(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, fmt, listp, caller);
			va_end(listp);
		}
	}
}

static void
serial_putc_crlf(char c)
{
	if (c == '\n') {
		uart_putc('\r');
	}
	uart_putc(c);
}

void
serial_putc(char c)
{
	uart_putc(c);
}

int
serial_getc(void)
{
	return uart_getc();
}
