/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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

#include <i386/mp.h>
#include <i386/cpu_data.h>
#include <i386/machine_cpu.h>
#include <i386/machine_routines.h>
#include <i386/misc_protos.h>
#include <vm/vm_kern.h>
#include <console/video_console.h>
#include <console/serial_protos.h>
#include <kern/kalloc.h>

static struct {
	char	*buffer;
	int	len;
	int	used;
	char	*write_ptr;
	char	*read_ptr;
	decl_simple_lock_data(,read_lock);
	decl_simple_lock_data(,write_lock);
} console_ring;

hw_lock_data_t cnputc_lock;
static volatile long console_output = 0;

typedef struct console_buf {
	char	*buf_base;
	char	*buf_end;
	char	*buf_ptr;
#define CPU_BUFFER_LEN	(256 - 3*(sizeof(char*)))
	char	buf[CPU_BUFFER_LEN];
} console_buf_t;

extern int serial_getc(void);
extern void serial_putc(int);

static void _serial_putc(int, int, int);

int vcgetc(int, int, boolean_t, boolean_t);

console_ops_t cons_ops[] = {
    {_serial_putc, _serial_getc},
    {vcputc, vcgetc}
};

uint32_t nconsops = (sizeof cons_ops / sizeof cons_ops[0]);

uint32_t cons_ops_index = VC_CONS_OPS;

/* This macro polls for pending TLB flushes while spinning on a lock
 */
#define SIMPLE_LOCK_NO_INTRS(l)				\
MACRO_BEGIN						\
	boolean_t istate = ml_get_interrupts_enabled();	\
	while (!simple_lock_try((l)))			\
	{						\
		if (!istate)				\
			handle_pending_TLB_flushes();	\
		cpu_pause();				\
	}						\
MACRO_END

void
console_init(void)
{
	int	ret;

	console_ring.len = PAGE_SIZE;
	ret = kmem_alloc(kernel_map, (vm_offset_t *) &console_ring.buffer,
			 console_ring.len);
	if (ret != KERN_SUCCESS)
		panic("console_ring_init() "
		      "failed to allocate ring buffer, error %d\n", ret);
	console_ring.used = 0;
	console_ring.read_ptr = console_ring.buffer;
	console_ring.write_ptr = console_ring.buffer;
	simple_lock_init(&console_ring.read_lock, 0);
	simple_lock_init(&console_ring.write_lock, 0);
	hw_lock_init(&cnputc_lock);
}

void *
console_cpu_alloc(__unused boolean_t boot_processor)
{
	int		ret;
	console_buf_t	*cbp;

	ret = kmem_alloc(kernel_map, (vm_offset_t *) &cbp,
				sizeof(console_buf_t));
	if (ret != KERN_SUCCESS) {
		printf("console_cpu_alloc() "
		      "failed to allocate cpu buffer, error=%d\n", ret);
		return NULL;
	}

	cbp->buf_base = (char *) &cbp->buf;
	cbp->buf_ptr = cbp->buf_base;
	cbp->buf_end = cbp->buf_base + CPU_BUFFER_LEN;

	return (void *) cbp;
}

void
console_cpu_free(void *buf)
{
	if (buf != NULL)
		kfree((void *) buf, sizeof(console_buf_t));
}

static inline int
console_ring_space(void)
{
	return console_ring.len - console_ring.used;
}

static boolean_t
console_ring_put(char ch)
{
	if (console_ring.used < console_ring.len) {
		console_ring.used++;;
		*console_ring.write_ptr++ = ch;
		if (console_ring.write_ptr - console_ring.buffer
		    == console_ring.len)
			console_ring.write_ptr = console_ring.buffer;
		return TRUE;
	} else {
		return FALSE;
	}
}

static int
console_ring_get(void)
{
	char	ch = 0;

	if (console_ring.used > 0) {
		console_ring.used--;
		ch = *console_ring.read_ptr++;
		if (console_ring.read_ptr - console_ring.buffer
		    == console_ring.len)
			console_ring.read_ptr = console_ring.buffer;
	}
	return (int) ch;	
}

static inline void
cpu_buffer_put(console_buf_t *cbp, char ch)
{
	if (ch != '\0' && cbp->buf_ptr < cbp->buf_end)
		*(cbp->buf_ptr++) = ch;
}

static inline void
_cnputc(char c)
{
	/* The console device output routines are assumed to be
	 * non-reentrant.
	 */
	mp_disable_preemption();
	if (!hw_lock_to(&cnputc_lock, LockTimeOut*10)) {
	/* If we timed out on the lock, and we're in the debugger,
	 * break the lock.
	 */
		if (debug_mode) {
			/* Since hw_lock_to takes a pre-emption count...*/
			mp_enable_preemption(); 
			hw_lock_init(&cnputc_lock);
			hw_lock_lock(&cnputc_lock);
		}
		else
			panic("Lock acquire timeout in _cnputc()");
	}
	cons_ops[cons_ops_index].putc(0, 0, c);
	if (c == '\n')
            cons_ops[cons_ops_index].putc(0, 0, '\r');
	hw_lock_unlock(&cnputc_lock);
	mp_enable_preemption();
}

void
cnputcusr(char c)
{
	/* Spin (with pre-emption enabled) waiting for console_ring_try_empty()
	 * to complete output. There is a small window here where we could
	 * end up with a stale value of console_output, but it's unlikely,
	 * and _cnputc(), which outputs to the console device, is internally
	 * synchronized. There's something of a conflict between the
	 * character-at-a-time (with pre-emption enabled) unbuffered
	 * output model here, and the buffered output from cnputc(),
	 * whose consumers include printf() ( which outputs a sequence
	 * with pre-emption disabled, and should be safe to call with
	 * interrupts off); we don't want to disable pre-emption indefinitely
	 * here, and spinlocks and mutexes are inappropriate.
	 */
	while (console_output != 0);

	_cnputc(c);
}

static void
console_ring_try_empty(void)
{
	boolean_t state = ml_get_interrupts_enabled();
	/*
	 * Try to get the read lock on the ring buffer to empty it.
	 * If this fails someone else is already emptying...
	 */
	if (!simple_lock_try(&console_ring.read_lock))
		return;
	/* Indicate that we're in the process of writing a block of data
	 * to the console.
	 */
	atomic_incl(&console_output, 1);
	for (;;) {
		char	ch;
		if (!state)
			handle_pending_TLB_flushes();
   	 	SIMPLE_LOCK_NO_INTRS(&console_ring.write_lock);
		ch = console_ring_get();
    		simple_unlock(&console_ring.write_lock);
		if (ch == 0)
			break;
		_cnputc(ch);
	}
	atomic_decl(&console_output, 1);
	simple_unlock(&console_ring.read_lock);
}

void
cnputc(char c)
{
	console_buf_t	*cbp;
#if MACH_KDB
	/* Bypass locking/buffering if in debugger */
	if (kdb_cpu == cpu_number()) {
		_cnputc(c);
		return;
	}
#endif /* MACH_KDB */	
	mp_disable_preemption();
	cbp = (console_buf_t *) current_cpu_datap()->cpu_console_buf;
	if (cbp == NULL) {
		mp_enable_preemption();
		/* Put directly if console ring is not initialized */
		_cnputc(c);
		return;
	}

	/* add to stack buf */
	if (c != '\n') {
		/* XXX - cpu_buffer_put() can fail silently if the buffer
		 * is exhausted, as can happen if there's a long sequence
		 * of data with no newlines. We should, instead, attempt
		 * a flush.
		 */
		cpu_buffer_put(cbp, c);
	} else {
		boolean_t	state;
		char		*cp;

		/* Here at end of printf -- time to try to output */
	
		/* copy this buffer into the shared ring buffer */
		state = ml_set_interrupts_enabled(FALSE);
		SIMPLE_LOCK_NO_INTRS(&console_ring.write_lock);

		/*
		 * Is there enough space in the shared ring buffer?
		 * Try to empty if not.
		 * Note, we want the entire local buffer to fit to
		 * avoid another cpu interjecting.
		 */
		while (cbp->buf_ptr-cbp->buf_base + 1 > console_ring_space()) {
			simple_unlock(&console_ring.write_lock);
			console_ring_try_empty();
			SIMPLE_LOCK_NO_INTRS(&console_ring.write_lock);
		}
		for (cp = cbp->buf_base; cp < cbp->buf_ptr; cp++)
			console_ring_put(*cp);
		console_ring_put('\n');
		cbp->buf_ptr = cbp->buf_base;
		simple_unlock(&console_ring.write_lock);
		ml_set_interrupts_enabled(state);
	}
	console_ring_try_empty();
	mp_enable_preemption();
}

int _serial_getc(__unused int a, __unused int b, boolean_t wait, __unused boolean_t raw)
{
    int c;
    do {
        c = serial_getc();
    } while (wait && c < 0);

    return c;
}

static void _serial_putc(__unused int a, __unused int b, int c)
{
    serial_putc(c);
}


int
cngetc(void)
{
	return cons_ops[cons_ops_index].getc(0, 0,
					     TRUE, FALSE);
}

int
cnmaygetc(void)
{
	return cons_ops[cons_ops_index].getc(0, 0,
					     FALSE, FALSE);
}

int
vcgetc(__unused int l, 
       __unused int u, 
       __unused boolean_t wait, 
       __unused boolean_t raw)
{
	char c;

	if( 0 == (*PE_poll_input)( 0, &c))
		return( c);
	else
		return( 0);
}
