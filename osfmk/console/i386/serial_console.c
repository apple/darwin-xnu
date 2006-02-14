/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <i386/mp.h>
#include <i386/cpu_data.h>
#include <i386/machine_cpu.h>
#include <i386/machine_routines.h>
#include <i386/misc_protos.h>
#include <vm/vm_kern.h>
#include <console/video_console.h>
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

typedef struct console_buf {
	char	*buf_base;
	char	*buf_end;
	char	*buf_ptr;
#define CPU_BUFFER_LEN	(256 - 3*(sizeof(char*)))
	char	buf[CPU_BUFFER_LEN];
} console_buf_t;

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
	if (cbp->buf_ptr < cbp->buf_end)
		*(cbp->buf_ptr++) = ch;
}

static inline void
_cnputc(char c)
{
	vcputc(0, 0, c);
	if (c == '\n')
		vcputc(0, 0,'\r');
}

void
cnputcusr(char c)
{	
	simple_lock(&console_ring.read_lock);
	_cnputc(c);
	simple_unlock(&console_ring.read_lock);
}

void
cnputc(char c)
{
	console_buf_t	*cbp;

	if (!(real_ncpus > 1)) {
		_cnputc(c);
		return;
	}

	mp_disable_preemption();
	/* add to stack buf */
	cbp = (console_buf_t *) current_cpu_datap()->cpu_console_buf;
	if (c != '\n') {
		cpu_buffer_put(cbp, c);
	} else {
		boolean_t	state;
		char		*cp;

		/* Here at end of printf -- time to try to output */
	
		/* copy this buffer into the shared ring buffer */
		state = ml_set_interrupts_enabled(FALSE);
		simple_lock(&console_ring.write_lock);
		for (cp = cbp->buf_base; cp < cbp->buf_ptr; cp++) {
			while (!console_ring_put(*cp))
				/* spin if share buffer full */
				cpu_pause();
		}
		(void) console_ring_put('\n');
		simple_unlock(&console_ring.write_lock);
		ml_set_interrupts_enabled(state);
		cbp->buf_ptr = cbp->buf_base;

		/*
		 * Try to get the read lock on the ring buffer to empty it.
		 * If this fails someone else is already emptying...
		 */
		if (simple_lock_try(&console_ring.read_lock)) {
			for (;;) {
				char	ch;

		   	 	simple_lock(&console_ring.write_lock);
				ch = console_ring_get();
		    		simple_unlock(&console_ring.write_lock);
				if (ch == 0)
					break;
				_cnputc(ch);
			}
			simple_unlock(&console_ring.read_lock);
		}
	}
	mp_enable_preemption();
}
