/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * file: pe_kprintf.c
 *    PPC platform expert debugging output initialization.
 */
#include <stdarg.h>
#include <machine/machine_routines.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/ppc/powermac.h>
#include <kern/debug.h>
#include <kern/simple_lock.h>

/* extern references */
extern void init_display_putc(unsigned char*, int, int);
extern void display_putc(char c);
extern int scc_putc(int unit, int line, int c);
extern void cnputc(char c);

/* Internal routines -- eventually put this in serial driver */
void serial_putc(char c);

/* Globals */
void (*PE_kputc)(char c) = 0;

unsigned int disableSerialOuput = TRUE;


static struct slock kprintf_lock;

void PE_init_kprintf(boolean_t vm_initialized)
{
	static vm_offset_t	scc;
	unsigned int	boot_arg;

	if (PE_state.initialized == FALSE)
		panic("Platform Expert not initialized");

	if (!vm_initialized)
	{
	    if (PE_parse_boot_arg("debug", &boot_arg)) 
	        if(boot_arg & DB_KPRT) disableSerialOuput = FALSE; 

	    if( (scc = PE_find_scc()))
            {
		initialize_serial( (void *) scc );
		PE_kputc = serial_putc;

		simple_lock_init(&kprintf_lock, 0);
            } else
		PE_kputc = cnputc;

	} else if( scc){
		initialize_serial( (void *) io_map( scc, 0x1000) );
	}

#if 0
	/*
	 * FUTURE: eventually let the boot command determine where
	 *         the debug output will be, serial, video, etc.
	 */
	switch (PE_state.debug_video.v_display) {
	    case kDebugTypeSerial:
		    PE_kputc = serial_putc;
		    break;

	    case kDebugTypeDisplay:
		    init_display_putc(  (unsigned char*)PE_state.debug_video.v_baseAddr,
							PE_state.debug_video.v_rowBytes,
							PE_state.debug_video.v_height);
		    PE_kputc = display_putc;
		    break;

	    default:
		    PE_state.debug_video.v_baseAddr = 0;
	}
#endif
}

void serial_putc(char c)
{
	(void) scc_putc(0, 1, c);
	if (c == '\n') (void) scc_putc(0, 1, '\r');

#if 0
	(void) scc_putc(0, (int)PE_state.debug_video.v_baseAddr, c);
	if (c == '\n') (void) scc_putc(0, (int)PE_state.debug_video.v_baseAddr, '\r');
#endif
}

void kprintf(const char *fmt, ...)
{
        va_list   listp;
	boolean_t state;
	
	state = ml_set_interrupts_enabled(FALSE);
	simple_lock(&kprintf_lock);
	
	if (!disableSerialOuput) {	
        	va_start(listp, fmt);
        	_doprnt(fmt, &listp, PE_kputc, 16);
        	va_end(listp);
	}
	
	simple_unlock(&kprintf_lock);
	ml_set_interrupts_enabled(state);
}

