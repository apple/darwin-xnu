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
 *    PPC platform expert debugging output initialization.
 */
#include <stdarg.h>
#include <machine/machine_routines.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/ppc/powermac.h>
#include <pexpert/device_tree.h>
#include <kern/debug.h>
#include <kern/simple_lock.h>
#include <vm/pmap.h>

/* extern references */
extern void scc_putc(int unit, int line, int c);
extern long strtol(const char *, char **, int);

/* Globals */
void (*PE_kputc)(char c);

unsigned int disable_serial_output = TRUE;

vm_offset_t	scc = 0;

struct slock kprintf_lock;

void PE_init_kprintf(__unused boolean_t vm_initialized)
{
	unsigned int	boot_arg;
	int32_t			serial_baud = -1;
	unsigned int	size;
	DTEntry         options;
	char            *str, baud[7];

	if (PE_state.initialized == FALSE)
		panic("Platform Expert not initialized");

	if (PE_parse_boot_arg("debug", &boot_arg))
		if(boot_arg & DB_KPRT) disable_serial_output = FALSE; 

	if (DTLookupEntry(NULL, "/options", &options) == kSuccess) {
	  if (DTGetProperty(options, "input-device", (void **)&str, &size) == kSuccess) {
		if ((size > 5) && !strncmp("scca:", str, 5)) {
		  size -= 5;
		  str += 5;
		  if (size <= 6) {
			strncpy(baud, str, size);
			baud[size] = '\0';
			gPESerialBaud = strtol(baud, NULL, 0);
		  }
		}
	  }
	  if (DTGetProperty(options, "output-device", (void **)&str, &size) == kSuccess) {
		if ((size > 5) && !strncmp("scca:", str, 5)) {
		  size -= 5;
		  str += 5;
		  if (size <= 6) {
			strncpy(baud, str, size);
			baud[size] = '\0';
			gPESerialBaud = strtol(baud, NULL, 0);
		  }
		}
	  }	  
	}

	/* Check the boot-args for new serial baud. */
	if (PE_parse_boot_arg("serialbaud", &serial_baud))
		if (serial_baud != -1) gPESerialBaud = serial_baud; 

	if( (scc = PE_find_scc())) {				/* See if we can find the serial port */
		scc = io_map_spec(scc, 0x1000, VM_WIMG_IO);	/* Map it in */
		initialize_serial((void *)scc, gPESerialBaud); /* Start up the serial driver */
		PE_kputc = serial_putc;

		simple_lock_init(&kprintf_lock, 0);
	} else
			PE_kputc = cnputc;

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
	scc_putc(0, 1, c);
	if (c == '\n')
		scc_putc(0, 1, '\r');
}

void kprintf(const char *fmt, ...)
{
        va_list   listp;
	boolean_t state;
	
	state = ml_set_interrupts_enabled(FALSE);
	simple_lock(&kprintf_lock);
	
	if (!disable_serial_output) {	
        	va_start(listp, fmt);
        	_doprnt(fmt, &listp, PE_kputc, 16);
        	va_end(listp);
	}
	
	simple_unlock(&kprintf_lock);
	ml_set_interrupts_enabled(state);
}

