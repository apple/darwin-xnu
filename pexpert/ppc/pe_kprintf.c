/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

vm_offset_t	scc = 0;

struct slock kprintf_lock;

void PE_init_kprintf(boolean_t vm_initialized)
{
	unsigned int	boot_arg;
	int32_t			cnt, size, serial_baud = -1;
	DTEntry         options;
	char            *str, baud[7];

	if (PE_state.initialized == FALSE)
		panic("Platform Expert not initialized");

	if (PE_parse_boot_arg("debug", &boot_arg))
		if(boot_arg & DB_KPRT) disableSerialOuput = FALSE; 

	if (DTLookupEntry(0, "/options", &options) == kSuccess) {
	  if (DTGetProperty(options, "input-device", &str, &size) == kSuccess) {
		if ((size > 5) && !strncmp("scca:", str, 5)) {
		  size -= 5;
		  str += 5;
		  if (size <= 6) {
			strncpy(baud, str, size);
			baud[size] = '\0';
			gPESerialBaud = strtol(baud, 0, 0);
		  }
		}
	  }
	  if (DTGetProperty(options, "output-device", &str, &size) == kSuccess) {
		if ((size > 5) && !strncmp("scca:", str, 5)) {
		  size -= 5;
		  str += 5;
		  if (size <= 6) {
			strncpy(baud, str, size);
			baud[size] = '\0';
			gPESerialBaud = strtol(baud, 0, 0);
		  }
		}
	  }	  
	}

	/* Check the boot-args for new serial baud. */
	if (PE_parse_boot_arg("serialbaud", &serial_baud))
		if (serial_baud != -1) gPESerialBaud = serial_baud; 

	if( (scc = PE_find_scc())) {				/* See if we can find the serial port */
		scc = io_map_spec(scc, 0x1000);				 /* Map it in */
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

