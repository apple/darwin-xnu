/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * file: pe_kprintf.c
 *    i386 platform expert debugging output initialization.
 */
#include <stdarg.h>
#include <pexpert/pexpert.h>
#include <kern/debug.h>

/* extern references */
extern void cnputc(char c);

/* Globals */
void (*PE_kputc)(char c) = 0;

unsigned int disableSerialOuput = TRUE;

void PE_init_kprintf(boolean_t vm_initialized)
{
	unsigned int	boot_arg;

	if (PE_state.initialized == FALSE)
		panic("Platform Expert not initialized");

	if (!vm_initialized)
	{
	    if (PE_parse_boot_arg("debug", &boot_arg)) 
	        if (boot_arg & DB_KPRT) disableSerialOuput = FALSE;
        
        /* FIXME - route output to serial port. */
        PE_kputc = cnputc;
    }
}

void kprintf(const char *fmt, ...)
{
	va_list listp;
    
    if (!disableSerialOuput) {
        va_start(listp, fmt);
        _doprnt(fmt, &listp, PE_kputc, 16);
        va_end(listp);
    }
}
