/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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

#include <i386/mp.h>
#include <i386/machine_routines.h>

void
cnputc(char c)
{
	boolean_t	nolock = mp_kdp_trap || !ml_get_interrupts_enabled();

	/*
	 * Note: this lock prevents other cpus interferring with the
	 * output is this one character to the console (screen). It
	 * does not prevent multiple printfs being interleaved - that's
	 * the responsibility of the caller.  Without this lock,
	 * an unreadable black-on-black or white-on-white display may result.
	 * We avoid taking this lock, however, if we're in the debugger or
	 * at interrupt level.
	 */
	if (!nolock)
		simple_lock(&mp_putc_lock);
	vcputc(0, 0, c);
	if (c == '\n')
		vcputc(0, 0,'\r');
	if (!nolock)
		simple_unlock(&mp_putc_lock);
}
