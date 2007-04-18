/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */



void serial_keyboard_init(void);
void serial_keyboard_start(void);
void serial_keyboard_poll(void);

extern uint32_t serialmode;
extern uint32_t cons_ops_index;
extern uint32_t nconsops;

extern int _serial_getc(int unit, int line, boolean_t wait, boolean_t raw);

extern boolean_t console_is_serial(void);
extern int switch_to_serial_console(void);
extern int switch_to_video_console(void);
extern void	 switch_to_old_console(int old_console);

struct console_ops {
	int	(*putc)(int, int, int);
	int	(*getc)(int, int, boolean_t, boolean_t);
} console_ops;
typedef struct console_ops console_ops_t;


#define SERIAL_CONS_OPS 0
#define VC_CONS_OPS 1
