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

#ifndef	_KERN_DEBUG_H_
#define _KERN_DEBUG_H_

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

extern unsigned int	systemLogDiags;

#ifdef MACH_KERNEL_PRIVATE

extern unsigned int	halt_in_debugger;

extern unsigned int     switch_debugger;

extern unsigned int     current_debugger;
#define NO_CUR_DB       0x0
#define KDP_CUR_DB      0x1
#define KDB_CUR_DB      0x2

extern unsigned int     active_debugger;
extern unsigned int 	debug_mode; 
extern unsigned int	disableDebugOuput;

extern unsigned int     panicDebugging;
extern unsigned int	logPanicDataToScreen;

extern int db_run_mode;

/* modes the system may be running in */

#define	STEP_NONE	0
#define	STEP_ONCE	1
#define	STEP_RETURN	2
#define	STEP_CALLT	3
#define	STEP_CONTINUE	4
#define STEP_INVISIBLE	5
#define	STEP_COUNT	6
#define STEP_TRACE	7	/* Show all calls to functions and returns */

extern char	*panicstr;

extern unsigned int	nestedpanic;

extern char *debug_buf;
extern char *debug_buf_ptr;
extern unsigned int debug_buf_size;

extern void	debug_log_init(void);
extern void	debug_putc(char);

#endif /* MACH_KERNEL_PRIVATE */

#define DB_HALT		0x1
#define DB_PRT		0x2
#define DB_NMI		0x4
#define DB_KPRT		0x8
#define DB_KDB		0x10
#define DB_SLOG		0x20
#define DB_ARP          0x40
#define DB_KDP_BP_DIS   0x80
#define DB_LOG_PI_SCRN	0x100
#define DB_KDP_GETC_ENA 0x200

#define DB_KERN_DUMP_ON_PANIC       0x400 /* Trigger core dump on panic*/
#define DB_KERN_DUMP_ON_NMI         0x800 /* Trigger core dump on NMI */
#define DB_DBG_POST_CORE            0x1000 /*Wait in debugger after NMI core */
#define DB_PANICLOG_DUMP            0x2000 /* Send paniclog on panic,not core*/
#endif	/* __APPLE_API_PRIVATE */

#endif	/* _KERN_DEBUG_H_ */
