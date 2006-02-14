/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#ifndef __AT386_MP_EVENTS__
#define	__AT386_MP_EVENTS__

/* Interrupt types */

#ifndef ASSEMBLER

#include <sys/cdefs.h>

typedef enum {
	MP_TLB_FLUSH = 0,
	MP_KDP,
	MP_KDB,
	MP_AST,
	MP_RENDEZVOUS,
	MP_IDLE,
	MP_UNIDLE,
	MP_LAST
} mp_event_t;

#define MP_EVENT_NAME_DECL()	\
const char *mp_event_name[] = {	\
	"MP_TLB_FLUSH",		\
	"MP_KDP",		\
	"MP_KDB",		\
	"MP_AST",		\
	"MP_RENDEZVOUS",	\
	"MP_IDLE",		\
	"MP_UNIDLE",		\
	"MP_LAST"		\
}
	
typedef enum { SYNC, ASYNC } mp_sync_t;

__BEGIN_DECLS

extern void	i386_signal_cpu(int cpu, mp_event_t event, mp_sync_t mode);
extern void	i386_signal_cpus(mp_event_t event, mp_sync_t mode);
extern int	i386_active_cpus(void);

__END_DECLS

#endif

#endif
