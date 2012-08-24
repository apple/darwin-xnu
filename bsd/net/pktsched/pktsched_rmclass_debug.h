/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

/* $NetBSD: altq_rmclass_debug.h,v 1.7 2006/10/12 19:59:08 peter Exp $	*/
/* $KAME: altq_rmclass_debug.h,v 1.3 2002/11/29 04:36:24 kjc Exp $	*/

/*
 * Copyright (c) Sun Microsystems, Inc. 1998 All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the SMCC Technology
 *      Development Group at Sun Microsystems, Inc.
 *
 * 4. The name of the Sun Microsystems, Inc nor may not be used to endorse or
 *      promote products derived from this software without specific prior
 *      written permission.
 *
 * SUN MICROSYSTEMS DOES NOT CLAIM MERCHANTABILITY OF THIS SOFTWARE OR THE
 * SUITABILITY OF THIS SOFTWARE FOR ANY PARTICULAR PURPOSE.  The software is
 * provided "as is" without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this software.
 */

#ifndef _NET_PKTSCHED_PKTSCHED_RMCLASS_DEBUG_H_
#define	_NET_PKTSCHED_PKTSCHED_RMCLASS_DEBUG_H_

/* #pragma ident	"@(#)rm_class_debug.h	1.7	98/05/04 SMI" */

/*
 * Cbq debugging macros
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BSD_KERNEL_PRIVATE

#ifdef	CBQ_TRACE
#ifndef NCBQTRACE
#define	NCBQTRACE (16 * 1024)
#endif

/*
 * To view the trace output, using adb, type:
 *	adb -k /dev/ksyms /dev/mem <cr>, then type
 *	cbqtrace_count/D to get the count, then type
 *	cbqtrace_buffer,0tcount/Dp4C" "Xn
 *	This will dump the trace buffer from 0 to count.
 */
/*
 * in ALTQ, "call cbqtrace_dump(N)" from DDB to display 20 events
 * from Nth event in the circular buffer.
 */

struct cbqtrace {
	int count;
	int function;		/* address of function */
	int trace_action;	/* descriptive 4 characters */
	int object;		/* object operated on */
};

extern struct cbqtrace cbqtrace_buffer[];
extern struct cbqtrace *cbqtrace_ptr;
extern int cbqtrace_count;

#define	CBQTRACEINIT() {						\
	if (cbqtrace_ptr == NULL)					\
		cbqtrace_ptr = cbqtrace_buffer;				\
	else {								\
		cbqtrace_ptr = cbqtrace_buffer;				\
		bzero((void *)cbqtrace_ptr, sizeof (cbqtrace_buffer));	\
		cbqtrace_count = 0;					\
	}								\
}

#define	CBQTRACE(func, act, obj) {					\
	int *_p = &cbqtrace_ptr->count;					\
	*_p++ = ++cbqtrace_count;					\
	*_p++ = (int)(func);						\
	*_p++ = (int)(act);						\
	*_p++ = (int)(obj);						\
	if ((struct cbqtrace *)(void *)_p >= &cbqtrace_buffer[NCBQTRACE]) \
		cbqtrace_ptr = cbqtrace_buffer;				\
	else								\
		cbqtrace_ptr = (struct cbqtrace *)(void *)_p;		\
	}
#else

/* If no tracing, define no-ops */
#define	CBQTRACEINIT()
#define	CBQTRACE(a, b, c)

#endif	/* !CBQ_TRACE */

#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
}
#endif

#endif	/* _NET_PKTSCHED_PKTSCHED_RMCLASS_DEBUG_H_ */
