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
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.11.1  1997/03/27  18:47:01  barbou
 * 	Merge smp_shared merges into mainline.
 * 	[1996/09/19  13:55:17  addis]
 * 	Make tr_indent NCPU safe.
 * 	[95/10/09            rwd]
 * 	Added TR_INIT() macro.
 * 	Change from NMK16.1 [93/09/22            paire]
 * 	[94/02/04            paire]
 * 	[97/02/25            barbou]
 *
 * Revision 1.1.6.1  1995/02/23  16:34:23  alanl
 * 	Taken from DIPC2_SHARED.  Change to !FREE Copyright.
 * 	[95/01/05            rwd]
 * 
 * Revision 1.1.4.4  1994/08/18  01:07:26  alanl
 * 	+ Allow tracing strictly based on MACH_TR;
 * 	don't also require MACH_ASSERT (alanl).
 * 	+ ANSI-fication:  cast tr arguments (alanl).
 * 	+ Added tr_indent and macros to use it (sjs).
 * 	[1994/08/18  01:06:09  alanl]
 * 
 * Revision 1.1.4.3  1994/08/08  17:59:35  rwd
 * 	Include mach_tr.h
 * 	[94/08/08            rwd]
 * 
 * Revision 1.1.4.2  1994/08/05  19:36:08  mmp
 * 	Added prototype for db_show_tr.
 * 
 * 	Conditionalize on MACH_TR
 * 	[94/07/20            rwd]
 * 
 * Revision 1.1.4.1  1994/08/04  01:43:04  mmp
 * 	DIPC:  moved from norma/ to ddb/.  Updated includes.
 * 	[1994/08/03  13:37:46  mmp]
 * 
 * Revision 1.1.9.1  1994/03/07  16:55:24  paire
 * 	Added ANSI prototypes.
 * 	[94/02/15            paire]
 * 
 * 	Added TR_INIT() macro.
 * 	Change from NMK16.1 [93/09/22            paire]
 * 	[94/02/04            paire]
 * 
 * Revision 1.1.2.2  1993/06/02  23:57:10  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:22:08  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:34:09  robert
 * 	Initial revision
 * 
 * $EndLog$
 */

/*
 *	File:		ddb/tr.h
 *	Author:		Alan Langerman, Jeffrey Heller
 *	Date:		1992
 *
 *	Internal trace routines.  Like old-style XPRs but
 *	less formatting.
 */

#include <mach_assert.h>
#include <mach_tr.h>

#include <kern/cpu_number.h>

/*
 *	Originally, we only wanted tracing when
 *	MACH_TR and MACH_ASSERT were turned on
 *	together.  Now, there's no reason why
 *	MACH_TR and MACH_ASSERT can't be completely
 *	orthogonal.
 */
#define	TRACE_BUFFER	(MACH_TR)

/*
 *	Log events in a circular trace buffer for future debugging.
 *	Events are unsigned integers.  Each event has a descriptive
 *	message.
 *
 *	TR_DECL must be used at the beginning of a routine using
 *	one of the tr calls.  The macro should be passed the name
 *	of the function surrounded by quotation marks, e.g.,
 *		TR_DECL("netipc_recv_intr");
 *	and should be terminated with a semi-colon.  The TR_DECL
 *	must be the *last* declaration in the variable declaration
 *	list, or syntax errors will be introduced when TRACE_BUFFER
 *	is turned off.
 */
#ifndef	_DDB_TR_H_
#define	_DDB_TR_H_

#if	TRACE_BUFFER

#include <machine/db_machdep.h>

#define	__ui__			(unsigned int)
#define	TR_INIT()		tr_init()
#define TR_SHOW(a,b,c)		show_tr((a),(b),(c))
#define	TR_DECL(funcname)	char	*__ntr_func_name__ = funcname
#define	tr1(msg)							\
	tr(__ntr_func_name__, __FILE__, __LINE__, (msg),		\
		0,0,0,0)
#define	tr2(msg,tag1)							\
	tr(__ntr_func_name__, __FILE__, __LINE__, (msg),		\
		__ui__(tag1),0,0,0)
#define	tr3(msg,tag1,tag2)						\
	tr(__ntr_func_name__, __FILE__, __LINE__, (msg),		\
		__ui__(tag1),__ui__(tag2),0,0)
#define	tr4(msg,tag1,tag2,tag3)						\
	tr(__ntr_func_name__, __FILE__, __LINE__, (msg),		\
		__ui__(tag1),__ui__(tag2),__ui__(tag3),0)
#define	tr5(msg,tag1,tag2,tag3,tag4)					\
	tr(__ntr_func_name__, __FILE__, __LINE__, (msg),		\
		__ui__(tag1),__ui__(tag2),__ui__(tag3),__ui__(tag4))

/*
 *	Adjust tr log indentation based on function
 *	call graph.
 */
#if	NCPUS == 1
extern int tr_indent;
#define	tr_start()	tr_indent++
#define tr_stop()	tr_indent--
#else	/* NCPUS == 1 */
extern int tr_indent[NCPUS];
#define	tr_start()	tr_indent[cpu_number()]++
#define tr_stop()	(--tr_indent[cpu_number()]<0?tr_indent[cpu_number()]=0:0);
#endif	/* NCPUS == 1 */

extern void	tr_init(void);
extern void	tr(
			char		*funcname,
			char		*file,
			unsigned int	lineno,
			char		*fmt,
			unsigned int	tag1,
		   	unsigned int	tag2,
			unsigned int	tag3,
			unsigned int	tag4);

extern void db_show_tr(
			db_expr_t	addr,
			boolean_t	have_addr,
			db_expr_t	count,
			char *		modif);

#else	/* TRACE_BUFFER */

#define	TR_INIT()
#define TR_SHOW(a,b,c)
#define	TR_DECL(funcname)
#define tr1(msg)
#define tr2(msg, tag1)
#define tr3(msg, tag1, tag2)
#define tr4(msg, tag1, tag2, tag3)
#define tr5(msg, tag1, tag2, tag3, tag4)
#define	tr_start()
#define tr_stop()

#endif	/* TRACE_BUFFER */

#endif	/* _DDB_TR_H_ */
