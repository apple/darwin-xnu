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
 * @OSF_COPYRIGHT@
 */
/*
 *	File:		ddb/tr.c
 *	Authors:	Alan Langerman, Jeffrey Heller
 *	Date:		1992
 *
 *	Internal trace routines.  Like old-style XPRs but
 *	less formatting.
 */

#include <ddb/tr.h>

#if	TRACE_BUFFER
#include <string.h>
#include <ddb/db_command.h>
#include <mach_kdb.h>
#include <kern/lock.h>
#include <kern/spl.h>

extern void fc_get(int *);

/*
 *	Primitive event tracing facility for kernel debugging.  Yes,
 *	this has some resemblance to XPRs.  However, it is primarily
 *	intended for post-mortem analysis through ddb.
 */

#define	TRACE_MAX	(4 * 1024)
#define	TRACE_WINDOW	40

typedef struct trace_event {
	char		*funcname;
	char		*file;
	char		*fmt;
#if	NCPUS > 1
	char		cpu_number;
#endif	/* NCPUS > 1 */
	unsigned int	lineno;
	unsigned int	tag1;
	unsigned int	tag2;
	unsigned int	tag3;
	unsigned int	tag4;
	int		indent;
	int		timestamp[2]; /* largest needed by any clock */
} trace_event;

trace_event	trace_buffer[TRACE_MAX];
unsigned long	trace_index;
#if	NCPUS == 1
int 		tr_indent = 0;
#else	/* NCPUS == 1 */
int 		tr_indent[NCPUS];
int		tr_limit = -1;
#endif	/* NCPUS == 1 */

decl_simple_lock_data(,trace_lock)

void
tr_init(void)
{
#if	NCPUS > 1
	int i;

	for(i=0;i<NCPUS;i++)
	    tr_indent[i]=0;
#endif	/* NCPUS > 1 */

	simple_lock_init(&trace_lock, 0);
}

void
tr(
	char		*funcname,
	char		*file,
	unsigned int	lineno,
	char		*fmt,
	unsigned int	tag1,
	unsigned int	tag2,
	unsigned int	tag3,
	unsigned int	tag4)
{
	int	s;
	register unsigned long ti, tn;
#if	NCPUS > 1
	char cpu;
#endif	/* NCPUS > 1 */

#if	PARAGON860
	/*
	 * The following loop replaces the spl_and_lock sequence that
	 * would normally be here, as they are too heavy weight.  The
	 * cmpsw (compare-and-swap) call returns -1 if unsuccessful.
	 */
	do {
		ti = trace_index;
		tn = ti + 1;
		if (tn >= TRACE_MAX - 1)
			tn = 0;
	} while (cmpsw(ti, tn, &trace_index) == -1);
	fc_get(trace_buffer[ti].timestamp);
#else	/* PARAGON860 */
	/*
	 * Until someone does a cmpsw for other platforms, do it
	 * the slow way
	 */
	s = splimp();
	simple_lock(&trace_lock);

	ti = trace_index++;
	if (trace_index >= TRACE_MAX - 1)
		trace_index = 0;

	simple_unlock(&trace_lock);
	splx(s);

	fc_get(trace_buffer[ti].timestamp);
/*	get_uniq_timestamp(trace_buffer[ti].timestamp);*/
#endif	/* PARAGON860 */

	trace_buffer[ti].funcname = funcname;
	trace_buffer[ti].file = file;
	trace_buffer[ti].lineno = lineno;
	trace_buffer[ti].fmt = fmt;
	trace_buffer[ti].tag1 = tag1;
	trace_buffer[ti].tag2 = tag2;
	trace_buffer[ti].tag3 = tag3;
	trace_buffer[ti].tag4 = tag4;
#if	NCPUS == 1
	trace_buffer[ti].indent = tr_indent;
#else	/* NCPUS == 1 */
	mp_disable_preemption();
	cpu = cpu_number();
	trace_buffer[ti].indent = tr_indent[cpu];
	trace_buffer[ti].cpu_number = cpu;
	mp_enable_preemption();
#endif	/* NCPUS == 1 */
}

#if	MACH_KDB
#include <ddb/db_output.h>

/*
 * Forward.
 */
void	show_tr(
		unsigned long	index,
		unsigned long	range,
		unsigned long	show_extra);

int	matches(
		char	*pattern,
		char	*target);

void	parse_tr(
		unsigned long	index,
		unsigned long	range);

/*
 *	The blank array must be a bit bigger than
 *	MAX_BLANKS to leave room for a terminating NULL.
 */
#define	MAX_BLANKS	16
char			blanks[MAX_BLANKS+4];

void
show_tr(
	unsigned long	index,
	unsigned long	range,
	unsigned long	show_extra)
{
	char		*filename, *cp;
#if	PARAGON860
	trace_event	*last_trace;
#endif	/* PARAGON860 */
	unsigned int	level;
	int		old_history;
	int		i;

	if (index == -1) {
		index = trace_index - (TRACE_WINDOW-4);
		range = TRACE_WINDOW;
	} else if (index == 0) {
		index = trace_index - (TRACE_WINDOW-4);
		range = TRACE_WINDOW;
		show_extra = 0;
	}
	if (index + range > TRACE_MAX)
		range = TRACE_MAX - index;
#if	PARAGON860
	last_trace = &trace_buffer[index-1];
#endif	/* PARAGON860 */
	level = trace_buffer[index-1].indent;
	/*
	 * Set up the indentation buffer
	 */
	memset(blanks, ' ', trace_buffer[index].indent);
	blanks[trace_buffer[index].indent] = '\0';
	for (i = index; i < index + range; ++i) {
#if	NCPUS > 1
		if ((tr_limit != -1) &&
		    (trace_buffer[i].cpu_number != tr_limit))
		    continue;
#endif	/* NCPUS > 1 */
		if (trace_buffer[i].file == (char *) 0 ||
		    trace_buffer[i].funcname == (char *) 0 ||
		    trace_buffer[i].lineno == 0 ||
		    trace_buffer[i].fmt == 0) {
			db_printf("[%04x%s]\n", i,
				  i >= trace_index ? "*" : "");
			continue;
		}

		old_history = (i >= trace_index);

		/*
		 * Adjust the blank count if necessary
		 */
		if (level != trace_buffer[i].indent) {
			level = trace_buffer[i].indent;
			if (level >= MAX_BLANKS)
				level = MAX_BLANKS;
			memset(blanks, ' ', level);
			blanks[level] = '\0';
		} 

		for (cp = trace_buffer[i].file; *cp; ++cp)
			if (*cp == '/')
				filename = cp + 1;
#if	NCPUS > 1
		db_printf("{%02d}",trace_buffer[i].cpu_number);
#endif	/* NCPUS > 1 */
		db_printf("[%04x%s] %s%-16s", i, old_history ? "*" : "",
			  blanks, trace_buffer[i].funcname);

		if (show_extra) {
			if (show_extra > 0) {
				db_printf(" (%x/%8x)", 
					  trace_buffer[i].timestamp[0],
					  trace_buffer[i].timestamp[1]);
#if	PARAGON860
				/*
				 *	For Paragon only, we compute and
				 *	print out deltas on the timestamps
				 *	accumulated in the tr buffer.  One
				 *	interesting case:  it is meaningless
				 *	to compute this delta for the last
				 *	current entry in the log.
				 */
				if (old_history &&
				    ((last_trace - trace_buffer)
				     < trace_index))
					db_printf("(N/A)");
				else
					db_printf("(%d)", 
						  timer_subtime(
						     trace_buffer[i].timestamp,
						     last_trace->timestamp));
#endif	/*PARAGON860*/
				db_printf(" ");
			}
			if (show_extra > 1) {
				db_printf("(%s:%05d):\n\t", 
					  filename, trace_buffer[i].lineno);
			}
		} else
			db_printf(":  ");
		db_printf(trace_buffer[i].fmt, trace_buffer[i].tag1,
			  trace_buffer[i].tag2, trace_buffer[i].tag3,
			  trace_buffer[i].tag4);
		db_printf("\n");
#if	PARAGON860
		last_trace = &trace_buffer[i];
#endif	/* PARAGON860 */
	}
}


int
matches(
	char	*pattern,
	char	*target)
{
	char	*cp, *cp1, *cp2;

	for (cp = target; *cp; ++cp) {
		for (cp2 = pattern, cp1 = cp; *cp2 && *cp1; ++cp2, ++cp1)
			if (*cp2 != *cp1)
				break;
		if (!*cp2)
			return 1;
	}
	return 0;
}


char	parse_tr_buffer[100] = "KMSG";

void
parse_tr(
	unsigned long	index,
	unsigned long	range)
{
	int		i;
	char		*filename, *cp;
	char		*string = parse_tr_buffer;

	if (index == 0) {
		index = trace_index - (TRACE_WINDOW-4);
		range = TRACE_WINDOW;
	}
	if (index + range > TRACE_MAX)
		range = TRACE_MAX - index;
	for (i = index; i < index + range; ++i) {
#if	NCPUS > 1
		if ((tr_limit != -1) &&
		    (trace_buffer[i].cpu_number != tr_limit))
		    continue;
#endif	/* NCPUS > 1 */
		if (trace_buffer[i].file == (char *) 0 ||
		    trace_buffer[i].funcname == (char *) 0 ||
		    trace_buffer[i].lineno == 0 ||
		    trace_buffer[i].fmt == 0) {
			db_printf("[%04x%s]\n", i,
				  i >= trace_index ? "*" : "");
			continue;
		}
		if (!matches(string, trace_buffer[i].fmt))
			continue;
		for (cp = trace_buffer[i].file; *cp; ++cp)
			if (*cp == '/')
				filename = cp + 1;
#if	NCPUS > 1
		db_printf("{%02d}",trace_buffer[i].cpu_number);
#endif	/* NCPUS > 1 */
		db_printf("[%04x%s] %s", i, i >= trace_index ? "*" : "",
		       trace_buffer[i].funcname);
		db_printf(":  ");
		db_printf(trace_buffer[i].fmt, trace_buffer[i].tag1,
			  trace_buffer[i].tag2, trace_buffer[i].tag3,
			  trace_buffer[i].tag4);
		db_printf("\n");
	}
}


void
db_show_tr(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif)
{
	int		flag, level;

	flag = 0, level = 0;
	if (db_option(modif, 'l')) {
		flag = 1;
		level = -1;
	}
	if (db_option(modif, 'a')) {
		flag = 2;
		level = -1;
	}

	TR_SHOW(level, 0, flag);
}

#endif	/* MACH_KDB */

#endif	/* TRACE_BUFFER */
