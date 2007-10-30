/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * #pragma ident	"@(#)dtrace_subr.c	1.7	06/04/24 SMI"
 */

#include <stdarg.h>
#include <string.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <kern/debug.h>

#if defined(__APPLE__)
#define proc_t struct proc
#endif

/* Copied from an arch specific dtrace_subr.c. */
int (*dtrace_fasttrap_probe_ptr)(struct regs *);

/*
 * Following DTrace hooks are taken from Solaris' dtrace_subr.c
 * They're assigned in dtrace.c but Darwin never calls them.
 */
void (*dtrace_cpu_init)(processorid_t);
void (*dtrace_modload)(struct modctl *);
void (*dtrace_modunload)(struct modctl *);
#if defined(__APPLE__)
void (*dtrace_helpers_cleanup)(proc_t *);
#endif
void (*dtrace_helpers_fork)(proc_t *, proc_t *);
void (*dtrace_cpustart_init)(void);
void (*dtrace_cpustart_fini)(void);

void (*dtrace_kreloc_init)(void);
void (*dtrace_kreloc_fini)(void);

void (*dtrace_debugger_init)(void);
void (*dtrace_debugger_fini)(void);

dtrace_vtime_state_t dtrace_vtime_active = 0;
dtrace_cacheid_t dtrace_predcache_id = DTRACE_CACHEIDNONE + 1;

void (*dtrace_fasttrap_fork_ptr)(proc_t *, proc_t *);
void (*dtrace_fasttrap_exec_ptr)(proc_t *);
void (*dtrace_fasttrap_exit_ptr)(proc_t *);

/*
 * This function is called by cfork() in the event that it appears that
 * there may be dtrace tracepoints active in the parent process's address
 * space. This first confirms the existence of dtrace tracepoints in the
 * parent process and calls into the fasttrap module to remove the
 * corresponding tracepoints from the child. By knowing that there are
 * existing tracepoints, and ensuring they can't be removed, we can rely
 * on the fasttrap module remaining loaded.
 */
void
dtrace_fasttrap_fork(proc_t *p, proc_t *cp)
{
#if !defined(__APPLE__)
	ASSERT(p->p_proc_flag & P_PR_LOCK);
	ASSERT(p->p_dtrace_count > 0);
#endif /* __APPLE__ */

	if (dtrace_fasttrap_fork_ptr) {
		(*dtrace_fasttrap_fork_ptr)(p, cp);
	}
}

typedef struct dtrace_invop_hdlr {
	int (*dtih_func)(uintptr_t, uintptr_t *, uintptr_t);
	struct dtrace_invop_hdlr *dtih_next;
} dtrace_invop_hdlr_t;

dtrace_invop_hdlr_t *dtrace_invop_hdlr;

int
dtrace_invop(uintptr_t, uintptr_t *, uintptr_t);

int
dtrace_invop(uintptr_t addr, uintptr_t *stack, uintptr_t eax)
{
	dtrace_invop_hdlr_t *hdlr;
	int rval;

	for (hdlr = dtrace_invop_hdlr; hdlr != NULL; hdlr = hdlr->dtih_next) {
		if ((rval = hdlr->dtih_func(addr, stack, eax)) != 0)
			return (rval);
	}

	return (0);
}

void
dtrace_invop_add(int (*func)(uintptr_t, uintptr_t *, uintptr_t))
{
	dtrace_invop_hdlr_t *hdlr;

	hdlr = kmem_alloc(sizeof (dtrace_invop_hdlr_t), KM_SLEEP);
	hdlr->dtih_func = func;
	hdlr->dtih_next = dtrace_invop_hdlr;
	dtrace_invop_hdlr = hdlr;
}

void
dtrace_invop_remove(int (*func)(uintptr_t, uintptr_t *, uintptr_t))
{
	dtrace_invop_hdlr_t *hdlr = dtrace_invop_hdlr, *prev = NULL;

	for (;;) {
		if (hdlr == NULL)
			panic("attempt to remove non-existent invop handler");

		if (hdlr->dtih_func == func)
			break;

		prev = hdlr;
		hdlr = hdlr->dtih_next;
	}

	if (prev == NULL) {
		ASSERT(dtrace_invop_hdlr == hdlr);
		dtrace_invop_hdlr = hdlr->dtih_next;
	} else {
		ASSERT(dtrace_invop_hdlr != hdlr);
		prev->dtih_next = hdlr->dtih_next;
	}

	kmem_free(hdlr, sizeof (dtrace_invop_hdlr_t));
}

