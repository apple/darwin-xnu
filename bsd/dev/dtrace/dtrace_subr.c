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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * #pragma ident	"@(#)dtrace_subr.c	1.8	07/06/05 SMI"
 */

#include <stdarg.h>
#include <string.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/proc_internal.h>
#include <kern/debug.h>
#include <kern/sched_prim.h>
#include <kern/task.h>

#if CONFIG_CSR
#include <sys/codesign.h>
#include <sys/csr.h>
#endif

/*
 * APPLE NOTE: Solaris proc_t is the struct.
 * Darwin's proc_t is a pointer to it.
 */
#define proc_t struct proc /* Steer clear of the Darwin typedef for proc_t */


/* Copied from an arch specific dtrace_subr.c. */
int (*dtrace_fasttrap_probe_ptr)(struct regs *);

/*
 * Following DTrace hooks are taken from Solaris' dtrace_subr.c
 * They're assigned in dtrace.c but Darwin never calls them.
 */
void (*dtrace_cpu_init)(processorid_t);
int (*dtrace_modload)(struct kmod_info *, uint32_t);
int (*dtrace_modunload)(struct kmod_info *);
void (*dtrace_helpers_cleanup)(proc_t *);
void (*dtrace_helpers_fork)(proc_t *, proc_t *);
void (*dtrace_cpustart_init)(void);
void (*dtrace_cpustart_fini)(void);

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
	if (dtrace_fasttrap_fork_ptr) {
		(*dtrace_fasttrap_fork_ptr)(p, cp);
	}
}


/*
 * DTrace wait for process execution
 *
 * This feature is using a list of entries, each entry containing a pointer
 * on a process description. The description is provided by a client, and it
 * contains the command we want to wait for along with a reserved space for
 * the caught process id.
 *
 * Once an awaited process has been spawned, it will be suspended before
 * notifying the client. Once the client has been back to userland, it's its
 * duty to resume the task.
 */

lck_mtx_t dtrace_procwaitfor_lock;

typedef struct dtrace_proc_awaited_entry {
	struct dtrace_procdesc			*pdesc;
	LIST_ENTRY(dtrace_proc_awaited_entry)	entries;
} dtrace_proc_awaited_entry_t;

LIST_HEAD(listhead, dtrace_proc_awaited_entry) dtrace_proc_awaited_head
	= LIST_HEAD_INITIALIZER(dtrace_proc_awaited_head);

void (*dtrace_proc_waitfor_exec_ptr)(proc_t*) = NULL;

static void
dtrace_proc_exec_notification(proc_t *p) {
	dtrace_proc_awaited_entry_t *entry, *tmp;

	ASSERT(p);
	ASSERT(p->p_pid != -1);
	ASSERT(current_task() != p->task);

	lck_mtx_lock(&dtrace_procwaitfor_lock);

	/*
	 * For each entry, if it has not been matched with a process yet we
	 * try to match it with the newly created process. If they match, the
	 * entry is initialized with the process id and the process task is
	 * suspended. Finally, we wake up the client's waiting thread.
	 */
	LIST_FOREACH_SAFE(entry, &dtrace_proc_awaited_head, entries, tmp) {
		if ((entry->pdesc->p_pid == -1)
		    && !strncmp(entry->pdesc->p_comm, &p->p_comm[0], sizeof(p->p_comm)))
		{
			entry->pdesc->p_pid = p->p_pid;
			task_pidsuspend(p->task);
			wakeup(entry);
		}
	}

	lck_mtx_unlock(&dtrace_procwaitfor_lock);
}

int
dtrace_proc_waitfor(dtrace_procdesc_t* pdesc) {
	dtrace_proc_awaited_entry_t entry;
	int res;

	ASSERT(pdesc);
	ASSERT(pdesc->p_comm);

	lck_mtx_lock(&dtrace_procwaitfor_lock);

	/* Initialize and insert the entry, then install the hook. */
	pdesc->p_pid = -1;
	entry.pdesc = pdesc;
	LIST_INSERT_HEAD(&dtrace_proc_awaited_head, &entry, entries);
	dtrace_proc_waitfor_exec_ptr = &dtrace_proc_exec_notification;

	/* Sleep until the process has been executed */
	res = msleep(&entry, &dtrace_procwaitfor_lock, PCATCH, "dtrace_proc_waitfor", NULL);

	/* Remove the entry and the hook if it is not needed anymore. */
	LIST_REMOVE(&entry, entries);
	if (LIST_EMPTY(&dtrace_proc_awaited_head))
		dtrace_proc_waitfor_exec_ptr = NULL;

	lck_mtx_unlock(&dtrace_procwaitfor_lock);

	return res;
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

/*
 * Check if DTrace has been restricted by the current security policy.
 */
boolean_t
dtrace_is_restricted(void)
{
#if CONFIG_CSR
	if (csr_check(CSR_ALLOW_UNRESTRICTED_DTRACE) != 0)
		return TRUE;
#endif

	return FALSE;
}

/*
 * Check if the process can be attached.
 */
boolean_t
dtrace_can_attach_to_proc(proc_t *proc)
{
#pragma unused(proc)
	ASSERT(proc != NULL);

#if CONFIG_CSR
	if ((cs_entitlement_flags(proc) & CS_GET_TASK_ALLOW) == 0)
		return FALSE;
#endif

	return TRUE;
}

