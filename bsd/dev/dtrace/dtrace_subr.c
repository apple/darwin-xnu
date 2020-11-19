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

#include <stdarg.h>
#include <string.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/proc_internal.h>
#include <sys/vnode.h>
#include <kern/debug.h>
#include <kern/sched_prim.h>
#include <kern/task.h>

#if CONFIG_CSR
#include <sys/codesign.h>
#include <sys/csr.h>

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
extern bool csr_unsafe_kernel_text;
#endif
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

static int
dtrace_proc_get_execpath(proc_t *p, char *buffer, int *maxlen)
{
	int err = 0, vid = 0;
	vnode_t tvp = NULLVP, nvp = NULLVP;

	ASSERT(p);
	ASSERT(buffer);
	ASSERT(maxlen);

	if ((tvp = p->p_textvp) == NULLVP)
		return ESRCH;

	vid = vnode_vid(tvp);
	if ((err = vnode_getwithvid(tvp, vid)) != 0)
		return err;

	if ((err = vn_getpath_fsenter(tvp, buffer, maxlen)) != 0)
		return err;
	vnode_put(tvp);

	if ((err = vnode_lookup(buffer, 0, &nvp, vfs_context_current())) != 0)
		return err;
	if (nvp != NULLVP)
		vnode_put(nvp);

	return 0;
}


static void
dtrace_proc_exec_notification(proc_t *p) {
	dtrace_proc_awaited_entry_t *entry, *tmp;
	static char execpath[MAXPATHLEN];

	ASSERT(p);
	ASSERT(p->p_pid != -1);
	ASSERT(current_task() != p->task);

	lck_mtx_lock(&dtrace_procwaitfor_lock);

	LIST_FOREACH_SAFE(entry, &dtrace_proc_awaited_head, entries, tmp) {
		/* By default consider we're using p_comm. */
		char *pname = p->p_comm;

		/* Already matched with another process. */
		if ((entry->pdesc->p_pid != -1))
			continue;

		/* p_comm is too short, use the execpath. */
		if (entry->pdesc->p_name_length >= MAXCOMLEN) {
			/*
			 * Retrieve the executable path. After the call, length contains
			 * the length of the string + 1.
			 */
			int length = sizeof(execpath);
			if (dtrace_proc_get_execpath(p, execpath, &length) != 0)
				continue;
			/* Move the cursor to the position after the last / */
			pname = &execpath[length - 1];
			while (pname != execpath && *pname != '/')
				pname--;
			pname = (*pname == '/') ? pname + 1 : pname;
		}

		if (!strcmp(entry->pdesc->p_name, pname)) {
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
	ASSERT(pdesc->p_name);

	/*
	 * Never trust user input, compute the length of the process name and ensure the
	 * string is null terminated.
	 */
	pdesc->p_name_length = (int) strnlen(pdesc->p_name, sizeof(pdesc->p_name));
	if (pdesc->p_name_length >= (int) sizeof(pdesc->p_name))
		return -1;

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

void*
dtrace_ptrauth_strip(void *ptr, uint64_t key)
{
#pragma unused(key)
#if __has_feature(ptrauth_calls)
	/*
	 * The key argument to ptrauth_strip needs to be a compile-time
	 * constant
	 */
	switch (key) {
	case ptrauth_key_asia:
		return ptrauth_strip(ptr, ptrauth_key_asia);
	case ptrauth_key_asib:
		return ptrauth_strip(ptr, ptrauth_key_asib);
	case ptrauth_key_asda:
		return ptrauth_strip(ptr, ptrauth_key_asda);
	case ptrauth_key_asdb:
		return ptrauth_strip(ptr, ptrauth_key_asdb);
	default:
		return ptr;
	}
#else
	return ptr;
#endif // __has_feature(ptrauth_calls)
}

int
dtrace_is_valid_ptrauth_key(uint64_t key)
{
#pragma unused(key)
#if __has_feature(ptrauth_calls)
	return (key == ptrauth_key_asia) || (key == ptrauth_key_asib) ||
	    (key == ptrauth_key_asda) || (key == ptrauth_key_asdb);
#else
	return (0);
#endif /* __has_feature(ptrauth_calls) */
}

uint64_t
dtrace_physmem_read(uint64_t addr, size_t size)
{
	switch (size) {
	case 1:
		return (uint64_t)ml_phys_read_byte_64((addr64_t)addr);
	case 2:
		return (uint64_t)ml_phys_read_half_64((addr64_t)addr);
	case 4:
		return (uint64_t)ml_phys_read_64((addr64_t)addr);
	case 8:
		return (uint64_t)ml_phys_read_double_64((addr64_t)addr);
	}
	DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);

	return (0);
}

void
dtrace_physmem_write(uint64_t addr, uint64_t data, size_t size)
{
	switch (size) {
	case 1:
		ml_phys_write_byte_64((addr64_t)addr, (unsigned int)data);
		break;
	case 2:
		ml_phys_write_half_64((addr64_t)addr, (unsigned int)data);
		break;
	case 4:
		ml_phys_write_64((addr64_t)addr, (unsigned int)data);
		break;
	case 8:
		ml_phys_write_double_64((addr64_t)addr, (unsigned long long)data);
		break;
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
	}
}

static minor_t next_minor = 0;
static dtrace_state_t* dtrace_clients[DTRACE_NCLIENTS] = {NULL};


minor_t
dtrace_state_reserve(void)
{
	for (int i = 0; i < DTRACE_NCLIENTS; i++) {
		minor_t minor = os_atomic_inc_orig(&next_minor, relaxed) % DTRACE_NCLIENTS;
		if (dtrace_clients[minor] == NULL)
			return minor;
	}
	return 0;
}

dtrace_state_t*
dtrace_state_get(minor_t minor)
{
	ASSERT(minor < DTRACE_NCLIENTS);
	return dtrace_clients[minor];
}

dtrace_state_t*
dtrace_state_allocate(minor_t minor)
{
	dtrace_state_t *state = _MALLOC(sizeof(dtrace_state_t), M_TEMP, M_ZERO | M_WAITOK);
	if (dtrace_casptr(&dtrace_clients[minor], NULL, state) != NULL) {
		// We have been raced by another client for this number, abort
		_FREE(state, M_TEMP);
		return NULL;
	}
	return state;
}

void
dtrace_state_free(minor_t minor)
{
	dtrace_state_t *state = dtrace_clients[minor];
	dtrace_clients[minor] = NULL;
	_FREE(state, M_TEMP);
}



void
dtrace_restriction_policy_load(void)
{
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

boolean_t
dtrace_are_restrictions_relaxed(void)
{
#if CONFIG_CSR
	if (csr_check(CSR_ALLOW_APPLE_INTERNAL) == 0)
		return TRUE;
#endif

	return FALSE;
}

boolean_t
dtrace_fbt_probes_restricted(void)
{

#if CONFIG_CSR
	if (dtrace_is_restricted() && !dtrace_are_restrictions_relaxed())
		return TRUE;
#endif

	return FALSE;
}

boolean_t
dtrace_sdt_probes_restricted(void)
{

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
	if (cs_restricted(proc))
		return FALSE;
#endif

	return TRUE;
}

