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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <miscfs/devfs/devfs.h>

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>

#include <sys/dtrace_glue.h>

#include <sys/lockstat.h>

#include <kern/lock_stat.h>

#define membar_producer dtrace_membar_producer

#define PROBE_ARGS0(a, b, c, d, e) "\000"
#define PROBE_ARGS1(a, b, c, d, e) a "\000"
#define PROBE_ARGS2(a, b, c, d, e) a "\000" b "\000"
#define PROBE_ARGS3(a, b, c, d, e) a "\000" b "\000" c "\000"
#define PROBE_ARGS4(a, b, c, d, e) a "\000" b "\000" c "\000" d "\000"
#define PROBE_ARGS5(a, b, c, d, e) a "\000" b "\000" c "\000" d "\000" e "\000"
#define PROBE_ARGS_(a, b, c, d, e, n, ...) PROBE_ARGS##n(a, b, c, d, e)
#define PROBE_ARGS(...) PROBE_ARGS_(__VA_ARGS__, 5, 4, 3, 2, 1, 0)

#define LOCKSTAT_PROBE(func, name, probe, ...) \
	{func, name, probe, DTRACE_IDNONE, PROBE_ARGS(__VA_ARGS__)}

#if defined(__x86_64__)
#define LOCKSTAT_AFRAMES 1
#elif   defined(__arm__) || defined(__arm64__)
#define LOCKSTAT_AFRAMES 2
#else
#error "architecture not supported"
#endif

typedef struct lockstat_probe {
	const char      *lsp_func;
	const char      *lsp_name;
	int             lsp_probe;
	dtrace_id_t     lsp_id;
	const char      *lsp_args;
} lockstat_probe_t;

lockstat_probe_t lockstat_probes[] =
{
	// Mutex probes
	LOCKSTAT_PROBE(LS_LCK_MTX_LOCK, LSA_ACQUIRE, LS_LCK_MTX_LOCK_ACQUIRE, "lck_mtx_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_LOCK, LSA_SPIN, LS_LCK_MTX_LOCK_SPIN, "lck_mtx_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_LOCK, LSA_BLOCK, LS_LCK_MTX_LOCK_BLOCK, "lck_mtx_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_TRY_LOCK, LSA_ACQUIRE, LS_LCK_MTX_TRY_LOCK_ACQUIRE, "lck_mtx_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_TRY_SPIN_LOCK, LSA_ACQUIRE, LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, "lck_mtx_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_UNLOCK, LSA_RELEASE, LS_LCK_MTX_UNLOCK_RELEASE, "lck_mtx_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_LOCK_SPIN_LOCK, LSA_ACQUIRE, LS_LCK_MTX_LOCK_SPIN_ACQUIRE, "lck_mtx_t"),
	// Extended mutexes are only implemented on Intel
#if defined(__x86_64__)
	LOCKSTAT_PROBE(LS_LCK_MTX_EXT_LOCK, LSA_SPIN, LS_LCK_MTX_EXT_LOCK_SPIN, "lck_mtx_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_EXT_LOCK, LSA_ACQUIRE, LS_LCK_MTX_EXT_LOCK_ACQUIRE, "lck_mtx_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_EXT_LOCK, LSA_BLOCK, LS_LCK_MTX_EXT_LOCK_BLOCK, "lck_mtx_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_MTX_EXT_UNLOCK, LSA_RELEASE, LS_LCK_MTX_EXT_UNLOCK_RELEASE, "lck_mtx_t"),
#endif

	// RW lock probes
	// TODO: This should not be a uint64_t !
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_SHARED, LSR_ACQUIRE, LS_LCK_RW_LOCK_SHARED_ACQUIRE, "lck_rw_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_SHARED, LSR_BLOCK, LS_LCK_RW_LOCK_SHARED_BLOCK, "lck_rw_t", "uint64_t", "_Bool", "_Bool", "int"),
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_SHARED, LSR_SPIN, LS_LCK_RW_LOCK_SHARED_SPIN, "lck_rw_t", "uint64_t", "_Bool", "_Bool", "int"),
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_EXCL, LSR_ACQUIRE, LS_LCK_RW_LOCK_EXCL_ACQUIRE, "lck_rw_t", "uint64_t"),
	// TODO: This should NOT be a uint64_t
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_EXCL, LSR_BLOCK, LS_LCK_RW_LOCK_EXCL_BLOCK, "lck_rw_t", "uint64_t", "_Bool", "_Bool", "int"),
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_EXCL, LSR_SPIN, LS_LCK_RW_LOCK_EXCL_SPIN, "lck_rw_t", "uint64_t", "int"),
	LOCKSTAT_PROBE(LS_LCK_RW_DONE, LSR_RELEASE, LS_LCK_RW_DONE_RELEASE, "lck_rw_t", "_Bool"),
	// TODO : This should NOT be a uint64_t
	LOCKSTAT_PROBE(LS_LCK_RW_TRY_LOCK_SHARED, LSR_ACQUIRE, LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, "lck_rw_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_RW_TRY_LOCK_EXCL, LSR_ACQUIRE, LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, "lck_rw_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_SHARED_TO_EXCL, LSR_UPGRADE, LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, "lck_rw_t", "_Bool"),
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_SHARED_TO_EXCL, LSR_SPIN, LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN, "lck_rw_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_SHARED_TO_EXCL, LSR_BLOCK, LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK, "lck_rw_t", "uint64_t", "_Bool", "_Bool", "int"),

	// Spin lock probes
	//TODO : Separate the probes for the hw_bit from the probe for the normal hw locks
	LOCKSTAT_PROBE(LS_LCK_SPIN_LOCK, LSS_ACQUIRE, LS_LCK_SPIN_LOCK_ACQUIRE, "hw_lock_t"),
	LOCKSTAT_PROBE(LS_LCK_SPIN_LOCK, LSS_SPIN, LS_LCK_SPIN_LOCK_SPIN, "hw_lock_t", "uint64_t", "uint64_t"),
	LOCKSTAT_PROBE(LS_LCK_SPIN_UNLOCK, LSS_RELEASE, LS_LCK_SPIN_UNLOCK_RELEASE, "hw_lock_t"),
	LOCKSTAT_PROBE(LS_LCK_RW_LOCK_EXCL_TO_SHARED, LSR_DOWNGRADE, LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, "lck_rw_t"),
	// Ticket lock probes
	LOCKSTAT_PROBE(LS_LCK_TICKET_LOCK, LST_ACQUIRE, LS_LCK_TICKET_LOCK_ACQUIRE, "lck_ticket_t"),
	LOCKSTAT_PROBE(LS_LCK_TICKET_LOCK, LST_RELEASE, LS_LCK_TICKET_LOCK_RELEASE, "lck_ticket_t"),
	LOCKSTAT_PROBE(LS_LCK_TICKET_LOCK, LST_SPIN, LS_LCK_TICKET_LOCK_SPIN, "lck_ticket_t"),
	{
		NULL, NULL, 0, 0, NULL
	}
};

dtrace_id_t lockstat_probemap[LS_NPROBES];
void (*lockstat_probe)(dtrace_id_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t);

static dtrace_provider_id_t lockstat_id;

/*ARGSUSED*/
static int
lockstat_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg) /* __APPLE__ */

	lockstat_probe_t *probe = parg;

	ASSERT(!lockstat_probemap[probe->lsp_probe]);

	lockstat_probemap[probe->lsp_probe] = id;
	membar_producer();

	return 0;
}

/*ARGSUSED*/
static void
lockstat_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id) /* __APPLE__ */

	lockstat_probe_t *probe = parg;

	ASSERT(lockstat_probemap[probe->lsp_probe]);

	lockstat_probemap[probe->lsp_probe] = 0;
	membar_producer();
}

/*ARGSUSED*/
static void
lockstat_provide(void *arg, const dtrace_probedesc_t *desc)
{
#pragma unused(arg, desc) /* __APPLE__ */

	int i = 0;

	for (i = 0; lockstat_probes[i].lsp_func != NULL; i++) {
		lockstat_probe_t *probe = &lockstat_probes[i];

		if (dtrace_probe_lookup(lockstat_id, "mach_kernel",
		    probe->lsp_func, probe->lsp_name) != 0) {
			continue;
		}

		ASSERT(!probe->lsp_id);
		probe->lsp_id = dtrace_probe_create(lockstat_id,
		    "mach_kernel", probe->lsp_func, probe->lsp_name,
		    LOCKSTAT_AFRAMES, probe);
	}
}


/*ARGSUSED*/
static void
lockstat_destroy(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id)

	lockstat_probe_t *probe = parg;

	ASSERT(!lockstat_probemap[probe->lsp_probe]);
	probe->lsp_id = 0;
}

static void
lockstat_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
#pragma unused(arg, id)
	lockstat_probe_t *probe = parg;
	const char* argdesc = probe->lsp_args;
	int narg = 0;

	desc->dtargd_native[0] = '\0';
	desc->dtargd_xlate[0] = '\0';

	while (argdesc[0] != '\0') {
		if (narg == desc->dtargd_ndx) {
			strlcpy(desc->dtargd_native, argdesc, DTRACE_ARGTYPELEN);
			return;
		}
		argdesc += strlen(argdesc) + 1;
		narg++;
	}

	desc->dtargd_ndx = DTRACE_ARGNONE;
}

static dtrace_pattr_t lockstat_attr = {
	{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
	{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
	{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
	{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
	{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
};

static dtrace_pops_t lockstat_pops = {
	.dtps_provide =         lockstat_provide,
	.dtps_provide_module =  NULL,
	.dtps_enable =          lockstat_enable,
	.dtps_disable =         lockstat_disable,
	.dtps_suspend =         NULL,
	.dtps_resume =          NULL,
	.dtps_getargdesc =      lockstat_getargdesc,
	.dtps_getargval =       NULL,
	.dtps_usermode =        NULL,
	.dtps_destroy =         lockstat_destroy
};

static int
lockstat_attach(dev_info_t *devi)
{
	if (ddi_create_minor_node(devi, "lockstat", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE ||
	    dtrace_register("lockstat", &lockstat_attr, DTRACE_PRIV_KERNEL,
	    NULL, &lockstat_pops, NULL, &lockstat_id) != 0) {
		ddi_remove_minor_node(devi, NULL);
		return DDI_FAILURE;
	}

	lockstat_probe = dtrace_probe;
	membar_producer();

	return DDI_SUCCESS;
}

static int
_lockstat_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev,flags,devtype,p)
	return 0;
}


static const struct cdevsw lockstat_cdevsw =
{
	.d_open = _lockstat_open,
	.d_close = eno_opcl,
	.d_read = eno_rdwrt,
	.d_write = eno_rdwrt,
	.d_ioctl = eno_ioctl,
	.d_stop = (stop_fcn_t *)nulldev,
	.d_reset = (reset_fcn_t *)nulldev,
	.d_select = eno_select,
	.d_mmap = eno_mmap,
	.d_strategy = eno_strat,
	.d_reserved_1 = eno_getc,
	.d_reserved_2 = eno_putc,
};

void lockstat_init( void );

void
lockstat_init( void )
{
	int majdevno = cdevsw_add(-1, &lockstat_cdevsw);

	if (majdevno < 0) {
		printf("lockstat_init: failed to allocate a major number!\n");
		return;
	}

	lockstat_attach((dev_info_t*)(uintptr_t)majdevno);
}
