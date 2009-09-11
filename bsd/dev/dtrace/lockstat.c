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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)lockstat.c	1.12	08/01/16 SMI" */


#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

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

#include <kern/processor.h>

#define membar_producer dtrace_membar_producer

/*
 * Hot patch values, x86
 */
#if defined(__i386__) || defined(__x86_64__)
#define	NOP	0x90
#define	RET	0xc3
#define LOCKSTAT_AFRAMES 1
#elif	__ppc__
#define	NOP	0x60000000
#define RET	0x4e800020	/* blr */
#define LOCKSTAT_AFRAMES 2
#else
#error "not ported to this architecture"
#endif


typedef struct lockstat_probe {
	const char	*lsp_func;
	const char	*lsp_name;
	int		lsp_probe;
	dtrace_id_t	lsp_id;
} lockstat_probe_t;

lockstat_probe_t lockstat_probes[] =
{
#if defined(__i386__) || defined(__x86_64__)
	/* Not implemented yet on PPC... */
	{ LS_LCK_MTX_LOCK,	LSA_ACQUIRE,	LS_LCK_MTX_LOCK_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_MTX_LOCK,	LSA_SPIN,	LS_LCK_MTX_LOCK_SPIN, DTRACE_IDNONE },
	{ LS_LCK_MTX_TRY_LOCK,	LSA_ACQUIRE,	LS_LCK_MTX_TRY_LOCK_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_MTX_TRY_SPIN_LOCK, LSA_ACQUIRE, LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_MTX_UNLOCK,	LSA_RELEASE,	LS_LCK_MTX_UNLOCK_RELEASE, DTRACE_IDNONE },
	{ LS_LCK_MTX_EXT_LOCK,	LSA_ACQUIRE,	LS_LCK_MTX_EXT_LOCK_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_MTX_EXT_LOCK,	LSA_SPIN,	LS_LCK_MTX_EXT_LOCK_SPIN, DTRACE_IDNONE },
	{ LS_LCK_MTX_EXT_TRY_LOCK, LSA_ACQUIRE,	LS_LCK_MTX_TRY_EXT_LOCK_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_MTX_UNLOCK,	LSA_RELEASE,	LS_LCK_MTX_EXT_UNLOCK_RELEASE, DTRACE_IDNONE },
	{ LS_LCK_MTX_LOCK_SPIN_LOCK,	LSA_ACQUIRE,	LS_LCK_MTX_LOCK_SPIN_ACQUIRE, DTRACE_IDNONE },
#endif
	{ LS_LCK_MTX_LOCK,	LSA_BLOCK,	LS_LCK_MTX_LOCK_BLOCK, DTRACE_IDNONE },
	{ LS_LCK_MTX_EXT_LOCK,	LSA_BLOCK,	LS_LCK_MTX_EXT_LOCK_BLOCK, DTRACE_IDNONE },

	{ LS_LCK_RW_LOCK_SHARED,	LSR_ACQUIRE,	LS_LCK_RW_LOCK_SHARED_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_SHARED,	LSR_BLOCK,	LS_LCK_RW_LOCK_SHARED_BLOCK, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_SHARED,	LSR_SPIN,	LS_LCK_RW_LOCK_SHARED_SPIN, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_EXCL,		LSR_ACQUIRE,	LS_LCK_RW_LOCK_EXCL_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_EXCL,		LSR_BLOCK,	LS_LCK_RW_LOCK_EXCL_BLOCK, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_EXCL,		LSR_SPIN,	LS_LCK_RW_LOCK_EXCL_SPIN, DTRACE_IDNONE },
	{ LS_LCK_RW_DONE,		LSR_RELEASE,	LS_LCK_RW_DONE_RELEASE, DTRACE_IDNONE },
	{ LS_LCK_RW_TRY_LOCK_SHARED,	LSR_ACQUIRE,	LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_RW_TRY_LOCK_EXCL,	LSR_ACQUIRE,	LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_SHARED_TO_EXCL, LSR_UPGRADE,	LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_SHARED_TO_EXCL,	LSR_BLOCK,	LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_SHARED_TO_EXCL,	LSR_SPIN,	LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN, DTRACE_IDNONE },
	{ LS_LCK_RW_LOCK_EXCL_TO_SHARED,	LSR_DOWNGRADE,	LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, DTRACE_IDNONE },


#ifdef	LATER
	/* Interlock and spinlock measurements would be nice, but later */
	{ LS_LCK_SPIN_LOCK,	LSS_ACQUIRE,	LS_LCK_SPIN_LOCK_ACQUIRE, DTRACE_IDNONE },
	{ LS_LCK_SPIN_LOCK,	LSS_SPIN,	LS_LCK_SPIN_LOCK_SPIN, DTRACE_IDNONE },
	{ LS_LCK_SPIN_UNLOCK,	LSS_RELEASE,	LS_LCK_SPIN_UNLOCK_RELEASE, DTRACE_IDNONE },

	{ LS_LCK_RW_LOCK_EXCL_TO_SHARED,	LSA_ILK_SPIN,	LS_LCK_RW_LOCK_EXCL_TO_SHARED_ILK_SPIN, DTRACE_IDNONE },
	{ LS_LCK_MTX_LOCK,	LSA_ILK_SPIN,	LS_LCK_MTX_LOCK_ILK_SPIN, DTRACE_IDNONE },
	{ LS_LCK_MTX_EXT_LOCK,	LSA_ILK_SPIN,	LS_LCK_MTX_EXT_LOCK_ILK_SPIN, DTRACE_IDNONE },
	{ LS_LCK_RW_TRY_LOCK_EXCL,	LSA_ILK_SPIN,	LS_LCK_RW_TRY_LOCK_EXCL_ILK_SPIN, DTRACE_IDNONE },
	{ LS_LCK_RW_TRY_LOCK_SHARED,	LSA_SPIN,	LS_LCK_RW_TRY_LOCK_SHARED_SPIN, DTRACE_IDNONE },
#endif

	{ NULL, NULL, 0, 0 }
};

dtrace_id_t lockstat_probemap[LS_NPROBES];

#if CONFIG_DTRACE
extern void lck_mtx_lock_lockstat_patch_point(void);
extern void lck_mtx_try_lock_lockstat_patch_point(void);
extern void lck_mtx_try_lock_spin_lockstat_patch_point(void);
extern void lck_mtx_unlock_lockstat_patch_point(void);
extern void lck_mtx_lock_ext_lockstat_patch_point(void);
extern void lck_mtx_ext_unlock_lockstat_patch_point(void);

extern void lck_rw_lock_shared_lockstat_patch_point(void);
extern void lck_rw_lock_exclusive_lockstat_patch_point(void);
extern void lck_rw_lock_shared_to_exclusive_lockstat_patch_point(void);
extern void lck_rw_try_lock_shared_lockstat_patch_point(void);
extern void lck_rw_try_lock_exclusive_lockstat_patch_point(void);
extern void lck_mtx_lock_spin_lockstat_patch_point(void);
#endif /* CONFIG_DTRACE */

vm_offset_t *assembly_probes[] = {
#if CONFIG_DTRACE
#if defined(__i386__) || defined(__x86_64__)
	/*
	 * On x86 these points are better done via hot patches, which ensure
	 * there is zero overhead when not in use.  On x86 these patch points
	 * are swapped between the return instruction and a no-op, with the
	 * Dtrace call following the return.
	 */ 
	(vm_offset_t *) lck_mtx_lock_lockstat_patch_point,
	(vm_offset_t *) lck_mtx_try_lock_lockstat_patch_point,
	(vm_offset_t *) lck_mtx_try_lock_spin_lockstat_patch_point,
	(vm_offset_t *) lck_mtx_unlock_lockstat_patch_point,
	(vm_offset_t *) lck_mtx_lock_ext_lockstat_patch_point,
	(vm_offset_t *) lck_mtx_ext_unlock_lockstat_patch_point,
	(vm_offset_t *) lck_rw_lock_shared_lockstat_patch_point,
	(vm_offset_t *) lck_rw_lock_exclusive_lockstat_patch_point,
	(vm_offset_t *) lck_rw_lock_shared_to_exclusive_lockstat_patch_point,
	(vm_offset_t *) lck_rw_try_lock_shared_lockstat_patch_point,
	(vm_offset_t *) lck_rw_try_lock_exclusive_lockstat_patch_point,
	(vm_offset_t *) lck_mtx_lock_spin_lockstat_patch_point,
#else
	(vm_offset_t *) lck_mtx_unlock_lockstat_patch_point,
#endif
#endif /* CONFIG_DTRACE */
	NULL
};
/*
 * Hot patch switches back and forth the probe points between NOP and RET.
 * The argument indicates whether the probe point is on or off.
 */
#if defined(__APPLE__)
static
#endif /* __APPLE__ */
void lockstat_hot_patch(boolean_t active)
{
#pragma unused(active)
	int i;


	for (i = 0; assembly_probes[i]; i++) {
#if defined(__i386__) || defined(__x86_64__)
		uint8_t instr;
		instr = (active ? NOP : RET );
		(void) ml_nofault_copy( (vm_offset_t)&instr, *(assembly_probes[i]), 
								sizeof(instr));
#endif
#ifdef __ppc__
		uint32_t instr;
		instr = (active ? NOP : RET );
		(void) ml_nofault_copy( (vm_offset_t)&instr, *(assembly_probes[i]), sizeof(instr));
#endif
	}
}



void (*lockstat_probe)(dtrace_id_t, uint64_t, uint64_t,
				    uint64_t, uint64_t, uint64_t);

static dev_info_t	*lockstat_devi;	/* saved in xxattach() for xxinfo() */
static dtrace_provider_id_t lockstat_id;

/*ARGSUSED*/
static void
lockstat_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg) /* __APPLE__ */
    
	lockstat_probe_t *probe = parg;

	ASSERT(!lockstat_probemap[probe->lsp_probe]);

	lockstat_probemap[probe->lsp_probe] = id;
	membar_producer();

	lockstat_hot_patch(TRUE);
	membar_producer();

}

/*ARGSUSED*/
static void
lockstat_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id) /* __APPLE__ */

	lockstat_probe_t *probe = parg;
	int i;

	ASSERT(lockstat_probemap[probe->lsp_probe]);

	lockstat_probemap[probe->lsp_probe] = 0;
	lockstat_hot_patch(FALSE);
	membar_producer();

	/*
	 * See if we have any probes left enabled.
	 */
	for (i = 0; i < LS_NPROBES; i++) {
		if (lockstat_probemap[i]) {
			/*
			 * This probe is still enabled.  We don't need to deal
			 * with waiting for all threads to be out of the
			 * lockstat critical sections; just return.
			 */
			return;
		}
	}

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
		    probe->lsp_func, probe->lsp_name) != 0)
			continue;

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
#pragma unused(arg, id) /* __APPLE__ */
    
	lockstat_probe_t *probe = parg;

	ASSERT(!lockstat_probemap[probe->lsp_probe]);
	probe->lsp_id = 0;
}

static dtrace_pattr_t lockstat_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
};

static dtrace_pops_t lockstat_pops = {
	lockstat_provide,
	NULL,
	lockstat_enable,
	lockstat_disable,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	lockstat_destroy
};

static int
lockstat_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "lockstat", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE ||
	    dtrace_register("lockstat", &lockstat_attr, DTRACE_PRIV_KERNEL,
	    NULL, &lockstat_pops, NULL, &lockstat_id) != 0) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	lockstat_probe = dtrace_probe;
	membar_producer();

	ddi_report_dev(devi);
	lockstat_devi = devi;
	return (DDI_SUCCESS);
}

d_open_t _lockstat_open;

int _lockstat_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev,flags,devtype,p)
	return 0;
}

#define LOCKSTAT_MAJOR  -24 /* let the kernel pick the device number */

/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */
static struct cdevsw lockstat_cdevsw =
{
	_lockstat_open,		/* open */
	eno_opcl,			/* close */
	eno_rdwrt,			/* read */
	eno_rdwrt,			/* write */
	eno_ioctl,			/* ioctl */
	(stop_fcn_t *)nulldev, /* stop */
	(reset_fcn_t *)nulldev, /* reset */
	NULL,				/* tty's */
	eno_select,			/* select */
	eno_mmap,			/* mmap */
	eno_strat,			/* strategy */
	eno_getc,			/* getc */
	eno_putc,			/* putc */
	0					/* type */
};

static int gLockstatInited = 0;

void lockstat_init( void );

void lockstat_init( void )
{
	if (0 == gLockstatInited)
	{
		int majdevno = cdevsw_add(LOCKSTAT_MAJOR, &lockstat_cdevsw);
		
		if (majdevno < 0) {
			printf("lockstat_init: failed to allocate a major number!\n");
			gLockstatInited = 0;
			return;
		}

		lockstat_attach( (dev_info_t	*)(uintptr_t)majdevno, DDI_ATTACH );
		gLockstatInited = 1;
	} else
		panic("lockstat_init: called twice!\n");
}
#undef LOCKSTAT_MAJOR
