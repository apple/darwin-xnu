/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)fbt.c	1.15	05/09/19 SMI" */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

#include <mach-o/loader.h> 
#include <kern/mach_header.h>

extern struct mach_header _mh_execute_header; /* the kernel's mach header */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <miscfs/devfs/devfs.h>
#include <pexpert/pexpert.h>

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/fbt.h>

#include <sys/dtrace_glue.h>

/* #include <machine/trap.h> */
struct savearea_t; /* Used anonymously */
typedef kern_return_t (*perfCallback)(int, struct savearea_t *, int, int);

#if defined (__ppc__) || defined (__ppc64__)
extern perfCallback tempDTraceTrapHook, tempDTraceIntHook;
extern kern_return_t fbt_perfCallback(int, struct savearea_t *, int, int);
extern kern_return_t fbt_perfIntCallback(int, struct savearea_t *, int, int);
#else
extern perfCallback tempDTraceTrapHook;
extern kern_return_t fbt_perfCallback(int, struct savearea_t *, int, int);
#endif

#define	FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & fbt_probetab_mask)
#define	FBT_PROBETAB_SIZE	0x8000		/* 32k entries -- 128K total */

static dev_info_t		*fbt_devi;
static int				fbt_probetab_size;
dtrace_provider_id_t	fbt_id;
fbt_probe_t				**fbt_probetab;
int						fbt_probetab_mask;
static int				fbt_verbose = 0;

void fbt_init( void );

/*ARGSUSED*/
static void
fbt_destroy(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg, *next, *hash, *last;
	int ndx;

	do {
		/*
		 * Now we need to remove this probe from the fbt_probetab.
		 */
		ndx = FBT_ADDR2NDX(fbt->fbtp_patchpoint);
		last = NULL;
		hash = fbt_probetab[ndx];

		while (hash != fbt) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->fbtp_hashnext;
		}

		if (last != NULL) {
			last->fbtp_hashnext = fbt->fbtp_hashnext;
		} else {
			fbt_probetab[ndx] = fbt->fbtp_hashnext;
		}

		next = fbt->fbtp_next;
		kmem_free(fbt, sizeof (fbt_probe_t));

		fbt = next;
	} while (fbt != NULL);
}

/*ARGSUSED*/
static void
fbt_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;

#if defined (__ppc__) || defined (__ppc64__)
	dtrace_casptr(&tempDTraceIntHook, NULL, fbt_perfIntCallback);
	if (tempDTraceIntHook != (perfCallback)fbt_perfIntCallback) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt_enable is failing for probe %s "
			    "in module %s: tempDTraceIntHook already occupied.",
			    fbt->fbtp_name, ctl->mod_modname);
		}
		return;
	}
#endif
	
	dtrace_casptr(&tempDTraceTrapHook, NULL, fbt_perfCallback);
	if (tempDTraceTrapHook != (perfCallback)fbt_perfCallback) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt_enable is failing for probe %s "
			    "in module %s: tempDTraceTrapHook already occupied.",
			    fbt->fbtp_name, ctl->mod_modname);
		}
		return;
	}

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		(void)ml_nofault_copy( (vm_offset_t)&fbt->fbtp_patchval, (vm_offset_t)fbt->fbtp_patchpoint, 
								sizeof(fbt->fbtp_patchval));
		
	dtrace_membar_consumer();
}

/*ARGSUSED*/
static void
fbt_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg;

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		(void)ml_nofault_copy( (vm_offset_t)&fbt->fbtp_savedval, (vm_offset_t)fbt->fbtp_patchpoint, 
								sizeof(fbt->fbtp_savedval));
		
	dtrace_membar_consumer();
}

/*ARGSUSED*/
static void
fbt_suspend(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg;

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		(void)ml_nofault_copy( (vm_offset_t)&fbt->fbtp_savedval, (vm_offset_t)fbt->fbtp_patchpoint, 
								sizeof(fbt->fbtp_savedval));
		
	dtrace_membar_consumer();
}

/*ARGSUSED*/
static void
fbt_resume(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;

#if defined (__ppc__) || defined (__ppc64__)
	dtrace_casptr(&tempDTraceIntHook, NULL, fbt_perfIntCallback);
	if (tempDTraceIntHook != (perfCallback)fbt_perfIntCallback) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt_enable is failing for probe %s "
			    "in module %s: tempDTraceIntHook already occupied.",
			    fbt->fbtp_name, ctl->mod_modname);
		}
		return;
	}
#endif
	
	dtrace_casptr(&tempDTraceTrapHook, NULL, fbt_perfCallback);
	if (tempDTraceTrapHook != (perfCallback)fbt_perfCallback) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt_resume is failing for probe %s "
			    "in module %s: tempDTraceTrapHook already occupied.",
			    fbt->fbtp_name, ctl->mod_modname);
		}
		return;
	}
	
	for (; fbt != NULL; fbt = fbt->fbtp_next)
		(void)ml_nofault_copy( (vm_offset_t)&fbt->fbtp_patchval, (vm_offset_t)fbt->fbtp_patchpoint, 
								sizeof(fbt->fbtp_patchval));
		
	dtrace_membar_consumer();
}

#if !defined(__APPLE__)
/*ARGSUSED*/
static void
fbt_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;
	struct module *mp = ctl->mod_mp;
	ctf_file_t *fp = NULL, *pfp;
	ctf_funcinfo_t f;
	int error;
	ctf_id_t argv[32], type;
	int argc = sizeof (argv) / sizeof (ctf_id_t);
	const char *parent;

	if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		goto err;

	if (fbt->fbtp_roffset != 0 && desc->dtargd_ndx == 0) {
		(void) strlcpy(desc->dtargd_native, "int",
			       sizeof(desc->dtargd_native));
		return;
	}

	if ((fp = ctf_modopen(mp, &error)) == NULL) {
		/*
		 * We have no CTF information for this module -- and therefore
		 * no args[] information.
		 */
		goto err;
	}

	/*
	 * If we have a parent container, we must manually import it.
	 */
	if ((parent = ctf_parent_name(fp)) != NULL) {
		struct modctl *mod;

		/*
		 * We must iterate over all modules to find the module that
		 * is our parent.
		 */
		for (mod = &modules; mod != NULL; mod = mod->mod_next) {
			if (strcmp(mod->mod_filename, parent) == 0)
				break;
		}

		if (mod == NULL)
			goto err;

		if ((pfp = ctf_modopen(mod->mod_mp, &error)) == NULL)
			goto err;

		if (ctf_import(fp, pfp) != 0) {
			ctf_close(pfp);
			goto err;
		}

		ctf_close(pfp);
	}

	if (ctf_func_info(fp, fbt->fbtp_symndx, &f) == CTF_ERR)
		goto err;

	if (fbt->fbtp_roffset != 0) {
		if (desc->dtargd_ndx > 1)
			goto err;

		ASSERT(desc->dtargd_ndx == 1);
		type = f.ctc_return;
	} else {
		if (desc->dtargd_ndx + 1 > f.ctc_argc)
			goto err;

		if (ctf_func_args(fp, fbt->fbtp_symndx, argc, argv) == CTF_ERR)
			goto err;

		type = argv[desc->dtargd_ndx];
	}

	if (ctf_type_name(fp, type, desc->dtargd_native,
	    DTRACE_ARGTYPELEN) != NULL) {
		ctf_close(fp);
		return;
	}
err:
	if (fp != NULL)
		ctf_close(fp);

	desc->dtargd_ndx = DTRACE_ARGNONE;
}
#endif /* __APPLE__ */

static dtrace_pattr_t fbt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pops_t fbt_pops = {
	NULL,
	fbt_provide_module,
	fbt_enable,
	fbt_disable,
	fbt_suspend,
	fbt_resume,
#if !defined(__APPLE__)
	fbt_getargdesc,
#else
	NULL, /* XXX where to look for xnu? */
#endif /* __APPLE__ */
	NULL,
	NULL,
	fbt_destroy
};

static void
fbt_cleanup(dev_info_t *devi)
{
	dtrace_invop_remove(fbt_invop);
	ddi_remove_minor_node(devi, NULL);
	kmem_free(fbt_probetab, fbt_probetab_size * sizeof (fbt_probe_t *));
	fbt_probetab = NULL;
	fbt_probetab_mask = 0;
}

static int
fbt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (fbt_probetab_size == 0)
		fbt_probetab_size = FBT_PROBETAB_SIZE;

	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab =
	    kmem_zalloc(fbt_probetab_size * sizeof (fbt_probe_t *), KM_SLEEP);

	dtrace_invop_add(fbt_invop);

	if (ddi_create_minor_node(devi, "fbt", S_IFCHR, 0,
	    DDI_PSEUDO, NULL) == DDI_FAILURE ||
	    dtrace_register("fbt", &fbt_attr, DTRACE_PRIV_KERNEL, NULL,
	    &fbt_pops, NULL, &fbt_id) != 0) {
		fbt_cleanup(devi);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	fbt_devi = devi;

	return (DDI_SUCCESS);
}

static d_open_t _fbt_open;

static int
_fbt_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev,flags,devtype,p)
	return 0;
}

#define FBT_MAJOR  -24 /* let the kernel pick the device number */

/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */
static struct cdevsw fbt_cdevsw =
{
	_fbt_open,		/* open */
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

static int gDisableFBT = 0;
struct modctl g_fbt_kernctl;
#undef kmem_alloc /* from its binding to dt_kmem_alloc glue */
#undef kmem_free /* from its binding to dt_kmem_free glue */
#include <vm/vm_kern.h>

void
fbt_init( void )
{

	PE_parse_boot_argn("DisableFBT", &gDisableFBT, sizeof (gDisableFBT));

	if (0 == gDisableFBT)
	{
		int majdevno = cdevsw_add(FBT_MAJOR, &fbt_cdevsw);
		int size = 0, header_size, round_size;
	   	kern_return_t ret;
		void *p, *q;
		
		if (majdevno < 0) {
			printf("fbt_init: failed to allocate a major number!\n");
			return;
		}

		/*
		 * Capture the kernel's mach_header in its entirety and the contents of
		 * its LINKEDIT segment (and only that segment). This is sufficient to
		 * build all the fbt probes lazily the first time a client looks to
		 * the fbt provider. Remeber thes on the global struct modctl g_fbt_kernctl.
		 */
		header_size = sizeof(struct mach_header) + _mh_execute_header.sizeofcmds;
		p = getsegdatafromheader(&_mh_execute_header, SEG_LINKEDIT, &size);

        round_size = round_page_32(header_size + size);
		ret = kmem_alloc_pageable(kernel_map, (vm_offset_t *)&q, round_size);

		if (p && (ret == KERN_SUCCESS)) {
			struct segment_command *sgp;

			bcopy( (void *)&_mh_execute_header, q, header_size);
			bcopy( p, (char *)q + header_size, size);

			sgp = getsegbynamefromheader(q, SEG_LINKEDIT);

			if (sgp) {
				sgp->vmaddr = (unsigned long)((char *)q + header_size);
				g_fbt_kernctl.address = (vm_address_t)q;
				g_fbt_kernctl.size = header_size + size;
			} else {
				kmem_free(kernel_map, (vm_offset_t)q, round_size);
				g_fbt_kernctl.address = (vm_address_t)NULL;
				g_fbt_kernctl.size = 0;
			}
		} else {
			if (ret == KERN_SUCCESS)
				kmem_free(kernel_map, (vm_offset_t)q, round_size);
			g_fbt_kernctl.address = (vm_address_t)NULL;
			g_fbt_kernctl.size = 0;
		}

		strncpy((char *)&(g_fbt_kernctl.mod_modname), "mach_kernel", KMOD_MAX_NAME);

		fbt_attach( (dev_info_t	*)majdevno, DDI_ATTACH );

		gDisableFBT = 1; /* Ensure this initialization occurs just one time. */
	}
	else
		printf("fbt_init: DisableFBT non-zero, no FBT probes will be provided.\n");
}
#undef FBT_MAJOR
