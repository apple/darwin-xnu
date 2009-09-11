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

/* #pragma ident	"@(#)sdt.c	1.9	08/07/01 SMI" */

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

#include <sys/sdt_impl.h>

struct savearea_t; /* Used anonymously */
typedef kern_return_t (*perfCallback)(int, struct savearea_t *, int, int);

#if defined (__ppc__) || defined (__ppc64__)
extern perfCallback tempDTraceTrapHook, tempDTraceIntHook;
extern kern_return_t fbt_perfCallback(int, struct savearea_t *, int, int);
extern kern_return_t fbt_perfIntCallback(int, struct savearea_t *, int, int);

#define	SDT_PATCHVAL	0x7c810808
#define SDT_AFRAMES     6
#elif defined(__i386__) || defined(__x86_64__)
extern perfCallback tempDTraceTrapHook;
extern kern_return_t fbt_perfCallback(int, struct savearea_t *, int, int);

#define	SDT_PATCHVAL	0xf0
#define	SDT_AFRAMES		6
#else
#error Unknown architecture
#endif

#define	SDT_PROBETAB_SIZE	0x1000		/* 4k entries -- 16K total */

#if defined(__x86_64__)
#define DTRACE_PROBE_PREFIX "_dtrace_probeDOLLAR"
#else
#define DTRACE_PROBE_PREFIX "_dtrace_probe$"
#endif

static dev_info_t		*sdt_devi;
static int			sdt_verbose = 0;
sdt_probe_t		**sdt_probetab;
int			sdt_probetab_size;
int			sdt_probetab_mask;

/*ARGSUSED*/
static void
__sdt_provide_module(void *arg, struct modctl *ctl)
{
#pragma unused(arg)
	struct module *mp = (struct module *)ctl->address;
	char *modname = ctl->mod_modname;
	sdt_probedesc_t *sdpd;
	sdt_probe_t *sdp, *old;
	sdt_provider_t *prov;
	int len;

	/*
	 * One for all, and all for one:  if we haven't yet registered all of
	 * our providers, we'll refuse to provide anything.
	 */
	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (prov->sdtp_id == DTRACE_PROVNONE)
			return;
	}

	if (!mp || mp->sdt_nprobes != 0 || (sdpd = mp->sdt_probes) == NULL)
		return;

	for (sdpd = mp->sdt_probes; sdpd != NULL; sdpd = sdpd->sdpd_next) {
	    const char *name = sdpd->sdpd_name, *func;
	    char *nname;
		int i, j;
		dtrace_id_t id;

		for (prov = sdt_providers; prov->sdtp_prefix != NULL; prov++) {
			const char *prefpart, *prefix = prov->sdtp_prefix;

			if ((prefpart = strstr(name, prefix))) {
				name = prefpart + strlen(prefix);
				break;
			}
		}

		nname = kmem_alloc(len = strlen(name) + 1, KM_SLEEP);

		for (i = 0, j = 0; name[j] != '\0'; i++) {
			if (name[j] == '_' && name[j + 1] == '_') {
				nname[i] = '-';
				j += 2;
			} else {
				nname[i] = name[j++];
			}
		}

		nname[i] = '\0';

		sdp = kmem_zalloc(sizeof (sdt_probe_t), KM_SLEEP);
		sdp->sdp_loadcnt = ctl->mod_loadcnt;
		sdp->sdp_ctl = ctl;
		sdp->sdp_name = nname;
		sdp->sdp_namelen = len;
		sdp->sdp_provider = prov;

		func = sdpd->sdpd_func;

		if (func == NULL)
			func = "<unknown>";

		/*
		 * We have our provider.  Now create the probe.
		 */
		if ((id = dtrace_probe_lookup(prov->sdtp_id, modname,
		    func, nname)) != DTRACE_IDNONE) {
			old = dtrace_probe_arg(prov->sdtp_id, id);
			ASSERT(old != NULL);

			sdp->sdp_next = old->sdp_next;
			sdp->sdp_id = id;
			old->sdp_next = sdp;
		} else {
			sdp->sdp_id = dtrace_probe_create(prov->sdtp_id,
			    modname, func, nname, SDT_AFRAMES, sdp);

			mp->sdt_nprobes++;
		}

		sdp->sdp_hashnext =
		    sdt_probetab[SDT_ADDR2NDX(sdpd->sdpd_offset)];
		sdt_probetab[SDT_ADDR2NDX(sdpd->sdpd_offset)] = sdp;

		sdp->sdp_patchval = SDT_PATCHVAL;
		sdp->sdp_patchpoint = (sdt_instr_t *)sdpd->sdpd_offset;
		sdp->sdp_savedval = *sdp->sdp_patchpoint;
	}
}

/*ARGSUSED*/
static void
sdt_destroy(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	sdt_probe_t *sdp = parg, *old, *last, *hash;
	int ndx;
#if !defined(__APPLE__)
	struct modctl *ctl = sdp->sdp_ctl;

	if (ctl != NULL && ctl->mod_loadcnt == sdp->sdp_loadcnt) {
		if ((ctl->mod_loadcnt == sdp->sdp_loadcnt &&
		    ctl->mod_loaded)) {
			((struct module *)(ctl->mod_mp))->sdt_nprobes--;
		}
	}
#endif /* __APPLE__ */

	while (sdp != NULL) {
		old = sdp;

		/*
		 * Now we need to remove this probe from the sdt_probetab.
		 */
		ndx = SDT_ADDR2NDX(sdp->sdp_patchpoint);
		last = NULL;
		hash = sdt_probetab[ndx];

		while (hash != sdp) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->sdp_hashnext;
		}

		if (last != NULL) {
			last->sdp_hashnext = sdp->sdp_hashnext;
		} else {
			sdt_probetab[ndx] = sdp->sdp_hashnext;
		}

		kmem_free(sdp->sdp_name, sdp->sdp_namelen);
		sdp = sdp->sdp_next;
		kmem_free(old, sizeof (sdt_probe_t));
	}
}

/*ARGSUSED*/
static void
sdt_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	sdt_probe_t *sdp = parg;
	struct modctl *ctl = sdp->sdp_ctl;

#if !defined(__APPLE__)
	ctl->mod_nenabled++;

	/*
	 * If this module has disappeared since we discovered its probes,
	 * refuse to enable it.
	 */
	if (!ctl->mod_loaded) {
		if (sdt_verbose) {
			cmn_err(CE_NOTE, "sdt is failing for probe %s "
			    "(module %s unloaded)",
			    sdp->sdp_name, ctl->mod_modname);
		}
		goto err;
	}

	/*
	 * Now check that our modctl has the expected load count.  If it
	 * doesn't, this module must have been unloaded and reloaded -- and
	 * we're not going to touch it.
	 */
	if (ctl->mod_loadcnt != sdp->sdp_loadcnt) {
		if (sdt_verbose) {
			cmn_err(CE_NOTE, "sdt is failing for probe %s "
			    "(module %s reloaded)",
			    sdp->sdp_name, ctl->mod_modname);
		}
		goto err;
	}
#endif /* __APPLE__ */

#if defined (__ppc__) || defined (__ppc64__)
	dtrace_casptr(&tempDTraceIntHook, NULL, fbt_perfIntCallback);
	if (tempDTraceIntHook != (perfCallback)fbt_perfIntCallback) {
		if (sdt_verbose) {
			cmn_err(CE_NOTE, "sdt_enable is failing for probe %s "
			    "in module %s: tempDTraceIntHook already occupied.",
			    sdp->sdp_name, ctl->mod_modname);
		}
		return;
	}
#endif
	
	dtrace_casptr(&tempDTraceTrapHook, NULL, fbt_perfCallback);
	if (tempDTraceTrapHook != (perfCallback)fbt_perfCallback) {
		if (sdt_verbose) {
			cmn_err(CE_NOTE, "sdt_enable is failing for probe %s "
			    "in module %s: tempDTraceTrapHook already occupied.",
			    sdp->sdp_name, ctl->mod_modname);
		}
		return;
	}

	while (sdp != NULL) {
		(void)ml_nofault_copy( (vm_offset_t)&sdp->sdp_patchval, (vm_offset_t)sdp->sdp_patchpoint, 
		                       (vm_size_t)sizeof(sdp->sdp_patchval));
		sdp = sdp->sdp_next;
	}
#if !defined(__APPLE__)
err:
#endif /* __APPLE__ */
	;
}

/*ARGSUSED*/
static void
sdt_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	sdt_probe_t *sdp = parg;
#if !defined(__APPLE__)
	struct modctl *ctl = sdp->sdp_ctl;

	ctl->mod_nenabled--;

	if (!ctl->mod_loaded || ctl->mod_loadcnt != sdp->sdp_loadcnt)
		goto err;
#endif /* __APPLE__ */

	while (sdp != NULL) {
		(void)ml_nofault_copy( (vm_offset_t)&sdp->sdp_savedval, (vm_offset_t)sdp->sdp_patchpoint, 
		                       (vm_size_t)sizeof(sdp->sdp_savedval));
		sdp = sdp->sdp_next;
	}

#if !defined(__APPLE__)
err:
#endif /* __APPLE__ */	
	;
}

static uint64_t
sdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
#pragma unused(arg,id,parg)	/* __APPLE__ */
	return dtrace_getarg(argno, aframes);
}

static dtrace_pops_t sdt_pops = {
	NULL,
	sdt_provide_module,
	sdt_enable,
	sdt_disable,
	NULL,
	NULL,
	sdt_getargdesc,
	sdt_getarg,
	NULL,
	sdt_destroy
};

/*ARGSUSED*/
static int
sdt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
#pragma unused(cmd)
	sdt_provider_t *prov;

	if (ddi_create_minor_node(devi, "sdt", S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		cmn_err(CE_NOTE, "/dev/sdt couldn't create minor node");
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	sdt_devi = devi;

	if (sdt_probetab_size == 0)
		sdt_probetab_size = SDT_PROBETAB_SIZE;

	sdt_probetab_mask = sdt_probetab_size - 1;
	sdt_probetab =
	    kmem_zalloc(sdt_probetab_size * sizeof (sdt_probe_t *), KM_SLEEP);
	dtrace_invop_add(sdt_invop);

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (dtrace_register(prov->sdtp_name, prov->sdtp_attr,
		    DTRACE_PRIV_KERNEL, NULL,
		    &sdt_pops, prov, &prov->sdtp_id) != 0) {
			cmn_err(CE_WARN, "failed to register sdt provider %s",
			    prov->sdtp_name);
		}
	}

	return (DDI_SUCCESS);
}

#if !defined(__APPLE__)
/*ARGSUSED*/
static int
sdt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sdt_provider_t *prov;

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (prov->sdtp_id != DTRACE_PROVNONE) {
			if (dtrace_unregister(prov->sdtp_id) != 0)
				return (DDI_FAILURE);

			prov->sdtp_id = DTRACE_PROVNONE;
		}
	}

	dtrace_invop_remove(sdt_invop);
	kmem_free(sdt_probetab, sdt_probetab_size * sizeof (sdt_probe_t *));

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
sdt_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)sdt_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED*/
static int
sdt_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	return (0);
}

static struct cb_ops sdt_cb_ops = {
	sdt_open,		/* open */
	nodev,			/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops sdt_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sdt_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sdt_attach,		/* attach */
	sdt_detach,		/* detach */
	nodev,			/* reset */
	&sdt_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev			/* dev power */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"Statically Defined Tracing",	/* name of module */
	&sdt_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
#else
d_open_t _sdt_open;

int _sdt_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev,flags,devtype,p)
	return 0;
}

#define SDT_MAJOR  -24 /* let the kernel pick the device number */

/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */
static struct cdevsw sdt_cdevsw =
{
	_sdt_open,		/* open */
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

static int gSDTInited = 0;
static struct modctl g_sdt_kernctl;
static struct module g_sdt_mach_module;

#include <mach-o/nlist.h>
#include <libkern/kernel_mach_header.h>

#if defined(__LP64__)
#define KERNEL_MAGIC MH_MAGIC_64
typedef struct nlist_64 kernel_nlist_t;
#else
#define KERNEL_MAGIC MH_MAGIC
typedef struct nlist kernel_nlist_t;
#endif

void sdt_init( void )
{
	if (0 == gSDTInited)
	{
		int majdevno = cdevsw_add(SDT_MAJOR, &sdt_cdevsw);
		
		if (majdevno < 0) {
			printf("sdt_init: failed to allocate a major number!\n");
			gSDTInited = 0;
			return;
		}

		if (KERNEL_MAGIC != _mh_execute_header.magic) {
        	g_sdt_kernctl.address = (vm_address_t)NULL;
        	g_sdt_kernctl.size = 0;
		} else {
		kernel_mach_header_t        *mh;
    		struct load_command         *cmd;
    		kernel_segment_command_t    *orig_ts = NULL, *orig_le = NULL;
    		struct symtab_command       *orig_st = NULL;
    		kernel_nlist_t		    *sym = NULL;
    		char                        *strings;
    		unsigned int 		    i;

		g_sdt_mach_module.sdt_nprobes = 0;
		g_sdt_mach_module.sdt_probes = NULL;

        	g_sdt_kernctl.address = (vm_address_t)&g_sdt_mach_module;
        	g_sdt_kernctl.size = 0;
		strncpy((char *)&(g_sdt_kernctl.mod_modname), "mach_kernel", KMOD_MAX_NAME);

		mh = &_mh_execute_header;
    		cmd = (struct load_command*) &mh[1];
    		for (i = 0; i < mh->ncmds; i++) {
        		if (cmd->cmd == LC_SEGMENT_KERNEL) {
            		kernel_segment_command_t *orig_sg = (kernel_segment_command_t *) cmd;

            		if (LIT_STRNEQL(orig_sg->segname, SEG_TEXT))
                		orig_ts = orig_sg;
            		else if (LIT_STRNEQL(orig_sg->segname, SEG_LINKEDIT))
                		orig_le = orig_sg;
            		else if (LIT_STRNEQL(orig_sg->segname, ""))
                		orig_ts = orig_sg; /* kexts have a single unnamed segment */
        		}
        		else if (cmd->cmd == LC_SYMTAB)
            		orig_st = (struct symtab_command *) cmd;
	
        		cmd = (struct load_command *) ((uintptr_t) cmd + cmd->cmdsize);
    		}
	
    		if ((orig_ts == NULL) || (orig_st == NULL) || (orig_le == NULL))
        		return;

		sym = (kernel_nlist_t *)(orig_le->vmaddr + orig_st->symoff - orig_le->fileoff);
		strings = (char *)(orig_le->vmaddr + orig_st->stroff - orig_le->fileoff);

    		for (i = 0; i < orig_st->nsyms; i++) {
        		uint8_t n_type = sym[i].n_type & (N_TYPE | N_EXT);
        		char *name = strings + sym[i].n_un.n_strx;
				const char *prev_name;
				unsigned long best;
				unsigned int j;

        		/* Check that the symbol is a global and that it has a name. */
        		if (((N_SECT | N_EXT) != n_type && (N_ABS | N_EXT) != n_type))
            		continue;

        		if (0 == sym[i].n_un.n_strx) /* iff a null, "", name. */
            		continue;

        		/* Lop off omnipresent leading underscore. */
        		if (*name == '_')
            		name += 1;

				if (strstr(name, DTRACE_PROBE_PREFIX)) {
					sdt_probedesc_t *sdpd = kmem_alloc(sizeof(sdt_probedesc_t), KM_SLEEP);
					int len = strlen(name) + 1;

					sdpd->sdpd_name = kmem_alloc(len, KM_SLEEP);
					strncpy(sdpd->sdpd_name, name, len); /* NUL termination is ensured. */

					prev_name = "<unknown>";
					best = 0;
					
					/* Avoid shadow build warnings */
					for (j = 0; j < orig_st->nsyms; j++) {
						uint8_t jn_type = sym[j].n_type & (N_TYPE | N_EXT);
						char *jname = strings + sym[j].n_un.n_strx;

						if (((N_SECT | N_EXT) != jn_type && (N_ABS | N_EXT) != jn_type))
							continue;

						if (0 == sym[j].n_un.n_strx) /* iff a null, "", name. */
							continue;

						if (*jname == '_')
							jname += 1;
						if (strstr(jname, DTRACE_PROBE_PREFIX))
							continue;

						if (*(unsigned long *)sym[i].n_value <= (unsigned long)sym[j].n_value)
							continue;

						if ((unsigned long)sym[j].n_value > best) {
							best = (unsigned long)sym[j].n_value;
							prev_name = jname;
						}
					}

					sdpd->sdpd_func = kmem_alloc((len = strlen(prev_name) + 1), KM_SLEEP);
					strncpy(sdpd->sdpd_func, prev_name, len); /* NUL termination is ensured. */

					sdpd->sdpd_offset = *(unsigned long *)sym[i].n_value;

					sdpd->sdpd_next = g_sdt_mach_module.sdt_probes;
					g_sdt_mach_module.sdt_probes = sdpd;
				} else {
					prev_name = name;
				}
			}
		}

		sdt_attach( (dev_info_t	*)(uintptr_t)majdevno, DDI_ATTACH );

		gSDTInited = 1;
	} else
		panic("sdt_init: called twice!\n");
}

#undef SDT_MAJOR

/*ARGSUSED*/
void
sdt_provide_module(void *arg, struct modctl *ctl)
{
#pragma unused(ctl)
#pragma unused(arg)
    __sdt_provide_module(arg, &g_sdt_kernctl);

	sdt_probedesc_t *sdpd = g_sdt_mach_module.sdt_probes;
	while (sdpd) {
		sdt_probedesc_t *this_sdpd = sdpd;
		kmem_free((void *)sdpd->sdpd_name, strlen(sdpd->sdpd_name) + 1);
		kmem_free((void *)sdpd->sdpd_func, strlen(sdpd->sdpd_func) + 1);
		sdpd = sdpd->sdpd_next;
		kmem_free((void *)this_sdpd, sizeof(sdt_probedesc_t));
	}
	g_sdt_mach_module.sdt_probes = NULL;
}

#endif /* __APPLE__ */
