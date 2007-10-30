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

/* #pragma ident	"@(#)sdt_subr.c	1.7	06/04/03 SMI" */

#include <sys/sdt_impl.h>

static dtrace_pattr_t vtrace_attr = {
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t info_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t fpu_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_CPU },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t fsinfo_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t stab_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t sdt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

sdt_provider_t sdt_providers[] = {
	{ "vtrace", "__vtrace____", &vtrace_attr, 0 },
	{ "sysinfo", "__cpu_sysinfo____", &info_attr, 0 },
	{ "vminfo", "__vminfo____", &info_attr, 0 },
	{ "fpuinfo", "__fpuinfo____", &fpu_attr, 0 },
	{ "sched", "__sched____", &stab_attr, 0 },
	{ "proc", "__proc____", &stab_attr, 0 },
	{ "io", "__io____", &stab_attr, 0 },
	{ "mib", "__mib____", &stab_attr, 0 },
	{ "fsinfo", "__fsinfo____", &fsinfo_attr, 0 },
	{ "sdt", "__sdt____", &sdt_attr, 0 },
	{ NULL }
};

#warning !!! Need xnu cognate for disp_t.
#warning !!! Need translators for bufinfo_t, cpuinfo_t, devinfo_t, fileinfo_t.
sdt_argdesc_t sdt_args[] = {
	{ "sched", "wakeup", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "wakeup", 1, 0, "struct proc *", "psinfo_t *" },
	{ "sched", "dequeue", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "dequeue", 1, 0, "struct proc *", "psinfo_t *" },
	{ "sched", "dequeue", 2, 1, "disp_t *", "cpuinfo_t *" },
	{ "sched", "enqueue", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "enqueue", 1, 0, "struct proc *", "psinfo_t *" },
	{ "sched", "enqueue", 2, 1, "disp_t *", "cpuinfo_t *" },
	{ "sched", "enqueue", 3, 2, "int", NULL },
	{ "sched", "off-cpu", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "off-cpu", 1, 0, "struct proc *", "psinfo_t *" },
	{ "sched", "tick", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "tick", 1, 0, "struct proc *", "psinfo_t *" },
	{ "sched", "change-pri", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "change-pri", 1, 0, "struct proc *", "psinfo_t *" },
	{ "sched", "change-pri", 2, 1, "pri_t", NULL },
	{ "sched", "schedctl-nopreempt", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "schedctl-nopreempt", 1, 0, "struct proc *", "psinfo_t *" },
	{ "sched", "schedctl-nopreempt", 2, 1, "int", NULL },
	{ "sched", "schedctl-preempt", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "schedctl-preempt", 1, 0, "struct proc *", "psinfo_t *" },
	{ "sched", "schedctl-yield", 0, 0, "int", NULL },
	{ "sched", "surrender", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "sched", "surrender", 1, 0, "struct proc *", "psinfo_t *" },

	{ "proc", "create", 0, 0, "struct proc *", "psinfo_t *" },
	{ "proc", "exec", 0, 0, "string", NULL },
	{ "proc", "exec-failure", 0, 0, "int", NULL },
	/* proc:::exec-success has no arguments */
	{ "proc", "exit", 0, 0, "int", NULL },
	{ "proc", "fault", 0, 0, "int", NULL },
	{ "proc", "fault", 1, 1, "siginfo_t *", NULL },
	{ "proc", "lwp-create", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "proc", "lwp-create", 1, 1, "struct proc *", "psinfo_t *" },
	/* proc:::lwp-start has no arguments */
	/* proc:::lwp-exit has no arguments */
	{ "proc", "signal-clear", 0, 0, "int", NULL },
	{ "proc", "signal-clear", 1, 1, "siginfo_t *", NULL },
	{ "proc", "signal-discard", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "proc", "signal-discard", 1, 1, "struct proc *", "psinfo_t *" },
	{ "proc", "signal-discard", 2, 2, "int", NULL },
	{ "proc", "signal-handle", 0, 0, "int", NULL },
	{ "proc", "signal-handle", 1, 1, "siginfo_t *", NULL },
	{ "proc", "signal-handle", 2, 2, "void (*)(void)", NULL },
	{ "proc", "signal-send", 0, 0, "struct thread *", "lwpsinfo_t *" },
	{ "proc", "signal-send", 1, 1, "struct proc *", "psinfo_t *" },
	{ "proc", "signal-send", 2, 2, "int", NULL },
	/* proc:::start has no arguments */

	{ "io", "start", 0, 0, "struct buf *", "bufinfo_t *" },
	{ "io", "start", 1, 0, "struct buf *", "devinfo_t *" },
	{ "io", "start", 2, 0, "struct buf *", "fileinfo_t *" },
	{ "io", "done", 0, 0, "struct buf *", "bufinfo_t *" },
	{ "io", "done", 1, 0, "struct buf *", "devinfo_t *" },
	{ "io", "done", 2, 0, "struct buf *", "fileinfo_t *" },
	{ "io", "wait-start", 0, 0, "struct buf *", "bufinfo_t *" },
	{ "io", "wait-start", 1, 0, "struct buf *", "devinfo_t *" },
	{ "io", "wait-start", 2, 0, "struct buf *", "fileinfo_t *" },
	{ "io", "wait-done", 0, 0, "struct buf *", "bufinfo_t *" },
	{ "io", "wait-done", 1, 0, "struct buf *", "devinfo_t *" },
	{ "io", "wait-done", 2, 0, "struct buf *", "fileinfo_t *" },

	{ "vminfo", "anonfree", 0, 0, "int", NULL },
	{ "vminfo", "anonpgin", 0, 0, "int", NULL },
	{ "vminfo", "anonpgout", 0, 0, "int", NULL },
	{ "vminfo", "as_fault", 0, 0, "int", NULL },
	{ "vminfo", "cow_fault", 0, 0, "int", NULL },
	{ "vminfo", "dfree", 0, 0, "int", NULL },
	{ "vminfo", "execfree", 0, 0, "int", NULL },
	{ "vminfo", "execpgin", 0, 0, "int", NULL },
	{ "vminfo", "execpgout", 0, 0, "int", NULL },
	{ "vminfo", "fsfree", 0, 0, "int", NULL },
	{ "vminfo", "fspgin", 0, 0, "int", NULL },
	{ "vminfo", "fspgout", 0, 0, "int", NULL },
	{ "vminfo", "kerenl_asflt", 0, 0, "int", NULL },
	{ "vminfo", "maj_fault", 0, 0, "int", NULL },
	{ "vminfo", "pgfrec", 0, 0, "int", NULL },
	{ "vminfo", "pgin", 0, 0, "int", NULL },
	{ "vminfo", "pgout", 0, 0, "int", NULL },
	{ "vminfo", "pgpgin", 0, 0, "int", NULL },
	{ "vminfo", "pgpgout", 0, 0, "int", NULL },
	{ "vminfo", "pgrec", 0, 0, "int", NULL },
	{ "vminfo", "pgrrun", 0, 0, "int", NULL },
	{ "vminfo", "pgswapin", 0, 0, "int", NULL },
	{ "vminfo", "pgswapout", 0, 0, "int", NULL },
	{ "vminfo", "prot_fault", 0, 0, "int", NULL },
	{ "vminfo", "rev", 0, 0, "int", NULL },
	{ "vminfo", "scan", 0, 0, "int", NULL },
	{ "vminfo", "softlock", 0, 0, "int", NULL },
	{ "vminfo", "swapin", 0, 0, "int", NULL },
	{ "vminfo", "swapout", 0, 0, "int", NULL },
	{ "vminfo", "zfod", 0, 0, "int", NULL },

	{ "mib", NULL, 0, 0, "int", NULL },
	{ "fsinfo", NULL, 0, 0, "struct vnode *", "fileinfo_t *" },
	{ "fsinfo", NULL, 1, 1, "int", "int" },
	{ NULL }
};

/*ARGSUSED*/
void
sdt_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
#pragma unused(arg, id)
	sdt_probe_t *sdp = parg;
	int i;

	desc->dtargd_native[0] = '\0';
	desc->dtargd_xlate[0] = '\0';

	for (i = 0; sdt_args[i].sda_provider != NULL; i++) {
		sdt_argdesc_t *a = &sdt_args[i];

		if (strcmp(sdp->sdp_provider->sdtp_name, a->sda_provider) != 0)
			continue;

		if (a->sda_name != NULL &&
		    strcmp(sdp->sdp_name, a->sda_name) != 0)
			continue;

		if (desc->dtargd_ndx != a->sda_ndx)
			continue;

		if (a->sda_native != NULL)
			(void) strcpy(desc->dtargd_native, a->sda_native);

		if (a->sda_xlate != NULL)
			(void) strcpy(desc->dtargd_xlate, a->sda_xlate);

		desc->dtargd_mapping = a->sda_mapping;
		return;
	}

	desc->dtargd_ndx = DTRACE_ARGNONE;
}
