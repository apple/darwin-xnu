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

/* #pragma ident	"@(#)systrace.c	1.6	06/09/19 SMI" */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

#include <kern/thread.h>
#include <mach/thread_status.h>

/* XXX All of these should really be derived from syscall_sw.h */
#if defined (__x86_64__)
#define SYSCALL_CLASS_SHIFT 24
#define SYSCALL_CLASS_MASK  (0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK (~SYSCALL_CLASS_MASK)
#define I386_SYSCALL_NUMBER_MASK (0xFFFF)
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <miscfs/devfs/devfs.h>

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/systrace_args.h>
#include "systrace.h"
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/user.h>

#include <machine/pal_routines.h>

#if defined (__x86_64__)
#define	SYSTRACE_ARTIFICIAL_FRAMES	2
#define MACHTRACE_ARTIFICIAL_FRAMES 3
#elif defined(__arm__) || defined(__arm64__)
#define SYSTRACE_ARTIFICIAL_FRAMES  2
#define MACHTRACE_ARTIFICIAL_FRAMES 3
#else
#error Unknown Architecture
#endif

#define SYSTRACE_NARGS (int)(sizeof(((uthread_t)NULL)->uu_arg) / sizeof(((uthread_t)NULL)->uu_arg[0]))

#include <sys/sysent.h>
#define sy_callc sy_call /* Map Solaris slot name to Darwin's */
#define NSYSCALL nsysent /* and is less than 500 or so */

extern const char *syscallnames[];

#include <sys/dtrace_glue.h>
#define casptr dtrace_casptr
#define membar_enter dtrace_membar_producer

#define LOADABLE_SYSCALL(a) 0 /* Not pertinent to Darwin. */
#define LOADED_SYSCALL(a) 1 /* Not pertinent to Darwin. */

extern lck_attr_t* dtrace_lck_attr;
extern lck_grp_t* dtrace_lck_grp;
static lck_mtx_t	dtrace_systrace_lock;		/* probe state lock */

systrace_sysent_t *systrace_sysent = NULL;
void (*systrace_probe)(dtrace_id_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t systrace_getargval(void *, dtrace_id_t, void *, int, int);
static void systrace_getargdesc(void *, dtrace_id_t, void *, dtrace_argdesc_t *);

void
systrace_stub(dtrace_id_t id, uint64_t arg0, uint64_t arg1,
    uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
#pragma unused(id,arg0,arg1,arg2,arg3,arg4)
}

int32_t
dtrace_systrace_syscall(struct proc *pp, void *uap, int *rv)
{
	unsigned short      code;	/* The system call number */

	systrace_sysent_t *sy;
	dtrace_id_t id;
	int32_t rval;
	syscall_arg_t *ip = (syscall_arg_t *)uap;
	uint64_t uargs[SYSTRACE_NARGS] = {0};

#if defined (__x86_64__)
	{
		pal_register_cache_state(current_thread(), VALID);
		x86_saved_state_t   *tagged_regs = (x86_saved_state_t *)find_user_regs(current_thread());

		if (is_saved_state64(tagged_regs)) {
			x86_saved_state64_t *regs = saved_state64(tagged_regs);
			code = regs->rax & SYSCALL_NUMBER_MASK;
			/*
			 * Check for indirect system call... system call number
			 * passed as 'arg0'
			 */
			if (code == 0) {
				code = regs->rdi;
			}
		} else {
			code = saved_state32(tagged_regs)->eax & I386_SYSCALL_NUMBER_MASK;

			if (code == 0) {
				vm_offset_t params = (vm_offset_t) (saved_state32(tagged_regs)->uesp + sizeof (int));
				code = fuword(params);
			}
		}
	}
#elif defined(__arm__)
	{
		/*
		 * On arm, syscall numbers depend on a flavor (indirect or not)
		 * and can be in either r0 or r12  (always u32)
		 */

		/* See bsd/dev/arm/systemcalls.c:arm_get_syscall_number */
		arm_saved_state_t *arm_regs = (arm_saved_state_t *) find_user_regs(current_thread());

		/* Check for indirect system call */
		if (arm_regs->r[12] != 0)
			code = arm_regs->r[12];
		else
			code = arm_regs->r[0];
	}
#elif defined(__arm64__)
	{
		/*
		 * On arm64, syscall numbers depend on a flavor (indirect or not)
		 * ... and for u32 can be in either r0 or r12
		 * ... and for u64 can be in either x0 or x16
		 */

		/* see bsd/dev/arm/systemcalls.c:arm_get_syscall_number */		
		arm_saved_state_t *arm_regs = (arm_saved_state_t *) find_user_regs(current_thread());

		if (is_saved_state32(arm_regs)) {
			/* Check for indirect system call */			
			if (saved_state32(arm_regs)->r[12] != 0) {
				code = saved_state32(arm_regs)->r[12];
			}
			else {
				code = saved_state32(arm_regs)->r[0];
			}
		} else {
			/* Check for indirect system call */
			if (saved_state64(arm_regs)->x[ARM64_SYSCALL_CODE_REG_NUM] != 0 ) {
				code = saved_state64(arm_regs)->x[ARM64_SYSCALL_CODE_REG_NUM];
			}
			else {
				code = saved_state64(arm_regs)->x[0];
			}
		}
	}
#else
#error Unknown Architecture
#endif

	// Bounds "check" the value of code a la unix_syscall
	sy = (code >= nsysent) ? &systrace_sysent[SYS_invalid] : &systrace_sysent[code];

	systrace_args(code, ip, uargs);

	if ((id = sy->stsy_entry) != DTRACE_IDNONE) {
		uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());		
		if (uthread)
			uthread->t_dtrace_syscall_args = uargs;
		
		static_assert(SYSTRACE_NARGS >= 5, "not enough system call arguments");
		(*systrace_probe)(id, uargs[0], uargs[1], uargs[2], uargs[3], uargs[4]);
		
		if (uthread)
			uthread->t_dtrace_syscall_args = NULL;
	}



#if 0 /* XXX */
	/*
	 * APPLE NOTE: Not implemented.
	 * We want to explicitly allow DTrace consumers to stop a process
	 * before it actually executes the meat of the syscall.
	 */
	p = ttoproc(curthread);
	mutex_enter(&p->p_lock);
	if (curthread->t_dtrace_stop && !curthread->t_lwp->lwp_nostop) {
		curthread->t_dtrace_stop = 0;
		stop(PR_REQUESTED, 0);
	}
	mutex_exit(&p->p_lock);
#endif

	rval = (*sy->stsy_underlying)(pp, uap, rv);

	if ((id = sy->stsy_return) != DTRACE_IDNONE) {
		uint64_t munged_rv0, munged_rv1;
    	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());

		if (uthread)
			uthread->t_dtrace_errno = rval; /* Establish t_dtrace_errno now in case this enabling refers to it. */

		/*
	 	 * "Decode" rv for use in the call to dtrace_probe()
	 	 */
		if (rval == ERESTART) {
			munged_rv0 = -1LL; /* System call will be reissued in user mode. Make DTrace report a -1 return. */
			munged_rv1 = -1LL;
		} else if (rval != EJUSTRETURN) {
			if (rval) {
				munged_rv0 = -1LL; /* Mimic what libc will do. */
				munged_rv1 = -1LL;
			} else {
				switch (sy->stsy_return_type) {
				case _SYSCALL_RET_INT_T:
					munged_rv0 = rv[0];
					munged_rv1 = rv[1];
					break;
				case _SYSCALL_RET_UINT_T:
					munged_rv0 = ((u_int)rv[0]);
					munged_rv1 = ((u_int)rv[1]);
					break;
				case _SYSCALL_RET_OFF_T:
				case _SYSCALL_RET_UINT64_T:
					munged_rv0 = *(u_int64_t *)rv;
					munged_rv1 = 0LL;
					break;
				case _SYSCALL_RET_ADDR_T:
				case _SYSCALL_RET_SIZE_T:
				case _SYSCALL_RET_SSIZE_T:
					munged_rv0 = *(user_addr_t *)rv;
					munged_rv1 = 0LL;
					break;
				case _SYSCALL_RET_NONE:
					munged_rv0 = 0LL;
					munged_rv1 = 0LL;
					break;
				default:
					munged_rv0 = 0LL;
					munged_rv1 = 0LL;
					break;
				}
			}
		} else {
			munged_rv0 = 0LL;
			munged_rv1 = 0LL;
		}

		/*
		 * <http://mail.opensolaris.org/pipermail/dtrace-discuss/2007-January/003276.html> says:
		 *
		 * "This is a bit of an historical artifact. At first, the syscall provider just
		 * had its return value in arg0, and the fbt and pid providers had their return
		 * values in arg1 (so that we could use arg0 for the offset of the return site).
		 * 
		 * We inevitably started writing scripts where we wanted to see the return
		 * values from probes in all three providers, and we made this script easier
		 * to write by replicating the syscall return values in arg1 to match fbt and
		 * pid. We debated briefly about removing the return value from arg0, but
		 * decided that it would be less confusing to have the same data in two places
		 * than to have some non-helpful, non-intuitive value in arg0.
		 * 
		 * This change was made 4/23/2003 according to the DTrace project's putback log."
		 */ 
		(*systrace_probe)(id, munged_rv0, munged_rv0, munged_rv1, (uint64_t)rval, 0);
	}

	return (rval);
}

void
dtrace_systrace_syscall_return(unsigned short code, int rval, int *rv)
{
	systrace_sysent_t *sy;
	dtrace_id_t id;

	// Bounds "check" the value of code a la unix_syscall_return
	sy = (code >= nsysent) ? &systrace_sysent[SYS_invalid] : &systrace_sysent[code];

	if ((id = sy->stsy_return) != DTRACE_IDNONE) {
		uint64_t munged_rv0, munged_rv1;
    	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());

		if (uthread)
			uthread->t_dtrace_errno = rval; /* Establish t_dtrace_errno now in case this enabling refers to it. */

		/*
	 	 * "Decode" rv for use in the call to dtrace_probe()
	 	 */
		if (rval == ERESTART) {
			munged_rv0 = -1LL; /* System call will be reissued in user mode. Make DTrace report a -1 return. */
			munged_rv1 = -1LL;
		} else if (rval != EJUSTRETURN) {
			if (rval) {
				munged_rv0 = -1LL; /* Mimic what libc will do. */
				munged_rv1 = -1LL;
			} else {
				switch (sy->stsy_return_type) {
				case _SYSCALL_RET_INT_T:
					munged_rv0 = rv[0];
					munged_rv1 = rv[1];
					break;
				case _SYSCALL_RET_UINT_T:
					munged_rv0 = ((u_int)rv[0]);
					munged_rv1 = ((u_int)rv[1]);
					break;
				case _SYSCALL_RET_OFF_T:
				case _SYSCALL_RET_UINT64_T:
					munged_rv0 = *(u_int64_t *)rv;
					munged_rv1 = 0LL;
					break;
				case _SYSCALL_RET_ADDR_T:
				case _SYSCALL_RET_SIZE_T:
				case _SYSCALL_RET_SSIZE_T:
					munged_rv0 = *(user_addr_t *)rv;
					munged_rv1 = 0LL;
					break;
				case _SYSCALL_RET_NONE:
					munged_rv0 = 0LL;
					munged_rv1 = 0LL;
					break;
				default:
					munged_rv0 = 0LL;
					munged_rv1 = 0LL;
					break;
				}
			}
		} else {
			munged_rv0 = 0LL;
			munged_rv1 = 0LL;
		}

		(*systrace_probe)(id, munged_rv0, munged_rv0, munged_rv1, (uint64_t)rval, 0);
	}
}

#define	SYSTRACE_SHIFT			16
#define	SYSTRACE_ISENTRY(x)		((int)(x) >> SYSTRACE_SHIFT)
#define	SYSTRACE_SYSNUM(x)		((int)(x) & ((1 << SYSTRACE_SHIFT) - 1))
#define	SYSTRACE_ENTRY(id)		((1 << SYSTRACE_SHIFT) | (id))
#define	SYSTRACE_RETURN(id)		(id)

#if ((1 << SYSTRACE_SHIFT) <= NSYSCALL)
#error 1 << SYSTRACE_SHIFT must exceed number of system calls
#endif

static dev_info_t *systrace_devi;
static dtrace_provider_id_t systrace_id;

/*
 * APPLE NOTE: Avoid name clash with Darwin automagic conf symbol.
 * See balanced undef below.
 */
#define systrace_init _systrace_init

static void
systrace_init(struct sysent *actual, systrace_sysent_t **interposed)
{

	systrace_sysent_t *ssysent = *interposed;  /* Avoid sysent shadow warning
							   from bsd/sys/sysent.h */
	unsigned int i;

	if (ssysent == NULL) {
		*interposed = ssysent = kmem_zalloc(sizeof (systrace_sysent_t) *
		    NSYSCALL, KM_SLEEP);
	}

	for (i = 0; i < NSYSCALL; i++) {
		struct sysent *a = &actual[i];
		systrace_sysent_t *s = &ssysent[i];

		if (LOADABLE_SYSCALL(a) && !LOADED_SYSCALL(a))
			continue;

		if (a->sy_callc == dtrace_systrace_syscall)
			continue;

		s->stsy_underlying = a->sy_callc;
		s->stsy_return_type = a->sy_return_type;
	}
	lck_mtx_init(&dtrace_systrace_lock, dtrace_lck_grp, dtrace_lck_attr);
}


/*ARGSUSED*/
static void
systrace_provide(void *arg, const dtrace_probedesc_t *desc)
{
#pragma unused(arg) /* __APPLE__ */
	unsigned int i;

	if (desc != NULL)
		return;

	systrace_init(sysent, &systrace_sysent);

	for (i = 0; i < NSYSCALL; i++) {
		if (systrace_sysent[i].stsy_underlying == NULL)
			continue;

		if (dtrace_probe_lookup(systrace_id, NULL,
		    syscallnames[i], "entry") != 0)
			continue;

		(void) dtrace_probe_create(systrace_id, NULL, syscallnames[i],
		    "entry", SYSTRACE_ARTIFICIAL_FRAMES,
		    (void *)((uintptr_t)SYSTRACE_ENTRY(i)));
		(void) dtrace_probe_create(systrace_id, NULL, syscallnames[i],
		    "return", SYSTRACE_ARTIFICIAL_FRAMES,
		    (void *)((uintptr_t)SYSTRACE_RETURN(i)));

		systrace_sysent[i].stsy_entry = DTRACE_IDNONE;
		systrace_sysent[i].stsy_return = DTRACE_IDNONE;
	}
}
#undef systrace_init

/*ARGSUSED*/
static void
systrace_destroy(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id) /* __APPLE__ */

	int sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);

#pragma unused(sysnum)  /* __APPLE__ */
	/*
	 * There's nothing to do here but assert that we have actually been
	 * disabled.
	 */
	if (SYSTRACE_ISENTRY((uintptr_t)parg)) {
		ASSERT(systrace_sysent[sysnum].stsy_entry == DTRACE_IDNONE);
	} else {
		ASSERT(systrace_sysent[sysnum].stsy_return == DTRACE_IDNONE);
	}
}

/*ARGSUSED*/
static int
systrace_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg) /* __APPLE__ */
    
	int sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	int enabled = (systrace_sysent[sysnum].stsy_entry != DTRACE_IDNONE ||
	    systrace_sysent[sysnum].stsy_return != DTRACE_IDNONE);

	if (SYSTRACE_ISENTRY((uintptr_t)parg)) {
		systrace_sysent[sysnum].stsy_entry = id;
	} else {
		systrace_sysent[sysnum].stsy_return = id;
	}

	if (enabled) {
		ASSERT(sysent[sysnum].sy_callc == dtrace_systrace_syscall);
		return(0);
	}

	lck_mtx_lock(&dtrace_systrace_lock);
	if (sysent[sysnum].sy_callc == systrace_sysent[sysnum].stsy_underlying) {
		vm_offset_t dss = (vm_offset_t)&dtrace_systrace_syscall;
		ml_nofault_copy((vm_offset_t)&dss, (vm_offset_t)&sysent[sysnum].sy_callc, sizeof(vm_offset_t));
	}
	lck_mtx_unlock(&dtrace_systrace_lock);
	return (0);
}

/*ARGSUSED*/
static void
systrace_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id) /* __APPLE__ */
    
	int sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	int disable = (systrace_sysent[sysnum].stsy_entry == DTRACE_IDNONE ||
	    systrace_sysent[sysnum].stsy_return == DTRACE_IDNONE);

	if (disable) {
		lck_mtx_lock(&dtrace_systrace_lock);
		if (sysent[sysnum].sy_callc == dtrace_systrace_syscall)
			ml_nofault_copy((vm_offset_t)&systrace_sysent[sysnum].stsy_underlying, (vm_offset_t)&sysent[sysnum].sy_callc, sizeof(systrace_sysent[sysnum].stsy_underlying));
		lck_mtx_unlock(&dtrace_systrace_lock);

	}

	if (SYSTRACE_ISENTRY((uintptr_t)parg)) {
		systrace_sysent[sysnum].stsy_entry = DTRACE_IDNONE;
	} else {
		systrace_sysent[sysnum].stsy_return = DTRACE_IDNONE;
	}
}

static dtrace_pattr_t systrace_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pops_t systrace_pops = {
	systrace_provide,
	NULL,
	systrace_enable,
	systrace_disable,
	NULL,
	NULL,
	systrace_getargdesc,
	systrace_getargval,
	NULL,
	systrace_destroy
};

static int
systrace_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	systrace_probe = (void(*))&dtrace_probe;
	membar_enter();

	if (ddi_create_minor_node(devi, "systrace", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE ||
	    dtrace_register("syscall", &systrace_attr, DTRACE_PRIV_USER, NULL,
	    &systrace_pops, NULL, &systrace_id) != 0) {
		systrace_probe = systrace_stub;
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	systrace_devi = devi;

	return (DDI_SUCCESS);
}


/*
 * APPLE NOTE:  systrace_detach not implemented
 */
#if !defined(__APPLE__)
static int
systrace_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (dtrace_unregister(systrace_id) != 0)
		return (DDI_FAILURE);

	ddi_remove_minor_node(devi, NULL);
	systrace_probe = systrace_stub;
	return (DDI_SUCCESS);
}
#endif /* __APPLE__ */


typedef kern_return_t (*mach_call_t)(void *);

/* APPLE NOTE: From #include <kern/syscall_sw.h> which may be changed for 64 bit! */
typedef void    mach_munge_t(void *);

typedef struct {
	int			mach_trap_arg_count;
	kern_return_t		(*mach_trap_function)(void *);
#if defined(__arm64__) || defined(__x86_64__)
	mach_munge_t		*mach_trap_arg_munge32; /* system call arguments for 32-bit */
#endif
	int			mach_trap_u32_words;
#if	MACH_ASSERT
	const char*		mach_trap_name;
#endif /* MACH_ASSERT */
} mach_trap_t;

extern const mach_trap_t              mach_trap_table[]; /* syscall_sw.h now declares this as const */
extern int                      mach_trap_count;

extern const char *mach_syscall_name_table[];

/* XXX From osfmk/i386/bsd_i386.c */
struct mach_call_args {
        syscall_arg_t arg1;
        syscall_arg_t arg2;
        syscall_arg_t arg3;
        syscall_arg_t arg4;
        syscall_arg_t arg5;
        syscall_arg_t arg6;
        syscall_arg_t arg7;
        syscall_arg_t arg8;
        syscall_arg_t arg9;
};

#undef NSYSCALL
#define NSYSCALL mach_trap_count

#if ((1 << SYSTRACE_SHIFT) <= NSYSCALL)
#error 1 << SYSTRACE_SHIFT must exceed number of Mach traps
#endif

typedef struct machtrace_sysent {
	dtrace_id_t	stsy_entry;
	dtrace_id_t	stsy_return;
	kern_return_t	(*stsy_underlying)(void *);
	int32_t		stsy_return_type;
} machtrace_sysent_t;

static machtrace_sysent_t *machtrace_sysent = NULL;

void (*machtrace_probe)(dtrace_id_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t);

static uint64_t machtrace_getarg(void *, dtrace_id_t, void *, int, int);	

static dev_info_t *machtrace_devi;
static dtrace_provider_id_t machtrace_id;

static kern_return_t
dtrace_machtrace_syscall(struct mach_call_args *args)
{
	int code;	/* The mach call number */

	machtrace_sysent_t *sy;
	dtrace_id_t id;
	kern_return_t rval;
#if 0 /* XXX */
	proc_t *p;
#endif
	syscall_arg_t *ip = (syscall_arg_t *)args;
	mach_call_t mach_call;

#if defined (__x86_64__)
	{
		pal_register_cache_state(current_thread(), VALID);
		x86_saved_state_t   *tagged_regs = (x86_saved_state_t *)find_user_regs(current_thread());

		if (is_saved_state64(tagged_regs)) {
			code = saved_state64(tagged_regs)->rax & SYSCALL_NUMBER_MASK;
		} else {
			code = -saved_state32(tagged_regs)->eax;
		}
	}
#elif defined(__arm__)
	{
		/* r12 has the machcall number, but it is -ve */
		arm_saved_state_t *arm_regs = (arm_saved_state_t *) find_user_regs(current_thread());
		code = (int)arm_regs->r[12];
		ASSERT(code < 0);    /* Otherwise it would be a Unix syscall */
		code = -code;
	}
#elif defined(__arm64__)
	{
		/* From arm/thread_status.h:get_saved_state_svc_number */
		arm_saved_state_t *arm_regs = (arm_saved_state_t *) find_user_regs(current_thread());
		if (is_saved_state32(arm_regs)) {
			code = (int)saved_state32(arm_regs)->r[12];
		} else {
			code = (int)saved_state64(arm_regs)->x[ARM64_SYSCALL_CODE_REG_NUM];
		}

                /* From bsd/arm64.c:mach_syscall */
		ASSERT(code < 0);    /* Otherwise it would be a Unix syscall */
		code = -code;		
	}
#else
#error Unknown Architecture
#endif

	sy = &machtrace_sysent[code];

	if ((id = sy->stsy_entry) != DTRACE_IDNONE) {
		uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());	

		if (uthread)
			uthread->t_dtrace_syscall_args = (void *)ip;
		
		(*machtrace_probe)(id, *ip, *(ip+1), *(ip+2), *(ip+3), *(ip+4));
		
		if (uthread)
			uthread->t_dtrace_syscall_args = (void *)0;		
	}

#if 0 /* XXX */
	/*
	 * APPLE NOTE:  Not implemented.
	 * We want to explicitly allow DTrace consumers to stop a process
	 * before it actually executes the meat of the syscall.
	 */
	p = ttoproc(curthread);
	mutex_enter(&p->p_lock);
	if (curthread->t_dtrace_stop && !curthread->t_lwp->lwp_nostop) {
		curthread->t_dtrace_stop = 0;
		stop(PR_REQUESTED, 0);
	}
	mutex_exit(&p->p_lock);
#endif

	mach_call = (mach_call_t)(*sy->stsy_underlying);
	rval = mach_call(args);

	if ((id = sy->stsy_return) != DTRACE_IDNONE)
		(*machtrace_probe)(id, (uint64_t)rval, 0, 0, 0, 0);

	return (rval);
}

static void
machtrace_init(const mach_trap_t *actual, machtrace_sysent_t **interposed)
{
	machtrace_sysent_t *msysent = *interposed;
	int i;

	if (msysent == NULL) {
		*interposed = msysent = kmem_zalloc(sizeof (machtrace_sysent_t) *
				NSYSCALL, KM_SLEEP);
	}

	for (i = 0; i < NSYSCALL; i++) {
		const mach_trap_t *a = &actual[i];
		machtrace_sysent_t *s = &msysent[i];

		if (LOADABLE_SYSCALL(a) && !LOADED_SYSCALL(a))
			continue;

		if (a->mach_trap_function == (mach_call_t)(dtrace_machtrace_syscall))
			continue;

		s->stsy_underlying = a->mach_trap_function;
	}
}

/*ARGSUSED*/
static void
machtrace_provide(void *arg, const dtrace_probedesc_t *desc)
{
#pragma unused(arg) /* __APPLE__ */
    
	int i;

	if (desc != NULL)
		return;

	machtrace_init(mach_trap_table, &machtrace_sysent);

	for (i = 0; i < NSYSCALL; i++) {
		
		if (machtrace_sysent[i].stsy_underlying == NULL)
			continue;

		if (dtrace_probe_lookup(machtrace_id, NULL,
					mach_syscall_name_table[i], "entry") != 0)
			continue;

		(void) dtrace_probe_create(machtrace_id, NULL, mach_syscall_name_table[i],
					   "entry", MACHTRACE_ARTIFICIAL_FRAMES,
					   (void *)((uintptr_t)SYSTRACE_ENTRY(i)));
		(void) dtrace_probe_create(machtrace_id, NULL, mach_syscall_name_table[i],
					   "return", MACHTRACE_ARTIFICIAL_FRAMES,
					   (void *)((uintptr_t)SYSTRACE_RETURN(i)));

		machtrace_sysent[i].stsy_entry = DTRACE_IDNONE;
		machtrace_sysent[i].stsy_return = DTRACE_IDNONE;
	}
}

/*ARGSUSED*/
static void
machtrace_destroy(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id) /* __APPLE__ */
	int sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	
#pragma unused(sysnum) /* __APPLE__ */

	/*
	 * There's nothing to do here but assert that we have actually been
	 * disabled.
	 */
	if (SYSTRACE_ISENTRY((uintptr_t)parg)) {
		ASSERT(machtrace_sysent[sysnum].stsy_entry == DTRACE_IDNONE);
	} else {
		ASSERT(machtrace_sysent[sysnum].stsy_return == DTRACE_IDNONE);
	}
}

/*ARGSUSED*/
static int
machtrace_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg) /* __APPLE__ */
    
	int sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	int enabled = (machtrace_sysent[sysnum].stsy_entry != DTRACE_IDNONE ||
			machtrace_sysent[sysnum].stsy_return != DTRACE_IDNONE);

	if (SYSTRACE_ISENTRY((uintptr_t)parg)) {
		machtrace_sysent[sysnum].stsy_entry = id;
	} else {
		machtrace_sysent[sysnum].stsy_return = id;
	}

	if (enabled) {
	    ASSERT(mach_trap_table[sysnum].mach_trap_function == (void *)dtrace_machtrace_syscall);
	    return(0);
	}

	lck_mtx_lock(&dtrace_systrace_lock);

	if (mach_trap_table[sysnum].mach_trap_function == machtrace_sysent[sysnum].stsy_underlying) {
		vm_offset_t dss = (vm_offset_t)&dtrace_machtrace_syscall;
		ml_nofault_copy((vm_offset_t)&dss, (vm_offset_t)&mach_trap_table[sysnum].mach_trap_function, sizeof(vm_offset_t));
	}

	lck_mtx_unlock(&dtrace_systrace_lock);

	return(0);
}

/*ARGSUSED*/
static void
machtrace_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id) /* __APPLE__ */
      
	int sysnum = SYSTRACE_SYSNUM((uintptr_t)parg);
	int disable = (machtrace_sysent[sysnum].stsy_entry == DTRACE_IDNONE ||
			machtrace_sysent[sysnum].stsy_return == DTRACE_IDNONE);

	if (disable) {

		lck_mtx_lock(&dtrace_systrace_lock);

		if (mach_trap_table[sysnum].mach_trap_function == (mach_call_t)dtrace_machtrace_syscall) {
			ml_nofault_copy((vm_offset_t)&machtrace_sysent[sysnum].stsy_underlying, (vm_offset_t)&mach_trap_table[sysnum].mach_trap_function, sizeof(vm_offset_t));
		}
		lck_mtx_unlock(&dtrace_systrace_lock);
	}

	if (SYSTRACE_ISENTRY((uintptr_t)parg)) {
		machtrace_sysent[sysnum].stsy_entry = DTRACE_IDNONE;
	} else {
		machtrace_sysent[sysnum].stsy_return = DTRACE_IDNONE;
	}
}

static dtrace_pattr_t machtrace_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pops_t machtrace_pops = {
	machtrace_provide,
	NULL,
	machtrace_enable,
	machtrace_disable,
	NULL,
	NULL,
	NULL,
	machtrace_getarg,
	NULL,
	machtrace_destroy
};

static int
machtrace_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
		case DDI_ATTACH:
			break;
		case DDI_RESUME:
			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
	}

	machtrace_probe = dtrace_probe;
	membar_enter();
	
	if (ddi_create_minor_node(devi, "machtrace", S_IFCHR, 0,
				DDI_PSEUDO, 0) == DDI_FAILURE ||
			dtrace_register("mach_trap", &machtrace_attr, DTRACE_PRIV_USER, NULL,
				&machtrace_pops, NULL, &machtrace_id) != 0) {
                machtrace_probe = (void (*))&systrace_stub;
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	machtrace_devi = devi;

	return (DDI_SUCCESS);
}

d_open_t _systrace_open;

int _systrace_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev,flags,devtype,p)
	return 0;
}

#define SYSTRACE_MAJOR  -24 /* let the kernel pick the device number */

/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */
static struct cdevsw systrace_cdevsw =
{
	_systrace_open,		/* open */
	eno_opcl,		/* close */
	eno_rdwrt,			/* read */
	eno_rdwrt,			/* write */
	eno_ioctl,		/* ioctl */
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

static int gSysTraceInited = 0;

void systrace_init( void );

void systrace_init( void )
{
	if (0 == gSysTraceInited) {
		if (dtrace_sdt_probes_restricted()) {
			return;
		}

		int majdevno = cdevsw_add(SYSTRACE_MAJOR, &systrace_cdevsw);

		if (majdevno < 0) {
			printf("systrace_init: failed to allocate a major number!\n");
			gSysTraceInited = 0;
			return;
		}

		systrace_attach( (dev_info_t	*)(uintptr_t)majdevno, DDI_ATTACH );
		machtrace_attach( (dev_info_t	*)(uintptr_t)majdevno, DDI_ATTACH );

		gSysTraceInited = 1;
	} else
		panic("systrace_init: called twice!\n");
}
#undef SYSTRACE_MAJOR

static uint64_t
systrace_getargval(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
#pragma unused(arg,id,parg,aframes)     /* __APPLE__ */
	uint64_t val = 0;
	uint64_t *uargs = NULL;

	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());	

	if (uthread)
		uargs = uthread->t_dtrace_syscall_args;
	if (!uargs)
		return(0);
	if (argno < 0 || argno > SYSTRACE_NARGS)
		return(0);

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	val = uargs[argno];
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
	return (val);
}

static void
systrace_getargdesc(void *arg, dtrace_id_t id, void *parg,
	dtrace_argdesc_t *desc)
{
#pragma unused(arg, id)
	int sysnum = SYSTRACE_SYSNUM(parg);
	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());
	uint64_t *uargs = NULL;

	if (!uthread) {
		desc->dtargd_ndx = DTRACE_ARGNONE;
		return;
	}

	uargs = uthread->t_dtrace_syscall_args;

	if (SYSTRACE_ISENTRY((uintptr_t)parg)) {
		systrace_entry_setargdesc(sysnum, desc->dtargd_ndx,
			desc->dtargd_native, sizeof(desc->dtargd_native));
	}
	else {
		systrace_return_setargdesc(sysnum, desc->dtargd_ndx,
			desc->dtargd_native, sizeof(desc->dtargd_native));
	}

	if (desc->dtargd_native[0] == '\0')
		desc->dtargd_ndx = DTRACE_ARGNONE;
}

static uint64_t
machtrace_getarg(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
#pragma unused(arg,id,parg,aframes)     /* __APPLE__ */
	uint64_t val = 0;
	syscall_arg_t *stack = (syscall_arg_t *)NULL;

	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());
	
	if (uthread)
		stack = (syscall_arg_t *)uthread->t_dtrace_syscall_args;
	
	if (!stack)
		return(0);

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	/* dtrace_probe arguments arg0 .. arg4 are 64bits wide */
	val = (uint64_t)*(stack+argno);	
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
	return (val);
}

